// SPDX-License-Identifier: Apache-2.0

//! Readiness: wait for an interface to exist and for the daemon to complete a
//! handshake before any host-level work is applied.
//!
//! Stored verbatim from the original single-file layout; see `main.rs` for
//! how a command drives these.

use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use vallum_config::Config;

/// How long `attach` waits for a `pre_up` hook to create the interface.
///
/// The timeout is one constant because the failure message quotes it: two
/// copies of "5 seconds" would drift, and the message would then describe a
/// wait that no longer happens.
pub(crate) const INTERFACE_WAIT: Duration = Duration::from_secs(5);

/// How often to look, while waiting.
const INTERFACE_POLL: Duration = Duration::from_millis(100);

/// Wait for an interface that something else is expected to create.
///
/// This function never creates one. `attach` runs the config's `pre_up` hooks
/// and calls this to wait for their result, so a timeout means the hooks did
/// not do their job — which is why the caller explains it rather than this
/// function guessing.
pub(crate) fn wait_for_interface(interface: &str) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + INTERFACE_WAIT;
    while Instant::now() < deadline {
        let status = Command::new("ip")
            .args(["link", "show", interface])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if status.success() {
            return Ok(());
        }
        sleep(INTERFACE_POLL);
    }
    Err(format!("interface `{interface}` did not come up").into())
}

/// Explain an interface that never appeared, in terms the operator can act on.
///
/// Takes the facts it needs rather than the config, so the two remedies stay
/// distinguishable without this function knowing anything about `Config`.
pub(crate) fn interface_missing(
    interface: &str,
    pre_up_count: usize,
    unit: Option<&str>,
) -> Box<dyn std::error::Error> {
    let waited = INTERFACE_WAIT.as_secs();
    if pre_up_count == 0 {
        // No unit name means the config's stem could not be read, and naming a
        // guessed `vallum@` instance would send the operator to a unit that
        // does not exist.
        return match unit {
            Some(unit) => format!(
                "interface `{interface}` did not appear within {waited}s, and no `pre_up` \
                 hook is configured, so nothing started the daemon. Start it first \
                 (`systemctl start vallum@{unit}`), or add a `pre_up` hook to [quick]."
            )
            .into(),
            None => format!(
                "interface `{interface}` did not appear within {waited}s, and no `pre_up` \
                 hook is configured, so nothing started the daemon. Start it first, or \
                 add a `pre_up` hook to [quick]."
            )
            .into(),
        };
    }
    format!(
        "interface `{interface}` did not appear within {waited}s of running {pre_up_count} \
         `pre_up` hook(s); check the daemon's log for why it exited"
    )
    .into()
}

/// Long enough for several handshake retries before a dead server is
/// declared; short enough that a failed unit reports promptly.
/// How long `attach` waits for a handshake before refusing to route a full
/// tunnel. 45 s, not 20: a fresh daemon's first handshake can legitimately take
/// longer than 20 s on a slow uplink, and a false refusal leaves the host
/// un-routed while the egress guard is already on — which is a machine with no
/// internet, not a machine with a dead tunnel.
const SESSION_WAIT: Duration = Duration::from_secs(45);

/// Readiness is a handshake, not an interface. A full tunnel attaches by
/// policy-routing every packet through the peer — if that peer never
/// completes a handshake the host's entire egress blackholes while the
/// unit reports success. Gate route installation on a real session: poll
/// the control socket until a peer reports a handshake, then route. Split
/// tunnels skip this — a dead /24 hurts only that subnet.
///
/// `[quick] app_class` skips it too, and for the same reason: the gate guards
/// *host* routing, and the per-app path installs none. There is no host egress to
/// blackhole, the host's resolver is untouched, and a member outside the tunnel
/// fails closed by construction. Waiting here would instead break the path it is
/// meant to protect: the first handshake in per-app mode comes from the first
/// member, after the namespace exists — so `attach` before any member would
/// refuse to create the very namespace the handshake needs. It is also what makes
/// recovery possible, since a crashed holder leaves a daemon whose last handshake
/// has aged out.
fn gates_on_session(config: &Config) -> bool {
    let full_tunnel = config.peers.iter().any(|peer| {
        peer.allowed_ips
            .iter()
            .any(|ip| ip == "0.0.0.0/0" || ip == "::/0")
    });
    full_tunnel && !config.quick.app_class
}

pub(crate) fn wait_for_session(
    config: &Config,
    config_path: &Path,
    interface: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if !gates_on_session(config) {
        return Ok(());
    }
    let socket = control_socket(config, config_path, interface);
    let started = std::time::Instant::now();
    let deadline = started + SESSION_WAIT;
    let mut reported = 0u64;
    while std::time::Instant::now() < deadline {
        match uapi_get(&socket) {
            Ok(reply) => {
                let established = reply.lines().any(|line| {
                    line.starts_with("last_handshake_time_sec=") && !line.ends_with("=0")
                });
                if established {
                    return Ok(());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                // A socket we are not allowed to open is not "no handshake
                // yet" — no amount of waiting fixes permissions. Name the
                // errno and the usual cause instead of burning the window.
                return Err(format!(
                    "cannot open the control socket {}: {e} — the daemon publishes it 0600 to the tunnel's owner, and this process's capability set does not include CAP_DAC_OVERRIDE (systemd unit sandboxes trim it); fix the unit's bounding set",
                    socket.display()
                )
                .into());
            }
            Err(_) => {} // daemon starting or socket not published yet: keep waiting
        }
        // A silent wait is indistinguishable from a hang, and this one can last
        // twenty seconds. Say we are still waiting, and for how long, so the
        // user can tell "working" from "wedged" without watching a clock.
        let elapsed = started.elapsed().as_secs();
        if elapsed >= 2 && elapsed - reported >= 2 {
            reported = elapsed;
            eprintln!(
                "vallum-quick: waiting for a handshake… ({elapsed}s of {}s)",
                SESSION_WAIT.as_secs()
            );
        }
        sleep(Duration::from_millis(200));
    }
    Err(format!(
        "no peer completed a handshake within {}s — the tunnel is up but the \
         server is not answering, and routing the host's traffic into it \
         would blackhole this machine; fix the server and retry",
        SESSION_WAIT.as_secs()
    )
    .into())
}

pub(crate) fn uapi_get(socket: &Path) -> std::io::Result<String> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(b"get=1\n\n")?;
    stream.shutdown(Shutdown::Write)?;
    let mut reply = String::new();
    stream.read_to_string(&mut reply)?;
    Ok(reply)
}

/// The control socket a config's daemon listens on.
pub(crate) fn control_socket(config: &Config, config_path: &Path, interface: &str) -> PathBuf {
    config
        .interface
        .control
        .clone()
        .map(|path| {
            if path.is_relative() {
                config_path
                    .parent()
                    .unwrap_or_else(|| Path::new("/"))
                    .join(path)
            } else {
                path
            }
        })
        .unwrap_or_else(|| vallum_config::socket_path(interface))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod interface_missing_tests {
    use super::{gates_on_session, interface_missing, wait_for_session, INTERFACE_WAIT};
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use vallum_config::Config;

    fn config(text: &str) -> Config {
        // One file per call. The pid alone is shared by every test in this
        // binary, and keying the name on `text.len()` collided whenever two
        // configs were the same length: one test's cleanup removed the other's
        // file between its write and its load, which failed as a parse error in
        // a test that had nothing to do with it.
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "vallum-session-gate-{}-{}.toml",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, text).expect("test config writes");
        let parsed = Config::load(&path).expect("test config parses");
        let _ = std::fs::remove_file(&path);
        parsed
    }

    #[test]
    fn the_session_gate_is_for_host_routing_only() {
        // A full tunnel without the class routes the host, so a dead server
        // would blackhole it: gated. The same config with `app_class` installs
        // nothing on the host and is not.
        let plain = config(
            "[interface]\nname = \"e\"\nprivate_key = \"k\"\n\n[[peer]]\nname = \"p\"\n\
             public_key = \"k\"\nallowed_ips = [\"0.0.0.0/0\"]\n",
        );
        assert!(gates_on_session(&plain));

        let per_app = config(
            "[interface]\nname = \"e\"\nprivate_key = \"k\"\naddress = \"10.7.0.2/24\"\n\n\
             [quick]\napp_class = true\n\n[[peer]]\nname = \"p\"\n\
             public_key = \"k\"\nallowed_ips = [\"0.0.0.0/0\"]\n",
        );
        assert!(!gates_on_session(&per_app));

        // A split tunnel never gated, with or without the class.
        let split = config(
            "[interface]\nname = \"e\"\nprivate_key = \"k\"\n\n[[peer]]\nname = \"p\"\n\
             public_key = \"k\"\nallowed_ips = [\"10.0.0.0/8\"]\n",
        );
        assert!(!gates_on_session(&split));
    }

    #[test]
    fn a_per_app_attach_never_waits_for_a_handshake() {
        // The whole point: the first handshake comes from the first member, so
        // waiting here would deadlock the path — and it returns at once rather
        // than polling a socket that does not exist.
        let per_app = config(
            "[interface]\nname = \"e\"\nprivate_key = \"k\"\naddress = \"10.7.0.2/24\"\n\n\
             [quick]\napp_class = true\n\n[[peer]]\nname = \"p\"\n\
             public_key = \"k\"\nallowed_ips = [\"0.0.0.0/0\"]\n",
        );
        let started = std::time::Instant::now();
        assert!(wait_for_session(&per_app, Path::new("/nonexistent.toml"), "e").is_ok());
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn no_hooks_names_the_unit_to_start() {
        let message = interface_missing("vallum-laptop", 0, Some("laptop")).to_string();
        assert!(
            message.contains("systemctl start vallum@laptop"),
            "{message}"
        );
        assert!(message.contains("no `pre_up` hook"), "{message}");
    }

    #[test]
    fn an_unknown_unit_is_never_guessed() {
        // The config's stem was unreadable, so there is no unit name to give.
        // Suggesting `vallum@vallum0` would send the operator to a unit that
        // does not exist, which is worse than saying nothing.
        let message = interface_missing("vallum-laptop", 0, None).to_string();
        assert!(!message.contains("systemctl start vallum@"), "{message}");
        assert!(message.contains("Start it first"), "{message}");
    }

    #[test]
    fn hooks_are_blamed_rather_than_missing_configuration() {
        let message = interface_missing("vallum-laptop", 2, Some("laptop")).to_string();
        assert!(message.contains("2 `pre_up` hook(s)"), "{message}");
        assert!(!message.contains("no `pre_up` hook"), "{message}");
    }

    #[test]
    fn the_quoted_wait_is_the_constant() {
        // The whole point of INTERFACE_WAIT is that the message cannot drift
        // from the behaviour; this fails the moment someone changes one only.
        let message = interface_missing("v", 1, None).to_string();
        assert!(
            message.contains(&format!("{}s", INTERFACE_WAIT.as_secs())),
            "{message}"
        );
    }
}
