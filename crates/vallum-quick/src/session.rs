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
const SESSION_WAIT: Duration = Duration::from_secs(20);

/// Readiness is a handshake, not an interface. A full tunnel attaches by
/// policy-routing every packet through the peer — if that peer never
/// completes a handshake the host's entire egress blackholes while the
/// unit reports success. Gate route installation on a real session: poll
/// the control socket until a peer reports a handshake, then route. Split
/// tunnels skip this — a dead /24 hurts only that subnet.
pub(crate) fn wait_for_session(
    config: &Config,
    config_path: &Path,
    interface: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let full_tunnel = config.peers.iter().any(|peer| {
        peer.allowed_ips
            .iter()
            .any(|ip| ip == "0.0.0.0/0" || ip == "::/0")
    });
    if !full_tunnel {
        return Ok(());
    }
    let socket = control_socket(config, config_path, interface);
    let started = std::time::Instant::now();
    let deadline = started + SESSION_WAIT;
    let mut reported = 0u64;
    while std::time::Instant::now() < deadline {
        if let Ok(reply) = uapi_get(&socket) {
            let established = reply
                .lines()
                .any(|line| line.starts_with("last_handshake_time_sec=") && !line.ends_with("=0"));
            if established {
                return Ok(());
            }
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
mod interface_missing_tests {
    use super::{interface_missing, INTERFACE_WAIT};

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
