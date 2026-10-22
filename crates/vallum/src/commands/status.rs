//! `vallum status` — the client's answer to "am I leaking?"
//!
//! Every other report Vallum produces needs the daemon alive. The case that
//! matters is the one where it is not: the process died, the interface is gone,
//! and the question is whether the host is now sending traffic in the clear.
//!
//! That answer is observable without the daemon — the guard table and the
//! interface are properties of the host, not of the process — so this verb
//! reads them directly and names which of the states the machine is in. The
//! distinction it exists to draw is **blocked** versus **leaking**: both mean
//! "the tunnel is down", and only one of them is safe.

use std::path::PathBuf;

use clap::Args;
use vallum_config::Config;

use crate::control;
use crate::error::Error;
use crate::policy::{self, GuardState, Mode};

#[derive(Debug, Args)]
pub struct StatusArgs {
    /// The config whose tunnel to report on.
    #[arg(long, short)]
    pub config: PathBuf,
    /// Machine-readable output.
    #[arg(long)]
    pub json: bool,
}

/// What the host is doing, in one word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The daemon answers and has completed a handshake.
    Up,
    /// The daemon answers but has not handshaken yet.
    Starting,
    /// The daemon is gone and the guard holds: blocked, not leaking.
    Blocked,
    /// The daemon is gone and nothing blocks: traffic is leaving in the clear.
    Leaking,
    /// The daemon is gone, nothing blocks, and this is a split tunnel — which
    /// is what the config asked for.
    Down,
    /// The daemon is gone and the guard cannot be determined from here.
    Unknown,
}

impl Verdict {
    /// The one-line answer.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Starting => "starting",
            Self::Blocked => "blocked",
            Self::Leaking => "LEAKING",
            Self::Down => "down",
            Self::Unknown => "unknown",
        }
    }

    /// Why, in a sentence a user can act on.
    #[must_use]
    pub fn detail(self) -> &'static str {
        match self {
            Self::Up => "the tunnel is up and carrying traffic",
            Self::Starting => "the daemon is running but no handshake has completed yet",
            Self::Blocked => "the daemon is not running; egress is blocked, so nothing leaks",
            Self::Leaking => {
                "the daemon is not running and no guard is installed — traffic is leaving \
                 outside the tunnel"
            }
            Self::Down => {
                "the daemon is not running; this is a split tunnel, so nothing is blocked"
            }
            Self::Unknown => {
                "the daemon is not running, and whether the guard holds cannot be read \
                 without root"
            }
        }
    }

    /// Whether this state deserves a non-zero exit code.
    #[must_use]
    pub fn is_failure(self) -> bool {
        matches!(self, Self::Leaking)
    }
}

/// Read one field from a uapi-style reply, accepting `k=v` and `k v`.
fn field<'a>(reply: &'a str, key: &str) -> Option<&'a str> {
    reply.lines().find_map(|line| {
        let line = line.trim();
        let (found, value) = match line.split_once('=') {
            Some((found, value)) => (found.trim(), value.trim()),
            None => {
                let mut parts = line.splitn(2, char::is_whitespace);
                (parts.next()?.trim(), parts.next()?.trim())
            }
        };
        (found == key).then_some(value)
    })
}

/// Decide the verdict from what is observable.
#[must_use]
pub fn verdict(live: Option<&str>, guard: GuardState, resolved: Mode) -> Verdict {
    match live {
        Some(reply) => {
            // `show` reports the handshake timestamp, not a boolean. Keying on
            // `vallum_up` alone reported a working tunnel as `starting`, because
            // that field is not in the reply at all.
            let handshaked = field(reply, "last_handshake_time_sec")
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|seconds| seconds > 0);
            if handshaked || field(reply, "vallum_up") == Some("1") {
                Verdict::Up
            } else {
                Verdict::Starting
            }
        }
        None => match guard {
            GuardState::Installed => Verdict::Blocked,
            GuardState::Absent if resolved == Mode::On => Verdict::Leaking,
            GuardState::Absent => Verdict::Down,
            GuardState::Unknown => Verdict::Unknown,
        },
    }
}

/// Run the verb.
///
/// # Errors
/// A missing config, or a config that cannot be read.
pub fn status(args: &StatusArgs) -> Result<(), Error> {
    let config = Config::load(&args.config).map_err(|source| Error::IoPath {
        action: "read the config",
        path: args.config.clone(),
        source: std::io::Error::other(source.to_string()),
    })?;
    let interface = policy::interface_name(&config);
    let socket = vallum_config::socket_path(&interface);

    // The daemon may be gone; that is the interesting case, not an error.
    let live = control::request(&socket, "get=1\n").ok();
    let guard = policy::guard_state();
    let resolved = policy::resolve(&config);
    let verdict = verdict(live.as_deref(), guard, resolved);

    if args.json {
        let report = serde_json::json!({
            "verdict": verdict.word(),
            "detail": verdict.detail(),
            "interface": interface,
            "daemon": if live.is_some() { "answering" } else { "not running" },
            "guard": match guard {
                GuardState::Installed => "installed",
                GuardState::Absent => "absent",
                GuardState::Unknown => "unknown",
            },
            "policy": match resolved {
                Mode::On => "on",
                Mode::Off => "off",
                Mode::Auto => "auto",
            },
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| Error::Usage(format!("json: {error}")))?
        );
    } else {
        println!("{:<10} {}", verdict.word(), verdict.detail());
        println!("{:<10} {interface}", "interface");
        println!(
            "{:<10} {}",
            "guard",
            match guard {
                GuardState::Installed => "installed",
                GuardState::Absent => "absent",
                GuardState::Unknown => "unknown (needs root)",
            }
        );
        println!(
            "{:<10} {}",
            "policy",
            match resolved {
                Mode::On => "on",
                Mode::Off => "off",
                Mode::Auto => "auto",
            }
        );
    }

    if verdict.is_failure() {
        return Err(Error::Usage(
            "traffic is leaving outside the tunnel; run `sudo vallum policy on` or stop the \
             interface"
                .to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_dead_daemon_with_a_guard_is_blocked_not_leaking() {
        assert_eq!(
            verdict(None, GuardState::Installed, Mode::On),
            Verdict::Blocked
        );
    }

    #[test]
    fn a_dead_daemon_with_no_guard_on_a_full_tunnel_is_leaking() {
        assert_eq!(
            verdict(None, GuardState::Absent, Mode::On),
            Verdict::Leaking
        );
        assert!(Verdict::Leaking.is_failure());
    }

    #[test]
    fn a_dead_daemon_with_no_guard_on_a_split_tunnel_is_merely_down() {
        assert_eq!(verdict(None, GuardState::Absent, Mode::Off), Verdict::Down);
        assert!(!Verdict::Down.is_failure());
    }

    #[test]
    fn an_unreadable_guard_is_not_reported_as_leaking() {
        // The whole point: not being able to look must never be mistaken for
        // evidence that nothing is there.
        assert_eq!(
            verdict(None, GuardState::Unknown, Mode::On),
            Verdict::Unknown
        );
        assert!(!Verdict::Unknown.is_failure());
    }

    #[test]
    fn a_live_daemon_reports_up_from_a_handshake() {
        let reply = "private_key=abc\nlisten_port=51820\nvallum_up=1\n";
        assert_eq!(
            verdict(Some(reply), GuardState::Absent, Mode::On),
            Verdict::Up
        );
    }

    #[test]
    fn a_handshake_timestamp_alone_means_up() {
        // What `show` actually returns on a working tunnel. The previous version
        // keyed only on `vallum_up` and reported this as `starting`.
        let reply = "endpoint=203.0.113.5:51820\nlast_handshake_time_sec=1792678349\n";
        assert_eq!(
            verdict(Some(reply), GuardState::Absent, Mode::On),
            Verdict::Up
        );
    }

    #[test]
    fn a_zero_handshake_timestamp_is_not_up() {
        let reply = "last_handshake_time_sec=0\n";
        assert_eq!(
            verdict(Some(reply), GuardState::Absent, Mode::On),
            Verdict::Starting
        );
    }

    #[test]
    fn a_live_daemon_without_a_handshake_is_starting() {
        let reply = "private_key=abc\nvallum_up=0\n";
        assert_eq!(
            verdict(Some(reply), GuardState::Absent, Mode::On),
            Verdict::Starting
        );
    }

    #[test]
    fn fields_parse_in_both_uapi_shapes() {
        assert_eq!(field("vallum_up=1\n", "vallum_up"), Some("1"));
        assert_eq!(field("vallum_up 1\n", "vallum_up"), Some("1"));
        assert_eq!(field("other=2\n", "vallum_up"), None);
    }
}
