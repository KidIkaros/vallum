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

use std::path::{Path, PathBuf};

use clap::Args;
use vallum_config::Config;
use vallum_core::timer::REJECT_AFTER_TIME_MS;

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
    /// The daemon answers, has handshaked, and is carrying traffic.
    Up,
    /// The daemon answers and has handshaked, but the tunnel is sending and not
    /// being answered. Handshake age cannot show this, which is why it exists.
    Degraded,
    /// The daemon answers, but its last handshake is older than the reject
    /// window: the session is dead even though the process is alive.
    ///
    /// Distinct from [`Self::Blocked`] on purpose — one means the *process* is
    /// gone, the other means the *session* is, and the first thing an operator
    /// does differs. Distinct from [`Self::Degraded`] because that verdict needs
    /// a delivery sample, and an idle host never produces one.
    Stale,
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
            Self::Degraded => "degraded",
            Self::Stale => "stale",
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
            Self::Degraded => {
                "the tunnel handshakes, but it is sending datagrams and not being \
                 answered — traffic is not getting through"
            }
            Self::Stale => {
                "the daemon is running, but its last handshake is past the 180 s reject \
                 window — the session is dead, so traffic is not getting through"
            }
            Self::Starting => "the daemon is running but no peer is connected yet",
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
    /// Whether traffic is leaving outside the tunnel.
    ///
    /// This is the LEAK contract, and it is deliberately narrow: a split
    /// tunnel with no daemon is not leaking (that is what a split tunnel
    /// asked for), an unreadable guard is not leaking (it is unknown), and a
    /// stale session with the guard holding is not leaking (it is blocked).
    /// Each of those has a test that says so.
    ///
    /// The question "is the tunnel working?" is a different question, and
    /// [`Self::is_working`] answers it. Both are needed: one command has one
    /// exit code, and the message it prints has to be true.
    pub fn is_failure(self) -> bool {
        matches!(self, Self::Leaking)
    }

    /// Whether the tunnel is doing its job.
    ///
    /// `Up` is a working tunnel. `Starting` is one that has not handshook yet:
    /// a daemon that is still coming up, not a broken one. Everything else is a
    /// tunnel that is not carrying — the peer is not answering (`Degraded`),
    /// the session is dead (`Stale`), the daemon is gone (`Blocked` or
    /// `Down`), or the guard cannot be determined (`Unknown`).
    ///
    /// A gate that only fails on `Leaking` says "fine" while the tunnel is
    /// dead, which is the opposite of what a user asking "am I protected?"
    /// needs to hear.
    pub fn is_working(self) -> bool {
        matches!(self, Self::Up | Self::Starting)
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

/// Datagrams below which a delivery ratio is not worth judging.
///
/// Three keepalives and a stray packet are not evidence of anything.
const DELIVERY_MIN_SAMPLE: u64 = 100;

/// Delivery below this is not carrying.
///
/// The observed failure was 0.013. A TCP bulk upload sits around 0.5 because the
/// ACKs come back, so the floor is set well under that.
const DELIVERY_FLOOR: f64 = 0.1;

/// The protocol's own reject window, in seconds.
///
/// Read from the crate that owns the timer rather than restated here: the
/// daemon declares a key spent at this point, and a report that disagreed with
/// it would be the same defect as reporting `up` from handshake presence.
const REJECT_AFTER_SECS: u64 = REJECT_AFTER_TIME_MS / 1000;

/// The oldest handshake stamp across peers that have one.
///
/// `show` returns one block per peer, and the device block carries none. The
/// oldest decides, mirroring the delivery rule's "the worst peer decides": one
/// peer whose session died is not hidden by another that is healthy, and a peer
/// that never handshook (stamp 0) is `starting`, not `stale`.
fn oldest_handshake(reply: &str) -> Option<u64> {
    reply
        .split("\n\n")
        .filter_map(|block| {
            field(block, "last_handshake_time_sec")
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|stamp| *stamp > 0)
        })
        .min()
}

/// The worst delivery ratio across peers that have sent enough to judge.
///
/// Returns `None` when no peer has a large enough sample, which is the right
/// answer for an idle tunnel: nothing sent is not the same as nothing delivered.
pub(crate) fn worst_delivery(reply: &str) -> Option<f64> {
    let mut worst: Option<f64> = None;
    for block in reply.split("\n\n") {
        let sent = field(block, "vallum_window_sent")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        if sent < DELIVERY_MIN_SAMPLE {
            continue;
        }
        let received = field(block, "vallum_window_received")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let ratio = received as f64 / sent as f64;
        worst = Some(worst.map_or(ratio, |current: f64| current.min(ratio)));
    }
    worst
}

/// Decide the verdict from what is observable.
///
/// `now` is the wall clock in Unix seconds, the same basis as the daemon's
/// `last_handshake_time_sec`. It is a parameter rather than a clock read so the
/// age rule can be tested at its boundaries.
#[must_use]
pub fn verdict(live: Option<&str>, guard: GuardState, resolved: Mode, now: u64) -> Verdict {
    match live {
        Some(reply) => {
            // `show` reports the handshake timestamp, not a boolean. Keying on
            // `vallum_up` alone reported a working tunnel as `starting`, because
            // that field is not in the reply at all.
            let handshake = oldest_handshake(reply);
            if handshake.is_none() && field(reply, "vallum_up") != Some("1") {
                return Verdict::Starting;
            }
            // A live process is not a live session. At `REJECT_AFTER_TIME` the
            // daemon stops using the key, so a stamp that old is the daemon's
            // own statement that the tunnel is dead. It is also the *only*
            // evidence an idle host has: the delivery rule needs 100 datagrams
            // sent in the window, and a quiet tunnel never sends that many —
            // which is how a laptop whose server died overnight reported `up`.
            if let Some(stamp) = handshake {
                if now.saturating_sub(stamp) >= REJECT_AFTER_SECS {
                    return Verdict::Stale;
                }
            }
            // A fresh handshake is not proof the tunnel carries anything. This
            // is the state a live deployment sat in while delivering 1 % of its
            // datagrams and reporting `up`.
            match worst_delivery(reply) {
                Some(ratio) if ratio < DELIVERY_FLOOR => Verdict::Degraded,
                _ => Verdict::Up,
            }
        }
        None => match guard {
            GuardState::Installed => Verdict::Blocked,
            GuardState::Absent if resolved.expects_guard() => Verdict::Leaking,
            GuardState::Absent => Verdict::Down,
            GuardState::Unknown => Verdict::Unknown,
        },
    }
}

/// The socket the config's daemon listens on: its own `control`, else the
/// runtime directory.
///
/// A config that names its own socket is a deployment that may not use
/// `/run/vallum` at all — a scratch root, a second instance, a test. Reading the
/// default path regardless reported such a daemon as `not running`, and the
/// verdict then says `down` or `blocked` about a tunnel that is up: exactly the
/// confidently-wrong answer this verb exists to prevent. `vallum metrics`
/// already resolves it this way, so the two surfaces cannot disagree about which
/// daemon they are describing.
fn control_socket(config_path: &Path, config: &Config, interface: &str) -> PathBuf {
    config
        .interface
        .control
        .as_ref()
        .map(|declared| crate::config::resolve_key_path(config_path, declared))
        .unwrap_or_else(|| vallum_config::socket_path(interface))
}

/// The account-cause hint for a handshake-failure verdict (ADR-0046).
///
/// `stale` (the daemon answers but the session is past the reject window)
/// and `starting` (no peer is connected) are the two verdicts where a
/// desk account — expired or at its byte cap — is a plausible cause. The
/// wording is the doctor's, so the two surfaces speak with one voice; a
/// config without a token gets `None` and the existing advice stands.
fn account_hint(config: &Config, verdict: Verdict) -> Option<String> {
    if !matches!(verdict, Verdict::Stale | Verdict::Starting) {
        return None;
    }
    crate::commands::doctor::desk_account_hint(&config.account)
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
    let socket = control_socket(&args.config, &config, &interface);

    // The daemon may be gone; that is the interesting case, not an error.
    let live = control::request(&socket, "get=1\n").ok();
    let guard = policy::guard_state(&interface);
    let resolved = policy::resolve(&config);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let verdict = verdict(live.as_deref(), guard, resolved, now);
    let account_hint = account_hint(&config, verdict);

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
            "policy": resolved.as_str(),
            "account_hint": account_hint,
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
        println!("{:<10} {}", "policy", resolved.as_str());
        if let Some(hint) = &account_hint {
            println!("{:<10} {}", "account", hint);
        }
    }

    if verdict.is_failure() {
        return Err(Error::Usage(
            "traffic is leaving outside the tunnel; run `sudo vallum policy on` or stop the \
             interface"
                .to_owned(),
        ));
    }
    if !verdict.is_working() {
        // Not a leak - the guard may well be holding - but the tunnel is not
        // carrying, so this is still a failure for anything asking "am I
        // protected?". The verdict's own sentence says which.
        return Err(Error::Usage(format!(
            "the tunnel is not carrying: {}",
            verdict.detail()
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Two contracts, two names. The leak contract is narrow on purpose, and
    /// the tests that say so are older than this one.
    #[test]
    fn the_leak_contract_is_only_leaking() {
        assert!(Verdict::Leaking.is_failure());
        assert!(!Verdict::Blocked.is_failure());
        assert!(!Verdict::Stale.is_failure());
        assert!(!Verdict::Down.is_failure());
        assert!(!Verdict::Unknown.is_failure());
        assert!(!Verdict::Degraded.is_failure());
    }

    /// The gate contract: a tunnel that is not carrying is not working, even
    /// when nothing is leaking.
    #[test]
    fn a_tunnel_that_is_not_carrying_is_not_working() {
        assert!(Verdict::Up.is_working());
        assert!(Verdict::Starting.is_working());
        assert!(!Verdict::Stale.is_working());
        assert!(!Verdict::Degraded.is_working());
        assert!(!Verdict::Blocked.is_working());
        assert!(!Verdict::Down.is_working());
        assert!(!Verdict::Unknown.is_working());
        assert!(!Verdict::Leaking.is_working());
    }

    /// The status line speaks about NOW. A cumulative counter elsewhere can
    /// truthfully say a handshake completed earlier in this daemon's life —
    /// a peer connected and went quiet — so the Starting detail must not
    /// claim "no handshake has completed". On the alpha server that sentence
    /// contradicted `handshakes_established_total 1` in the same scrape, and
    /// a user cannot tell which of the two sentences is the lie.
    #[test]
    fn the_starting_detail_claims_present_state_not_absent_history() {
        let detail = Verdict::Starting.detail();
        assert!(!detail.contains("no handshake has completed"));
        assert!(detail.contains("no peer is connected"));
    }

    /// The clock every age rule is judged against: the fixture stamps below
    /// are a little earlier, so a reply is fresh unless a test moves it.
    const NOW: u64 = 1_792_678_400;

    #[test]
    fn a_dead_daemon_with_a_guard_is_blocked_not_leaking() {
        assert_eq!(
            verdict(None, GuardState::Installed, Mode::On, NOW),
            Verdict::Blocked
        );
    }

    #[test]
    fn a_dead_daemon_with_no_guard_on_a_full_tunnel_is_leaking() {
        assert_eq!(
            verdict(None, GuardState::Absent, Mode::On, NOW),
            Verdict::Leaking
        );
        assert!(Verdict::Leaking.is_failure());
    }

    #[test]
    fn a_dead_daemon_with_no_guard_on_a_split_tunnel_is_merely_down() {
        assert_eq!(
            verdict(None, GuardState::Absent, Mode::Off, NOW),
            Verdict::Down
        );
        assert!(!Verdict::Down.is_failure());
    }

    #[test]
    fn an_unreadable_guard_is_not_reported_as_leaking() {
        // The whole point: not being able to look must never be mistaken for
        // evidence that nothing is there.
        assert_eq!(
            verdict(None, GuardState::Unknown, Mode::On, NOW),
            Verdict::Unknown
        );
        assert!(!Verdict::Unknown.is_failure());
    }

    #[test]
    fn a_live_daemon_reports_up_from_a_handshake() {
        let reply = "private_key=abc\nlisten_port=51820\nvallum_up=1\n";
        assert_eq!(
            verdict(Some(reply), GuardState::Absent, Mode::On, NOW),
            Verdict::Up
        );
    }

    #[test]
    fn a_fresh_handshake_with_no_delivery_is_degraded() {
        // The exact shape of the live failure: handshake 42 s old, 13 datagrams
        // back against 1000 sent. The old verdict said `up` throughout.
        let reply = "last_handshake_time_sec=1792678349\nvallum_window_sent=1000\nvallum_window_received=13\n";
        assert_eq!(
            verdict(Some(reply), GuardState::Absent, Mode::On, NOW),
            Verdict::Degraded
        );
    }

    #[test]
    fn a_fresh_handshake_with_delivery_is_up() {
        let reply = "last_handshake_time_sec=1792678349\nvallum_window_sent=1000\nvallum_window_received=850\n";
        assert_eq!(
            verdict(Some(reply), GuardState::Absent, Mode::On, NOW),
            Verdict::Up
        );
    }

    #[test]
    fn a_sample_too_small_to_judge_is_not_degraded() {
        // Three keepalives and no answer is an idle tunnel, not a broken one —
        // while its handshake is fresh. An idle tunnel whose handshake is past
        // the reject window is `stale`, not `up`; see the age tests below.
        let reply =
            "last_handshake_time_sec=1792678349\nvallum_window_sent=3\nvallum_window_received=0\n";
        assert_eq!(
            verdict(Some(reply), GuardState::Absent, Mode::On, NOW),
            Verdict::Up
        );
    }

    #[test]
    fn the_worst_peer_decides() {
        let reply = "last_handshake_time_sec=1792678349\nvallum_window_sent=1000\nvallum_window_received=900\n\nlast_handshake_time_sec=1792678349\nvallum_window_sent=1000\nvallum_window_received=5\n";
        assert_eq!(
            verdict(Some(reply), GuardState::Absent, Mode::On, NOW),
            Verdict::Degraded
        );
    }

    #[test]
    fn a_handshake_timestamp_alone_means_up() {
        // What `show` actually returns on a working tunnel. The previous version
        // keyed only on `vallum_up` and reported this as `starting`.
        let reply = "endpoint=203.0.113.5:51820\nlast_handshake_time_sec=1792678349\n";
        assert_eq!(
            verdict(Some(reply), GuardState::Absent, Mode::On, NOW),
            Verdict::Up
        );
    }

    #[test]
    fn a_zero_handshake_timestamp_is_not_up() {
        let reply = "last_handshake_time_sec=0\n";
        assert_eq!(
            verdict(Some(reply), GuardState::Absent, Mode::On, NOW),
            Verdict::Starting
        );
    }

    #[test]
    fn a_live_daemon_without_a_handshake_is_starting() {
        let reply = "private_key=abc\nvallum_up=0\n";
        assert_eq!(
            verdict(Some(reply), GuardState::Absent, Mode::On, NOW),
            Verdict::Starting
        );
    }

    #[test]
    fn fields_parse_in_both_uapi_shapes() {
        assert_eq!(field("vallum_up=1\n", "vallum_up"), Some("1"));
        assert_eq!(field("vallum_up 1\n", "vallum_up"), Some("1"));
        assert_eq!(field("other=2\n", "vallum_up"), None);
    }

    #[test]
    fn the_socket_is_the_one_the_config_names() {
        // A config that names its own control socket — a scratch root, a second
        // instance, a test namespace — is a live daemon that the default
        // /run/vallum path does not describe. Reading the default regardless
        // made `status` report such a tunnel as dead and blocked.
        let dir = std::env::temp_dir().join(format!("vallum-status-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let named = dir.join("client.toml");
        std::fs::write(
            &named,
            "[interface]\nprivate_key = \"client.key\"\ncontrol = \"c.sock\"\n",
        )
        .unwrap();
        let config = Config::load(&named).unwrap();
        assert_eq!(
            control_socket(&named, &config, "vallumrc0"),
            dir.join("c.sock")
        );

        // No `control`: the runtime directory, which is what every systemd
        // deployment uses.
        let plain = dir.join("plain.toml");
        std::fs::write(&plain, "[interface]\nprivate_key = \"client.key\"\n").unwrap();
        let config = Config::load(&plain).unwrap();
        assert_eq!(
            control_socket(&plain, &config, "vallum0"),
            vallum_config::socket_path("vallum0")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// One peer's block, with the stamp set relative to [`NOW`].
    fn reply(stamp: u64, sent: u64, received: u64) -> String {
        format!(
            "last_handshake_time_sec={stamp}\nvallum_window_sent={sent}\n\
             vallum_window_received={received}\n"
        )
    }

    #[test]
    fn a_stale_handshake_is_not_up_even_though_the_daemon_answers() {
        // The state this verdict exists for: the process is alive and answers
        // the socket, the server died half an hour ago, and the host is idle —
        // so there is no delivery sample to judge and it used to read `up`.
        assert_eq!(
            verdict(
                Some(&reply(NOW - 1_800, 3, 0)),
                GuardState::Installed,
                Mode::On,
                NOW
            ),
            Verdict::Stale
        );
        assert!(!Verdict::Stale.is_failure());
    }

    #[test]
    fn a_stale_handshake_without_a_guard_is_stale_not_leaking() {
        // No guard and a full-tunnel config is `leaking` only when the daemon is
        // *gone*. With it running, outbound packets enter the tunnel and are
        // dropped for want of a session — nothing escapes, and paging LEAKING
        // (which has no grace period) would be a false alarm.
        assert_eq!(
            verdict(
                Some(&reply(NOW - 1_800, 3, 0)),
                GuardState::Absent,
                Mode::On,
                NOW
            ),
            Verdict::Stale
        );
    }

    #[test]
    fn the_reject_window_is_the_boundary() {
        // Exactly the window is spent: the protocol's own check is `>=`.
        assert_eq!(
            verdict(
                Some(&reply(NOW - REJECT_AFTER_SECS, 3, 0)),
                GuardState::Absent,
                Mode::On,
                NOW
            ),
            Verdict::Stale
        );
        assert_eq!(
            verdict(
                Some(&reply(NOW - REJECT_AFTER_SECS + 1, 3, 0)),
                GuardState::Absent,
                Mode::On,
                NOW
            ),
            Verdict::Up
        );
    }

    #[test]
    fn a_stamp_from_the_future_is_not_stale() {
        // A clock stepped back must not make a healthy tunnel read dead; the
        // age saturates at zero the same way the daemon's timers do.
        assert_eq!(
            verdict(
                Some(&reply(NOW + 30, 3, 0)),
                GuardState::Absent,
                Mode::On,
                NOW
            ),
            Verdict::Up
        );
    }

    #[test]
    fn the_oldest_peer_decides_staleness() {
        let both = format!(
            "{}\n{}",
            reply(NOW - 30, 1_000, 900),
            reply(NOW - 600, 1_000, 900)
        );
        assert_eq!(
            verdict(Some(&both), GuardState::Absent, Mode::On, NOW),
            Verdict::Stale
        );
    }

    #[test]
    fn a_peer_that_never_handshook_does_not_make_a_tunnel_stale() {
        // A configured peer with no session yet is `starting` for itself, and a
        // working peer beside it must still report the tunnel as up.
        let both = format!("{}\n{}", reply(NOW - 30, 1_000, 900), reply(0, 0, 0));
        assert_eq!(
            verdict(Some(&both), GuardState::Absent, Mode::On, NOW),
            Verdict::Up
        );
    }

    /// ADR-0046: a dead session (`stale`) or a never-completed handshake
    /// (`starting`) on a config that carries a desk account names the
    /// account as a cause and points at the desk — the invite-code user
    /// cannot re-enrol on the server.
    #[test]
    fn a_handshake_failure_with_a_desk_account_is_pointed_at_the_desk() {
        let dir =
            std::env::temp_dir().join(format!("vallum-status-account-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("client.toml");
        std::fs::write(
            &path,
            "[interface]\nprivate_key = \"client.key\"\n\n[account]\n\
             token = \"0123456789abcdef0123456789abcdef\"\n\
             endpoint = \"https://desk.wingman.gold\"\n",
        )
        .unwrap();
        let config = Config::load(&path).unwrap();
        for verdict in [Verdict::Stale, Verdict::Starting] {
            let hint = super::account_hint(&config, verdict).expect("a desk hint");
            assert!(hint.contains("desk account"), "{hint}");
            assert!(hint.contains("expired"), "{hint}");
            assert!(hint.contains("byte cap"), "{hint}");
            assert!(hint.contains("vallum account"), "{hint}");
            assert!(hint.contains("https://desk.wingman.gold/account"), "{hint}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Without a token the existing advice stands: the verdict's own
    /// sentence, unchanged, and no account line.
    #[test]
    fn a_handshake_failure_without_an_account_keeps_the_existing_advice() {
        let dir =
            std::env::temp_dir().join(format!("vallum-status-noaccount-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("client.toml");
        std::fs::write(&path, "[interface]\nprivate_key = \"client.key\"\n").unwrap();
        let config = Config::load(&path).unwrap();
        assert!(super::account_hint(&config, Verdict::Stale).is_none());
        assert!(super::account_hint(&config, Verdict::Starting).is_none());
        assert!(Verdict::Stale.detail().contains("reject window"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The hint is a handshake-failure hint: a carrying tunnel, a degraded
    /// one (fresh handshakes), and the daemon-gone verdicts get none.
    #[test]
    fn only_handshake_failure_verdicts_get_the_account_hint() {
        let dir = std::env::temp_dir().join(format!("vallum-status-scope-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("client.toml");
        std::fs::write(
            &path,
            "[interface]\nprivate_key = \"client.key\"\n\n[account]\n\
             token = \"0123456789abcdef0123456789abcdef\"\n",
        )
        .unwrap();
        let config = Config::load(&path).unwrap();
        for verdict in [
            Verdict::Up,
            Verdict::Degraded,
            Verdict::Blocked,
            Verdict::Leaking,
            Verdict::Down,
            Verdict::Unknown,
        ] {
            assert!(
                super::account_hint(&config, verdict).is_none(),
                "{verdict:?} must not carry an account hint"
            );
        }
        // A token without an endpoint still gets the hint — without a URL.
        let hint = super::account_hint(&config, Verdict::Stale).expect("a desk hint");
        assert!(hint.contains("vallum account"), "{hint}");
        assert!(!hint.contains("/account"), "{hint}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
