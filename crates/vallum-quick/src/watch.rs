// SPDX-License-Identifier: Apache-2.0

//! The `watch` command: hold the routes only while the session is alive and
//! carrying, and decide fail-closed vs fail-open on session failure.
//!
//! The verdict logic is pure so the rule "a full tunnel with a dead session or
//! non-carrying delivery must not own the host's default route" is testable
//! without a kernel, a socket or a clock.
//!
//! Stored verbatim from the original single-file layout; see `main.rs` for
//! how a command drives these.

use std::path::Path;
use std::thread::sleep;
use std::time::{Duration, Instant};

use vallum_config::Config;

use crate::hooks::check_config_ownership;
use crate::routes::{
    apply_blackhole_routes, apply_routes, plan_routes, read_plan, remove_routes, state_path,
};
use crate::session::{control_socket, uapi_get};

/// What the watchdog should do with the routes on one tick.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum Verdict {
    Hold,
    Withdraw(WithdrawReason),
    Restore,
}

/// Why routes were withdrawn by the watchdog.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum WithdrawReason {
    NoHandshake,
    DeliveryDegraded,
}

/// What happens when the tunnel session fails: `block` (fail-closed) or `restore` (fail-open).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum FailurePolicy {
    /// Install blackhole routes for the tunnel's prefixes so traffic cannot escape.
    Block,
    /// Withdraw the tunnel routes so traffic returns to the host's physical gateway.
    Restore,
}

/// Which failure policy applies: the environment first, the config second,
/// fail closed last. Precedence is visible here, at the edge, because this is
/// the one place a name must not hide which source overrode which.
pub(crate) fn failure_policy(config: &Config) -> FailurePolicy {
    std::env::var("VALLUM_FAILURE_POLICY")
        .ok()
        .and_then(|value| FailurePolicy::parse(&value))
        .or_else(|| Some(FailurePolicy::from_config(config)))
        .unwrap_or(FailurePolicy::Block)
}

impl FailurePolicy {
    /// The policy in the config, or the default. Pure: the environment is
    /// consulted by [`failure_policy`] at the wire's edge, not here.
    pub(crate) fn from_config(config: &Config) -> Self {
        if let Ok(val) = std::env::var("VALLUM_FAILURE_POLICY") {
            if let Some(policy) = Self::parse(&val) {
                return policy;
            }
        }
        config
            .quick
            .failure_policy
            .as_deref()
            .and_then(Self::parse)
            .unwrap_or(Self::Block)
    }

    pub(crate) fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "block" | "block-on-failure" | "closed" | "fail-closed" => Some(Self::Block),
            "restore" | "open" | "fail-open" => Some(Self::Restore),
            _ => None,
        }
    }
}

/// Datagrams below which a delivery ratio is not worth judging.
///
/// Three keepalives and a stray packet are not evidence of anything.
const DELIVERY_MIN_SAMPLE: u64 = 100;

/// Delivery below this is not carrying.
///
/// A ratio under 0.1 indicates the tunnel is sending into a void (e.g. far-side
/// dropped session or routing blackhole).
const DELIVERY_FLOOR: f64 = 0.1;

/// How long delivery must stay below threshold before routes are withdrawn.
///
/// Defaults to the protocol's rekey interval (120 s). A momentary dip or transient
/// loss must not flap the routes; but once a full rekey cycle elapses with no
/// traffic carrying, the tunnel is sending into a void.
const DEGRADED_AFTER: Duration = Duration::from_secs(120);

fn degraded_after() -> Duration {
    std::env::var("VALLUM_DEGRADED_AFTER_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(DEGRADED_AFTER)
}

/// Decide from the session's age and whether the routes are currently in (legacy handshake-only check).
#[cfg(test)]
pub(crate) fn verdict(
    attached: bool,
    session_age: Option<Duration>,
    dead_after: Duration,
) -> Verdict {
    verdict_carrying(
        attached,
        session_age,
        dead_after,
        None,
        Duration::ZERO,
        DEGRADED_AFTER,
    )
}

/// Decide route status from handshake age, delivery ratio, and degraded duration.
///
/// Pure, so the rule "a full tunnel with a dead session or non-carrying delivery
/// must not own the host's default route" is testable without a kernel, a socket or a clock.
pub(crate) fn verdict_carrying(
    attached: bool,
    session_age: Option<Duration>,
    dead_after: Duration,
    worst_delivery: Option<f64>,
    degraded_duration: Duration,
    degraded_threshold: Duration,
) -> Verdict {
    let handshake_live = session_age.is_some_and(|age| age < dead_after);
    if !handshake_live {
        return match attached {
            true => Verdict::Withdraw(WithdrawReason::NoHandshake),
            false => Verdict::Hold,
        };
    }

    let delivery_degraded = worst_delivery.is_some_and(|ratio| ratio < DELIVERY_FLOOR);
    if delivery_degraded && degraded_duration >= degraded_threshold {
        return match attached {
            true => Verdict::Withdraw(WithdrawReason::DeliveryDegraded),
            false => Verdict::Hold,
        };
    }

    if delivery_degraded {
        return Verdict::Hold;
    }

    match attached {
        true => Verdict::Hold,
        false => Verdict::Restore,
    }
}

/// How stale the newest handshake may be before the tunnel counts as dead.
///
/// This must be **longer than the protocol's own expiry**. `REJECT_AFTER_TIME_MS`
/// in `vallum-core` is 180 s: until that point the daemon still considers the
/// session valid and will accept data on it, so a shorter window withdraws the
/// routes from a tunnel that is working.
///
/// Measured on a real deployment with the previous 90 s value: an idle full
/// tunnel flapped every ~125 s — routes withdrawn, then restored ~35 s later
/// when the next rekey landed — costing about a third of all connectivity in a
/// steady state that looked perfectly healthy. The old comment justified 90 s as
/// "three keepalive periods plus slack", which only holds if the peer sends
/// keepalives; a client that does not sends nothing at all while idle.
///
/// 180 s plus 30 s of slack, so a rekey that lands late is not a withdrawal.
pub(crate) const DEAD_AFTER: Duration = Duration::from_secs(210);

/// How often the watchdog asks the daemon whether the session is alive.
pub(crate) const WATCH_POLL: Duration = Duration::from_secs(5);

fn dead_after() -> Duration {
    let configured = std::env::var("VALLUM_DEAD_AFTER_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(DEAD_AFTER);
    clamp_dead_after(configured)
}

#[cfg(test)]
mod dead_after_tests {
    use super::*;

    /// The watchdog must outlive the protocol's own expiry. `REJECT_AFTER_TIME_MS`
    /// lives in `vallum-core` (180 s); this crate does not depend on it, so the
    /// number is asserted here rather than imported. If either moves, this fails.
    #[test]
    fn the_watchdog_window_outlives_the_protocol_expiry() {
        assert!(
            DEAD_AFTER.as_secs() > 180,
            "DEAD_AFTER must exceed REJECT_AFTER_TIME_MS (180 s) or the watchdog \
             withdraws routes from a live tunnel"
        );
    }
}

/// A window no longer than the poll interval can never be observed: every
/// sample would land after it closed, so the routes would be withdrawn and
/// never restored. Two intervals guarantees a live session is seen.
pub(crate) fn clamp_dead_after(configured: Duration) -> Duration {
    configured.max(WATCH_POLL * 2)
}

/// Health metrics parsed from the daemon's UAPI reply.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct SessionHealth {
    pub(crate) age: Option<Duration>,
    pub(crate) worst_delivery: Option<f64>,
}

fn parse_session_health(reply: &str) -> SessionHealth {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
        .unwrap_or(0);
    parse_session_health_at(reply, now)
}

pub(crate) fn parse_session_health_at(reply: &str, now_unix_secs: u64) -> SessionHealth {
    let mut newest_handshake: Option<u64> = None;
    let mut worst_ratio: Option<f64> = None;

    for block in reply.split("\n\n") {
        for line in block.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("last_handshake_time_sec=") {
                if let Ok(secs) = rest.trim().parse::<u64>() {
                    if secs > 0 {
                        newest_handshake = Some(newest_handshake.map_or(secs, |e| e.max(secs)));
                    }
                }
            }
        }

        let sent = block
            .lines()
            .find_map(|l| l.trim().strip_prefix("vallum_window_sent="))
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(0);

        if sent >= DELIVERY_MIN_SAMPLE {
            let received = block
                .lines()
                .find_map(|l| l.trim().strip_prefix("vallum_window_received="))
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(0);
            let ratio = received as f64 / sent as f64;
            worst_ratio = Some(worst_ratio.map_or(ratio, |e| e.min(ratio)));
        }
    }

    let age = newest_handshake.map(|secs| Duration::from_secs(now_unix_secs.saturating_sub(secs)));
    SessionHealth {
        age,
        worst_delivery: worst_ratio,
    }
}

fn session_health(socket: &Path) -> Option<SessionHealth> {
    let reply = uapi_get(socket).ok()?;
    Some(parse_session_health(&reply))
}

/// Take the tunnel routes out according to the failure policy, and release it
/// truthfully:
///
/// * on `Block`, the blackhole `route replace` **overwrites** the tunnel routes
///   in the policy table, so the recorded plan no longer describes what is
///   installed. The record is deleted for the same reason [`remove_routes`]
///   deletes it on `Restore` — otherwise a restarted watchdog re-derives
///   `attached` as true from the stale record, and with a live session it
///   holds forever: the blackhole outlives the failure that installed it and
///   the recovered host stays offline until a human intervenes.
/// * on `Restore`, [`remove_routes`] already removes the record.
pub(crate) fn withdraw_for_failure(
    config: &Config,
    interface: &str,
    table: &str,
    policy: FailurePolicy,
    dry_run: bool,
    msg: &str,
) {
    match policy {
        FailurePolicy::Block => {
            if dry_run {
                println!("would block {interface}: {msg} (fail-closed blackhole)");
            } else {
                apply_blackhole_routes(config, interface, table, false);
                let _ = std::fs::remove_file(state_path(interface));
                eprintln!(
                    "vallum-quick: {interface}: {msg} — blackhole routes installed (fail-closed), \
                     traffic blocked"
                );
            }
        }
        FailurePolicy::Restore => {
            if dry_run {
                println!("would withdraw {interface}: {msg}");
            } else {
                remove_routes(config, interface, table, false);
                eprintln!(
                    "vallum-quick: {interface}: {msg} — routes withdrawn, \
                     this host keeps its own gateway"
                );
            }
        }
    }
}

/// Hold the routes only while the session is alive and carrying.
///
/// `attach` gates installation on a handshake, but nothing took the routes back
/// out when the peer stopped answering: the daemon stays up, the interface
/// stays up, and a full tunnel keeps the host's traffic pointed at a peer that
/// is not there. A dead server then costs the host its internet until someone
/// reboots it. This is the other half of that gate.
pub(crate) fn watch(
    config_path: &Path,
    dry_run: bool,
    allow_insecure_config: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = crate::load_normalized(config_path)?;
    check_config_ownership(config_path, &config, allow_insecure_config)?;
    let interface = config
        .interface
        .name
        .clone()
        .unwrap_or_else(|| "vallum0".to_owned());
    let table = config.quick.table.as_deref().unwrap_or("auto");

    let socket = control_socket(&config, config_path, &interface);
    let dead_after = dead_after();
    let degraded_threshold = degraded_after();
    let failure_policy = failure_policy(&config);
    // Guard exactly what attach installed. A config whose routes are all covered
    // by its own interface installs nothing, so there is nothing to withdraw —
    // but the process stays resident so the unit has one lifecycle either way.
    let guarded = !plan_routes(&config, &interface, table, dry_run)?
        .commands
        .is_empty();
    if !guarded {
        eprintln!("vallum-quick: {interface}: no routes of its own to guard");
    }
    let mut attached = read_plan(&state_path(&interface)).is_some();
    let mut degraded_since: Option<Instant> = None;

    loop {
        if guarded {
            let health = session_health(&socket);
            let age = health.as_ref().and_then(|h| h.age);
            let delivery = health.as_ref().and_then(|h| h.worst_delivery);

            let is_degraded = delivery.is_some_and(|ratio| ratio < DELIVERY_FLOOR);
            let degraded_duration = if is_degraded {
                let start = degraded_since.get_or_insert_with(Instant::now);
                start.elapsed()
            } else {
                degraded_since = None;
                Duration::ZERO
            };

            match verdict_carrying(
                attached,
                age,
                dead_after,
                delivery,
                degraded_duration,
                degraded_threshold,
            ) {
                Verdict::Withdraw(reason) => {
                    let msg = match reason {
                        WithdrawReason::NoHandshake => {
                            format!("no handshake within {}s", dead_after.as_secs())
                        }
                        WithdrawReason::DeliveryDegraded => {
                            format!(
                                "delivery below threshold (10%) for {}s",
                                degraded_threshold.as_secs()
                            )
                        }
                    };
                    withdraw_for_failure(&config, &interface, table, failure_policy, dry_run, &msg);
                    attached = false;
                }
                Verdict::Restore => {
                    degraded_since = None;
                    if dry_run {
                        println!("would restore {interface}: the session is back and carrying");
                    } else {
                        match apply_routes(&config, &interface, table, false) {
                            Ok(()) => {
                                attached = true;
                                eprintln!(
                                    "vallum-quick: {interface}: session is back and carrying — routes restored"
                                );
                            }
                            Err(error) => {
                                eprintln!("vallum-quick: {interface}: could not restore: {error}");
                            }
                        }
                    }
                }
                Verdict::Hold => {}
            }
        }
        sleep(WATCH_POLL);
    }
}
