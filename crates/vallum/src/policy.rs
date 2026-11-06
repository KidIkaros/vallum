//! The fail-closed egress policy.
//!
//! The rule is one sentence: **a packet leaves this host only through the
//! tunnel, or to the endpoint that carries it.** See ADR-0018.
//!
//! The guard owns the block, not the daemon. `vallum run` holds the TUN, and if
//! it dies its cleanup takes the routes with it — the host then silently reverts
//! to the physical default route and traffic that was in the tunnel leaves
//! outside it. A separate `vallum-guard@` unit, ordered *before* the tunnel and
//! deliberately not `PartOf` it, is the difference between fail-closed and
//! fail-open with extra steps.
//!
//! Two details carry most of the safety:
//!
//! - **The endpoint is permitted.** A kill switch that also blocks the
//!   handshake is a machine that can never reconnect.
//! - **A family the tunnel does not carry is dropped outright.** This holds
//!   even for a config that still claims `::/0`, which is what made a v4-only
//!   server leak v6 egress.

use std::net::{IpAddr, ToSocketAddrs};

use vallum_config::Config;

use crate::error::Error;
use crate::hostnet::{self, HostStep};

/// The nftables table Vallum owns for this policy.
pub const TABLE: &str = "vallum_policy";

/// Private ranges a LAN exception covers.
const LAN_V4: &str = "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16";
const LAN_V6: &str = "fe80::/10";

/// What the guard does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// No block.
    Off,
    /// Block egress outside the tunnel.
    On,
    /// Block when the tunnel is a full tunnel, otherwise leave it alone.
    Auto,
}

impl Mode {
    /// Parse the config value. `None` means the text is not a mode.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "off" | "false" | "no" | "0" => Some(Self::Off),
            "on" | "true" | "yes" | "1" => Some(Self::On),
            "auto" | "" => Some(Self::Auto),
            _ => None,
        }
    }

    /// The mode this config asks for, before `auto` is resolved.
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        config
            .quick
            .policy
            .as_deref()
            .and_then(Self::parse)
            .unwrap_or(Self::Auto)
    }
}

/// The interface name this config's tunnel uses.
///
/// Shared by the guard (which permits that interface) and by `vallum status`
/// (which reports on it), so the two can never disagree about the name.
#[must_use]
pub fn interface_name(config: &Config) -> String {
    config
        .interface
        .name
        .clone()
        .unwrap_or_else(|| "vallum0".to_owned())
}

/// Whether some peer routes a default route, making this a full tunnel.
#[must_use]
pub fn is_full_tunnel(config: &Config) -> bool {
    config.peers.iter().any(|peer| {
        peer.allowed_ips.iter().any(|prefix| {
            let prefix = prefix.trim();
            prefix == "0.0.0.0/0" || prefix == "::/0"
        })
    })
}

/// Resolve `auto` against the config. A split tunnel is left alone: the whole
/// point of a split tunnel is that some traffic is meant to go elsewhere.
#[must_use]
pub fn resolve(config: &Config) -> Mode {
    match Mode::from_config(config) {
        Mode::Auto => {
            if is_full_tunnel(config) {
                Mode::On
            } else {
                Mode::Off
            }
        }
        other => other,
    }
}

/// Which families the tunnel itself carries, from its own addresses.
///
/// This is the authority, not `allowed_ips`: a config can claim a family the
/// interface has no address in, and that claim is exactly what leaked.
#[must_use]
pub fn carries(config: &Config) -> (bool, bool) {
    let mut v4 = false;
    let mut v6 = false;
    for address in config
        .interface
        .addresses
        .iter()
        .chain(config.interface.address.iter())
    {
        if address.contains(':') {
            v6 = true;
        } else {
            v4 = true;
        }
    }
    (v4, v6)
}

/// The endpoint addresses the handshake must reach.
///
/// A name is resolved once, here, at install time — the guard runs before the
/// tunnel exists, so there is no resolver to lean on later. If nothing
/// resolves, the guard refuses to install: blocking every destination while
/// also blocking the way back in is a bricked machine, not a policy.
fn endpoints(config: &Config) -> Result<Vec<(IpAddr, u16)>, Error> {
    let mut out = Vec::new();
    for peer in &config.peers {
        let Some(endpoint) = peer.endpoint.as_deref() else {
            continue;
        };
        match endpoint.to_socket_addrs() {
            Ok(addrs) => {
                for addr in addrs {
                    if !out.contains(&(addr.ip(), addr.port())) {
                        out.push((addr.ip(), addr.port()));
                    }
                }
            }
            Err(source) => {
                return Err(Error::Usage(format!(
                    "the endpoint `{endpoint}` does not resolve ({source}); a guard with no \
                     permitted destination would block the handshake it exists to protect"
                )))
            }
        }
    }
    if out.is_empty() {
        return Err(Error::Usage(
            "no peer has an `endpoint`; there is nothing to permit, so a guard here would \
             block every packet including the handshake"
                .to_owned(),
        ));
    }
    Ok(out)
}

/// Render the ruleset for one interface.
///
/// # Errors
/// Fails when no permitted endpoint can be determined — see [`endpoints`].
pub fn ruleset(config: &Config, interface: &str) -> Result<String, Error> {
    let (v4, v6) = carries(config);
    let endpoints = endpoints(config)?;
    let quick = &config.quick;

    let mut rules = String::new();
    // The canonical idempotent replace: declaring the table makes the delete
    // legal whether or not it already exists.
    rules.push_str(&format!("table inet {TABLE}\n"));
    rules.push_str(&format!("delete table inet {TABLE}\n"));
    rules.push_str(&format!("table inet {TABLE} {{\n"));
    rules.push_str("  chain output {\n");
    rules.push_str("    type filter hook output priority 0; policy accept;\n");

    // Loopback, then the tunnel itself.
    rules.push_str("    oifname \"lo\" accept\n");
    rules.push_str(&format!("    oifname \"{interface}\" accept\n"));

    // The handshake. Without this the tunnel can never come back.
    for (ip, port) in &endpoints {
        match ip {
            IpAddr::V4(addr) => {
                rules.push_str(&format!("    ip daddr {addr} udp dport {port} accept\n"));
            }
            IpAddr::V6(addr) => {
                rules.push_str(&format!("    ip6 daddr {addr} udp dport {port} accept\n"));
            }
        }
    }

    // DHCP, so an interface can still get an address and a default route.
    rules.push_str("    udp sport 68 udp dport 67 accept\n");
    rules.push_str("    ip6 nexthdr udp udp sport 546 udp dport 547 accept\n");

    // DNS: Port 53 outside the tunnel must not leak, even under LAN or allow rules.
    rules.push_str("    udp dport 53 drop\n");
    rules.push_str("    tcp dport 53 drop\n");

    if quick.allow_lan {
        rules.push_str(&format!("    ip daddr {{ {LAN_V4} }} accept\n"));
        rules.push_str(&format!("    ip6 daddr {{ {LAN_V6} }} accept\n"));
    }
    for entry in &quick.allow {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        if entry.contains(':') {
            rules.push_str(&format!("    ip6 daddr {entry} accept\n"));
        } else {
            rules.push_str(&format!("    ip daddr {entry} accept\n"));
        }
    }

    // A family the tunnel does not carry must not leave. This is the packet-side
    // half of the v6 leak. The config-side half is that `peer add` allocates one
    // address per family, so a `::/0` claim has a route behind it; this rule is
    // what stops a hand-written config from re-introducing the leak.
    if !v6 {
        rules.push_str("    meta nfproto ipv6 drop\n");
    }
    if !v4 {
        rules.push_str("    meta nfproto ipv4 drop\n");
    }

    rules.push_str("    drop\n");
    rules.push_str("  }\n");
    rules.push_str("}\n");
    Ok(rules)
}

/// The steps that install the guard.
///
/// # Errors
/// Propagates [`ruleset`]'s refusal when there is nothing safe to permit.
pub fn guard_steps(config: &Config, interface: &str) -> Result<Vec<HostStep>, Error> {
    Ok(vec![HostStep::Run {
        summary: format!("block egress outside `{interface}`, except its endpoint"),
        program: "nft".to_owned(),
        args: vec!["-f".to_owned(), "-".to_owned()],
        stdin: Some(ruleset(config, interface)?),
        ignore_failure: false,
    }])
}

/// The steps that remove it. Missing is success — the table may never have
/// existed, and an uninstall must not fail because of that.
#[must_use]
pub fn unguard_steps() -> Vec<HostStep> {
    vec![HostStep::Run {
        summary: "remove the egress policy".to_owned(),
        program: "nft".to_owned(),
        args: vec![
            "delete".to_owned(),
            "table".to_owned(),
            "inet".to_owned(),
            TABLE.to_owned(),
        ],
        stdin: None,
        ignore_failure: true,
    }]
}

/// What the host says about the guard.
///
/// The distinction between [`GuardState::Absent`] and [`GuardState::Unknown`]
/// is load-bearing. `nft list` needs `CAP_NET_ADMIN`, so an unprivileged
/// `vallum status` cannot tell "no table" from "not allowed to look". Reporting
/// the second as the first would tell a user their traffic is leaking while it
/// is blocked — a false alarm is worse than no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardState {
    /// The table exists: egress outside the tunnel is blocked.
    Installed,
    /// The table is genuinely not there.
    Absent,
    /// Could not determine — not root, or `nft` is missing.
    Unknown,
}

/// Read the guard's state from the host.
#[must_use]
pub fn guard_state() -> GuardState {
    let Ok(output) = std::process::Command::new("nft")
        .args(["list", "table", "inet", TABLE])
        .output()
    else {
        return GuardState::Unknown;
    };
    if output.status.success() {
        return GuardState::Installed;
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    // nft's wording when the table simply is not there.
    if stderr.contains("No such file or directory") {
        GuardState::Absent
    } else {
        GuardState::Unknown
    }
}

/// Install the guard. `dry_run` prints instead of applying.
///
/// # Errors
/// Propagates a refusal to build the ruleset, or a failed `nft`.
pub fn guard(config: &Config, interface: &str, dry_run: bool) -> Result<Vec<String>, Error> {
    hostnet::apply(&guard_steps(config, interface)?, dry_run)
}

/// Remove the guard.
///
/// # Errors
/// Only a genuine `nft` failure; a missing table is fine.
pub fn unguard(dry_run: bool) -> Result<Vec<String>, Error> {
    hostnet::apply(&unguard_steps(), dry_run)
}

/// Whether an explicit `on` is declined because the config's own shape says a
/// guard would do more harm than good.
///
/// A split tunnel under `auto` deliberately leaves egress alone: blocking it
/// would cut the user off from everything the tunnel does not carry. Asking for
/// `on` does not override that, so the request is refused — and must be
/// reported as a refusal, because a refusal that exits 0 is indistinguishable
/// from a guard that was installed.
pub fn declines_guard(config: &Config, wanted: Mode) -> bool {
    !is_full_tunnel(config) && wanted != Mode::On
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn config(text: &str) -> Config {
        toml::from_str(text).unwrap()
    }

    const FULL_V4: &str = r#"
[interface]
name = "vallum-laptop"
private_key = "k.key"
addresses = ["10.7.0.2/32"]

[quick]
policy = "on"

[[peer]]
name = "server"
public_key = "vallum1:0003:aa:-"
endpoint = "203.0.113.5:51820"
allowed_ips = ["0.0.0.0/0"]
"#;

    #[test]
    fn a_full_v4_tunnel_permits_its_endpoint_and_drops_v6() {
        let rules = ruleset(&config(FULL_V4), "vallum-laptop").unwrap();
        assert!(rules.contains("ip daddr 203.0.113.5 udp dport 51820 accept"));
        assert!(rules.contains("oifname \"vallum-laptop\" accept"));
        assert!(
            rules.contains("meta nfproto ipv6 drop"),
            "a tunnel with no v6 address must drop v6, or it escapes"
        );
        assert!(!rules.contains("meta nfproto ipv4 drop"));
    }

    /// The same peer, carried by a split tunnel, with no `[quick] policy`.
    const SPLIT_V4: &str = r#"
[interface]
name = "vallum-laptop"
private_key = "k.key"
addresses = ["10.7.0.2/32"]

[[peer]]
name = "server"
public_key = "vallum1:0003:aa:-"
endpoint = "203.0.113.5:51820"
allowed_ips = ["10.7.0.1/32"]
"#;

    #[test]
    fn a_split_tunnel_under_auto_declines_an_explicit_on() {
        let split = config(SPLIT_V4);
        assert!(declines_guard(&split, Mode::from_config(&split)));
    }

    #[test]
    fn a_split_tunnel_that_asks_for_on_is_not_declined() {
        // The documented escape: state the intent in the config and a split
        // tunnel is guarded anyway.
        let asked = config(&SPLIT_V4.replace("[[peer]]", "[quick]\npolicy = \"on\"\n\n[[peer]]"));
        assert!(!declines_guard(&asked, Mode::from_config(&asked)));
    }

    #[test]
    fn a_full_tunnel_under_auto_is_not_declined() {
        let full = config(&FULL_V4.replace("policy = \"on\"\n", ""));
        assert!(!declines_guard(&full, Mode::from_config(&full)));
    }

    #[test]
    fn the_tunnel_and_loopback_are_always_permitted() {
        let rules = ruleset(&config(FULL_V4), "vallum-laptop").unwrap();
        assert!(rules.contains("oifname \"lo\" accept"));
    }

    #[test]
    fn a_guard_with_no_endpoint_refuses_to_install() {
        let text = FULL_V4.replace("endpoint = \"203.0.113.5:51820\"\n", "");
        let error = ruleset(&config(&text), "vallum-laptop").unwrap_err();
        assert!(
            format!("{error}").contains("nothing to permit"),
            "a guard that permits nothing blocks the handshake: {error}"
        );
    }

    #[test]
    fn auto_is_on_for_a_full_tunnel_and_off_for_a_split_one() {
        let full = config(&FULL_V4.replace("policy = \"on\"", "policy = \"auto\""));
        assert_eq!(resolve(&full), Mode::On);

        let split = config(
            &FULL_V4
                .replace(
                    "allowed_ips = [\"0.0.0.0/0\"]",
                    "allowed_ips = [\"10.7.0.0/24\"]",
                )
                .replace("policy = \"on\"", "policy = \"auto\""),
        );
        assert_eq!(resolve(&split), Mode::Off);
    }

    #[test]
    fn a_config_with_no_policy_key_defaults_to_auto() {
        let implicit = config(&FULL_V4.replace("policy = \"on\"\n", ""));
        assert_eq!(Mode::from_config(&implicit), Mode::Auto);
        assert_eq!(resolve(&implicit), Mode::On);
    }

    #[test]
    fn an_explicit_off_wins_over_auto() {
        let off = config(&FULL_V4.replace("policy = \"on\"", "policy = \"off\""));
        assert_eq!(resolve(&off), Mode::Off);
    }

    #[test]
    fn a_lan_exception_is_opt_in() {
        let without = ruleset(&config(FULL_V4), "vallum-laptop").unwrap();
        assert!(!without.contains("192.168.0.0/16"));

        let with = ruleset(
            &config(&FULL_V4.replace("policy = \"on\"", "policy = \"on\"\nallow_lan = true")),
            "vallum-laptop",
        )
        .unwrap();
        assert!(with.contains("192.168.0.0/16"));
    }

    #[test]
    fn dns_outside_the_tunnel_is_dropped_even_with_lan_exceptions() {
        let with_lan = ruleset(
            &config(&FULL_V4.replace("policy = \"on\"", "policy = \"on\"\nallow_lan = true")),
            "vallum-laptop",
        )
        .unwrap();
        assert!(with_lan.contains("udp dport 53 drop"));
        assert!(with_lan.contains("tcp dport 53 drop"));
        let dns_drop = with_lan.find("udp dport 53 drop").unwrap();
        let lan_allow = with_lan.find("192.168.0.0/16").unwrap();
        assert!(
            dns_drop < lan_allow,
            "port 53 drop must precede LAN allow rules to prevent DNS leaking to local routers"
        );
    }

    #[test]
    fn the_ruleset_is_idempotent() {
        let rules = ruleset(&config(FULL_V4), "vallum-laptop").unwrap();
        // Declare-then-delete is what makes re-installing safe.
        let declare = rules.find(&format!("table inet {TABLE}\n")).unwrap();
        let delete = rules.find(&format!("delete table inet {TABLE}\n")).unwrap();
        assert!(
            declare < delete,
            "the table must be declared before deleting"
        );
    }
}
