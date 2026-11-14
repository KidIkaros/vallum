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

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use vallum_config::Config;

use crate::error::Error;
use crate::hostnet::{self, HostStep};

/// The nftables table Vallum owns for this policy.
/// The prefix of the nft table that holds an interface's egress guard.
pub const TABLE_PREFIX: &str = "vallum_policy";

/// The nft table that holds ONE interface's egress guard.
///
/// One table per interface, not one table for the host. With a single table,
/// installing the guard for a second tunnel replaced the first tunnel's
/// ruleset - the first tunnel's guard silently stopped being there - and
/// `policy off` removed the guard for every interface at once, whichever one
/// the operator was thinking about.
///
/// nft identifiers are `[A-Za-z_][A-Za-z0-9_]*`, and an interface name may
/// contain a hyphen, so anything that is not a letter or a digit becomes an
/// underscore. Two interface names that differ only in punctuation therefore
/// share a table; the names are bounded at 15 characters and are
/// alphanumeric in practice, so that needs two deliberate names to happen.
#[must_use]
pub fn table_name(interface: &str) -> String {
    let mut name = format!("{TABLE_PREFIX}_");
    for ch in interface.chars() {
        name.push(if ch.is_ascii_alphanumeric() { ch } else { '_' });
    }
    name
}

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
    /// Stay blocked even while disconnected or before DNS is available at early boot.
    Lockdown,
}

impl Mode {
    /// Parse the config value. `None` means the text is not a mode.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "off" | "false" | "no" | "0" => Some(Self::Off),
            "on" | "true" | "yes" | "1" => Some(Self::On),
            "auto" | "" => Some(Self::Auto),
            "lockdown" | "always" => Some(Self::Lockdown),
            _ => None,
        }
    }

    /// Whether this resolved mode expects the egress guard to be installed.
    #[must_use]
    pub fn expects_guard(self) -> bool {
        matches!(self, Self::On | Self::Lockdown)
    }

    /// The canonical config/JSON name for this mode.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::On => "on",
            Self::Auto => "auto",
            Self::Lockdown => "lockdown",
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
                )));
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

/// Resolve configured endpoints best-effort without failing on unresolvable hostnames.
///
/// Used by lockdown / early-boot mode where egress must be blocked before DNS is
/// reachable; literal IP endpoints are still permitted immediately.
fn best_effort_endpoints(config: &Config) -> Vec<(IpAddr, u16)> {
    let mut out = Vec::new();
    for peer in &config.peers {
        let Some(endpoint) = peer.endpoint.as_deref() else {
            continue;
        };
        if let Ok(addr) = endpoint.parse::<SocketAddr>() {
            if !out.contains(&(addr.ip(), addr.port())) {
                out.push((addr.ip(), addr.port()));
            }
            continue;
        }
        if let Ok(addrs) = endpoint.to_socket_addrs() {
            for addr in addrs {
                if !out.contains(&(addr.ip(), addr.port())) {
                    out.push((addr.ip(), addr.port()));
                }
            }
        }
    }
    out
}

/// Extract the host IP addresses assigned to the tunnel interface from its
/// configured CIDR strings, deduplicated and preserving order.
fn own_ips(config: &Config) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for raw in config
        .interface
        .addresses
        .iter()
        .chain(config.interface.address.iter())
    {
        let ip_str = raw.split('/').next().unwrap_or("").trim();
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out
}

/// Render the ruleset for one interface from pre-resolved endpoints.
fn ruleset_with_endpoints(config: &Config, interface: &str, endpoints: &[(IpAddr, u16)]) -> String {
    let (v4, v6) = carries(config);
    let quick = &config.quick;
    let carrier = config.interface.carrier.unwrap_or_default();
    let tunnel_ips = own_ips(config);

    let mut rules = String::new();
    // The canonical idempotent replace: declaring the table makes the delete
    // legal whether or not it already exists.
    let table = table_name(interface);
    rules.push_str(&format!("table inet {table}\n"));
    rules.push_str(&format!("delete table inet {table}\n"));
    rules.push_str(&format!("table inet {table} {{\n"));
    rules.push_str("  chain output {\n");
    rules.push_str("    type filter hook output priority 0; policy accept;\n");

    // Loopback, then the tunnel itself.
    rules.push_str("    oifname \"lo\" accept\n");
    rules.push_str(&format!("    oifname \"{interface}\" accept\n"));

    // The handshake. Without this the tunnel can never come back.
    for (ip, port) in endpoints {
        match ip {
            IpAddr::V4(addr) => {
                if carrier.uses_udp() {
                    rules.push_str(&format!("    ip daddr {addr} udp dport {port} accept\n"));
                }
                if carrier.uses_tcp() {
                    rules.push_str(&format!("    ip daddr {addr} tcp dport {port} accept\n"));
                }
            }
            IpAddr::V6(addr) => {
                if carrier.uses_udp() {
                    rules.push_str(&format!("    ip6 daddr {addr} udp dport {port} accept\n"));
                }
                if carrier.uses_tcp() {
                    rules.push_str(&format!("    ip6 daddr {addr} tcp dport {port} accept\n"));
                }
            }
        }
    }

    // DHCP, so an interface can still get an address and a default route.
    rules.push_str("    udp sport 68 udp dport 67 accept\n");
    rules.push_str("    ip6 nexthdr udp udp sport 546 udp dport 547 accept\n");
    if v6 {
        rules.push_str(
            "    ip6 nexthdr icmpv6 icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept\n",
        );
    }

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

    // CVE-2019-14899: drop packets destined to the tunnel's own IP addresses if
    // they arrive on a non-tunnel interface before conntrack sees them.
    if !tunnel_ips.is_empty() {
        let v4_list: Vec<String> = tunnel_ips
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(addr) => Some(addr.to_string()),
                IpAddr::V6(_) => None,
            })
            .collect();
        let v6_list: Vec<String> = tunnel_ips
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(_) => None,
                IpAddr::V6(addr) => Some(addr.to_string()),
            })
            .collect();
        if !v4_list.is_empty() || !v6_list.is_empty() {
            rules.push_str("  chain input {\n");
            rules.push_str("    type filter hook input priority -300; policy accept;\n");
            rules.push_str(&format!("    iifname \"{interface}\" accept\n"));
            if !v4_list.is_empty() {
                rules.push_str(&format!(
                    "    iifname != \"{interface}\" ip daddr {{ {} }} drop\n",
                    v4_list.join(", ")
                ));
            }
            if !v6_list.is_empty() {
                rules.push_str(&format!(
                    "    iifname != \"{interface}\" ip6 daddr {{ {} }} drop\n",
                    v6_list.join(", ")
                ));
            }
            rules.push_str("  }\n");
        }
    }

    rules.push_str("}\n");
    rules
}

/// Render the ruleset for one interface.
///
/// A chain of rules matching `interface` so a second guarded tunnel does not
/// replace the first, allowing the endpoints (matched against [`Carrier`]),
/// DHCP, ICMPv6 NDP, optional LAN/allowlist exceptions, and anti-spoofing input guards
/// for the tunnel's own IPs (CVE-2019-14899), then dropping everything else.
///
/// # Errors
/// Fails when no permitted endpoint can be determined — see [`endpoints`].
pub fn ruleset(config: &Config, interface: &str) -> Result<String, Error> {
    let resolved_endpoints = endpoints(config)?;
    Ok(ruleset_with_endpoints(
        config,
        interface,
        &resolved_endpoints,
    ))
}

/// Render a lockdown / early-boot ruleset that blocks all non-tunnel egress even
/// when peer hostnames cannot be resolved yet or no endpoint is configured.
#[must_use]
pub fn lockdown_ruleset(config: &Config, interface: &str) -> String {
    let resolved_endpoints = best_effort_endpoints(config);
    ruleset_with_endpoints(config, interface, &resolved_endpoints)
}

fn ruleset_steps(config: &Config, interface: &str, rules: String) -> Vec<HostStep> {
    let mut steps = vec![HostStep::Run {
        summary: format!("block egress outside `{interface}`, except its endpoint"),
        program: "nft".to_owned(),
        args: vec!["-f".to_owned(), "-".to_owned()],
        stdin: Some(rules),
        ignore_failure: false,
    }];
    if carries(config).0 {
        steps.push(HostStep::Run {
            summary: "enable fwmark-aware reverse-path filtering (src_valid_mark=1)".to_owned(),
            program: "sysctl".to_owned(),
            args: vec![
                "-w".to_owned(),
                "net.ipv4.conf.all.src_valid_mark=1".to_owned(),
            ],
            stdin: None,
            ignore_failure: true,
        });
        steps.push(HostStep::Run {
            summary: "restrict ARP replies to the ingress link's own addresses (arp_ignore=2)"
                .to_owned(),
            program: "sysctl".to_owned(),
            args: vec![
                "-w".to_owned(),
                "net.ipv4.conf.all.arp_ignore=2".to_owned(),
            ],
            stdin: None,
            ignore_failure: true,
        });
    }
    steps
}

/// The steps that install the guard, including CVE-2019-14899 sysctl hardening
/// for IPv4 policy routing (`src_valid_mark=1` and `arp_ignore=2`).
///
/// When `[quick] policy = "lockdown"`, unresolvable endpoints fall back to the
/// fail-closed lockdown ruleset instead of failing before boot networking is up.
///
/// # Errors
/// Propagates [`ruleset`]'s refusal when there is nothing safe to permit and
/// lockdown mode is not active.
pub fn guard_steps(config: &Config, interface: &str) -> Result<Vec<HostStep>, Error> {
    let rules = match ruleset(config, interface) {
        Ok(rules) => rules,
        Err(_) if Mode::from_config(config) == Mode::Lockdown => lockdown_ruleset(config, interface),
        Err(error) => return Err(error),
    };
    Ok(ruleset_steps(config, interface, rules))
}

/// The steps that install lockdown / early-boot blocking without requiring DNS
/// resolution for peer hostnames.
#[must_use]
pub fn lockdown_steps(config: &Config, interface: &str) -> Vec<HostStep> {
    ruleset_steps(config, interface, lockdown_ruleset(config, interface))
}

/// The steps that remove it. Missing is success — the table may never have
/// existed, and an uninstall must not fail because of that.
///
/// The legacy host-wide table is removed too. It was named
/// `vallum_policy` and every interface used it, so an installation from
/// before the per-interface tables leaves that table behind; leaving it
/// behind would keep a stale guard blocking egress for an interface that no
/// longer exists.
#[must_use]
pub fn unguard_steps(interface: &str) -> Vec<HostStep> {
    vec![
        HostStep::Run {
            summary: format!("remove the egress policy for `{interface}`"),
            program: "nft".to_owned(),
            args: vec![
                "delete".to_owned(),
                "table".to_owned(),
                "inet".to_owned(),
                table_name(interface),
            ],
            stdin: None,
            ignore_failure: true,
        },
        HostStep::Run {
            summary: "remove the legacy host-wide egress policy".to_owned(),
            program: "nft".to_owned(),
            args: vec![
                "delete".to_owned(),
                "table".to_owned(),
                "inet".to_owned(),
                TABLE_PREFIX.to_owned(),
            ],
            stdin: None,
            ignore_failure: true,
        },
    ]
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

impl GuardState {
    /// The word `vallum policy --json` reports for this state.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::Absent => "absent",
            Self::Unknown => "unknown",
        }
    }

    /// What this state means for egress, in one word.
    ///
    /// [`GuardState::Unknown`] is deliberately not [`GuardState::Absent`]: an
    /// unprivileged reader who cannot see the table must not be told their
    /// traffic is unrestricted.
    #[must_use]
    pub fn egress(self) -> &'static str {
        match self {
            Self::Installed => "blocked",
            Self::Absent => "unrestricted",
            Self::Unknown => "unknown",
        }
    }
}

/// Read the guard's state from the host.
#[must_use]
pub fn guard_state(interface: &str) -> GuardState {
    let Ok(output) = std::process::Command::new("nft")
        .args(["list", "table", "inet", &table_name(interface)])
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

/// Install a fail-closed lockdown / early-boot egress block without requiring
/// DNS resolution. `dry_run` prints instead of applying.
///
/// # Errors
/// Propagates a failed `nft` invocation.
pub fn lockdown(config: &Config, interface: &str, dry_run: bool) -> Result<Vec<String>, Error> {
    hostnet::apply(&lockdown_steps(config, interface), dry_run)
}

/// Remove the guard.
///
/// # Errors
/// Only a genuine `nft` failure; a missing table is fine.
pub fn unguard(interface: &str, dry_run: bool) -> Result<Vec<String>, Error> {
    hostnet::apply(&unguard_steps(interface), dry_run)
}

/// Whether an explicit `on` is declined because the config's own shape says a
/// guard would do more harm than good.
///
/// A split tunnel under `auto` deliberately leaves egress alone: blocking it
/// would cut the user off from everything the tunnel does not carry. Asking for
/// `on` or `lockdown` overrides that, whereas an explicit refusal exits 0
/// nowhere — so it is reported cleanly.
pub fn declines_guard(config: &Config, wanted: Mode) -> bool {
    !is_full_tunnel(config) && !wanted.expects_guard()
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
    fn every_guard_state_has_its_own_word_for_egress() {
        assert_eq!(GuardState::Installed.egress(), "blocked");
        assert_eq!(GuardState::Absent.egress(), "unrestricted");
        assert_eq!(
            GuardState::Unknown.egress(),
            "unknown",
            "not being able to look is not the same as nothing being there"
        );
    }

    /// One host-wide table meant that installing the guard for a second
    /// tunnel replaced the first tunnel's ruleset - the first tunnel's guard
    /// silently stopped being there - and that `policy off` removed every
    /// interface's guard at once.
    #[test]
    fn each_interface_has_its_own_guard_table() {
        assert_ne!(table_name("vallum0"), table_name("vpn1"));
        assert!(table_name("vallum0").starts_with(TABLE_PREFIX));
        // nft identifiers are `[A-Za-z_][A-Za-z0-9_]*`, and an interface name
        // may contain a hyphen.
        let dashed = table_name("vallum-laptop");
        assert!(
            dashed
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_'),
            "{dashed} is not an nft identifier"
        );
        // Known limitation, and a narrow one: two interface names that
        // differ only in punctuation share a table. Linux interface names are
        // alphanumeric in practice, and the name is bounded at 15
        // characters, so this needs two deliberate names to happen.
        assert_eq!(dashed, table_name("vallum_laptop"));
    }

    /// The ruleset must name THIS interface's table, so one tunnel's guard
    /// cannot replace another's.
    #[test]
    fn the_ruleset_names_this_interfaces_table() {
        let rules = ruleset(&config(FULL_V4), "vallum-laptop").unwrap();
        assert!(
            rules.contains("table inet vallum_policy_vallum_laptop"),
            "{rules}"
        );
        assert!(
            !rules.contains("table inet vallum_policy_vallum0"),
            "the ruleset named another interface's table: {rules}"
        );
    }

    #[test]
    fn the_ruleset_is_idempotent() {
        let rules = ruleset(&config(FULL_V4), "vallum-laptop").unwrap();
        // Declare-then-delete is what makes re-installing safe.
        let table = table_name("vallum-laptop");
        let declare = rules.find(&format!("table inet {table}\n")).unwrap();
        let delete = rules.find(&format!("delete table inet {table}\n")).unwrap();
        assert!(
            declare < delete,
            "the table must be declared before deleting"
        );
    }

    #[test]
    fn ruleset_hardens_input_chain_against_off_tunnel_injection() {
        let rules = ruleset(&config(FULL_V4), "vallum-laptop").unwrap();
        assert!(rules.contains("chain input {"), "{rules}");
        assert!(
            rules.contains("iifname != \"vallum-laptop\" ip daddr { 10.7.0.2 } drop"),
            "{rules}"
        );
    }

    #[test]
    fn ruleset_and_guard_steps_adapt_to_auto_carrier_and_include_sysctls() {
        let auto_cfg = FULL_V4.replace(
            "addresses = [\"10.7.0.2/32\"]",
            "addresses = [\"10.7.0.2/32\"]\ncarrier = \"auto\"",
        );
        let cfg = config(&auto_cfg);
        let rules = ruleset(&cfg, "vallum-laptop").unwrap();
        assert!(rules.contains("ip daddr 203.0.113.5 udp dport 51820 accept"));
        assert!(rules.contains("ip daddr 203.0.113.5 tcp dport 51820 accept"));

        let steps = guard_steps(&cfg, "vallum-laptop").unwrap();
        assert_eq!(steps.len(), 3);
    }

    #[test]
    fn mode_parses_lockdown_and_resolves_for_split_or_full_tunnels() {
        assert_eq!(Mode::parse("lockdown"), Some(Mode::Lockdown));
        assert_eq!(Mode::parse("always"), Some(Mode::Lockdown));
        assert!(Mode::Lockdown.expects_guard());
        assert_eq!(Mode::Lockdown.as_str(), "lockdown");

        let split_lockdown = config(&SPLIT_V4.replace(
            "[[peer]]",
            "[quick]\npolicy = \"lockdown\"\n\n[[peer]]",
        ));
        assert_eq!(resolve(&split_lockdown), Mode::Lockdown);
        assert!(!declines_guard(
            &split_lockdown,
            Mode::from_config(&split_lockdown)
        ));
    }

    #[test]
    fn v6_capable_tunnel_permits_icmpv6_ndp_before_drop() {
        let dual_stack = FULL_V4.replace(
            "addresses = [\"10.7.0.2/32\"]",
            "addresses = [\"10.7.0.2/32\", \"fd00:7::2/128\"]",
        );
        let rules = ruleset(&config(&dual_stack), "vallum-laptop").unwrap();
        assert!(
            rules.contains(
                "ip6 nexthdr icmpv6 icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept"
            ),
            "{rules}"
        );
        let ndp_pos = rules.find("nd-neighbor-advert").unwrap();
        let drop_pos = rules.rfind("    drop\n").unwrap();
        assert!(ndp_pos < drop_pos);
    }

    #[test]
    fn lockdown_ruleset_succeeds_without_resolvable_endpoints_at_early_boot() {
        let unresolved = FULL_V4
            .replace("policy = \"on\"", "policy = \"lockdown\"")
            .replace(
                "endpoint = \"203.0.113.5:51820\"",
                "endpoint = \"nonexistent.invalid:51820\"",
            );
        let cfg = config(&unresolved);
        let rules = lockdown_ruleset(&cfg, "vallum-laptop");
        assert!(rules.contains("oifname \"vallum-laptop\" accept"), "{rules}");
        assert!(rules.contains("    drop\n"), "{rules}");
        let steps = guard_steps(&cfg, "vallum-laptop").expect("lockdown falls back without DNS");
        assert_eq!(steps.len(), 3);
    }
}
