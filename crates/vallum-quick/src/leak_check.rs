// SPDX-License-Identifier: Apache-2.0

//! Active leak checker (Mullvad §9.8): periodic non-tunnel TTL=1 probe.
//!
//! Static routing checks (`ip route get`) confirm what the kernel *intends* to
//! do; an active probe bound to a physical non-tunnel interface verifies that
//! the egress guard actually stops packets from leaving the host outside the
//! tunnel.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use vallum_config::Config;

const PROBE_TARGET_V4: &str = "1.1.1.1";
const PROBE_TARGET_V6: &str = "2606:4700:4700::1111";

/// Address family for an active non-tunnel probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    V4,
    V6,
}

impl Family {
    fn ip_flag(self) -> &'static str {
        match self {
            Self::V4 => "-4",
            Self::V6 => "-6",
        }
    }

    fn ping_target(self) -> String {
        let env_key = match self {
            Self::V4 => "VALLUM_LEAK_PROBE_V4",
            Self::V6 => "VALLUM_LEAK_PROBE_V6",
        };
        std::env::var(env_key)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| match self {
                Self::V4 => PROBE_TARGET_V4.to_owned(),
                Self::V6 => PROBE_TARGET_V6.to_owned(),
            })
    }

    fn label(self) -> &'static str {
        match self {
            Self::V4 => "IPv4",
            Self::V6 => "IPv6",
        }
    }
}

/// Outcome of probing a single non-tunnel interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProbeOutcome {
    Blocked(&'static str),
    Leaked(String),
    Inconclusive(String),
}

/// Aggregated active leak-check verdict across all probed interfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LeakVerdict {
    Clean { probed: Vec<String> },
    Leaking { leaks: Vec<String> },
    Skipped { reason: String },
}

impl LeakVerdict {
    pub(crate) fn status_str(&self) -> &'static str {
        match self {
            Self::Clean { .. } => "clean",
            Self::Leaking { .. } => "leaking",
            Self::Skipped { .. } => "skipped",
        }
    }

    pub(crate) fn detail(&self) -> String {
        match self {
            Self::Clean { probed } => {
                format!("non-tunnel egress blocked on {}", probed.join(", "))
            }
            Self::Leaking { leaks } => leaks.join("; "),
            Self::Skipped { reason } => reason.clone(),
        }
    }
}

/// Determine whether the config claims a full tunnel for IPv4 and/or IPv6.
pub(crate) fn has_full_tunnel(config: &Config) -> (bool, bool) {
    let mut v4 = false;
    let mut v6 = false;
    for peer in &config.peers {
        for cidr in &peer.allowed_ips {
            let trimmed = cidr.trim();
            if trimmed == "0.0.0.0/0" {
                v4 = true;
            } else if trimmed == "::/0" {
                v6 = true;
            }
        }
    }
    (v4, v6)
}

/// Parse `ip route show default` output and return unique non-tunnel interface names.
pub(crate) fn parse_default_route_devs(ip_route_output: &str, tunnel_if: &str) -> Vec<String> {
    let mut devs = Vec::new();
    for line in ip_route_output.lines() {
        let mut tokens = line.split_whitespace();
        while let Some(tok) = tokens.next() {
            if tok == "dev" {
                if let Some(dev) = tokens.next() {
                    if dev != tunnel_if && dev != "lo" && !devs.iter().any(|d| d == dev) {
                        devs.push(dev.to_owned());
                    }
                }
                break;
            }
        }
    }
    devs
}

/// Classify the output of `ping -n -c 1 -W 1 -t 1 -I <dev> <target>`.
///
/// Pure so every kernel/ping response shape is testable without raw sockets.
pub(crate) fn classify_ping_output(
    family: Family,
    dev: &str,
    status_ok: bool,
    stdout: &str,
    stderr: &str,
) -> ProbeOutcome {
    let combined = format!("{stdout}\n{stderr}");
    let lower = combined.to_ascii_lowercase();

    // An upstream hop replied with TTL=1 exceeded, or the target replied directly:
    // a packet physically left `dev` and reached the network.
    if lower.contains("time to live exceeded")
        || lower.contains("bytes from")
        || lower.contains("1 received")
    {
        let hop = combined
            .lines()
            .find(|l| {
                let ll = l.to_ascii_lowercase();
                ll.contains("time to live exceeded") || ll.contains("bytes from")
            })
            .map(str::trim)
            .unwrap_or("external reply received");
        return ProbeOutcome::Leaked(format!(
            "{} probe via `{dev}` escaped host ({hop})",
            family.label()
        ));
    }

    // Socket creation itself failed (e.g. unprivileged without ping_group_range).
    if lower.contains("socket: operation not permitted")
        || lower.contains("cannot assign requested address")
    {
        return ProbeOutcome::Inconclusive(format!(
            "{} probe on `{dev}` lacked socket permission",
            family.label()
        ));
    }

    // Kernel/nftables blocked transmission at sendmsg/output hook.
    if lower.contains("operation not permitted") || lower.contains("network is unreachable") {
        return ProbeOutcome::Blocked("egress blocked by kernel/firewall");
    }

    if lower.contains("0 received") || lower.contains("100% packet loss") {
        return ProbeOutcome::Blocked("no egress reply");
    }

    if status_ok {
        return ProbeOutcome::Leaked(format!(
            "{} probe via `{dev}` succeeded outside tunnel",
            family.label()
        ));
    }

    let reason = combined
        .lines()
        .find(|l| !l.trim().is_empty())
        .map(str::trim)
        .unwrap_or("unknown probe error");
    ProbeOutcome::Inconclusive(format!("{} probe on `{dev}`: {reason}", family.label()))
}

/// Aggregate individual interface probe outcomes into a single verdict.
pub(crate) fn evaluate_probes(outcomes: &[(Family, String, ProbeOutcome)]) -> LeakVerdict {
    if outcomes.is_empty() {
        return LeakVerdict::Skipped {
            reason: "no non-tunnel default-route interfaces to probe".to_owned(),
        };
    }

    let mut leaks = Vec::new();
    let mut probed = Vec::new();
    let mut inconclusive = Vec::new();

    for (family, dev, outcome) in outcomes {
        let tag = format!("{dev}({})", family.label());
        match outcome {
            ProbeOutcome::Leaked(msg) => leaks.push(msg.clone()),
            ProbeOutcome::Blocked(_) => probed.push(tag),
            ProbeOutcome::Inconclusive(msg) => inconclusive.push(msg.clone()),
        }
    }

    if !leaks.is_empty() {
        return LeakVerdict::Leaking { leaks };
    }
    if !probed.is_empty() {
        return LeakVerdict::Clean { probed };
    }
    LeakVerdict::Skipped {
        reason: inconclusive.join("; "),
    }
}

fn default_route_devs(family: Family, tunnel_if: &str) -> Vec<String> {
    let Ok(out) = Command::new("ip")
        .args([family.ip_flag(), "route", "show", "default"])
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&out.stdout);
    parse_default_route_devs(&text, tunnel_if)
}

fn probe_interface(family: Family, dev: &str) -> ProbeOutcome {
    let target = family.ping_target();
    let mut cmd = Command::new("ping");
    if family == Family::V6 {
        cmd.arg("-6");
    }
    cmd.args(["-n", "-c", "1", "-W", "1", "-t", "1", "-I", dev, &target]);

    match cmd.output() {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            classify_ping_output(family, dev, out.status.success(), &stdout, &stderr)
        }
        Err(err) => ProbeOutcome::Inconclusive(format!(
            "{} probe on `{dev}` failed to run `ping`: {err}",
            family.label()
        )),
    }
}

/// Run an active non-tunnel TTL=1 probe for all full-tunnel families.
pub(crate) fn run_active_leak_check(config: &Config, interface: &str) -> LeakVerdict {
    let (full_v4, full_v6) = has_full_tunnel(config);
    if !full_v4 && !full_v6 {
        return LeakVerdict::Skipped {
            reason: "split tunnel (no 0.0.0.0/0 or ::/0 default claim)".to_owned(),
        };
    }

    let mut outcomes = Vec::new();
    if full_v4 {
        for dev in default_route_devs(Family::V4, interface) {
            let outcome = probe_interface(Family::V4, &dev);
            outcomes.push((Family::V4, dev, outcome));
        }
    }
    if full_v6 {
        for dev in default_route_devs(Family::V6, interface) {
            let outcome = probe_interface(Family::V6, &dev);
            outcomes.push((Family::V6, dev, outcome));
        }
    }

    evaluate_probes(&outcomes)
}

pub(crate) fn state_path(interface: &str) -> PathBuf {
    crate::routes::state_path(interface).with_extension("leak-check")
}

/// Persist the latest leak-check verdict to `/run/vallum/<if>.leak-check` as JSON.
pub(crate) fn write_state(interface: &str, verdict: &LeakVerdict) {
    let path = state_path(interface);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let escaped_detail = verdict.detail().replace('\\', "\\\\").replace('"', "\\\"");
    let json = format!(
        "{{\"status\":\"{}\",\"detail\":\"{}\",\"checked_at\":{now}}}\n",
        verdict.status_str(),
        escaped_detail
    );
    let _ = fs::write(path, json);
}

pub(crate) fn remove_state(interface: &str, dry_run: bool) {
    let path = state_path(interface);
    if dry_run {
        println!("would remove {}", path.display());
    } else {
        let _ = fs::remove_file(path);
    }
}

/// CLI handler for `vallum-quick leak-check`.
pub(crate) fn leak_check_cmd(
    config_path: &Path,
    json: bool,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = crate::load_normalized(config_path)?;
    let interface = config
        .interface
        .name
        .clone()
        .unwrap_or_else(|| "vallum0".to_owned());

    if dry_run {
        let (full_v4, full_v6) = has_full_tunnel(&config);
        println!(
            "would run active non-tunnel leak check for {interface} (v4={full_v4}, v6={full_v6})"
        );
        return Ok(());
    }

    let verdict = run_active_leak_check(&config, &interface);
    write_state(&interface, &verdict);

    if json {
        let escaped = verdict.detail().replace('\\', "\\\\").replace('"', "\\\"");
        println!(
            "{{\"interface\":\"{interface}\",\"status\":\"{}\",\"detail\":\"{escaped}\"}}",
            verdict.status_str()
        );
    } else {
        println!(
            "vallum-quick: {interface}: leak-check {}: {}",
            verdict.status_str(),
            verdict.detail()
        );
    }

    if let LeakVerdict::Leaking { leaks } = verdict {
        return Err(format!("active egress leak detected: {}", leaks.join("; ")).into());
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_default_route_devs_excludes_tunnel_and_lo_and_dedups() {
        let sample = "\
default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.42 metric 100
default via 10.0.0.1 dev vallum0 metric 50
default via 192.168.1.1 dev eth0 metric 200
default via 10.20.0.1 dev wlan0 metric 600
default dev lo scope link
";
        assert_eq!(
            parse_default_route_devs(sample, "vallum0"),
            vec!["eth0".to_owned(), "wlan0".to_owned()]
        );
    }

    #[test]
    fn classify_ping_detects_ttl_exceeded_as_confirmed_leak() {
        let stdout = "\
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
From 192.168.1.1 icmp_seq=1 Time to live exceeded

--- 1.1.1.1 ping statistics ---
1 packets transmitted, 0 received, +1 errors, 100% packet loss, time 0ms
";
        let outcome = classify_ping_output(Family::V4, "eth0", false, stdout, "");
        assert!(matches!(outcome, ProbeOutcome::Leaked(_)));
    }

    #[test]
    fn classify_ping_treats_sendmsg_eperm_as_blocked_not_inconclusive() {
        let stderr = "ping: sendmsg: Operation not permitted\n";
        let outcome = classify_ping_output(Family::V4, "eth0", false, "", stderr);
        assert_eq!(
            outcome,
            ProbeOutcome::Blocked("egress blocked by kernel/firewall")
        );
    }

    #[test]
    fn classify_ping_treats_socket_eperm_as_inconclusive() {
        let stderr = "ping: socket: Operation not permitted\n";
        let outcome = classify_ping_output(Family::V4, "eth0", false, "", stderr);
        assert!(matches!(outcome, ProbeOutcome::Inconclusive(_)));
    }

    #[test]
    fn evaluate_probes_flags_any_leak_over_clean_interfaces() {
        let verdict = evaluate_probes(&[
            (
                Family::V4,
                "eth0".to_owned(),
                ProbeOutcome::Blocked("egress blocked by kernel/firewall"),
            ),
            (
                Family::V6,
                "eth0".to_owned(),
                ProbeOutcome::Leaked("IPv6 probe via `eth0` escaped host".to_owned()),
            ),
        ]);
        assert_eq!(verdict.status_str(), "leaking");
    }
}
