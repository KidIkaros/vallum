// SPDX-License-Identifier: Apache-2.0

//! `vallum doctor`: a read-only readiness report.

use std::path::{Path, PathBuf};

use clap::Args;
use vallum_crypto_sdk::SdkSuite;

use crate::config::{Config, ResolveConfig};
use crate::control;
use crate::uapi;
use crate::Error;

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// The configuration file to check.
    #[arg(long, short, value_name = "FILE")]
    config: Option<PathBuf>,

    /// The control socket to query, instead of the config's `control`.
    #[arg(long, value_name = "SOCKET")]
    control: Option<PathBuf>,

    /// Probe the path MTU to this host with `ping -M do` and compare it with
    /// the config's `outer_mtu`.
    ///
    /// This is the one active check: it sends packets. Without the flag,
    /// `doctor` is read-only.
    #[arg(long, value_name = "HOST")]
    probe_mtu: Option<String>,

    /// Emit JSON instead of a table.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Pass,
    Warn,
    Fail,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }

    fn json(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

struct Check {
    name: &'static str,
    status: Status,
    detail: String,
}

impl Check {
    fn new(name: &'static str, status: Status, detail: impl Into<String>) -> Self {
        Self {
            name,
            status,
            detail: detail.into(),
        }
    }
}

/// Run the checks and print the report.
///
/// # Errors
///
/// Returns an error after printing if any check failed.
pub fn doctor(args: &DoctorArgs) -> Result<(), Error> {
    let mut checks = Vec::new();
    checks.push(Check::new(
        "platform",
        if cfg!(target_os = "linux") {
            Status::Pass
        } else {
            Status::Warn
        },
        format!(
            "{} (Linux is the supported tier this release)",
            std::env::consts::OS
        ),
    ));

    let config = match args.config.as_deref() {
        Some(path) => match check_config(path) {
            Ok(config) => {
                checks.push(Check::new(
                    "config",
                    Status::Pass,
                    format!("{} parsed and resolved", path.display()),
                ));
                Some(config)
            }
            Err(error) => {
                checks.push(Check::new("config", Status::Fail, error.to_string()));
                None
            }
        },
        None => {
            checks.push(Check::new(
                "config",
                Status::Warn,
                "no --config given; only the control socket and tools are checked",
            ));
            None
        }
    };

    let socket = args
        .control
        .clone()
        .or_else(|| config.as_ref().and_then(control_from_config));
    match socket {
        Some(path) => match check_control(&path) {
            Ok(detail) => {
                checks.push(Check::new("control", Status::Pass, detail));
                // The parts can all pass while nothing crosses the wire. This
                // is the only check that says whether the tunnel is *live*.
                checks.push(check_tunnel(&path));
            }
            Err(error) => checks.push(Check::new("control", Status::Fail, error.to_string())),
        },
        None => checks.push(Check::new(
            "control",
            if args.config.is_none() && args.control.is_none() {
                Status::Fail
            } else {
                Status::Warn
            },
            "no control socket configured; give --control or a config with `control`",
        )),
    }

    if let Some(resolved) = &config {
        // A port of 0 is an ephemeral client; anything else is a server, and a
        // server that cannot forward or is not reachable is not working.
        if resolved.listen.port() != 0 {
            checks.push(check_forwarding(resolved));
            checks.push(check_firewall(resolved.listen.port()));
        }
        let rotating: Vec<&str> = resolved
            .peers
            .iter()
            .filter(|peer| !peer.previous_identities().is_empty())
            .map(vallum_tunnel::PeerConfig::name)
            .collect();
        if !rotating.is_empty() {
            checks.push(Check::new(
                "rotation",
                Status::Warn,
                format!(
                    "{} still accepts a previous key; run `vallum peer finalize` once the \
                     device has the new one",
                    rotating.join(", ")
                ),
            ));
        }
        checks.push(check_service(args.config.as_deref()));
        checks.push(check_config_mode(args.config.as_deref()));
        if let Some(host) = &args.probe_mtu {
            checks.push(check_path_mtu(host, resolved));
        }
    }

    for tool in ["ip", "systemctl", "journalctl", "resolvconf", "nft"] {
        let found = which(tool);
        checks.push(Check::new(
            tool,
            if found { Status::Pass } else { Status::Warn },
            if found {
                "found on PATH".to_owned()
            } else {
                "not found on PATH; the related action will show a command instead".to_owned()
            },
        ));
    }

    let failures = checks
        .iter()
        .filter(|check| check.status == Status::Fail)
        .count();
    if args.json {
        let value = serde_json::json!(checks
            .iter()
            .map(|check| serde_json::json!({
                "check": check.name,
                "status": check.status.json(),
                "detail": check.detail,
            }))
            .collect::<Vec<_>>());
        println!(
            "{}",
            serde_json::to_string_pretty(&value).map_err(|e| Error::Usage(e.to_string()))?
        );
    } else {
        for check in &checks {
            println!(
                "{} {:<10} {}",
                crate::style::status_badge(check.status.as_str()),
                check.name,
                check.detail
            );
        }
    }
    if failures == 0 {
        Ok(())
    } else {
        Err(Error::Usage(format!("doctor found {failures} failure(s)")))
    }
}

fn check_config(path: &Path) -> Result<crate::config::Resolved, Error> {
    let config = Config::load(path)?;
    let suite_id = config.suite_id(path)?;
    let suite = SdkSuite::from_id(suite_id)
        .map_err(|e| Error::Suite(format!("suite 0x{suite_id:04x}: {e}")))?;
    config.resolve(path, &suite)
}

fn control_from_config(config: &crate::config::Resolved) -> Option<PathBuf> {
    config.control.clone()
}

fn check_control(path: &Path) -> Result<String, Error> {
    let reply = control::request(path, "get=1\n")?;
    if !reply.lines().any(|line| line == "errno=0") {
        return Err(Error::Invalid {
            path: path.to_path_buf(),
            what: format!("control request failed: {}", reply.trim()),
        });
    }
    let response = uapi::parse_response(&reply);
    let interface = response.field(uapi::field::VALLUM_INTERFACE).unwrap_or("?");
    let port = response.field(uapi::field::LISTEN_PORT).unwrap_or("?");
    let suite = response.field(uapi::field::VALLUM_SUITE).unwrap_or("?");
    let peers = response.peers.len();
    Ok(format!(
        "interface `{interface}`, listen {port}, suite {suite}, {peers} peer(s)"
    ))
}

/// Whether traffic is actually crossing: the age of the newest handshake.
///
/// Three dogfood failures ended in "everything configured" and "no internet":
/// a unit that could not exec, a config root could not read, and a default
/// route into a dead interface. `doctor` checked the parts and passed all three
/// times. This check is about the whole.
fn check_tunnel(path: &Path) -> Check {
    let reply = match control::request(path, "get=1\n") {
        Ok(reply) => reply,
        Err(error) => return Check::new("tunnel", Status::Warn, error.to_string()),
    };
    let response = uapi::parse_response(&reply);
    if response.peers.is_empty() {
        return Check::new(
            "tunnel",
            Status::Warn,
            "no peers yet: enrol one, then this check reports the handshake age",
        );
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    // `parse_response` returns raw key/value blocks; read the field directly.
    let newest = response
        .peers
        .iter()
        .filter_map(|peer| {
            peer.iter()
                .find(|(key, _)| key == uapi::field::LAST_HANDSHAKE_TIME_SEC)
                .and_then(|(_, value)| value.parse::<u64>().ok())
        })
        .max();
    match newest {
        Some(secs) if secs > 0 => {
            let age = now.saturating_sub(secs);
            if age <= 180 {
                Check::new("tunnel", Status::Pass, format!("handshake {age}s ago"))
            } else {
                Check::new(
                    "tunnel",
                    Status::Warn,
                    format!(
                        "last handshake {age}s ago — the peer may be offline, or the path \
                         changed. `vallum show` has the counters"
                    ),
                )
            }
        }
        _ => Check::new(
            "tunnel",
            Status::Warn,
            format!(
                "no handshake since the daemon started: UDP {} may be filtered on one \
                 side, the endpoint may be wrong, or the other daemon may not be running",
                response.field(uapi::field::LISTEN_PORT).unwrap_or("?")
            ),
        ),
    }
}

fn which(program: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| dir.join(program).is_file())
}

fn output(program: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn sysctl(path: &str) -> bool {
    std::fs::read_to_string(path).is_ok_and(|value| value.trim() == "1")
}

/// A server has to forward, or clients reach nothing but the server.
fn check_forwarding(resolved: &crate::config::Resolved) -> Check {
    let has_v4 = resolved
        .addresses
        .iter()
        .any(|prefix| prefix.as_ipnet().addr().is_ipv4());
    let has_v6 = resolved
        .addresses
        .iter()
        .any(|prefix| prefix.as_ipnet().addr().is_ipv6());
    let mut missing = Vec::new();
    if has_v4 && !sysctl("/proc/sys/net/ipv4/ip_forward") {
        missing.push("net.ipv4.ip_forward");
    }
    if has_v6 && !sysctl("/proc/sys/net/ipv6/conf/all/forwarding") {
        missing.push("net.ipv6.conf.all.forwarding");
    }
    // A firewall can filter forwarding even with the sysctl on: Docker,
    // Tailscale, and iptables-based ufw all install chains in `ip filter`,
    // which is invisible to the nft-native chains the firewall check reads.
    if missing.is_empty() && crate::hostnet::inspect().iptables_forward_drop {
        let interface = resolved.interface_name.as_deref().unwrap_or("vallum0");
        let accepted = output("iptables", &["-S", "FORWARD"]).is_some_and(|rules| {
            rules
                .lines()
                .any(|line| line.contains(&format!("-i {interface}")) && line.contains("-j ACCEPT"))
        });
        return if accepted {
            Check::new(
                "forwarding",
                Status::Pass,
                format!("IP forwarding is on, and iptables accepts traffic on {interface}"),
            )
        } else {
            Check::new(
                "forwarding",
                Status::Warn,
                format!(
                    "IP forwarding is on, but iptables filters forwarded traffic (Docker, \
                     Tailscale, or another manager); run `vallum server init --force`, or \
                     `iptables -I FORWARD -i {interface} -j ACCEPT`"
                ),
            )
        };
    }
    if missing.is_empty() {
        Check::new(
            "forwarding",
            Status::Pass,
            "IP forwarding is enabled for every address family the tunnel uses",
        )
    } else {
        Check::new(
            "forwarding",
            Status::Warn,
            format!(
                "{} is off; clients will not reach beyond this host — \
                 `vallum server init` enables it",
                missing.join(" and ")
            ),
        )
    }
}

/// The UDP port has to be reachable from outside, or nothing connects.
fn check_firewall(port: u16) -> Check {
    let state = crate::hostnet::inspect();
    let (status, detail) = match state.firewall {
        crate::hostnet::Firewall::Ufw => {
            let allowed = ufw_allows(port);
            (
                if allowed { Status::Pass } else { Status::Warn },
                if allowed {
                    format!("ufw allows UDP {port}")
                } else {
                    format!("ufw does not allow UDP {port}; run `ufw allow {port}/udp`")
                },
            )
        }
        crate::hostnet::Firewall::Firewalld => {
            let allowed = output("firewall-cmd", &[&format!("--query-port={port}/udp")]).is_some();
            (
                if allowed { Status::Pass } else { Status::Warn },
                if allowed {
                    format!("firewalld allows UDP {port}")
                } else {
                    format!(
                        "firewalld does not allow UDP {port}; run \
                         `firewall-cmd --permanent --add-port={port}/udp`"
                    )
                },
            )
        }
        crate::hostnet::Firewall::Nftables => {
            let allowed = output("nft", &["list", "ruleset"])
                .is_some_and(|rules| rules.contains(&format!("dport {port}")));
            if allowed {
                (Status::Pass, format!("nftables accepts UDP {port}"))
            } else if !state.input_drop {
                // Nothing is dropping the port, so there is no rule to add.
                // Saying otherwise sends the operator to edit a chain that is
                // not blocking anything.
                (
                    Status::Pass,
                    if state.ufw_installed {
                        if ufw_allows(port) {
                            format!(
                                "nothing blocks UDP {port}; ufw is installed but not enabled, \
                                 and the allow rule is stored for when you enable it"
                            )
                        } else {
                            format!(
                                "nothing blocks UDP {port}; ufw is installed but not enabled — \
                                 if you enable it, run `ufw allow {port}/udp` first"
                            )
                        }
                    } else {
                        format!("nothing blocks UDP {port}; the nftables input chain has no drop policy")
                    },
                )
            } else {
                (
                    Status::Warn,
                    format!(
                        "the nftables input chain drops UDP {port}; run `vallum server init \
                         --force`, or add an accept rule to `inet filter input`"
                    ),
                )
            }
        }
        crate::hostnet::Firewall::None => (
            Status::Pass,
            if state.ufw_installed && !ufw_allows(port) {
                format!(
                    "no host firewall is active, so nothing blocks UDP {port}; ufw is \
                     installed but not enabled — run `ufw allow {port}/udp` before enabling it"
                )
            } else {
                "no host firewall detected, so nothing is blocking the port".to_owned()
            },
        ),
    };
    Check::new("firewall", status, detail)
}

/// Whether ufw stores an allow rule for this port.
///
/// `ufw status` only lists rules while ufw is enabled; `ufw show added` reads
/// the stored ones, which is what matters for a manager that is installed but
/// switched off.
fn ufw_allows(port: u16) -> bool {
    let rule = format!("{port}/udp");
    ["status", "show added"].iter().any(|args| {
        let args: Vec<&str> = args.split(' ').collect();
        output("ufw", &args).is_some_and(|text| {
            text.lines()
                .any(|line| line.contains(&rule) && line.to_lowercase().contains("allow"))
        })
    })
}

/// Whether the unit that should own this config is running.
fn check_service(config: Option<&Path>) -> Check {
    let Some(path) = config else {
        return Check::new(
            "service",
            Status::Warn,
            "no --config given, so there is no unit to look up",
        );
    };
    if !Path::new("/run/systemd/system").exists() {
        return Check::new(
            "service",
            Status::Warn,
            "no systemd on this host; the daemon is run directly",
        );
    }
    let instance = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("vallum0");
    let unit = format!("vallum@{instance}");
    // `systemctl is-active` exits non-zero for anything but `active`, so the
    // status is the text, not the exit code.
    let state = std::process::Command::new("systemctl")
        .args(["is-active", &unit])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    match state.as_str() {
        "active" => Check::new("service", Status::Pass, format!("{unit} is active")),
        "inactive" => Check::new(
            "service",
            Status::Warn,
            format!("{unit} is inactive; `systemctl enable --now {unit}`"),
        ),
        "failed" => Check::new(
            "service",
            Status::Fail,
            format!("{unit} failed; `journalctl -u {unit}` has the reason"),
        ),
        other => Check::new("service", Status::Warn, format!("{unit} is {other}")),
    }
}

/// The largest ICMP payload that crosses the path, by bisection.
///
/// Bounds are the IPv4 minimum reassembly buffer (576 - 28 = 548) and a
/// 1500-byte Ethernet path (1500 - 28 = 1472). Nine probes at most.
fn bisect_mtu(mut fits: impl FnMut(u16) -> bool) -> Option<u16> {
    const MIN: u16 = 548;
    const MAX: u16 = 1472;
    if !fits(MIN) {
        return None;
    }
    if fits(MAX) {
        return Some(MAX);
    }
    let mut good = MIN;
    let mut bad = MAX;
    while bad - good > 1 {
        let middle = good + (bad - good) / 2;
        if fits(middle) {
            good = middle;
        } else {
            bad = middle;
        }
    }
    Some(good)
}

fn ping_fits(host: &str, payload: u16) -> bool {
    std::process::Command::new("ping")
        .args([
            "-M",
            "do",
            "-s",
            &payload.to_string(),
            "-c",
            "1",
            "-W",
            "2",
            host,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Measure the outer path and say whether `outer_mtu` fits it.
fn check_path_mtu(host: &str, resolved: &crate::config::Resolved) -> Check {
    let configured = u16::try_from(resolved.outer_budget + 48).unwrap_or(u16::MAX);
    let Some(payload) = bisect_mtu(|size| ping_fits(host, size)) else {
        return Check::new(
            "path-mtu",
            Status::Warn,
            format!(
                "inconclusive: no ICMP reply from {host} at any size (filtered, or no route).                  Measure it by hand: ping -M do -s 1472 {host}"
            ),
        );
    };
    let measured = payload + 28;
    if measured >= configured {
        Check::new(
            "path-mtu",
            Status::Pass,
            format!("{host} carries {measured} bytes; outer_mtu {configured} fits"),
        )
    } else {
        Check::new(
            "path-mtu",
            Status::Warn,
            format!(
                "{host} carries {measured} bytes, below outer_mtu {configured};                  set `interface.outer_mtu = {measured}` or packets will be dropped"
            ),
        )
    }
}

/// A config can name a PSK file, so it should not be group- or world-readable.
fn check_config_mode(config: Option<&Path>) -> Check {
    use std::os::unix::fs::PermissionsExt;
    let Some(path) = config else {
        return Check::new("config mode", Status::Warn, "no --config given");
    };
    let Ok(metadata) = std::fs::metadata(path) else {
        return Check::new(
            "config mode",
            Status::Warn,
            format!("cannot read {}", path.display()),
        );
    };
    // The units run with a bounded capability set, so root does not get
    // CAP_DAC_OVERRIDE and cannot read a 0600 file owned by someone else. A
    // config moved in from a user's directory keeps its owner and then fails
    // to load with "permission denied" — as root.
    let owned_by_root = std::os::unix::fs::MetadataExt::uid(&metadata) == 0;
    if path.starts_with("/etc/vallum") && !owned_by_root {
        return Check::new(
            "config owner",
            Status::Warn,
            format!(
                "{} is owned by uid {}; the units run without CAP_DAC_OVERRIDE, so they                  cannot read it. `sudo chown root:root {}`",
                path.display(),
                std::os::unix::fs::MetadataExt::uid(&metadata),
                path.display()
            ),
        );
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 == 0 {
        Check::new(
            "config mode",
            Status::Pass,
            format!("{mode:04o} (owner only)"),
        )
    } else {
        Check::new(
            "config mode",
            Status::Warn,
            format!(
                "{mode:04o} is group/world readable; `chmod 600 {}`",
                path.display()
            ),
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::bisect_mtu;

    #[test]
    fn the_search_finds_the_threshold() {
        assert_eq!(bisect_mtu(|size| size <= 1400), Some(1400));
        assert_eq!(bisect_mtu(|size| size <= 1471), Some(1471));
        assert_eq!(bisect_mtu(|size| size <= 548), Some(548));
    }

    #[test]
    fn a_path_that_carries_everything_reports_the_ceiling() {
        assert_eq!(bisect_mtu(|_| true), Some(1472));
    }

    #[test]
    fn a_path_that_carries_nothing_is_inconclusive() {
        assert_eq!(bisect_mtu(|_| false), None);
    }

    #[test]
    fn the_search_is_bounded() {
        let mut probes = 0;
        let found = bisect_mtu(|size| {
            probes += 1;
            size <= 1200
        });
        assert_eq!(found, Some(1200));
        assert!(probes <= 12, "{probes} probes is too many");
    }
}
