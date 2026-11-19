// SPDX-License-Identifier: Apache-2.0

//! Host-level network setup for a tunnel endpoint: forwarding, firewall, NAT.
//!
//! The daemon owns the tunnel and nothing else. This module is the one place
//! that touches the *host*: it enables IP forwarding, opens the UDP port, and
//! installs the masquerade rule that lets a client reach the internet through
//! the server. `vallum server init` calls it; `vallum-quick` does not, because
//! it is per-interface work and this is per-host work.
//!
//! Everything here is a **plan first**: [`inspect`] reads the host, the
//! `plan_*` functions turn that state into [`HostStep`]s, and [`apply`] runs
//! them. `--dry-run` prints the plan and executes nothing, which is the only
//! honest way to ship a tool that edits a firewall.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ipnet::IpNet;

use crate::Error;

/// The firewall actually in charge of the host.
///
/// Detection order matters: `ufw` and `firewalld` both render into nftables
/// under the hood, so a rule added to Vallum's own table would be shadowed by
/// their drop policy. Their own CLIs are used when they are active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Firewall {
    /// Uncomplicated Firewall (`ufw status` reports active).
    Ufw,
    /// firewalld (`firewall-cmd --state` reports running).
    Firewalld,
    /// Plain nftables.
    Nftables,
    /// Nothing detected; the host has no filtering to open.
    None,
}

impl Firewall {
    /// The name an operator would recognise.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ufw => "ufw",
            Self::Firewalld => "firewalld",
            Self::Nftables => "nftables",
            Self::None => "none",
        }
    }
}

/// What the host looks like right now.
#[derive(Debug, Clone)]
pub struct HostState {
    /// The active firewall.
    pub firewall: Firewall,
    /// Whether nftables' `inet filter` input chain has a drop policy.
    pub input_drop: bool,
    /// Whether nftables' `inet filter` forward chain has a drop policy.
    pub forward_drop: bool,
    /// Whether `net.ipv4.ip_forward` is already on.
    pub forward_v4: bool,
    /// Whether `net.ipv6.conf.all.forwarding` is already on.
    pub forward_v6: bool,
    /// Whether `ufw` is installed, whether or not it is enabled.
    ///
    /// An inactive manager still stores rules, and an operator who enables it
    /// later expects the tunnel to survive. Ignoring it here is how a working
    /// server stops working months later with no change to Vallum.
    pub ufw_installed: bool,
    /// Whether `firewall-cmd` is installed, whether or not it is running.
    pub firewalld_installed: bool,
    /// Whether iptables filters forwarded traffic.
    ///
    /// Docker, Tailscale, and a ufw with the iptables backend all install
    /// chains here, and the nft-native `inet filter` chains this module reads
    /// for nftables do not see them. A `DROP` in one of those chains is the
    /// classic "the tunnel pings but nothing forwards" host.
    pub iptables_forward_drop: bool,
    /// Whether iptables filters input traffic.
    pub iptables_input_drop: bool,
}

/// One host change, described before it is run.
#[derive(Debug, Clone)]
pub enum HostStep {
    /// Run a program.
    Run {
        /// What the operator is being told this does.
        summary: String,
        /// The program.
        program: String,
        /// Its arguments.
        args: Vec<String>,
        /// Standard input, for `nft -f -`.
        stdin: Option<String>,
        /// Whether a non-zero exit is acceptable (a delete that finds nothing).
        ignore_failure: bool,
    },
    /// Write a file.
    Write {
        /// What the operator is being told this does.
        summary: String,
        /// The path.
        path: PathBuf,
        /// The contents.
        contents: String,
        /// The mode to set, when the file is created.
        mode: u32,
    },
}

impl HostStep {
    /// What this step does, for a plan or a summary line.
    #[must_use]
    pub fn summary(&self) -> &str {
        match self {
            Self::Run { summary, .. } | Self::Write { summary, .. } => summary,
        }
    }

    fn execute(&self) -> Result<bool, Error> {
        match self {
            Self::Run {
                program,
                args,
                stdin,
                ignore_failure,
                summary,
            } => {
                let mut command = Command::new(program);
                command.args(args);
                command.stdout(Stdio::null());
                command.stderr(Stdio::piped());
                if stdin.is_some() {
                    command.stdin(Stdio::piped());
                }
                let mut child = command.spawn().map_err(|source| Error::IoPath {
                    action: "run",
                    path: PathBuf::from(program),
                    source,
                })?;
                if let Some(body) = stdin {
                    use std::io::Write;
                    if let Some(handle) = child.stdin.as_mut() {
                        handle.write_all(body.as_bytes()).map_err(Error::Io)?;
                    }
                }
                let output = child.wait_with_output().map_err(Error::Io)?;
                if output.status.success() || *ignore_failure {
                    return Ok(true);
                }
                let detail = String::from_utf8_lossy(&output.stderr);
                Err(Error::Usage(format!(
                    "{summary}: `{program} {}` failed: {}",
                    args.join(" "),
                    detail.trim()
                )))
            }
            Self::Write {
                path,
                contents,
                mode,
                ..
            } => {
                if std::fs::read_to_string(path).is_ok_and(|existing| existing == *contents) {
                    return Ok(false);
                }
                if let Some(parent) = path.parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent).map_err(|source| Error::IoPath {
                            action: "create",
                            path: parent.to_path_buf(),
                            source,
                        })?;
                    }
                }
                write_mode(path, contents.as_bytes(), *mode)?;
                Ok(true)
            }
        }
    }
}

fn write_mode(path: &Path, bytes: &[u8], mode: u32) -> Result<(), Error> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(mode);
    let mut file = options.open(path).map_err(|source| Error::IoPath {
        action: "write",
        path: path.to_path_buf(),
        source,
    })?;
    file.write_all(bytes).map_err(|source| Error::IoPath {
        action: "write",
        path: path.to_path_buf(),
        source,
    })
}

/// The path the forwarding setting is persisted to.
pub const SYSCTL_FILE: &str = "/etc/sysctl.d/90-vallum.conf";

/// The nftables table Vallum owns for masquerading.
pub const NAT_TABLE: &str = "vallum";

fn output_of(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn read_sysctl(path: &str) -> bool {
    std::fs::read_to_string(path).is_ok_and(|value| value.trim() == "1")
}

/// Read the host's current state.
#[must_use]
pub fn inspect() -> HostState {
    let ufw_active =
        output_of("ufw", &["status"]).is_some_and(|status| status.contains("Status: active"));
    let firewalld_active =
        output_of("firewall-cmd", &["--state"]).is_some_and(|state| state.trim() == "running");
    let nft_present = output_of("nft", &["--version"]).is_some();

    let firewall = if ufw_active {
        Firewall::Ufw
    } else if firewalld_active {
        Firewall::Firewalld
    } else if nft_present {
        Firewall::Nftables
    } else {
        Firewall::None
    };

    let input = output_of("nft", &["list", "chain", "inet", "filter", "input"]).unwrap_or_default();
    let forward =
        output_of("nft", &["list", "chain", "inet", "filter", "forward"]).unwrap_or_default();

    HostState {
        firewall,
        input_drop: input.contains("policy drop"),
        forward_drop: forward.contains("policy drop"),
        forward_v4: read_sysctl("/proc/sys/net/ipv4/ip_forward"),
        forward_v6: read_sysctl("/proc/sys/net/ipv6/conf/all/forwarding"),
        ufw_installed: output_of("ufw", &["--version"]).is_some(),
        firewalld_installed: output_of("firewall-cmd", &["--version"]).is_some(),
        iptables_forward_drop: iptables_filters("FORWARD"),
        iptables_input_drop: iptables_filters("INPUT"),
    }
}

/// Whether iptables has rules on `chain` and a `DROP` somewhere in the table.
///
/// The `DROP` may live in a chain `FORWARD` jumps to (`DOCKER-USER`,
/// `ts-forward`), so the whole table is searched; a host with no rules on the
/// chain is not filtering, and gets nothing.
fn iptables_filters(chain: &str) -> bool {
    let Some(rules) = output_of("iptables", &["-S", chain]) else {
        return false;
    };
    let filters = rules
        .lines()
        .any(|line| line.starts_with(&format!("-A {chain}")));
    filters && output_of("iptables", &["-S"]).is_some_and(|all| all.contains("-j DROP"))
}

/// Persist and apply IP forwarding.
#[must_use]
pub fn plan_forwarding(state: &HostState, v4: bool, v6: bool) -> Vec<HostStep> {
    let mut steps = Vec::new();
    if !v4 && !v6 {
        return steps;
    }
    let mut lines = String::from("# Written by `vallum server init`.\n");
    if v4 {
        lines.push_str("net.ipv4.ip_forward = 1\n");
    }
    if v6 {
        lines.push_str("net.ipv6.conf.all.forwarding = 1\n");
    }
    steps.push(HostStep::Write {
        summary: format!("persist forwarding in {SYSCTL_FILE}"),
        path: PathBuf::from(SYSCTL_FILE),
        contents: lines,
        mode: 0o644,
    });
    if v4 && !state.forward_v4 {
        steps.push(HostStep::Write {
            summary: "enable IPv4 forwarding now".to_owned(),
            path: PathBuf::from("/proc/sys/net/ipv4/ip_forward"),
            contents: "1\n".to_owned(),
            mode: 0o644,
        });
    }
    if v6 && !state.forward_v6 {
        steps.push(HostStep::Write {
            summary: "enable IPv6 forwarding now".to_owned(),
            path: PathBuf::from("/proc/sys/net/ipv6/conf/all/forwarding"),
            contents: "1\n".to_owned(),
            mode: 0o644,
        });
    }
    steps
}

/// Open a single UDP port in whichever firewall the host actually uses, without
/// adding forwarding rules. Used for the enrolment responder's port so it does
/// not duplicate the interface's FORWARD rules.
#[must_use]
pub fn plan_port(state: &HostState, port: u16) -> Vec<HostStep> {
    let mut state = state.clone();
    state.forward_drop = false;
    state.iptables_forward_drop = false;
    plan_firewall(&state, port, "")
}

/// Open the UDP port and let forwarded traffic through, in whichever firewall
/// the host actually uses.
#[must_use]
pub fn plan_firewall(state: &HostState, port: u16, interface: &str) -> Vec<HostStep> {
    let mut steps = plan_active_firewall(state, port, interface);
    // No active manager, but one installed: its rule is stored for the day it
    // is enabled, which is the difference between a tunnel that survives that
    // day and one that silently stops.
    // iptables filters in `ip filter`, which the nft-native chains above never
    // show. An accept at the top of the chain is what an operator writes by
    // hand, and it is the only thing that gets past `DOCKER-USER` or
    // `ts-forward`.
    if state.iptables_forward_drop {
        steps.push(HostStep::Run {
            summary: format!("allow traffic from {interface} in iptables FORWARD"),
            program: "iptables".to_owned(),
            args: vec![
                "-I".to_owned(),
                "FORWARD".to_owned(),
                "1".to_owned(),
                "-i".to_owned(),
                interface.to_owned(),
                "-j".to_owned(),
                "ACCEPT".to_owned(),
            ],
            stdin: None,
            ignore_failure: false,
        });
        steps.push(HostStep::Run {
            summary: format!("allow traffic to {interface} in iptables FORWARD"),
            program: "iptables".to_owned(),
            args: vec![
                "-I".to_owned(),
                "FORWARD".to_owned(),
                "2".to_owned(),
                "-o".to_owned(),
                interface.to_owned(),
                "-j".to_owned(),
                "ACCEPT".to_owned(),
            ],
            stdin: None,
            ignore_failure: false,
        });
    }
    if state.iptables_input_drop {
        steps.push(HostStep::Run {
            summary: format!("allow UDP {port} in iptables INPUT"),
            program: "iptables".to_owned(),
            args: vec![
                "-I".to_owned(),
                "INPUT".to_owned(),
                "1".to_owned(),
                "-p".to_owned(),
                "udp".to_owned(),
                "--dport".to_owned(),
                port.to_string(),
                "-j".to_owned(),
                "ACCEPT".to_owned(),
            ],
            stdin: None,
            ignore_failure: false,
        });
    }
    if matches!(state.firewall, Firewall::Nftables | Firewall::None) {
        if state.ufw_installed {
            steps.push(HostStep::Run {
                summary: format!(
                    "allow UDP {port} through ufw (installed, not enabled — the rule applies \
                     when you enable it)"
                ),
                program: "ufw".to_owned(),
                args: vec!["allow".to_owned(), format!("{port}/udp")],
                stdin: None,
                ignore_failure: false,
            });
        } else if state.firewalld_installed {
            steps.push(HostStep::Run {
                summary: format!(
                    "allow UDP {port} through firewalld (installed, not running — the rule \
                     applies when it starts)"
                ),
                program: "firewall-cmd".to_owned(),
                args: vec!["--permanent".to_owned(), format!("--add-port={port}/udp")],
                stdin: None,
                ignore_failure: true,
            });
        }
    }
    steps
}

fn plan_active_firewall(state: &HostState, port: u16, interface: &str) -> Vec<HostStep> {
    match state.firewall {
        Firewall::Ufw => vec![HostStep::Run {
            summary: format!("allow UDP {port} through ufw"),
            program: "ufw".to_owned(),
            args: vec!["allow".to_owned(), format!("{port}/udp")],
            stdin: None,
            ignore_failure: false,
        }],
        Firewall::Firewalld => vec![
            HostStep::Run {
                summary: format!("allow UDP {port} through firewalld"),
                program: "firewall-cmd".to_owned(),
                args: vec!["--permanent".to_owned(), format!("--add-port={port}/udp")],
                stdin: None,
                ignore_failure: true,
            },
            HostStep::Run {
                summary: "reload firewalld".to_owned(),
                program: "firewall-cmd".to_owned(),
                args: vec!["--reload".to_owned()],
                stdin: None,
                ignore_failure: false,
            },
        ],
        Firewall::Nftables => {
            // A rule in Vallum's own table cannot override a `drop` policy in
            // the host's `inet filter` chain: every base chain at the hook is
            // evaluated, and one drop wins. So the rule goes where the policy
            // is, and nowhere at all when there is no policy to open.
            let mut steps = Vec::new();
            if state.input_drop {
                steps.push(HostStep::Run {
                    summary: format!("allow UDP {port} in the nftables input chain"),
                    program: "nft".to_owned(),
                    args: vec![
                        "add".to_owned(),
                        "rule".to_owned(),
                        "inet".to_owned(),
                        "filter".to_owned(),
                        "input".to_owned(),
                        "udp".to_owned(),
                        "dport".to_owned(),
                        port.to_string(),
                        "accept".to_owned(),
                    ],
                    stdin: None,
                    ignore_failure: false,
                });
            }
            if state.forward_drop {
                steps.push(HostStep::Run {
                    summary: format!("allow forwarded traffic on {interface}"),
                    program: "nft".to_owned(),
                    args: vec![
                        "add".to_owned(),
                        "rule".to_owned(),
                        "inet".to_owned(),
                        "filter".to_owned(),
                        "forward".to_owned(),
                        "iifname".to_owned(),
                        format!("\"{interface}\""),
                        "accept".to_owned(),
                    ],
                    stdin: None,
                    ignore_failure: false,
                });
                steps.push(HostStep::Run {
                    summary: format!("allow replies to forwarded traffic on {interface}"),
                    program: "nft".to_owned(),
                    args: vec![
                        "add".to_owned(),
                        "rule".to_owned(),
                        "inet".to_owned(),
                        "filter".to_owned(),
                        "forward".to_owned(),
                        "oifname".to_owned(),
                        format!("\"{interface}\""),
                        "ct".to_owned(),
                        "state".to_owned(),
                        "established,related".to_owned(),
                        "accept".to_owned(),
                    ],
                    stdin: None,
                    ignore_failure: false,
                });
            }
            steps
        }
        Firewall::None => Vec::new(),
    }
}

/// Install the masquerade rule for the tunnel's own subnets, and — when
/// `isolate` names the tunnel interface — drop tunnel-to-tunnel forwarding.
///
/// The table is Vallum's own (`inet vallum`), so it can be replaced wholesale on
/// every run without touching the operator's rules, and deleted on uninstall.
/// That wholesale replace is also what makes the isolation toggle converge:
/// re-running the plan with the flag off removes the drop chain again.
///
/// Isolation lives in this table rather than the host's filter chains because
/// a drop in *any* base chain at the forward hook wins over an accept in
/// another, so it holds under ufw, firewalld and plain nftables alike without
/// editing a single operator rule (ADR-0047, service tenancy).
#[must_use]
pub fn plan_nat(v4: &[IpNet], v6: &[IpNet], isolate: Option<&str>) -> Vec<HostStep> {
    if v4.is_empty() && v6.is_empty() {
        return Vec::new();
    }
    let mut script = String::new();
    script.push_str(&format!("table inet {NAT_TABLE} {{\n"));
    script.push_str("  chain postrouting {\n");
    script.push_str("    type nat hook postrouting priority srcnat; policy accept;\n");
    for subnet in v4 {
        script.push_str(&format!("    ip saddr {subnet} masquerade\n"));
    }
    for subnet in v6 {
        script.push_str(&format!("    ip6 saddr {subnet} masquerade\n"));
    }
    script.push_str("  }\n");
    if let Some(interface) = isolate {
        // Entering and leaving the same tunnel interface is peer-to-peer
        // traffic; client-to-internet leaves a different interface and
        // client-to-server is input, not forward, so neither is touched.
        script.push_str("  chain forward {\n");
        script.push_str("    type filter hook forward priority filter; policy accept;\n");
        script.push_str(&format!(
            "    iifname \"{interface}\" oifname \"{interface}\" drop\n"
        ));
        script.push_str("  }\n");
    }
    script.push_str("}\n");
    vec![
        HostStep::Run {
            summary: format!("replace the `inet {NAT_TABLE}` NAT table"),
            program: "nft".to_owned(),
            args: vec![
                "delete".to_owned(),
                "table".to_owned(),
                "inet".to_owned(),
                NAT_TABLE.to_owned(),
            ],
            stdin: None,
            ignore_failure: true,
        },
        HostStep::Run {
            summary: "install the masquerade rule".to_owned(),
            program: "nft".to_owned(),
            args: vec!["-f".to_owned(), "-".to_owned()],
            stdin: Some(script),
            ignore_failure: false,
        },
    ]
}

/// Undo the host networking changes `server init` installed: the NAT table and
/// the firewall / FORWARD rules for `ports` and `interface`.
#[must_use]
pub fn plan_teardown(state: &HostState, ports: &[u16], interface: &str) -> Vec<HostStep> {
    let mut steps = vec![HostStep::Run {
        summary: format!("remove the `inet {NAT_TABLE}` NAT table"),
        program: "nft".to_owned(),
        args: vec![
            "delete".to_owned(),
            "table".to_owned(),
            "inet".to_owned(),
            NAT_TABLE.to_owned(),
        ],
        stdin: None,
        ignore_failure: true,
    }];
    if state.iptables_forward_drop {
        for flag in ["-i", "-o"] {
            steps.push(HostStep::Run {
                summary: format!("remove iptables FORWARD rule ({flag} {interface})"),
                program: "iptables".to_owned(),
                args: vec![
                    "-D".to_owned(),
                    "FORWARD".to_owned(),
                    flag.to_owned(),
                    interface.to_owned(),
                    "-j".to_owned(),
                    "ACCEPT".to_owned(),
                ],
                stdin: None,
                ignore_failure: true,
            });
        }
    }
    for &port in ports {
        if matches!(state.firewall, Firewall::Ufw) || state.ufw_installed {
            steps.push(HostStep::Run {
                summary: format!("remove UDP {port} from ufw"),
                program: "ufw".to_owned(),
                args: vec![
                    "delete".to_owned(),
                    "allow".to_owned(),
                    format!("{port}/udp"),
                ],
                stdin: None,
                ignore_failure: true,
            });
        }
        if matches!(state.firewall, Firewall::Firewalld) || state.firewalld_installed {
            steps.push(HostStep::Run {
                summary: format!("remove UDP {port} from firewalld"),
                program: "firewall-cmd".to_owned(),
                args: vec![
                    "--permanent".to_owned(),
                    format!("--remove-port={port}/udp"),
                ],
                stdin: None,
                ignore_failure: true,
            });
        }
        if state.iptables_input_drop {
            steps.push(HostStep::Run {
                summary: format!("remove UDP {port} from iptables INPUT"),
                program: "iptables".to_owned(),
                args: vec![
                    "-D".to_owned(),
                    "INPUT".to_owned(),
                    "-p".to_owned(),
                    "udp".to_owned(),
                    "--dport".to_owned(),
                    port.to_string(),
                    "-j".to_owned(),
                    "ACCEPT".to_owned(),
                ],
                stdin: None,
                ignore_failure: true,
            });
        }
    }
    if matches!(state.firewall, Firewall::Firewalld) {
        steps.push(HostStep::Run {
            summary: "reload firewalld".to_owned(),
            program: "firewall-cmd".to_owned(),
            args: vec!["--reload".to_owned()],
            stdin: None,
            ignore_failure: true,
        });
    }
    steps
}

/// Run a plan, or print it.
///
/// # Errors
///
/// The first step that fails, named with what it was trying to do.
pub fn apply(steps: &[HostStep], dry_run: bool) -> Result<Vec<String>, Error> {
    let mut applied = Vec::new();
    for step in steps {
        if dry_run {
            println!("   would {}", step.summary());
            applied.push(step.summary().to_owned());
            continue;
        }
        if step.execute()? {
            println!("   ok    {}", step.summary());
            applied.push(step.summary().to_owned());
        } else {
            println!("   --    {} (already in place)", step.summary());
        }
    }
    Ok(applied)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn state(firewall: Firewall) -> HostState {
        HostState {
            firewall,
            input_drop: true,
            forward_drop: true,
            forward_v4: false,
            forward_v6: false,
            ufw_installed: false,
            firewalld_installed: false,
            iptables_forward_drop: false,
            iptables_input_drop: false,
        }
    }

    #[test]
    fn forwarding_is_persisted_even_when_it_is_already_on() {
        let mut host = state(Firewall::None);
        host.forward_v4 = true;
        let steps = plan_forwarding(&host, true, false);
        assert!(steps
            .iter()
            .any(|step| step.summary().contains("persist forwarding")));
        assert!(!steps
            .iter()
            .any(|step| step.summary().contains("enable IPv4 forwarding")));
    }

    #[test]
    fn a_dual_stack_server_enables_both_families() {
        let steps = plan_forwarding(&state(Firewall::None), true, true);
        let text = steps
            .iter()
            .filter_map(|step| match step {
                HostStep::Write { contents, .. } => Some(contents.clone()),
                HostStep::Run { .. } => None,
            })
            .collect::<Vec<_>>()
            .join("");
        assert!(text.contains("net.ipv4.ip_forward = 1"));
        assert!(text.contains("net.ipv6.conf.all.forwarding = 1"));
    }

    #[test]
    fn teardown_removes_nat_forward_and_both_ports() {
        let state = HostState {
            forward_v4: true,
            forward_v6: false,
            firewall: Firewall::Ufw,
            ufw_installed: true,
            firewalld_installed: false,
            input_drop: false,
            forward_drop: false,
            iptables_input_drop: true,
            iptables_forward_drop: true,
        };
        let steps = plan_teardown(&state, &[51820, 51821], "vallum0");
        let summaries: Vec<&str> = steps.iter().map(HostStep::summary).collect();
        assert!(summaries
            .iter()
            .any(|s| s.contains("remove the `inet vallum` NAT table")));
        assert!(summaries
            .iter()
            .any(|s| s.contains("remove iptables FORWARD rule (-i vallum0)")));
        assert!(summaries
            .iter()
            .any(|s| s.contains("remove UDP 51820 from ufw")));
        assert!(summaries
            .iter()
            .any(|s| s.contains("remove UDP 51821 from ufw")));
        assert!(summaries
            .iter()
            .any(|s| s.contains("remove UDP 51820 from iptables INPUT")));
    }

    #[test]
    fn ufw_gets_its_own_rule_not_an_nft_rule() {
        let steps = plan_firewall(&state(Firewall::Ufw), 51820, "vallum0");
        assert_eq!(steps.len(), 1);
        assert!(steps[0].summary().contains("ufw"));
    }

    #[test]
    fn a_plain_nft_host_gets_the_rule_in_the_policy_chain() {
        let steps = plan_firewall(&state(Firewall::Nftables), 51820, "vallum0");
        assert!(steps
            .iter()
            .any(|step| step.summary().contains("input chain")));
        assert!(steps
            .iter()
            .any(|step| step.summary().contains("forwarded traffic")));
    }

    #[test]
    fn iptables_filtering_forwarding_gets_accept_rules() {
        let mut host = state(Firewall::Nftables);
        host.input_drop = false;
        host.forward_drop = false;
        host.iptables_forward_drop = true;
        let steps = plan_firewall(&host, 51820, "vallum0");
        assert_eq!(steps.len(), 2);
        assert!(steps
            .iter()
            .all(|step| step.summary().contains("iptables FORWARD")));
        assert!(steps[0].summary().contains("from vallum0"));
        assert!(steps[1].summary().contains("to vallum0"));
    }

    #[test]
    fn iptables_filtering_input_opens_the_port() {
        let mut host = state(Firewall::Nftables);
        host.input_drop = false;
        host.forward_drop = false;
        host.iptables_input_drop = true;
        let steps = plan_firewall(&host, 51820, "vallum0");
        assert_eq!(steps.len(), 1);
        assert!(steps[0].summary().contains("iptables INPUT"));
        match &steps[0] {
            HostStep::Run { args, .. } => {
                assert!(args.contains(&"51820".to_owned()));
                assert!(args.contains(&"udp".to_owned()));
            }
            HostStep::Write { .. } => panic!("expected a run step"),
        }
    }

    #[test]
    fn an_installed_but_disabled_ufw_still_gets_its_rule() {
        let mut host = state(Firewall::Nftables);
        host.input_drop = false;
        host.forward_drop = false;
        host.ufw_installed = true;
        let steps = plan_firewall(&host, 51820, "vallum0");
        assert_eq!(steps.len(), 1);
        assert!(steps[0].summary().contains("ufw"), "{}", steps[0].summary());
        assert!(steps[0].summary().contains("not enabled"));
    }

    #[test]
    fn a_dormant_manager_does_not_replace_the_active_rule() {
        let mut host = state(Firewall::Nftables);
        host.ufw_installed = true;
        let steps = plan_firewall(&host, 51820, "vallum0");
        assert!(steps
            .iter()
            .any(|step| step.summary().contains("input chain")));
        assert!(steps.iter().any(|step| step.summary().contains("ufw")));
    }

    #[test]
    fn a_dormant_firewalld_gets_a_permanent_rule() {
        let mut host = state(Firewall::Nftables);
        host.input_drop = false;
        host.forward_drop = false;
        host.firewalld_installed = true;
        let steps = plan_firewall(&host, 51820, "vallum0");
        assert_eq!(steps.len(), 1);
        assert!(steps[0].summary().contains("firewalld"));
    }

    #[test]
    fn an_nft_host_without_a_drop_policy_needs_no_open() {
        let mut host = state(Firewall::Nftables);
        host.input_drop = false;
        host.forward_drop = false;
        assert!(plan_firewall(&host, 51820, "vallum0").is_empty());
    }

    fn nat_script(steps: &[HostStep]) -> String {
        steps
            .iter()
            .find_map(|step| match step {
                HostStep::Run { stdin, .. } => stdin.clone(),
                HostStep::Write { .. } => None,
            })
            .unwrap()
    }

    #[test]
    fn the_nat_script_names_both_families_and_owns_its_table() {
        let v4: Vec<IpNet> = vec!["10.7.0.0/24".parse().unwrap()];
        let v6: Vec<IpNet> = vec!["fd00:7::/64".parse().unwrap()];
        let steps = plan_nat(&v4, &v6, None);
        let script = nat_script(&steps);
        assert!(script.contains("ip saddr 10.7.0.0/24 masquerade"));
        assert!(script.contains("ip6 saddr fd00:7::/64 masquerade"));
        assert!(script.contains("table inet vallum"));
        // The personal default is flat: no forward chain, no drop (ADR-0047).
        assert!(!script.contains("chain forward"));
        assert!(!script.contains("drop"));
    }

    #[test]
    fn isolation_drops_tunnel_to_tunnel_in_vallums_own_table() {
        // A drop in any base chain at the hook wins over an accept elsewhere,
        // so Vallum's own table enforces isolation under every host firewall
        // without touching the operator's rules.
        let v4: Vec<IpNet> = vec!["10.7.0.0/24".parse().unwrap()];
        let steps = plan_nat(&v4, &[], Some("vallum0"));
        let script = nat_script(&steps);
        assert!(script.contains("table inet vallum"));
        assert!(script.contains("chain forward"));
        assert!(script.contains("type filter hook forward priority filter; policy accept;"));
        assert!(script.contains("iifname \"vallum0\" oifname \"vallum0\" drop"));
        // Isolation must not eat the egress path: masquerade stays.
        assert!(script.contains("ip saddr 10.7.0.0/24 masquerade"));
        // The wholesale replace is what makes a toggle converge.
        assert!(steps.iter().any(|step| step.summary().contains("replace")));
    }

    #[test]
    fn isolation_is_family_agnostic() {
        // iifname/oifname match in the inet table regardless of family, so a
        // v6-only tunnel is isolated by the same rule.
        let v6: Vec<IpNet> = vec!["fd00:7::/64".parse().unwrap()];
        let steps = plan_nat(&[], &v6, Some("vallum9"));
        let script = nat_script(&steps);
        assert!(script.contains("iifname \"vallum9\" oifname \"vallum9\" drop"));
    }

    #[test]
    fn no_subnets_means_no_nat() {
        assert!(plan_nat(&[], &[], None).is_empty());
        assert!(plan_nat(&[], &[], Some("vallum0")).is_empty());
    }
}
