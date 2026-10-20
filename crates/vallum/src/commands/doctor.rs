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
            Ok(detail) => checks.push(Check::new("control", Status::Pass, detail)),
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
        checks.push(check_service(args.config.as_deref()));
        checks.push(check_config_mode(args.config.as_deref()));
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
                "{:<5} {:<10} {}",
                check.status.as_str(),
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
            let allowed = output("ufw", &["status"]).is_some_and(|status| {
                status.lines().any(|line| {
                    line.contains(&format!("{port}/udp")) && line.to_lowercase().contains("allow")
                })
            });
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
            (
                if allowed { Status::Pass } else { Status::Warn },
                if allowed {
                    format!("nftables accepts UDP {port}")
                } else {
                    format!(
                        "no nftables rule accepts UDP {port}; add one to the chain that \
                         drops it, or run `vallum server init --force`"
                    )
                },
            )
        }
        crate::hostnet::Firewall::None => (
            Status::Pass,
            "no host firewall detected, so nothing is blocking the port".to_owned(),
        ),
    };
    Check::new("firewall", status, detail)
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
