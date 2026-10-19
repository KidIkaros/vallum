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
            Status::Warn,
            "no control socket configured; the daemon may be down",
        )),
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
