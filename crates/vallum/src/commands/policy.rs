//! `vallum policy` — the fail-closed egress guard, as an operator command.
//!
//! The guard is normally installed by `vallum-guard@<if>.service`, which runs
//! before the tunnel and is deliberately not part of it. This verb is the
//! manual path: it is what an operator reaches for when they need the block
//! gone *now*, and it works with no daemon and no network — the only state it
//! needs is the config file.

use std::path::{Path, PathBuf};

use clap::{Args, ValueEnum};
use serde_json::{Value, json};
use vallum_config::Config;

use crate::error::Error;
use crate::policy::{self, Mode};

#[derive(Debug, Args)]
pub struct PolicyArgs {
    /// What to do.
    #[arg(value_enum)]
    pub action: PolicyAction,
    /// The config whose tunnel is guarded.
    #[arg(long, short)]
    pub config: PathBuf,
    /// Print what would happen without changing the host.
    #[arg(long)]
    pub dry_run: bool,
    /// Emit JSON instead of a report, so an agent can read the answer.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PolicyAction {
    /// Block egress outside the tunnel, except the endpoint that carries it.
    On,
    /// Remove the block. This is the escape hatch; it needs no daemon.
    Off,
    /// Report what the config asks for and what the host currently has.
    Status,
}

fn load(path: &Path) -> Result<Config, Error> {
    Config::load(path).map_err(|source| Error::IoPath {
        action: "read the config",
        path: path.to_path_buf(),
        source: std::io::Error::other(source.to_string()),
    })
}

/// Run the verb.
///
/// # Errors
/// A missing config, an unresolvable endpoint (a guard with nothing permitted
/// would block the handshake), or a failed `nft`.
pub fn policy(args: &PolicyArgs) -> Result<(), Error> {
    let config = load(&args.config)?;
    let interface = policy::interface_name(&config);
    let wanted = policy::Mode::from_config(&config);
    let resolved = policy::resolve(&config);

    match args.action {
        PolicyAction::On => {
            if policy::declines_guard(&config, wanted) {
                return Err(Error::Precondition(
                    "this is a split tunnel and [quick] policy is `auto`, so nothing was \
                     blocked. Pass `policy = \"on\"` in [quick] to block anyway."
                        .to_owned(),
                ));
            }
            if args.dry_run {
                let rules = policy::ruleset(&config, &interface)?;
                if args.json {
                    emit(&json!({
                        "action": "on",
                        "interface": interface,
                        "dry_run": true,
                        "ruleset": rules,
                    }))?;
                    return Ok(());
                }
                println!("   would install this ruleset:");
                println!();
                print!("{rules}");
                return Ok(());
            }
            policy::guard(&config, &interface, false)?;
            if args.json {
                emit(&json!({
                    "action": "on",
                    "interface": interface,
                    "dry_run": false,
                    "egress": "blocked",
                }))?;
            } else {
                println!("   on    egress outside `{interface}` is blocked");
            }
        }
        PolicyAction::Off => {
            policy::unguard(args.dry_run)?;
            if args.json {
                emit(&json!({
                    "action": "off",
                    "dry_run": args.dry_run,
                    "egress": "unrestricted",
                }))?;
            } else if !args.dry_run {
                println!("   off   egress is no longer restricted");
            }
        }
        PolicyAction::Status => {
            let guard = policy::guard_state();
            let (v4, v6) = policy::carries(&config);
            // The one line an operator, or an agent, has to be able to act on.
            let fix = (resolved == Mode::On && guard == policy::GuardState::Absent)
                .then(|| format!("sudo systemctl start vallum-guard@{interface}"));
            if args.json {
                let mut families = Vec::new();
                if v4 {
                    families.push("v4");
                }
                if v6 {
                    families.push("v6");
                }
                let mut report = json!({
                    "action": "status",
                    "interface": interface,
                    "declared": mode_name(wanted),
                    "policy": mode_name(resolved),
                    "guard": guard.name(),
                    "egress": guard.egress(),
                    "families": families,
                });
                if let Some(fix) = fix {
                    report["fix"] = Value::String(fix);
                }
                emit(&report)?;
                return Ok(());
            }
            println!("interface  {interface}");
            println!("config     {}", describe(wanted));
            println!("resolved   {}", describe(resolved));
            println!(
                "installed  {}",
                match guard {
                    policy::GuardState::Installed => "yes",
                    policy::GuardState::Absent => "no",
                    policy::GuardState::Unknown => "unknown (needs root)",
                }
            );
            println!(
                "families   {}{}{}",
                if v4 { "v4" } else { "" },
                if v4 && v6 { " + " } else { "" },
                if v6 { "v6" } else { "" }
            );
            if let Some(fix) = fix {
                println!();
                println!("   the config asks for a guard and none is installed:");
                println!("   {fix}");
            }
        }
    }
    Ok(())
}

/// Print one JSON object.
///
/// Failures are not JSON: they keep the exit-2/stdout-silent contract in
/// `docs/deployment/automation.md`, and a caller that wants the reason reads
/// stderr the same way it does for every other verb.
fn emit(report: &Value) -> Result<(), Error> {
    println!(
        "{}",
        serde_json::to_string_pretty(report)
            .map_err(|error| Error::Usage(format!("json: {error}")))?
    );
    Ok(())
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Off => "off",
        Mode::On => "on",
        Mode::Auto => "auto",
    }
}

fn describe(mode: Mode) -> &'static str {
    match mode {
        Mode::Off => "off",
        Mode::On => "on",
        Mode::Auto => "auto (on for a full tunnel)",
    }
}
