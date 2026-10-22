//! `vallum policy` — the fail-closed egress guard, as an operator command.
//!
//! The guard is normally installed by `vallum-guard@<if>.service`, which runs
//! before the tunnel and is deliberately not part of it. This verb is the
//! manual path: it is what an operator reaches for when they need the block
//! gone *now*, and it works with no daemon and no network — the only state it
//! needs is the config file.

use std::path::{Path, PathBuf};

use clap::{Args, ValueEnum};
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

fn interface_name(config: &Config) -> String {
    config
        .interface
        .name
        .clone()
        .unwrap_or_else(|| "vallum0".to_owned())
}

/// Run the verb.
///
/// # Errors
/// A missing config, an unresolvable endpoint (a guard with nothing permitted
/// would block the handshake), or a failed `nft`.
pub fn policy(args: &PolicyArgs) -> Result<(), Error> {
    let config = load(&args.config)?;
    let interface = interface_name(&config);
    let wanted = policy::Mode::from_config(&config);
    let resolved = policy::resolve(&config);

    match args.action {
        PolicyAction::On => {
            if !policy::is_full_tunnel(&config) && wanted != Mode::On {
                eprintln!(
                    "vallum: this is a split tunnel, so `auto` leaves egress alone. \
                     Pass `policy = \"on\"` in [quick] to block anyway."
                );
                return Ok(());
            }
            if args.dry_run {
                println!("   would install this ruleset:");
                println!();
                print!("{}", policy::ruleset(&config, &interface)?);
                return Ok(());
            }
            policy::guard(&config, &interface, false)?;
            println!("   on    egress outside `{interface}` is blocked");
        }
        PolicyAction::Off => {
            policy::unguard(args.dry_run)?;
            if !args.dry_run {
                println!("   off   egress is no longer restricted");
            }
        }
        PolicyAction::Status => {
            let installed = policy::installed();
            println!("interface  {interface}");
            println!("config     {}", describe(wanted));
            println!("resolved   {}", describe(resolved));
            println!("installed  {}", if installed { "yes" } else { "no" });
            let (v4, v6) = policy::carries(&config);
            println!(
                "families   {}{}{}",
                if v4 { "v4" } else { "" },
                if v4 && v6 { " + " } else { "" },
                if v6 { "v6" } else { "" }
            );
            if resolved == Mode::On && !installed {
                println!();
                println!("   the config asks for a guard and none is installed:");
                println!("   sudo systemctl start vallum-guard@{interface}");
            }
        }
    }
    Ok(())
}

fn describe(mode: Mode) -> &'static str {
    match mode {
        Mode::Off => "off",
        Mode::On => "on",
        Mode::Auto => "auto (on for a full tunnel)",
    }
}
