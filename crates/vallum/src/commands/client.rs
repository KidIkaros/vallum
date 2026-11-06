//! `vallum client` — the client-side lifecycle commands.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::commands::server::systemctl;
use crate::error::Error;
use crate::say;

#[derive(Debug, Args)]
pub struct ClientArgs {
    #[command(subcommand)]
    pub command: ClientCommand,
}

#[derive(Debug, Subcommand)]
pub enum ClientCommand {
    /// Disconnect and remove a client tunnel installed by `vallum setup`.
    Teardown(TeardownArgs),
}

#[derive(Debug, Args)]
pub struct TeardownArgs {
    /// The client configuration file to tear down.
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// The client name — resolves to `/etc/vallum/<name>.toml`.
    ///
    /// Either this or `--config` names the tunnel to remove; `--name` is what
    /// `vallum setup` printed when the tunnel was enrolled.
    #[arg(long, value_name = "NAME", conflicts_with = "config")]
    pub name: Option<String>,

    /// Also delete the config file and key in `/etc/vallum`. Without this,
    /// they stay in place so the tunnel can be brought back up.
    #[arg(long)]
    pub purge: bool,

    /// Show what would be removed, without changing the host.
    #[arg(long)]
    pub dry_run: bool,
}

/// Reverse the host changes `vallum setup` installed for a client.
///
/// `server teardown` exists for the server half; without this, removing a
/// trial client is a manual `systemctl disable` plus remembering which files
/// in `/etc/vallum` belonged to it — the same inflow-without-outflow gap.
pub fn teardown(args: &TeardownArgs) -> Result<(), Error> {
    if !args.dry_run && !nix::unistd::geteuid().is_root() {
        return Err(Error::Precondition(
            "`vallum client teardown` removes systemd units; run it as root, \
             or pass --dry-run to see the plan"
                .to_owned(),
        ));
    }
    let config_path = match (&args.config, &args.name) {
        (Some(path), None) => path.clone(),
        (None, Some(name)) => PathBuf::from(format!("/etc/vallum/{name}.toml")),
        (None, None) => {
            return Err(Error::Usage(
                "say which client: --name <name> or --config <file>".to_owned(),
            ));
        }
        (Some(_), Some(_)) => unreachable!("clap enforces --name/--config exclusivity"),
    };
    let instance = config_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("vallum0")
        .to_owned();
    let config = vallum_config::Config::load(&config_path).ok();
    if config.is_none() && !args.dry_run {
        return Err(Error::Precondition(format!(
            "cannot load {}; teardown needs the config to find the unit and key",
            config_path.display()
        )));
    }
    let interface = config
        .as_ref()
        .and_then(|cfg| cfg.interface.name.clone())
        .unwrap_or_else(|| format!("vallum-{instance}"));
    let socket = config
        .as_ref()
        .and_then(|cfg| cfg.interface.control.clone())
        .unwrap_or_else(|| vallum_config::socket_path(&interface));

    for unit in [
        format!("vallum-quick@{instance}"),
        format!("vallum@{instance}"),
    ] {
        if args.dry_run {
            say!("   would disable --now {unit}");
        } else {
            let _ = systemctl(&["disable", "--now", &unit]);
        }
    }

    if socket.exists() || args.dry_run {
        if args.dry_run {
            say!("   would remove {}", socket.display());
        } else {
            let _ = std::fs::remove_file(&socket);
            say!("   ok    remove {}", socket.display());
        }
    }

    if args.purge {
        let key = config
            .as_ref()
            .map(|cfg| crate::config::resolve_key_path(&config_path, &cfg.interface.private_key));
        if args.dry_run {
            say!(
                "   would remove {} and its key (--purge)",
                config_path.display()
            );
        } else {
            if let Some(key) = key {
                let _ = std::fs::remove_file(key);
            }
            let _ = std::fs::remove_file(&config_path);
            say!("   ok    removed {}", config_path.display());
        }
    } else {
        say!(
            "   kept  {} (pass --purge to delete the config and key too)",
            config_path.display()
        );
    }
    say!("torn down: client `{instance}`");
    Ok(())
}

pub fn client(args: &ClientArgs) -> Result<(), Error> {
    match &args.command {
        ClientCommand::Teardown(args) => teardown(args),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn teardown_requires_a_target() {
        let args = TeardownArgs {
            config: None,
            name: None,
            purge: false,
            dry_run: true,
        };
        assert!(teardown(&args).is_err());
    }

    #[test]
    fn teardown_dry_run_succeeds_without_root() {
        let dir =
            std::env::temp_dir().join(format!("vallum-client-teardown-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("laptop.toml");
        std::fs::write(&config, "[interface]\nname = \"vallum-laptop\"\n").unwrap();
        teardown(&TeardownArgs {
            config: Some(config.clone()),
            name: None,
            purge: true,
            dry_run: true,
        })
        .unwrap();
        // A dry run removes nothing.
        assert!(config.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn name_resolves_to_etc_vallum() {
        // `client teardown --name laptop` must aim at the path `setup` wrote,
        // which is how an operator refers to a tunnel they enrolled by name.
        let name = "laptop";
        let path = PathBuf::from(format!("/etc/vallum/{name}.toml"));
        assert_eq!(path.file_stem().unwrap(), "laptop");
    }
}
