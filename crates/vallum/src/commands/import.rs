// SPDX-License-Identifier: Apache-2.0

//! `vallum import-bundle`: unpack a client bundle file.

use std::path::{Path, PathBuf};

use clap::Args;

use crate::{say, Error};

#[derive(Debug, Args)]
pub struct ImportArgs {
    /// The `.vallum-bundle` file to import.
    #[arg(value_name = "FILE")]
    pub bundle: PathBuf,

    /// Directory for the config and key (default: /etc/vallum with --install,
    /// the current directory otherwise).
    #[arg(long, value_name = "DIR")]
    pub output_dir: Option<PathBuf>,

    /// Overwrite an existing config or key.
    #[arg(long)]
    pub force: bool,

    /// Refuse a bundle that weakens this client's defaults instead of warning.
    #[arg(long)]
    pub strict: bool,

    /// Accept a bundle that carries `[quick]` hooks, which run as root.
    #[arg(long)]
    pub allow_hooks: bool,

    /// Accept a bundle that carries this client's **private key**.
    ///
    /// The bundle is the one path where the key existed on another machine
    /// first. Every other path generates it on the device, so the safe
    /// alternative always exists - which is why this is refused by default
    /// rather than warned about.
    #[arg(long)]
    pub allow_shipped_key: bool,

    /// Install to /etc/vallum, install the units, and start the tunnel.
    #[arg(long)]
    pub install: bool,
}

/// `vallum import-bundle`.
///
/// # Errors
///
/// If the bundle cannot be read or written, or `--install` is used without root.
pub fn import(args: &ImportArgs) -> Result<(), Error> {
    let directory = args.output_dir.clone().unwrap_or_else(|| {
        if args.install {
            crate::host::paths::config_dir().to_path_buf()
        } else {
            PathBuf::from(".")
        }
    });

    if args.install && !nix::unistd::geteuid().is_root() {
        return Err(Error::Precondition(
            "--install writes /etc/vallum and the systemd units; run it as root, or \
             import without --install and copy the files yourself"
                .to_owned(),
        ));
    }

    let bundle = crate::bundle::read(&args.bundle).map_err(Error::Usage)?;
    // Say what the bundle does to this client's policy *before* writing it:
    // a server deciding the client's sandbox is not a detail to discover later
    // (ADR-0033).
    let policy = crate::bundle::inspect_policy(&bundle).map_err(Error::Usage)?;
    for finding in &policy {
        eprintln!("warning: {}", finding.label());
    }
    let imported = crate::bundle::import_with_policy(
        &bundle,
        &directory,
        args.force,
        args.strict,
        args.allow_hooks,
        args.allow_shipped_key,
    )
    .map_err(Error::Usage)?;

    say!("config {}", imported.config.display());
    say!("key    {}", imported.key.display());
    // A bundle is the one path where this machine's private key existed on
    // another machine first. Say so: it is a custody fact, not a detail.
    if args.allow_shipped_key {
        say!();
        say!("note: this key was generated on the server and travelled in the bundle.");
        say!("      `vallum setup --remote` and `vallum setup --join` never do that —");
        say!("      the key is generated here and only its public line leaves.");
    }

    if !args.install {
        say!();
        say!("next:");
        // A unit can only run a config in /etc/vallum; anything else has to be
        // run directly, and saying otherwise sends the operator to a command
        // that cannot work.
        let config = imported.config.display().to_string();
        if imported
            .config
            .starts_with(crate::host::paths::config_dir())
        {
            say!(
                "   sudo systemctl enable --now vallum@{}",
                instance_of(&imported.config)
            );
        } else {
            say!("   sudo vallum run --config {config}");
        }
        return Ok(());
    }

    // The units exec /usr/bin/vallum{,-quick}; installing them without those
    // binaries produces a service that fails with 203/EXEC after the operator
    // was told it worked.
    crate::commands::server::require_installed_binaries()?;
    let instance = instance_of(&imported.config);
    let service = crate::commands::server::install_service(&instance, false)?;
    say!("service vallum@{instance}: {service}");
    say!();
    say!("check it:");
    say!(
        "   sudo vallum doctor --config {}",
        imported.config.display()
    );
    Ok(())
}

/// The systemd instance name: the config file's stem, which is what
/// `vallum@<instance>.service` reads from `/etc/vallum/<instance>.toml`.
fn instance_of(config: &Path) -> String {
    config
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("vallum0")
        .to_owned()
}
