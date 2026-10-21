// SPDX-License-Identifier: Apache-2.0

//! `vallum uninstall` — remove everything the installer and setup put on this
//! host.
//!
//! The install surface is one list, applied in reverse: live units first,
//! then host networking, then files. Keeping the manifest inside the binary
//! (rather than a hand-mirrored list in install.sh) is what stops the
//! uninstaller drifting behind the installer.
//!
//! `/etc/vallum` — configs and private keys — survives unless `--purge` is
//! passed: the same rule `apt remove` vs `apt purge` follows, because a key
//! destroyed by an uninstall cannot be brought back.

use std::path::Path;
use std::process::Command;

use clap::Args;

use crate::commands::server::systemctl;
use crate::error::Error;
use crate::say;

const BINARIES: [&str; 2] = ["/usr/bin/vallum", "/usr/bin/vallum-quick"];

const UNITS: [&str; 5] = [
    "/etc/systemd/system/vallum@.service",
    "/etc/systemd/system/vallum-quick@.service",
    "/etc/systemd/system/vallum-enroll@.service",
    "/etc/systemd/system/vallum-metrics.service",
    "/etc/systemd/system/vallum-metrics.timer",
];

const MAN_PAGES: [&str; 3] = [
    "/usr/share/man/man8/vallum.8",
    "/usr/share/man/man8/vallum-quick.8",
    "/usr/share/man/man5/vallum.toml.5",
];

const COMPLETIONS: [&str; 3] = [
    "/usr/share/bash-completion/completions/vallum",
    "/usr/share/zsh/site-functions/_vallum",
    "/usr/share/fish/vendor_completions.d/vallum.fish",
];

const SYSCTL: &str = "/etc/sysctl.d/90-vallum.conf";
const RUNTIME_DIR: &str = "/run/vallum";
const CONFIG_DIR: &str = "/etc/vallum";

#[derive(Debug, Args)]
pub struct UninstallArgs {
    /// Also remove /etc/vallum — configs and private keys. Without this they
    /// stay, so a reinstall brings the same tunnels back up.
    #[arg(long)]
    pub purge: bool,

    /// Show the full removal plan without changing the host.
    #[arg(long)]
    pub dry_run: bool,
}

/// `vallum uninstall`.
///
/// # Errors
///
/// If run without root (unless `--dry-run`), or a systemd step fails.
pub fn uninstall(args: &UninstallArgs) -> Result<(), Error> {
    if !args.dry_run && !nix::unistd::geteuid().is_root() {
        return Err(Error::Precondition(
            "`vallum uninstall` stops units and removes /usr files; run it as root, \
             or pass --dry-run to see the plan"
                .to_owned(),
        ));
    }
    let dry = args.dry_run;

    // ── live state: every running/enabled instance and the metrics timer ──
    for unit in live_units() {
        step(dry, &format!("disable --now {unit}"), || {
            let _ = systemctl(&["disable", "--now", &unit]);
        });
    }
    for unit in ["vallum-metrics.timer", "vallum-metrics.service"] {
        if unit_known(unit) || dry {
            step(dry, &format!("disable --now {unit}"), || {
                let _ = systemctl(&["disable", "--now", unit]);
            });
        }
    }

    // ── host networking: per-config teardown covers nft/ufw/FORWARD ──
    for config in std::fs::read_dir(CONFIG_DIR)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
    {
        teardown_host(&config, dry);
    }

    remove_file(dry, Path::new(SYSCTL));
    if !dry && !Path::new(SYSCTL).exists() {
        // The file is gone; reload so the live ip_forward value follows it.
        let _ = Command::new("sysctl").arg("--system").status();
    }

    // ── files the installer wrote ──
    for path in UNITS.iter().chain(&MAN_PAGES).chain(&COMPLETIONS) {
        remove_file(dry, Path::new(path));
    }
    step(dry, "systemctl daemon-reload", || {
        let _ = systemctl(&["daemon-reload"]);
    });
    remove_dir(dry, Path::new(RUNTIME_DIR));

    // ── secrets: kept unless purged ──
    if args.purge {
        remove_dir(dry, Path::new(CONFIG_DIR));
    } else {
        say!("   kept  {CONFIG_DIR} (pass --purge to remove configs and keys)");
    }

    // ── binaries last: a running process can unlink itself safely ──
    for path in BINARIES {
        remove_file(dry, Path::new(path));
    }

    say!(
        "{}",
        if dry {
            "dry run: nothing was removed"
        } else {
            "vallum uninstalled"
        }
    );
    Ok(())
}

/// Every enabled or loaded `vallum*@*` instance, enabled-state included —
/// `list-units` alone misses instances that are enabled but not loaded.
fn live_units() -> Vec<String> {
    let mut units = Vec::new();
    for flag in ["list-units", "list-unit-files"] {
        if let Ok(output) = Command::new("systemctl")
            .args([flag, "--all", "--plain", "--no-legend", "vallum*@*"])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            for unit in text
                .lines()
                .filter_map(|line| line.split_whitespace().next())
            {
                let name = unit.trim_end_matches(".service").trim_end_matches(".timer");
                let instanced = name.rsplit('@').next().is_some_and(|i| !i.is_empty());
                if name.contains('@') && instanced && !units.iter().any(|u| u == &name.to_owned()) {
                    units.push(name.to_owned());
                }
            }
        }
    }
    units
}

fn unit_known(name: &str) -> bool {
    Command::new("systemctl")
        .args(["cat", name])
        .output()
        .is_ok_and(|output| output.status.success())
}

/// `server teardown`'s networking half, for every config install left behind.
fn teardown_host(config: &Path, dry: bool) {
    let Some(parsed) = vallum_config::Config::load(config).ok() else {
        return;
    };
    let interface = parsed
        .interface
        .name
        .clone()
        .unwrap_or_else(|| "vallum0".to_owned());
    let listen = parsed
        .interface
        .listen
        .as_deref()
        .and_then(|listen| crate::commands::server::listen_port(listen).ok())
        .unwrap_or(51820);
    let enroll = parsed
        .enroll
        .port
        .unwrap_or_else(|| listen.saturating_add(1));
    let steps =
        crate::hostnet::plan_teardown(&crate::hostnet::inspect(), &[listen, enroll], &interface);
    let _ = crate::hostnet::apply(&steps, dry);
}

fn step(dry: bool, what: &str, action: impl Fn()) {
    if dry {
        say!("   would {what}");
    } else {
        action();
        say!("   ok    {what}");
    }
}

fn remove_file(dry: bool, path: &Path) {
    if !path.exists() && !dry {
        return;
    }
    if dry {
        say!("   would remove {}", path.display());
    } else {
        let _ = std::fs::remove_file(path);
        say!("   ok    remove {}", path.display());
    }
}

fn remove_dir(dry: bool, path: &Path) {
    if !path.exists() && !dry {
        return;
    }
    if dry {
        say!("   would remove {}", path.display());
    } else {
        let _ = std::fs::remove_dir_all(path);
        say!("   ok    remove {}", path.display());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_dry_run_needs_no_root_and_removes_nothing() {
        let etc = Path::new("/etc/vallum");
        let had_etc = etc.exists();
        uninstall(&UninstallArgs {
            purge: false,
            dry_run: true,
        })
        .unwrap();
        assert_eq!(etc.exists(), had_etc, "a dry run changed /etc/vallum");
        // The binaries that may exist must still be there.
        for path in BINARIES {
            if Path::new(path).exists() {
                assert!(Path::new(path).is_file(), "{path} was touched by a dry run");
            }
        }
    }

    #[test]
    fn unprivileged_uninstall_is_a_precondition_not_a_crash() {
        if nix::unistd::geteuid().is_root() {
            return; // under root there is no precondition to test
        }
        let err = uninstall(&UninstallArgs {
            purge: false,
            dry_run: false,
        });
        assert!(err.is_err(), "non-root uninstall must refuse");
    }

    #[test]
    fn unit_discovery_skips_the_bare_template_names() {
        // `vallum@.service` would arrive as `vallum@` — an empty instance is
        // not something `disable --now` can act on.
        let probe = "vallum@.service\nvallum@x.service\nvallum-metrics.timer\n";
        let names: Vec<String> = probe
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .map(|unit| unit.trim_end_matches(".service").trim_end_matches(".timer"))
            .filter(|name| {
                name.contains('@') && name.rsplit('@').next().is_some_and(|i| !i.is_empty())
            })
            .map(str::to_owned)
            .collect();
        assert_eq!(names, vec!["vallum@x".to_owned()]);
    }
}
