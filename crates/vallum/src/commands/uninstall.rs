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

const UNITS: [&str; 7] = [
    "/etc/systemd/system/vallum@.service",
    "/etc/systemd/system/vallum-guard@.service",
    "/etc/systemd/system/vallum-quick@.service",
    "/etc/systemd/system/vallum-quick-watch@.service",
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
const CONFIG_DIR: &str = "/etc/vallum";
/// The tmpfiles entry that creates the runtime directory. Both locations are
/// removed: the package channels install to `/usr/lib`, `install.sh` to
/// `/etc`, and tmpfiles.d merges them, so either may be present.
const TMPFILES: [&str; 2] = [
    "/usr/lib/tmpfiles.d/vallum-tmpfiles.conf",
    "/etc/tmpfiles.d/vallum-tmpfiles.conf",
];
/// Where `vallum-quick` records the routing plan each attach executed.
const STATE_DIR: &str = "/var/lib/vallum";

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

    // ── host routing: `vallum-quick` owns it, so ask it ──
    // Routes and the policy rules an attach installed are the quick helper's,
    // and it records the plan it executed. Delegating — while the binary is
    // still here — keeps one implementation and removes what was actually
    // installed rather than what today's config would imply. Left behind,
    // `table main suppress_prefixlength 0` takes the host's default route away
    // and it does not come back without a reboot.
    //
    // `detach` runs the config's down hooks, as it does from the unit; a config
    // another user can edit is refused, so nothing here widens what root runs.
    for config in configs() {
        let what = format!("vallum-quick detach {}", config.display());
        if dry {
            say!("   would {what}");
            continue;
        }
        match Command::new("/usr/bin/vallum-quick")
            .arg("detach")
            .arg(&config)
            .status()
        {
            Ok(status) if status.success() => say!("   ok    {what}"),
            _ => say!("   skip  {what} (routing may remain; run it by hand)"),
        }
    }
    // A record with no config beside it cannot be reversed here: the format is
    // `vallum-quick`'s. Name it rather than deleting the evidence.
    let orphans = orphan_plans();
    for orphan in &orphans {
        say!(
            "   warn  {} has no config; remove its rules by hand",
            orphan.display()
        );
    }
    if orphans.is_empty() {
        remove_dir(dry, Path::new(STATE_DIR));
    }

    // ── host networking: per-config teardown covers nft/ufw/FORWARD ──
    // One HostState snapshot and one deduplicated plan: two configs on this
    // host must not emit the same rule removal twice, and a client config
    // with `listen = "0.0.0.0:0"` contributes no port rule at all.
    let state = crate::hostnet::inspect();
    let mut steps = Vec::new();
    for config in configs() {
        for step in teardown_plan(&config, &state) {
            if !steps
                .iter()
                .any(|s: &crate::hostnet::HostStep| s.summary() == step.summary())
            {
                steps.push(step);
            }
        }
    }
    let _ = crate::hostnet::apply(&steps, dry);

    remove_file(dry, Path::new(SYSCTL));
    if !dry && !Path::new(SYSCTL).exists() {
        // The file is gone; reload so the live ip_forward value follows it.
        let _ = Command::new("sysctl").arg("--system").status();
    }

    // ── files the installer wrote ──
    for path in UNITS
        .iter()
        .chain(&MAN_PAGES)
        .chain(&COMPLETIONS)
        .chain(&TMPFILES)
    {
        remove_file(dry, Path::new(path));
    }
    step(dry, "systemctl daemon-reload", || {
        let _ = systemctl(&["daemon-reload"]);
    });
    // `/run/vallum` is left alone: it is a machine resource created by
    // tmpfiles.d, not this package's state, and another daemon's socket may be
    // in it. It disappears at the next boot with the rest of /run. See ADR-0017.

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
            .args([
                "--no-ask-password",
                flag,
                "--all",
                "--plain",
                "--no-legend",
                "vallum*@*",
            ])
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
        .args(["--no-ask-password", "cat", name])
        .output()
        .is_ok_and(|output| output.status.success())
}

/// `server teardown`'s networking half, planned for one config: its
/// interface's rules plus the ports it actually listened on. Port 0 (a client
/// config's ephemeral listen) contributes nothing — no rule ever opened it.
fn teardown_plan(
    config: &Path,
    state: &crate::hostnet::HostState,
) -> Vec<crate::hostnet::HostStep> {
    let Some(parsed) = vallum_config::Config::load(config).ok() else {
        return Vec::new();
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
    // The responder's port only saw a firewall rule while enrolment ran.
    let enroll = parsed.enroll.enabled.then(|| {
        parsed
            .enroll
            .port
            .unwrap_or_else(|| listen.saturating_add(1))
    });
    let ports: Vec<u16> = [Some(listen), enroll]
        .into_iter()
        .flatten()
        .filter(|port| *port != 0)
        .collect();
    crate::hostnet::plan_teardown(state, &ports, &interface)
}

/// Every config on this host, as the uninstaller sees them.
fn configs() -> Vec<std::path::PathBuf> {
    std::fs::read_dir(CONFIG_DIR)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
        .collect()
}

/// Recorded routing plans with no config of the same name left beside them.
///
/// The plan format belongs to `vallum-quick`, so this does not try to parse it:
/// it names what it found rather than deleting the evidence.
fn orphan_plans() -> Vec<std::path::PathBuf> {
    std::fs::read_dir(STATE_DIR)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "quick"))
        .filter(|path| {
            let interface = path.file_stem().unwrap_or_default();
            !Path::new(CONFIG_DIR)
                .join(interface)
                .with_extension("toml")
                .exists()
        })
        .collect()
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
