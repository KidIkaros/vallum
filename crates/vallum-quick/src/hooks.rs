// SPDX-License-Identifier: Apache-2.0

//! Shell hooks and the privilege boundary around them.
//!
//! `pre_up`/`post_up`/`pre_down`/`post_down` are `sh -c` strings executed as
//! root, so the config file is a privilege boundary, not just settings. The
//! installed path (`/etc/vallum/<iface>.toml`) is root-owned and `0600`; a
//! config anywhere else, or one that is group/world-writable, is refused
//! rather than silently becoming root execution. `wg-quick` has the same shape
//! and the same warning; this one fails closed.
//!
//! Stored verbatim from the original single-file layout; see `main.rs` for
//! how a command drives these.

use std::path::Path;
use std::process::Command;

use vallum_config::Config;

/// Refuse to run hooks from a config another user can edit.
pub(crate) fn check_config_ownership(
    config_path: &Path,
    config: &Config,
    allow_insecure: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    check_config_ownership_as(config_path, config, effective_uid_is_root(), allow_insecure)
        .map_err(Into::into)
}

/// Whether a config asks for any shell hooks at all.
fn has_hooks(config: &Config) -> bool {
    !(config.quick.pre_up.is_empty()
        && config.quick.post_up.is_empty()
        && config.quick.pre_down.is_empty()
        && config.quick.post_down.is_empty())
}

/// Whether this process runs as root, read without a libc dependency.
///
/// `/proc/self/status` lists real, effective, saved and filesystem uids; the
/// second is the effective one, which is what decides whether hooks escalate.
fn effective_uid_is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("Uid:"))
                .and_then(|rest| rest.split_whitespace().nth(1).map(|uid| uid == "0"))
        })
        .unwrap_or(false)
}

pub(crate) fn check_config_ownership_as(
    config_path: &Path,
    config: &Config,
    is_root: bool,
    allow_insecure: bool,
) -> Result<(), String> {
    if !is_root || !has_hooks(config) {
        // Nothing escalates: either the caller keeps their own privileges, or
        // there is no hook to run as root. Routes and DNS from a user's own
        // config are not a privilege boundary.
        return Ok(());
    }
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = std::fs::metadata(config_path)
        .map_err(|error| format!("read {}: {error}", config_path.display()))?;
    let owner = metadata.uid();
    let writable_by_others = metadata.permissions().mode() & 0o022 != 0;
    if owner == 0 && !writable_by_others {
        return Ok(());
    }
    if allow_insecure {
        eprintln!(
            "vallum-quick: warning: {} is owned by uid {owner} or writable by others; \
             its hooks run as root",
            config_path.display()
        );
        return Ok(());
    }
    Err(format!(
        "{} is owned by uid {owner}{} — its hooks (pre_up, post_up, …) would run as \
         root from a file another user can change.\n\
         Move it to /etc/vallum and chown root:root, or pass \
         --allow-insecure-config if you trust every writer of that path.",
        config_path.display(),
        if writable_by_others {
            " and is writable by others"
        } else {
            ""
        }
    ))
}

pub(crate) fn run_hook(hook: &str, dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
    if dry_run {
        println!("sh -c {hook:?}");
        return Ok(());
    }
    let status = Command::new("sh").arg("-c").arg(hook).status()?;
    if !status.success() {
        return Err(format!("hook failed: {hook}").into());
    }
    Ok(())
}
