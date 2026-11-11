// SPDX-License-Identifier: Apache-2.0

//! Privilege separation: shed what the daemon no longer needs, as soon as it
//! no longer needs it.
//!
//! The daemon's only privileged operations are `TUNSETIFF` (and the interface
//! configuration that follows it) and binding a port. Both happen before the
//! loop starts; after that the process reads a file descriptor, reads a socket,
//! and does arithmetic. P6.5 recorded the gap as F6: the process kept whatever
//! it started with, so a bug in the wire parser ran as root.
//!
//! # The order is the mechanism
//!
//! 1. `setgroups(&[])` — after `setuid` this is impossible, so it must be first.
//! 2. `setgid` — likewise, and doing it before `setuid` means the saved-set-uid
//!    dance cannot regain root.
//! 3. `setuid` — permanent: with no saved-set-uid the process cannot climb back.
//! 4. `PR_SET_NO_NEW_PRIVS` — even if a later `exec` happened, setuid binaries
//!    could not raise privileges.
//! 5. **Verify** — `geteuid`/`getegid` must equal the target. A `setuid` that
//!    silently did not take is the failure this whole module exists to prevent,
//!    so it is checked rather than assumed.
//!
//! Every step fails closed. A daemon that cannot drop exits with the reason; it
//! does not run with the privileges it was meant to shed.

use crate::error::Error;

/// What the operator asked the daemon to become.
///
/// Names are kept for the log line and the error messages; ids are what the
/// system calls take. `group` without `user` means "drop the group only", which
/// is legal and warned about at load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Privileges {
    /// The user name, if one was configured.
    pub user: Option<String>,
    /// The group name, if one was configured (or derived from the user).
    pub group: Option<String>,
    /// The numeric uid to become.
    pub uid: Option<u32>,
    /// The numeric gid to become.
    pub gid: Option<u32>,
}

impl Privileges {
    /// A log-safe description.
    #[must_use]
    pub fn describe(&self) -> String {
        match (&self.user, &self.group) {
            (Some(user), Some(group)) => format!("{user}:{group}"),
            (Some(user), None) => user.clone(),
            (None, Some(group)) => format!("group {group}"),
            (None, None) => "nothing (this is a bug)".to_owned(),
        }
    }
}

/// Resolve the configured names to ids.
///
/// # Errors
///
/// [`Error::Privileges`] if a name does not exist, or [`Error::Usage`] if the
/// fields are set on a platform without this backend.
#[cfg(target_os = "linux")]
pub fn resolve(
    user: Option<&str>,
    group: Option<&str>,
    warnings: &mut Vec<String>,
) -> Result<Option<Privileges>, Error> {
    if user.is_none() && group.is_none() {
        return Ok(None);
    }

    let group_id = match group {
        Some(name) => {
            let entry = nix::unistd::Group::from_name(name)
                .map_err(|e| Error::Privileges(format!("look up group `{name}`: {e}")))?
                .ok_or_else(|| Error::Privileges(format!("no such group: `{name}`")))?;
            Some(entry.gid.as_raw())
        }
        None => None,
    };

    let (uid, gid) = match user {
        Some(name) => {
            let entry = nix::unistd::User::from_name(name)
                .map_err(|e| Error::Privileges(format!("look up user `{name}`: {e}")))?
                .ok_or_else(|| Error::Privileges(format!("no such user: `{name}`")))?;
            let gid = group_id.unwrap_or_else(|| entry.gid.as_raw());
            (Some(entry.uid.as_raw()), Some(gid))
        }
        None => {
            warnings.push(
                "interface.group is set without interface.user: only the group id will \
                 change, and the process keeps its uid"
                    .to_owned(),
            );
            (None, group_id)
        }
    };

    Ok(Some(Privileges {
        user: user.map(str::to_owned),
        group: group.map(str::to_owned),
        uid,
        gid,
    }))
}

/// On a platform without this backend, asking for it is an error rather than a
/// silent no-op — the operator asked for a security property.
///
/// # Errors
///
/// Always, when either field is set.
#[cfg(not(target_os = "linux"))]
pub fn resolve(
    user: Option<&str>,
    group: Option<&str>,
    _warnings: &mut Vec<String>,
) -> Result<Option<Privileges>, Error> {
    if user.is_some() || group.is_some() {
        return Err(Error::Usage(
            "interface.user/interface.group are only implemented on Linux".to_owned(),
        ));
    }
    Ok(None)
}

/// Drop to the resolved ids and verify it took.
///
/// # Errors
///
/// [`Error::Privileges`] if any system call fails, or if the verification after
/// them disagrees with the target. The daemon must not continue in that case.
#[cfg(target_os = "linux")]
/// Pin currently-mapped pages so key material cannot be written to swap.
///
/// Called before the privilege drop: `mlockall` needs `RLIMIT_MEMLOCK`, which
/// a dropped daemon may not have. `MCL_CURRENT` only, deliberately — MOOR's
/// note applies here too: `MCL_FUTURE` fights pthread stack allocation under
/// typical memlock limits.
///
/// Best-effort by design: a host with a tiny memlock limit should warn, not
/// refuse to run the tunnel.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)] // mlockall has no safe wrapper; see the SAFETY note.
pub fn lock_memory() -> Result<(), String> {
    // SAFETY: mlockall takes no pointers and cannot violate memory safety; a
    // failure is reported through errno.
    let result = unsafe { libc::mlockall(libc::MCL_CURRENT) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().to_string())
    }
}

#[cfg(not(target_os = "linux"))]
pub fn lock_memory() -> Result<(), String> {
    Err("mlockall is only implemented for Linux".to_owned())
}

pub fn drop_to(privileges: &Privileges) -> Result<(), Error> {
    use nix::unistd::{getegid, geteuid, setgid, setgroups, setuid, Gid, Uid};

    // Supplementary groups first: after `setuid` this call cannot succeed.
    if privileges.gid.is_some() {
        setgroups(&[]).map_err(|e| {
            Error::Privileges(format!(
                "setgroups([]) failed: {e}; the daemon cannot shed supplementary groups"
            ))
        })?;
    }

    if let Some(gid) = privileges.gid {
        setgid(Gid::from_raw(gid))
            .map_err(|e| Error::Privileges(format!("setgid({gid}) failed: {e}")))?;
    }

    if let Some(uid) = privileges.uid {
        setuid(Uid::from_raw(uid))
            .map_err(|e| Error::Privileges(format!("setuid({uid}) failed: {e}")))?;
    }

    nix::sys::prctl::set_no_new_privs()
        .map_err(|e| Error::Privileges(format!("PR_SET_NO_NEW_PRIVS failed: {e}")))?;

    if let Some(uid) = privileges.uid {
        if geteuid().as_raw() != uid {
            return Err(Error::Privileges(format!(
                "setuid({uid}) did not take: effective uid is {}",
                geteuid().as_raw()
            )));
        }
    }
    if let Some(gid) = privileges.gid {
        if getegid().as_raw() != gid {
            return Err(Error::Privileges(format!(
                "setgid({gid}) did not take: effective gid is {}",
                getegid().as_raw()
            )));
        }
    }

    Ok(())
}

/// As [`drop_to`], for a build without the Linux backend: nothing was resolved,
/// so there is nothing to do.
///
/// # Errors
///
/// Never; `resolve` refuses the configuration on this platform.
#[cfg(not(target_os = "linux"))]
pub fn drop_to(_privileges: &Privileges) -> Result<(), Error> {
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn describe_names_what_changed() {
        let p = Privileges {
            user: Some("vallum".into()),
            group: Some("vallum".into()),
            uid: Some(1000),
            gid: Some(1000),
        };
        assert_eq!(p.describe(), "vallum:vallum");

        let group_only = Privileges {
            user: None,
            group: Some("vallum".into()),
            uid: None,
            gid: Some(1000),
        };
        assert_eq!(group_only.describe(), "group vallum");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nothing_configured_resolves_to_none() {
        let mut warnings = Vec::new();
        assert_eq!(resolve(None, None, &mut warnings).unwrap(), None);
        assert!(warnings.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_unknown_user_is_an_error_not_a_silent_no_op() {
        let mut warnings = Vec::new();
        let error = resolve(Some("vallum-no-such-user"), None, &mut warnings).unwrap_err();
        assert!(
            matches!(error, Error::Privileges(ref why) if why.contains("no such user")),
            "got {error:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_group_without_a_user_is_allowed_and_warned_about() {
        let mut warnings = Vec::new();
        // `root` exists everywhere this test can run.
        let resolved = resolve(None, Some("root"), &mut warnings).unwrap();
        let resolved = resolved.expect("a group-only drop is a drop");
        assert_eq!(resolved.uid, None);
        assert_eq!(resolved.gid, Some(0));
        assert_eq!(warnings.len(), 1, "{warnings:?}");
    }
}
