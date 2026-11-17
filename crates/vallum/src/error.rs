// SPDX-License-Identifier: Apache-2.0

//! The daemon's failures.
//!
//! One enum, because a daemon has one place to report from: `main` prints the
//! error and exits non-zero. The variants are grouped by *what the operator can
//! do about it* rather than by where the error came from — a bad config file, a
//! key file that does not match the configured suite, a routing table the
//! transport refused, and an interface that would not come up are four different
//! repairs.

use std::fmt;
use std::io;
use std::path::PathBuf;

use vallum_tunnel::ConfigError;

/// Anything the daemon can fail at.
#[derive(Debug)]
pub enum Error {
    /// The operating system refused something: a socket, an interface, a file.
    Io(io::Error),

    /// An I/O failure that names the path it happened on.
    IoPath {
        /// What was being done, e.g. `read key file`.
        action: &'static str,
        /// The file involved.
        path: PathBuf,
        /// The underlying failure.
        source: io::Error,
    },

    /// The layer-3 interface would not open.
    ///
    /// Separate from [`Error::Io`] because this one is almost always a privilege
    /// problem on a first run, and the message should say so rather than leaving
    /// the operator with a bare `EPERM`.
    Interface {
        /// The interface name the operator asked for, if they named one.
        name: Option<String>,
        /// The underlying failure.
        source: io::Error,
    },

    /// The TOML did not parse. `toml` already reports line and column.
    Toml {
        /// The config file.
        path: PathBuf,
        /// The parse failure.
        source: toml::de::Error,
    },

    /// The TOML parsed but does not describe a usable tunnel — a peer claims
    /// addresses another already claims, or the same identity is configured
    /// twice. Refused rather than resolved, by [`vallum_tunnel::Device`].
    Routing(ConfigError),

    /// A configuration value is wrong in a way the type system cannot catch —
    /// an unparsable prefix, a suite the key file and the device disagree about.
    Invalid {
        /// The config file, or the key file, being described.
        path: PathBuf,
        /// What is wrong.
        what: String,
    },

    /// A key file, or a public key, could not be read or decoded.
    Key {
        /// What was being decoded.
        what: String,
        /// Why it failed.
        why: String,
    },

    /// The requested cryptographic suite is unknown, or was built without the
    /// feature it needs.
    Suite(String),

    /// A handshake primitive refused to derive a key from the given seed.
    Identity(String),

    /// The operator asked for something that cannot be done, and the message
    /// says what to run instead.
    Usage(String),

    /// A precondition is not met, so nothing was attempted: not root, no
    /// systemd, a host that cannot be prepared. Distinct from [`Self::Usage`]
    /// because the command was correct — the environment is not.
    Precondition(String),

    /// Some steps succeeded and one did not. The message names the step, and
    /// what is already in place, so a retry is safe.
    Partial(String),

    /// A private key file is readable by someone other than its owner.
    ///
    /// Refused rather than warned about (P6.5's F7): a key that a group or the
    /// world can read is not a private key, and a warning in a log is not a
    /// control. `--allow-insecure-key-permissions` is the explicit override for
    /// the cases where the operator has a reason.
    KeyPermissions {
        /// The file.
        path: PathBuf,
        /// The mode and what it means.
        detail: String,
    },

    /// Privilege separation failed: a lookup, a `set*id`, or the verification
    /// after it.
    Privileges(String),

    /// The syscall filter could not be compiled or installed (ADR-0028).
    ///
    /// Fatal by design: a daemon that was configured to be filtered and is not
    /// has a worse posture than one that never asked, because everything
    /// downstream assumes the filter is there.
    Sandbox(String),
}

/// Why a readable-looking file is not readable by the daemon.
///
/// The service runs with a narrow capability bounding set, which means no
/// CAP_DAC_OVERRIDE: root is only root for files it owns. An operator who
/// copies a config in as their own user gets a bare "Permission denied" that
/// looks like a bug in the daemon rather than an ownership mistake.
fn permission_hint(path: &std::path::Path) -> String {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(path) {
        Ok(meta) => format!(
            "`{}` is mode {:o}, owned by uid {} gid {}. The daemon runs without \
             CAP_DAC_OVERRIDE, so it can only read files owned by the user it runs as \
             (root). Fix it with `sudo chown root:root {} && sudo chmod 600 {}`.",
            path.display(),
            meta.mode() & 0o777,
            meta.uid(),
            meta.gid(),
            path.display(),
            path.display()
        ),
        Err(_) => "the file is not readable by the user the daemon runs as".to_owned(),
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Interface { name, source } => {
                match name {
                    Some(name) => write!(f, "open interface `{name}`: {source}")?,
                    None => write!(f, "open the interface: {source}")?,
                }
                if source.kind() == io::ErrorKind::PermissionDenied {
                    write!(
                        f,
                        "\n  hint: creating an interface needs root or CAP_NET_ADMIN"
                    )?;
                }
                Ok(())
            }
            Self::IoPath {
                action,
                path,
                source,
            } => {
                write!(f, "{action} `{}`: {source}", path.display())?;
                // The unit's CapabilityBoundingSet drops CAP_DAC_OVERRIDE, so the
                // daemon is subject to ordinary file permissions even as root: a
                // config owned by anyone else is unreadable, and "Permission
                // denied" names the symptom but not the one thing to change.
                if source.kind() == io::ErrorKind::PermissionDenied {
                    write!(f, "\n  hint: {}", permission_hint(path))?;
                }
                Ok(())
            }
            Self::Toml { path, source } => {
                // `toml::de::Error` quotes the offending line, and a misplaced
                // `preshared_key` is the secret itself. This is the string
                // `vallum doctor` prints, i.e. the text users paste into an
                // issue — see `vallum_config::redact_secrets` for the rule.
                write!(
                    f,
                    "{}: {}",
                    path.display(),
                    vallum_config::redact_secrets(&source.to_string())
                )
            }
            Self::Routing(e) => write!(f, "peer table refused: {e}"),
            Self::Invalid { path, what } => write!(f, "{}: {what}", path.display()),
            Self::Key { what, why } => write!(f, "{what}: {why}"),
            Self::Suite(why) => write!(f, "{why}"),
            Self::Identity(why) => write!(f, "{why}"),
            Self::Usage(why) => write!(f, "{why}"),
            Self::Precondition(why) => write!(f, "{why}"),
            Self::Partial(why) => write!(f, "{why}"),
            Self::KeyPermissions { path, detail } => write!(
                f,
                "{}: {detail}\n  hint: chmod 600 it, or pass \
                 --allow-insecure-key-permissions if this is deliberate",
                path.display()
            ),
            Self::Privileges(why) => write!(f, "privilege separation failed: {why}"),
            Self::Sandbox(why) => write!(f, "the syscall filter failed: {why}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Interface { source, .. } => Some(source),
            Self::IoPath { source, .. } => Some(source),
            Self::Toml { source, .. } => Some(source),
            Self::Routing(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<ConfigError> for Error {
    fn from(e: ConfigError) -> Self {
        Self::Routing(e)
    }
}
