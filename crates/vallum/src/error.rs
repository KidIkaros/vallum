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
            } => write!(f, "{action} `{}`: {source}", path.display()),
            Self::Toml { path, source } => {
                write!(f, "{}: {source}", path.display())
            }
            Self::Routing(e) => write!(f, "peer table refused: {e}"),
            Self::Invalid { path, what } => write!(f, "{}: {what}", path.display()),
            Self::Key { what, why } => write!(f, "{what}: {why}"),
            Self::Suite(why) => write!(f, "{why}"),
            Self::Identity(why) => write!(f, "{why}"),
            Self::Usage(why) => write!(f, "{why}"),
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
