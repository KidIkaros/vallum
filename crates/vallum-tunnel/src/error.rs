// SPDX-License-Identifier: Apache-2.0

//! Configuration errors.
//!
//! Runtime errors are not here. A datagram that fails to parse, open, or verify
//! is *dropped* — a tunnel that returns an error for every junk packet would
//! hand an attacker a control channel into the process's error path, and a
//! transport loop has nothing useful to do with "someone sent garbage" except
//! count it and continue. What remains are the mistakes a caller can make once,
//! at configuration time, and that it should be told about loudly.

use std::fmt;

use crate::routing::IpNet;

/// A configuration that cannot be honoured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// Two peers claim overlapping addresses.
    ///
    /// Routing would then depend on configuration order, and the inbound
    /// source-address check would accept one peer's traffic as the other's.
    /// Refused rather than resolved.
    OverlappingAllowedIps {
        /// The earlier peer, by name.
        first: String,
        /// The later peer, by name.
        second: String,
        /// The overlapping prefix.
        network: IpNet,
    },
    /// The same peer identity was configured twice.
    DuplicatePeer {
        /// The peer whose key was already present, by name.
        existing: String,
        /// The peer being added, by name.
        duplicate: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OverlappingAllowedIps {
                first,
                second,
                network,
            } => write!(
                f,
                "peers `{first}` and `{second}` both claim {network}; \
                 cryptokey routing would be ambiguous"
            ),
            Self::DuplicatePeer {
                existing,
                duplicate,
            } => write!(f, "peer `{duplicate}` duplicates `{existing}`"),
        }
    }
}

impl std::error::Error for ConfigError {}
