// SPDX-License-Identifier: Apache-2.0

//! The configuration file.
//!
//! TOML, because an operator edits this by hand and a VPN's config should not
//! require a parser to read. Everything is validated here and nowhere else, and
//! the peer table is handed to [`vallum_tunnel::Device`] to apply *its* rules —
//! overlap, duplicate identity — rather than re-implementing them, so there is
//! one definition of an ambiguous routing table.
//!
//! ```toml
//! [interface]
//! name = "vallum0"
//! private_key = "/etc/vallum/private.key"
//! address = "10.7.0.1/24"
//! listen = "0.0.0.0:51820"
//!
//! [log]
//! level = "info"
//!
//! [[peer]]
//! name = "laptop"
//! public_key = "vallum1:0003:…:-"
//! endpoint = "203.0.113.7:51820"
//! allowed_ips = ["10.7.0.2/32", "fd00:7::2/128"]
//! ```
//!
//! # Unknown fields are refused
//!
//! `deny_unknown_fields` on every table. A typo in a security-relevant key —
//! `allowed_ip` for `allowed_ips` — would otherwise be *ignored*, and a peer with
//! no addresses is a peer that can never be reached, silently. Better a startup
//! error that names the line.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use vallum_core::identity::StaticIdentity;
use vallum_core::shaping::Machine;
use vallum_crypto::CryptoSuite;
use vallum_tunnel::{IpNet, PeerConfig};

use crate::error::Error;
use crate::keys::{self, SecretFile};
use crate::logging::Level;
use crate::tun::DEFAULT_MTU;

/// The port a Vallum daemon listens on unless told otherwise. The same number
/// WireGuard chose, so a firewall rule is memorable rather than arbitrary.
pub const DEFAULT_PORT: u16 = 51820;

/// A parsed configuration file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The interface and the daemon's own identity.
    pub interface: Interface,
    /// The peers, in `[[peer]]` order.
    #[serde(default, rename = "peer")]
    pub peers: Vec<PeerEntry>,
    /// Logging.
    #[serde(default)]
    pub log: Log,
}

/// The `[interface]` table.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interface {
    /// The kernel interface name. `vallum0` if absent.
    #[serde(default)]
    pub name: Option<String>,
    /// The private-key file.
    ///
    /// A relative path is resolved against the directory holding this config, not
    /// against the process's working directory: a config names its own files, so
    /// `-c /etc/vallum/vallum.toml` finds `/etc/vallum/private.key` from
    /// anywhere. An absolute path is used as written.
    pub private_key: PathBuf,
    /// The address and prefix to assign the interface.
    #[serde(default)]
    pub address: Option<String>,
    /// The inner MTU.
    #[serde(default)]
    pub mtu: Option<u16>,
    /// The UDP address to listen on.
    #[serde(default)]
    pub listen: Option<String>,
}

/// One `[[peer]]` table.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerEntry {
    /// A name for logs.
    pub name: String,
    /// The peer's public line. See [`crate::keys`].
    pub public_key: String,
    /// An address to dial, or absent to roam from the peer's handshakes.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// The addresses this peer may use.
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    /// Traffic-analysis shaping machines for this peer's tunnel.
    #[serde(default)]
    pub shaping: Vec<ShapingSpec>,
}

/// One entry in a peer's `shaping` list.
///
/// The three shapes are the ones P5 measured; a raw state machine is deliberately
/// not expressible from a config file, because a config file that can describe
/// arbitrary machines is a config file that can describe a flood.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ShapingSpec {
    /// Pad every packet to `size` bytes of sealed plaintext.
    PadToSize {
        /// The target.
        size: u16,
    },
    /// Hold outgoing packets for `interval_ms` after each one.
    MinInterval {
        /// The hold, in milliseconds.
        interval_ms: u64,
    },
    /// Answer received packets with padding, probabilistically.
    RespondWithPadding {
        /// The payload size of an injected packet.
        size: u16,
        /// Weight of the "inject" branch against one unit of "pass".
        injections: u32,
        /// The most injections before the machine goes inert.
        cap: u32,
    },
}

impl ShapingSpec {
    /// The machine this describes.
    #[must_use]
    pub fn machine(&self) -> Machine {
        match *self {
            Self::PadToSize { size } => Machine::pad_to_size(size),
            Self::MinInterval { interval_ms } => Machine::min_interval(interval_ms),
            Self::RespondWithPadding {
                size,
                injections,
                cap,
            } => Machine::respond_with_padding(size, injections, cap),
        }
    }
}

/// The `[log]` table.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Log {
    /// `error`, `warn`, `info`, or `debug`.
    pub level: String,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            level: "info".to_owned(),
        }
    }
}

/// A configuration that has been checked, with a key file read and a peer table
/// that [`vallum_tunnel::Device`] will accept.
pub struct Resolved {
    /// The interface name, or `None` to let the kernel pick.
    pub interface_name: Option<String>,
    /// The address to assign, if any.
    pub address: Option<IpNet>,
    /// The inner MTU.
    pub mtu: u16,
    /// The UDP address to bind.
    pub listen: SocketAddr,
    /// The daemon's own identity, expanded from the key file.
    pub identity: StaticIdentity,
    /// The peer table.
    pub peers: Vec<PeerConfig>,
    /// The log threshold.
    pub level: Level,
    /// Things the operator should know. Logged, not fatal.
    pub warnings: Vec<String>,
}

impl std::fmt::Debug for Resolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `StaticIdentity` has a redacting `Debug`; the peer list does too. This
        // impl exists so the whole struct can be printed without a key ever
        // reaching a log line.
        f.debug_struct("Resolved")
            .field("interface_name", &self.interface_name)
            .field("address", &self.address)
            .field("mtu", &self.mtu)
            .field("listen", &self.listen)
            .field("peer_count", &self.peers.len())
            .field("level", &self.level)
            .field("warnings", &self.warnings)
            .finish_non_exhaustive()
    }
}

impl Config {
    /// Read and parse a configuration file.
    ///
    /// # Errors
    ///
    /// If the file cannot be read, or does not parse.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path).map_err(|source| Error::IoPath {
            action: "read config",
            path: path.to_path_buf(),
            source,
        })?;
        toml::from_str(&text).map_err(|source| Error::Toml {
            path: path.to_path_buf(),
            source,
        })
    }

    /// The suite id named by the private-key file.
    ///
    /// The suite is a property of the key, not of a flag: a seed is only a key
    /// under the suite it was expanded with. This is the one read of the key file
    /// that must happen *before* a suite exists, so it is separate from
    /// [`Config::resolve`] — which needs a suite to check everything else against.
    ///
    /// # Errors
    ///
    /// If the key file cannot be read or parsed.
    pub fn suite_id(&self, config_path: &Path) -> Result<u16, Error> {
        let path = resolve_key_path(config_path, &self.interface.private_key);
        Ok(keys::load_secret(&path)?.suite)
    }

    /// Check the configuration, read the key file, and build the peer table.
    ///
    /// # Errors
    ///
    /// Anything the operator can fix: an unparsable address, a key file that does
    /// not match the suite, a peer line from a different suite, or a peer table
    /// the transport refuses.
    pub fn resolve(&self, path: &Path, suite: &dyn CryptoSuite) -> Result<Resolved, Error> {
        let mut warnings = Vec::new();

        let level = Level::parse(&self.log.level).ok_or_else(|| Error::Invalid {
            path: path.to_path_buf(),
            what: format!(
                "log.level `{}` is not one of error, warn, info, debug",
                self.log.level
            ),
        })?;

        let address = match self.interface.address.as_deref() {
            Some(text) => Some(text.parse::<IpNet>().map_err(|e| Error::Invalid {
                path: path.to_path_buf(),
                what: format!("interface.address `{text}`: {e}"),
            })?),
            None => None,
        };

        let listen = match self.interface.listen.as_deref() {
            Some(text) => text.parse::<SocketAddr>().map_err(|e| Error::Invalid {
                path: path.to_path_buf(),
                what: format!("interface.listen `{text}`: {e}"),
            })?,
            None => SocketAddr::from(([0, 0, 0, 0], DEFAULT_PORT)),
        };

        let mtu = self.interface.mtu.unwrap_or(DEFAULT_MTU);

        // Read the key file before anything else: it is the one thing whose
        // absence makes every other check pointless. A relative path is taken
        // relative to the config, so the pair travels together.
        let key_path = resolve_key_path(path, &self.interface.private_key);
        let secret: SecretFile = keys::load_secret(&key_path)?;
        if let Some(warning) = keys::permission_warning(&key_path) {
            warnings.push(warning);
        }
        let identity = keys::identity(suite, &secret)?;

        let mut peers = Vec::with_capacity(self.peers.len());
        for (index, entry) in self.peers.iter().enumerate() {
            let where_ = || format!("peer[{index}] `{}`", entry.name);

            let (peer_suite, peer_identity) =
                keys::decode_public(&entry.public_key).map_err(|e| Error::Invalid {
                    path: path.to_path_buf(),
                    what: format!("{}: {e}", where_()),
                })?;
            if peer_suite != suite.suite_id() {
                return Err(Error::Invalid {
                    path: path.to_path_buf(),
                    what: format!(
                        "{}: public key is for suite 0x{peer_suite:04x} ({}) but this \
                         daemon speaks 0x{:04x} ({})",
                        where_(),
                        keys::describe_suite(peer_suite),
                        suite.suite_id(),
                        keys::describe_suite(suite.suite_id()),
                    ),
                });
            }

            let mut nets = Vec::with_capacity(entry.allowed_ips.len());
            for text in &entry.allowed_ips {
                let net = text.parse::<IpNet>().map_err(|e| Error::Invalid {
                    path: path.to_path_buf(),
                    what: format!("{}: allowed_ips `{text}`: {e}", where_()),
                })?;
                nets.push(net);
            }

            let mut config =
                PeerConfig::new(entry.name.clone(), peer_identity).with_allowed_ips(nets.clone());
            if let Some(text) = entry.endpoint.as_deref() {
                let endpoint = text.parse::<SocketAddr>().map_err(|e| Error::Invalid {
                    path: path.to_path_buf(),
                    what: format!("{}: endpoint `{text}`: {e}", where_()),
                })?;
                config = config.with_endpoint(endpoint);
            }
            if !entry.shaping.is_empty() {
                config =
                    config.with_shaping(entry.shaping.iter().map(ShapingSpec::machine).collect());
            }

            // The interface prefix should cover the peer, or the kernel has no
            // connected route and the packet never reaches the tunnel. Worth
            // saying; not worth refusing, because an operator may install the
            // route some other way.
            if let Some(net) = address {
                for allowed in &nets {
                    if !net.contains(allowed) {
                        warnings.push(format!(
                            "{}: allowed_ips {allowed} is outside the interface's {net}; \
                             a route to it is needed (ip route add {allowed} dev <interface>)",
                            where_()
                        ));
                    }
                }
            }

            peers.push(config);
        }

        Ok(Resolved {
            interface_name: self.interface.name.clone(),
            address,
            mtu,
            listen,
            identity,
            peers,
            level,
            warnings,
        })
    }
}

/// Resolve a path declared in a config against the config's own directory.
///
/// An absolute `declared` is used as written. A relative one is joined onto the
/// directory holding `config_path`, so a config and the files it names travel
/// together: `vallum run -c /etc/vallum/vallum.toml` finds
/// `/etc/vallum/private.key` no matter what the working directory is.
#[must_use]
pub fn resolve_key_path(config_path: &Path, declared: &Path) -> PathBuf {
    if declared.is_absolute() {
        return declared.to_path_buf();
    }
    match config_path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join(declared),
        _ => declared.to_path_buf(),
    }
}
