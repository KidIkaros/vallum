// SPDX-License-Identifier: Apache-2.0

//! The TOML schema, and nothing else.
//!
//! This crate is what `vallum-quick` needs: the types an operator edits, parsed
//! with `deny_unknown_fields`. Resolution — reading the key, expanding the
//! identity, validating prefixes, resolving privileges — lives in the daemon,
//! because it needs the crypto suite and the OS. Keeping the schema separate
//! means the admin tool does not depend on the daemon's TUN, socket, or
//! privilege layer.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use vallum_core::shaping::Machine;

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
    /// Options only `vallum-quick` uses. The daemon parses and ignores them.
    #[serde(default)]
    pub quick: Quick,
}

/// The `[quick]` table: OS-level work done by `vallum-quick`, never the daemon.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quick {
    /// DNS servers to install on the interface, through `resolvconf`.
    #[serde(default)]
    pub dns: Vec<String>,
    /// `auto`, `off`, or a routing-table number.
    #[serde(default)]
    pub table: Option<String>,
    /// Commands run by `vallum-quick` before and after the interface.
    #[serde(default)]
    pub pre_up: Vec<String>,
    /// See [`Quick::pre_up`].
    #[serde(default)]
    pub post_up: Vec<String>,
    /// See [`Quick::pre_up`].
    #[serde(default)]
    pub pre_down: Vec<String>,
    /// See [`Quick::pre_up`].
    #[serde(default)]
    pub post_down: Vec<String>,
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
    ///
    /// A single-address shorthand for [`Interface::addresses`]; both may be
    /// used. A dual-stack tunnel names one address of each family in
    /// `addresses`.
    #[serde(default)]
    pub address: Option<String>,
    /// Addresses to assign to the interface, of either or both families.
    ///
    /// Every entry is assigned over netlink after the device exists, so a
    /// dual-stack tunnel is one config:
    ///
    /// ```toml
    /// addresses = ["10.7.0.1/24", "fd00:7::1/64"]
    /// ```
    ///
    /// IPv4-mapped IPv6 prefixes (`::ffff:10.0.0.1/128`) are refused: they do
    /// not match a v4 source in `allowed_ips`, so they are a trap rather than a
    /// shorthand.
    #[serde(default)]
    pub addresses: Vec<String>,
    /// The inner MTU.
    #[serde(default)]
    pub mtu: Option<u16>,
    /// The UDP address to listen on.
    #[serde(default)]
    pub listen: Option<String>,
    /// A Unix socket to serve the control UAPI on.
    ///
    /// Absent means no control plane. The socket is `0600`; a relative path is
    /// resolved against the config, like the key file.
    #[serde(default)]
    pub control: Option<PathBuf>,
    /// A socket mark for policy routing, as `SO_MARK`. `0` means unset.
    ///
    /// Requires `CAP_NET_ADMIN`; it is applied before the privilege drop.
    #[serde(default)]
    pub fwmark: Option<u32>,
    /// The outer path's MTU. Defaults to 1500.
    ///
    /// This is how a narrower path — PPPoE at 1492, an IPsec tunnel at 1400 — is
    /// supported: every datagram is cut to `outer_mtu - 48` so the kernel is
    /// never asked to fragment. It does **not** discover anything; the operator
    /// states the path. Values above 1500 are refused, because the protocol's
    /// parse cap and the segmentation budget are both built on
    /// [`MAX_OUTER_DATAGRAM`].
    #[serde(default)]
    pub outer_mtu: Option<u16>,
    /// The user to become after the interface and socket are open.
    ///
    /// Absent means "keep the privileges the process started with", which is
    /// what every deployment before this field did.
    #[serde(default)]
    pub user: Option<String>,
    /// The group to become. Defaults to the user's primary group.
    ///
    /// A group without a user is legal — it drops the group id only — and is
    /// warned about, because it is rarely what an operator means.
    #[serde(default)]
    pub group: Option<String>,
}

/// One `[[peer]]` table.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerEntry {
    /// A name for logs.
    pub name: String,
    /// The peer's public line. See the `vallum1:` public line.
    pub public_key: String,
    /// An address to dial, or absent to roam from the peer's handshakes.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// The addresses this peer may use.
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    /// Send an empty packet every this many seconds, even when idle, to hold a
    /// NAT binding open for a peer that has nothing to send. Omitted means off;
    /// `0` is refused rather than read as "off", because a field the operator
    /// wrote and the daemon ignores is how a security setting goes missing.
    #[serde(default)]
    pub persistent_keepalive: Option<u16>,
    /// A 32-byte preshared key as 64 hex characters, mixed into the handshake.
    ///
    /// The secret sits in the config file, so prefer [`Self::preshared_key_file`]
    /// unless the file's own permissions already protect it. Both fields set is
    /// an error rather than a precedence rule.
    #[serde(default)]
    pub preshared_key: Option<String>,
    /// A file holding the PSK as 64 hex characters.
    ///
    /// The same permission policy as the private key applies: group/world bits
    /// are refused unless `--allow-insecure-key-permissions` is passed.
    #[serde(default)]
    pub preshared_key_file: Option<PathBuf>,
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

impl Config {
    /// Read and parse a configuration file.
    ///
    /// # Errors
    ///
    /// If the file cannot be read, or does not parse.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        toml::from_str(&text).map_err(|source| ConfigError::Toml {
            path: path.to_path_buf(),
            source,
        })
    }
}

/// A configuration file that could not be read or parsed.
#[derive(Debug)]
pub enum ConfigError {
    /// The file could not be read.
    Io {
        /// The path involved.
        path: PathBuf,
        /// The underlying failure.
        source: std::io::Error,
    },
    /// The TOML did not parse.
    Toml {
        /// The path involved.
        path: PathBuf,
        /// The parse failure.
        source: toml::de::Error,
    },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "read config `{}`: {source}", path.display())
            }
            Self::Toml { path, source } => {
                write!(f, "parse config `{}`: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Toml { source, .. } => Some(source),
        }
    }
}
