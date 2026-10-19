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
//! addresses = ["10.7.0.1/24", "fd00:7::1/64"]
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
//! persistent_keepalive = 25
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
use std::time::Duration;

use serde::Deserialize;
use vallum_core::identity::StaticIdentity;
use vallum_core::shaping::Machine;
use vallum_crypto::CryptoSuite;
use vallum_tunnel::{IpNet, PeerConfig};

use crate::error::Error;
use crate::keys::{self, SecretFile};
use crate::logging::Level;
use crate::tun::{DATA_OVERHEAD, DEFAULT_MTU, MIN_MTU};
use vallum_core::segment::MAX_OUTER_DATAGRAM;

/// The port a Vallum daemon listens on unless told otherwise. The same number
/// WireGuard chose, so a firewall rule is memorable rather than arbitrary.
pub const DEFAULT_PORT: u16 = 51820;

/// What an outer path spends before the UDP payload: an IPv6 header (40) and a
/// UDP header (8). The same arithmetic [`MAX_OUTER_DATAGRAM`] is built on.
pub const OUTER_HEADER_LEN: u16 = 48;

/// The outer MTU assumed when the operator does not name one.
pub const DEFAULT_OUTER_MTU: u16 = 1500;

/// The smallest link MTU IPv6 permits (RFC 8200 §5). The kernel refuses to
/// assign a v6 address to an interface below it, so the inner MTU is floored
/// here when the address is v6 — and the resulting segmentation is warned about.
pub const IPV6_MIN_MTU: u16 = 1280;

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
    /// The peer's public line. See [`crate::keys`].
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
    /// The addresses to assign, in config order.
    pub addresses: Vec<IpNet>,
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
    /// Who to become after the privileged setup. `None` keeps the process as it
    /// started.
    pub privileges: Option<crate::privileges::Privileges>,
    /// The largest UDP payload the outer path can carry: `outer_mtu - 48`.
    pub outer_budget: usize,
}

impl std::fmt::Debug for Resolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `StaticIdentity` has a redacting `Debug`; the peer list does too. This
        // impl exists so the whole struct can be printed without a key ever
        // reaching a log line.
        f.debug_struct("Resolved")
            .field("interface_name", &self.interface_name)
            .field("addresses", &self.addresses)
            .field("mtu", &self.mtu)
            .field("listen", &self.listen)
            .field("peer_count", &self.peers.len())
            .field("level", &self.level)
            .field("warnings", &self.warnings)
            .field("privileges", &self.privileges)
            .field("outer_budget", &self.outer_budget)
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

        // `address` is the single-address shorthand; `addresses` is the list.
        // Both may be used, and the result is de-duplicated so a config that
        // repeats an address is not an error, just noisy.
        let mut addresses: Vec<IpNet> = Vec::new();
        if let Some(text) = self.interface.address.as_deref() {
            addresses.push(parse_net(path, "interface.address", text)?);
        }
        for (index, text) in self.interface.addresses.iter().enumerate() {
            addresses.push(parse_net(
                path,
                &format!("interface.addresses[{index}]"),
                text,
            )?);
        }
        let mut unique: Vec<IpNet> = Vec::with_capacity(addresses.len());
        for net in addresses {
            if unique.contains(&net) {
                warnings.push(format!(
                    "interface address {net} is listed twice; ignoring the duplicate"
                ));
                continue;
            }
            unique.push(net);
        }
        let addresses = unique;
        let has_v6 = addresses.iter().any(|net| matches!(net, IpNet::V6(_)));

        let listen = match self.interface.listen.as_deref() {
            Some(text) => text.parse::<SocketAddr>().map_err(|e| Error::Invalid {
                path: path.to_path_buf(),
                what: format!("interface.listen `{text}`: {e}"),
            })?,
            None => SocketAddr::from(([0, 0, 0, 0], DEFAULT_PORT)),
        };

        // The outer path's budget. 1500 is the assumption the product was built
        // on; a narrower path names its MTU here and every datagram is cut to
        // fit, so the kernel is never asked to fragment one.
        let outer_mtu = self.interface.outer_mtu.unwrap_or(DEFAULT_OUTER_MTU);
        let budget = usize::from(outer_mtu)
            .checked_sub(usize::from(OUTER_HEADER_LEN))
            .ok_or_else(|| Error::Invalid {
                path: path.to_path_buf(),
                what: format!(
                    "interface.outer_mtu {outer_mtu} is below the {OUTER_HEADER_LEN}-byte \
                     outer header"
                ),
            })?;
        // A budget must still hold the smallest legal inner packet plus the data
        // plane's overhead, or no configuration could work on this path.
        let minimum_budget = usize::from(MIN_MTU) + DATA_OVERHEAD;
        if budget < minimum_budget {
            return Err(Error::Invalid {
                path: path.to_path_buf(),
                what: format!(
                    "interface.outer_mtu {outer_mtu} leaves a {budget}-byte budget, but the \
                     smallest inner MTU ({MIN_MTU}) plus the {DATA_OVERHEAD}-byte data \
                     overhead needs {minimum_budget}; use an outer_mtu of at least {}",
                    minimum_budget + usize::from(OUTER_HEADER_LEN)
                ),
            });
        }
        if budget > MAX_OUTER_DATAGRAM {
            return Err(Error::Invalid {
                path: path.to_path_buf(),
                what: format!(
                    "interface.outer_mtu {outer_mtu} is above {DEFAULT_OUTER_MTU}: the \
                     protocol's {MAX_OUTER_DATAGRAM}-byte budget and parse cap assume a \
                     1500-byte path, and this knob adapts downward only"
                ),
            });
        }

        // The inner MTU: explicit, or derived so a data packet still fits one
        // datagram on this path.
        let mtu = match self.interface.mtu {
            Some(mtu) => {
                // An explicit `0` used to be silently replaced by the default,
                // which is the kind of quiet coercion this config refuses
                // everywhere else: the operator asked for something incoherent
                // and got a working tunnel with a different MTU than the file
                // says. Below IPv4's minimum reassembly buffer the request is
                // incoherent too.
                if mtu < MIN_MTU {
                    return Err(Error::Invalid {
                        path: path.to_path_buf(),
                        what: format!(
                            "interface.mtu {mtu} is below the IPv4 minimum of {MIN_MTU} \
                             bytes; omit it for the default {DEFAULT_MTU}"
                        ),
                    });
                }
                // IPv6 has a higher floor, and the kernel enforces it by
                // refusing the address. Say so at load instead of failing in
                // netlink with an errno the operator cannot act on.
                if has_v6 && mtu < IPV6_MIN_MTU {
                    return Err(Error::Invalid {
                        path: path.to_path_buf(),
                        what: format!(
                            "interface.mtu {mtu} is below IPv6's minimum link MTU of \
                             {IPV6_MIN_MTU}; the kernel will not assign a v6 address \
                             to this interface"
                        ),
                    });
                }
                if usize::from(mtu) + DATA_OVERHEAD > budget {
                    warnings.push(format!(
                        "interface.mtu {mtu} plus the {DATA_OVERHEAD}-byte data overhead \
                         exceeds the {budget}-byte outer budget: data packets will be \
                         segmented (and still correct, but no longer one datagram each)"
                    ));
                }
                mtu
            }
            None => {
                let mut fits = u16::try_from(budget - DATA_OVERHEAD).unwrap_or(DEFAULT_MTU);
                fits = fits.min(DEFAULT_MTU);
                // A narrow outer path can derive an inner MTU below IPv6's
                // floor. The floor wins, and the cost is segmentation — which is
                // what the envelope exists for, so it is a warning, not a
                // refusal.
                if has_v6 && fits < IPV6_MIN_MTU {
                    warnings.push(format!(
                        "interface.outer_mtu {outer_mtu} would derive an inner MTU of \
                         {fits}, below IPv6's minimum of {IPV6_MIN_MTU}; using \
                         {IPV6_MIN_MTU} and segmenting every full-size data packet"
                    ));
                    fits = IPV6_MIN_MTU;
                }
                fits
            }
        };

        // Read the key file before anything else: it is the one thing whose
        // absence makes every other check pointless. A relative path is taken
        // relative to the config, so the pair travels together.
        //
        // The file's mode is *not* checked here: the CLI owns that decision,
        // because refusing a key is a startup policy with an explicit override,
        // not a property of a config file. See `keys::check_permissions`.
        let key_path = resolve_key_path(path, &self.interface.private_key);
        let secret: SecretFile = keys::load_secret(&key_path)?;

        // Privilege separation is resolved here, but applied by the daemon after
        // the interface and socket exist — see `privileges::drop_to`.
        let privileges = crate::privileges::resolve(
            self.interface.user.as_deref(),
            self.interface.group.as_deref(),
            &mut warnings,
        )?;
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

            // A key of the wrong length is not a key. Without this check the
            // handshake fails later, inside `encapsulate`, and the loop has
            // nowhere to report it: the tunnel simply never comes up and the
            // operator sees silence. Check the length where the operator can see
            // the mistake — at load, naming the peer.
            //
            // `sign_pk_max` is an upper bound by name, but every suite in the
            // registry has exactly one signing-key size, so it is the size this
            // suite expects. A suite with variable-size signing keys would need
            // this check revisited.
            let sizes = suite.sizes();
            let kem_len = peer_identity.kem().len();
            if kem_len != sizes.kem_pk {
                return Err(Error::Invalid {
                    path: path.to_path_buf(),
                    what: format!(
                        "{}: KEM public key is {kem_len} bytes, but suite 0x{:04x} \
                         ({}) uses {} bytes",
                        where_(),
                        suite.suite_id(),
                        keys::describe_suite(suite.suite_id()),
                        sizes.kem_pk,
                    ),
                });
            }
            if let Some(signing) = peer_identity.signing() {
                let signing_len = signing.len();
                if signing_len != sizes.sign_pk_max {
                    return Err(Error::Invalid {
                        path: path.to_path_buf(),
                        what: format!(
                            "{}: signing public key is {signing_len} bytes, but suite \
                             0x{:04x} ({}) uses {} bytes",
                            where_(),
                            suite.suite_id(),
                            keys::describe_suite(suite.suite_id()),
                            sizes.sign_pk_max,
                        ),
                    });
                }
            }

            let mut nets = Vec::with_capacity(entry.allowed_ips.len());
            for text in &entry.allowed_ips {
                nets.push(parse_net(
                    path,
                    &format!("{}: allowed_ips", where_()),
                    text,
                )?);
            }

            if nets.is_empty() {
                // `allowed_ips` is both the destinations routed to the peer and
                // the sources accepted from it. Empty is not "no restriction":
                // it is a peer that can neither send nor receive, silently.
                return Err(Error::Invalid {
                    path: path.to_path_buf(),
                    what: format!(
                        "{}: allowed_ips is empty, so nothing can be routed to or from this peer",
                        where_()
                    ),
                });
            }

            let mut config =
                PeerConfig::new(entry.name.clone(), peer_identity).with_allowed_ips(nets.clone());
            match entry.persistent_keepalive {
                None => {}
                // A whole number of seconds, because that is the unit an
                // operator thinks in and the one WireGuard uses. The upper
                // bound is the field width, nothing deeper: it is a cadence,
                // not a crypto parameter, so a large one is merely useless.
                Some(seconds) if seconds > 0 => {
                    config =
                        config.with_persistent_keepalive(Duration::from_secs(u64::from(seconds)));
                }
                Some(_) => {
                    return Err(Error::Invalid {
                        path: path.to_path_buf(),
                        what: format!(
                            "{}: persistent_keepalive is 0 seconds; omit the field to \
                             disable it, or give a whole number of seconds",
                            where_()
                        ),
                    });
                }
            }
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
            if !addresses.is_empty() {
                let prefixes = addresses
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                for allowed in &nets {
                    if !addresses.iter().any(|net| net.contains(allowed)) {
                        warnings.push(format!(
                            "{}: allowed_ips {allowed} is outside the interface's \
                             {prefixes}; a route to it is needed \
                             (ip route add {allowed} dev <interface>)",
                            where_()
                        ));
                    }
                }
            }

            peers.push(config);
        }

        Ok(Resolved {
            interface_name: self.interface.name.clone(),
            addresses,
            mtu,
            listen,
            identity,
            peers,
            level,
            warnings,
            privileges,
            outer_budget: budget,
        })
    }
}

/// Parse one prefix, refusing the IPv4-mapped IPv6 trap.
///
/// `::ffff:10.0.0.1/128` is a v6 prefix, so it never matches an inner v4 source
/// in `allowed_ips` and never routes a v4 packet. An operator who writes it
/// means `10.0.0.1/32`, and the error says so. Used for both the interface
/// addresses and each peer's `allowed_ips` — the trap is the same in both.
fn parse_net(path: &Path, field: &str, text: &str) -> Result<IpNet, Error> {
    let net: IpNet = text.parse().map_err(|e| Error::Invalid {
        path: path.to_path_buf(),
        what: format!("{field} `{text}`: {e}"),
    })?;
    if let IpNet::V6(net6) = net {
        if let Some(v4) = net6.addr().to_ipv4_mapped() {
            return Err(Error::Invalid {
                path: path.to_path_buf(),
                what: format!(
                    "{field} `{text}` is an IPv4-mapped IPv6 prefix; write the IPv4                      address instead (`{v4}/{}`)",
                    net6.prefix_len().saturating_sub(96)
                ),
            });
        }
    }
    Ok(net)
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
