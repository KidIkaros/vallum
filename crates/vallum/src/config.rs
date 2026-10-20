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

use vallum_core::identity::{IdentityDocument, PeerIdentity, StaticIdentity, Validity};
use vallum_crypto::{CryptoSuite, SharedSecret};
use vallum_tunnel::{PeerConfig, Prefix};

pub use vallum_config::{Config, ConfigError, Interface, Log, PeerEntry, Quick, ShapingSpec};

use crate::error::Error;
use crate::keys::{self, SecretFile};
use crate::logging::Level;
use crate::tun::{DATA_OVERHEAD, DEFAULT_MTU, MIN_MTU};
use vallum_tunnel::segment::MAX_OUTER_DATAGRAM;

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

/// A configuration that has been checked, with a key file read and a peer table
/// that [`vallum_tunnel::Device`] will accept.
pub struct Resolved {
    /// The interface name, or `None` to let the kernel pick.
    pub interface_name: Option<String>,
    /// The addresses to assign, in config order.
    pub addresses: Vec<Prefix>,
    /// The inner MTU.
    pub mtu: u16,
    /// The UDP address to bind.
    pub listen: SocketAddr,
    /// The control socket, if configured.
    pub control: Option<PathBuf>,
    /// The socket mark; `0` means unset.
    pub fwmark: u32,
    /// The daemon's own identity, expanded from the key file.
    pub identity: StaticIdentity,
    /// The seed the identity was expanded from, for the control plane and an
    /// export. Redacted by `SharedSecret`'s `Debug` and erased on drop.
    pub seed: SharedSecret,
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
            .field("seed", &self.seed)
            .field("control", &self.control)
            .field("fwmark", &self.fwmark)
            .field("peer_count", &self.peers.len())
            .field("level", &self.level)
            .field("warnings", &self.warnings)
            .field("privileges", &self.privileges)
            .field("outer_budget", &self.outer_budget)
            .finish_non_exhaustive()
    }
}

impl From<ConfigError> for Error {
    fn from(error: ConfigError) -> Self {
        match error {
            ConfigError::Io { path, source } => Error::IoPath {
                action: "read config",
                path,
                source,
            },
            ConfigError::Toml { path, source } => Error::Toml { path, source },
        }
    }
}

/// Resolution of a parsed [`Config`], which needs the daemon's key handling and
/// OS policy; the schema crate cannot know either.
pub trait ResolveConfig {
    /// The suite id named by the private-key file.
    ///
    /// # Errors
    ///
    /// If the key file cannot be read or parsed.
    fn suite_id(&self, config_path: &Path) -> Result<u16, Error>;

    /// Check the configuration, read the key file, and build the peer table.
    ///
    /// # Errors
    ///
    /// Anything the operator can fix: an unparsable address, a key file that does
    /// not match the suite, a peer line from a different suite, or a peer table
    /// the transport refuses.
    fn resolve(&self, path: &Path, suite: &dyn CryptoSuite) -> Result<Resolved, Error>;

    /// Resolve, with the private-key permission override.
    ///
    /// # Errors
    ///
    /// As [`ResolveConfig::resolve`].
    fn resolve_with(
        &self,
        path: &Path,
        suite: &dyn CryptoSuite,
        allow_insecure_key: bool,
    ) -> Result<Resolved, Error>;
}

impl ResolveConfig for Config {
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
    fn suite_id(&self, config_path: &Path) -> Result<u16, Error> {
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
    fn resolve(&self, path: &Path, suite: &dyn CryptoSuite) -> Result<Resolved, Error> {
        self.resolve_with(path, suite, false)
    }

    /// Resolve, with the private-key permission override.
    ///
    /// [`Self::resolve`] is the strict form; the daemon passes the CLI override
    /// here so a deliberately exposed key file is a warning rather than a
    /// refusal.
    fn resolve_with(
        &self,
        path: &Path,
        suite: &dyn CryptoSuite,
        allow_insecure_key: bool,
    ) -> Result<Resolved, Error> {
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
        let mut addresses: Vec<Prefix> = Vec::new();
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
        let mut unique: Vec<Prefix> = Vec::with_capacity(addresses.len());
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
        let has_v6 = addresses
            .iter()
            .any(|net| matches!(net.as_ipnet(), ipnet::IpNet::V6(_)));

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
        let control = self
            .interface
            .control
            .as_ref()
            .map(|declared| resolve_key_path(path, declared));

        let privileges = crate::privileges::resolve(
            self.interface.user.as_deref(),
            self.interface.group.as_deref(),
            &mut warnings,
        )?;
        let identity = keys::identity(suite, &secret)?;
        let issuer = match self.interface.identity_issuer.as_deref() {
            Some(text) => {
                let bytes = keys::hex_decode(text).map_err(|why| Error::Invalid {
                    path: path.to_path_buf(),
                    what: format!("interface.identity_issuer is not hex: {why}"),
                })?;
                let expected = suite.sizes().sign_pk_max;
                if bytes.len() != expected {
                    return Err(Error::Invalid {
                        path: path.to_path_buf(),
                        what: format!(
                            "interface.identity_issuer is {} bytes, but suite 0x{:04x} \
                             uses {expected}",
                            bytes.len(),
                            suite.suite_id()
                        ),
                    });
                }
                Some(vallum_crypto::SignPublicKey::new(bytes))
            }
            None => None,
        };
        let now = now_unix();
        let seed_bytes: [u8; 32] = keys::hex_decode(&secret.seed)
            .map_err(|why| Error::Invalid {
                path: key_path.clone(),
                what: format!("private key seed is not hex: {why}"),
            })?
            .try_into()
            .map_err(|_| Error::Invalid {
                path: key_path.clone(),
                what: "private key seed is not 32 bytes".to_owned(),
            })?;
        let seed = SharedSecret::new(seed_bytes);

        let mut peers = Vec::with_capacity(self.peers.len());
        for (index, entry) in self.peers.iter().enumerate() {
            let where_ = || format!("peer[{index}] `{}`", entry.name);

            let (peer_suite, peer_identity, validity) =
                resolve_peer_identity(entry, suite, issuer.as_ref(), now, path, &where_)?;
            let mut previous = Vec::new();
            if entry.previous_public_key.is_some()
                || entry.previous_identity.is_some()
                || entry.previous_identity_file.is_some()
            {
                let (previous_suite, previous_identity, previous_validity) = resolve_identity(
                    entry.previous_public_key.as_deref(),
                    entry.previous_identity.as_deref(),
                    entry.previous_identity_file.as_deref(),
                    "previous_identity",
                    suite,
                    issuer.as_ref(),
                    now,
                    path,
                    &where_,
                )?;
                if previous_suite != suite.suite_id() {
                    return Err(Error::Invalid {
                        path: path.to_path_buf(),
                        what: format!(
                            "{}: previous key is for suite 0x{previous_suite:04x}, but this \
                             daemon speaks 0x{:04x}",
                            where_(),
                            suite.suite_id()
                        ),
                    });
                }
                previous.push((previous_identity, previous_validity));
            }
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

            // G1: an optional configured PSK, inline or from a file. Both set
            // is an error: a precedence rule would let one silently shadow the
            // other, and a PSK is not a field to guess about.
            let preshared_key = match (
                entry.preshared_key.as_deref(),
                entry.preshared_key_file.as_deref(),
            ) {
                (Some(_), Some(_)) => {
                    return Err(Error::Invalid {
                        path: path.to_path_buf(),
                        what: format!(
                            "{}: preshared_key and preshared_key_file are both set; \
                             choose one",
                            where_()
                        ),
                    });
                }
                (Some(text), None) => {
                    let psk = keys::parse_psk(text).map_err(|why| Error::Invalid {
                        path: path.to_path_buf(),
                        what: format!("{}: preshared_key: {why}", where_()),
                    })?;
                    Some(psk)
                }
                (None, Some(declared)) => {
                    let file = resolve_key_path(path, declared);
                    let (psk, warning) = keys::load_psk(&file, allow_insecure_key)?;
                    if let Some(warning) = warning {
                        warnings.push(format!("{}: {warning}", where_()));
                    }
                    Some(psk)
                }
                (None, None) => None,
            };

            let mut config =
                PeerConfig::new(entry.name.clone(), peer_identity).with_allowed_ips(nets.clone());
            if let Some(validity) = validity {
                config = config.with_validity(validity);
            }
            for (identity, validity) in previous {
                config = config.with_previous_identity(identity, validity);
            }
            if let Some(psk) = preshared_key {
                config = config.with_preshared_key(psk);
            }
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
                let endpoint = resolve_endpoint(text).map_err(|why| Error::Invalid {
                    path: path.to_path_buf(),
                    what: format!("{}: endpoint `{text}`: {why}", where_()),
                })?;
                config = config.with_endpoint(endpoint);
            }
            if entry.pin_endpoint {
                if entry.endpoint.is_none() {
                    return Err(Error::Invalid {
                        path: path.to_path_buf(),
                        what: format!(
                            "{}: pin_endpoint needs an endpoint — there is no address to pin to",
                            where_()
                        ),
                    });
                }
                config = config.with_pinned_endpoint();
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
                    if !addresses.iter().any(|net| net.contains(&allowed.addr())) {
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
            control,
            fwmark: self.interface.fwmark.unwrap_or(0),
            identity,
            seed,
            peers,
            level,
            warnings,
            privileges,
            outer_budget: budget,
        })
    }
}

/// Resolve an endpoint: an address literal, or a hostname with bounded retries.
///
/// WireGuard's `wg` resolves hostnames at set time; so does this. A name is not
/// re-resolved periodically — that would silently move a peer, and the endpoint
/// is a security-relevant value.
fn resolve_endpoint(text: &str) -> Result<SocketAddr, String> {
    use std::net::ToSocketAddrs;

    if let Ok(address) = text.parse::<SocketAddr>() {
        return Ok(address);
    }
    let retries: u32 = std::env::var("VALLUM_ENDPOINT_RESOLUTION_RETRIES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(3);
    let mut last = String::new();
    for attempt in 0..=retries {
        match text.to_socket_addrs() {
            Ok(mut addresses) => match addresses.next() {
                Some(address) => return Ok(address),
                None => last = "no addresses".to_owned(),
            },
            Err(error) => last = error.to_string(),
        }
        if attempt < retries {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
    Err(format!("could not resolve: {last}"))
}

/// Parse one prefix, refusing the IPv4-mapped IPv6 trap.
///
/// `::ffff:10.0.0.1/128` is a v6 prefix, so it never matches an inner v4 source
/// in `allowed_ips` and never routes a v4 packet. An operator who writes it
/// means `10.0.0.1/32`, and the error says so. Used for both the interface
/// addresses and each peer's `allowed_ips` — the trap is the same in both.
fn parse_net(path: &Path, field: &str, text: &str) -> Result<Prefix, Error> {
    let net: Prefix = text.parse().map_err(|e| Error::Invalid {
        path: path.to_path_buf(),
        what: format!("{field} `{text}`: {e}"),
    })?;
    if let ipnet::IpNet::V6(net6) = net.as_ipnet() {
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
/// The wall clock, in Unix seconds.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

/// A peer's identity: a public line, or a document with a window.
///
/// The document path verifies the signature **and** the window at load, so a
/// credential that is already expired is an error naming the peer rather than a
/// tunnel that silently never comes up. The window is also carried into
/// [`PeerConfig`] and re-checked at every handshake.
fn resolve_peer_identity(
    entry: &vallum_config::PeerEntry,
    suite: &dyn CryptoSuite,
    issuer: Option<&vallum_crypto::SignPublicKey>,
    now: u64,
    path: &Path,
    where_: &dyn Fn() -> String,
) -> Result<(u16, PeerIdentity, Option<Validity>), Error> {
    let (suite_id, identity, validity) = resolve_identity(
        entry.public_key.as_deref(),
        entry.identity.as_deref(),
        entry.identity_file.as_deref(),
        "identity",
        suite,
        issuer,
        now,
        path,
        where_,
    )?;
    Ok((suite_id, identity, validity))
}

/// Resolve one identity from a public line, an inline document, or a file.
///
/// `label` names the field in an error, so a bad `previous_identity_file` says
/// so rather than pointing at the current one.
#[allow(clippy::too_many_arguments)]
fn resolve_identity(
    public_key: Option<&str>,
    identity: Option<&str>,
    identity_file: Option<&Path>,
    label: &str,
    suite: &dyn CryptoSuite,
    issuer: Option<&vallum_crypto::SignPublicKey>,
    now: u64,
    path: &Path,
    where_: &dyn Fn() -> String,
) -> Result<(u16, PeerIdentity, Option<Validity>), Error> {
    let invalid = |what: String| Error::Invalid {
        path: path.to_path_buf(),
        what: format!("{}: {what}", where_()),
    };

    let document_text = match (identity, identity_file) {
        (Some(_), Some(_)) => {
            return Err(invalid(format!(
                "{label} and {label}_file are both set; choose one"
            )))
        }
        (Some(text), None) => Some(text.to_owned()),
        (None, Some(file)) => {
            let resolved = resolve_key_path(path, file);
            Some(
                std::fs::read_to_string(&resolved)
                    .map_err(|source| Error::IoPath {
                        action: "read identity document",
                        path: resolved,
                        source,
                    })?
                    .trim()
                    .to_owned(),
            )
        }
        (None, None) => None,
    };

    if document_text.is_some() && public_key.is_some() {
        return Err(invalid(format!(
            "{label} and public_key are both set; an identity document already carries the key"
        )));
    }

    let Some(text) = document_text else {
        let line = public_key.ok_or_else(|| {
            invalid(format!(
                "no {label}, {label}_file, or public key names this peer"
            ))
        })?;
        let (suite_id, identity) = keys::decode_public(line).map_err(|e| invalid(e.to_string()))?;
        return Ok((suite_id, identity, None));
    };

    let bytes = keys::hex_decode(&text).map_err(|why| invalid(format!("{label}: {why}")))?;
    let document = IdentityDocument::decode(&bytes)
        .map_err(|why| invalid(format!("{label} document: {why}")))?;
    let validity = document.validity();
    let peer = match issuer {
        Some(issuer) => document.to_peer(suite, issuer, now),
        None => {
            if !document.is_self_signed(suite) {
                return Err(invalid(format!(
                    "the {label} document is not self-signed, and interface.identity_issuer \
                     is not set"
                )));
            }
            document.to_peer(suite, document.signing(), now)
        }
    }
    .map_err(|why| {
        invalid(format!(
            "{label} document: {why} (window {}..{})",
            validity.not_before, validity.not_after
        ))
    })?;
    Ok((suite.suite_id(), peer, Some(validity)))
}

pub fn resolve_key_path(config_path: &Path, declared: &Path) -> PathBuf {
    if declared.is_absolute() {
        return declared.to_path_buf();
    }
    match config_path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join(declared),
        _ => declared.to_path_buf(),
    }
}
