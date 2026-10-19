// SPDX-License-Identifier: Apache-2.0

//! The peer table's configuration half.
//!
//! A peer is a *public* key plus the addresses it is allowed to use. Nothing
//! secret lives here: the peer's KEM key is what the handshake encapsulates to,
//! its optional signing key is what a signature is checked against, and its
//! addresses are the cryptokey routing entry. Our own secrets live in
//! [`vallum_core::StaticIdentity`].
//!
//! Identity mode is **local policy and never negotiated**. A peer configured
//! with only a KEM key requires no signature; a peer configured with a signing
//! key must present one, and its absence or an unexpected signature fails the
//! handshake closed (P3). The wire says nothing about which mode a session is in,
//! so an attacker cannot downgrade one.

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use vallum_core::identity::PeerIdentity;
use vallum_core::shaping::Machine;
use vallum_crypto::SharedSecret;

use crate::routing::{AllowedIps, Prefix};

/// A handle to a configured peer.
///
/// Stable for the life of a [`crate::Device`]: peers are append-only, so an id
/// never refers to a different peer than it did when it was handed out. Actions
/// carry one so a caller can name a peer in a log without re-deriving the
/// mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId(usize);

impl PeerId {
    /// The peer's position in the table.
    #[must_use]
    pub fn index(self) -> usize {
        self.0
    }

    /// Wrap a table position. Crate-internal: a caller gets its ids from
    /// [`crate::Device`], never invents one.
    #[must_use]
    pub(crate) fn from_index(index: usize) -> Self {
        Self(index)
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "peer#{}", self.0)
    }
}

/// The public configuration of one peer.
///
/// Built with [`PeerConfig::new`] and the `with_*` setters, all of which are
/// additive and cheap to chain:
///
/// ```no_run
/// use std::net::SocketAddr;
/// use std::str::FromStr;
/// use vallum_core::PeerIdentity;
/// use vallum_tunnel::{PeerConfig, Prefix};
///
/// # fn peer_identity() -> PeerIdentity { unimplemented!() }
/// let config = PeerConfig::new("laptop", peer_identity())
///     .with_allowed_ips(["10.0.0.2/32".parse::<Prefix>().unwrap()])
///     .with_endpoint(SocketAddr::from(([203, 0, 113, 7], 51820)));
/// assert_eq!(config.name(), "laptop");
/// ```
#[derive(Debug, Clone)]
pub struct PeerConfig {
    name: String,
    identity: PeerIdentity,
    allowed_ips: AllowedIps,
    endpoint: Option<SocketAddr>,
    persistent_keepalive: Option<Duration>,
    shaping: Vec<Machine>,
}

impl PeerConfig {
    /// A peer known by its public identity.
    ///
    /// The default endpoint is `None`, which means *roaming from the peer's own
    /// handshakes*: the address is learned from the first authenticated message
    /// and then tracked. A peer that must be dialled needs
    /// [`Self::with_endpoint`].
    #[must_use]
    pub fn new(name: impl Into<String>, identity: PeerIdentity) -> Self {
        Self {
            name: name.into(),
            identity,
            allowed_ips: AllowedIps::default(),
            endpoint: None,
            persistent_keepalive: None,
            shaping: Vec::new(),
        }
    }

    /// The addresses this peer may send from and receive to.
    #[must_use]
    pub fn with_allowed_ips(mut self, nets: impl IntoIterator<Item = Prefix>) -> Self {
        self.allowed_ips = AllowedIps::new(nets.into_iter().collect());
        self
    }

    /// A static address to dial, instead of learning it from the peer.
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: SocketAddr) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    /// Require this peer to use a configured preshared key (G1).
    ///
    /// The key is mixed into the handshake's key schedule; it never appears on
    /// the wire, and the peer must be configured with the same one or the
    /// confirmation fails.
    #[must_use]
    pub fn with_preshared_key(mut self, psk: SharedSecret) -> Self {
        self.identity = self.identity.clone().with_preshared_key(psk);
        self
    }

    /// The configured PSK, if any.
    #[must_use]
    pub fn preshared_key(&self) -> Option<&SharedSecret> {
        self.identity.preshared_key()
    }

    /// Replace the PSK, as a runtime `set` does.
    pub fn set_preshared_key(&mut self, psk: Option<SharedSecret>) {
        self.identity.set_preshared_key(psk);
    }

    /// Replace the allowed addresses, as a runtime `set` does.
    pub fn set_allowed_ips(&mut self, nets: Vec<Prefix>) {
        self.allowed_ips = AllowedIps::new(nets);
    }

    /// Append allowed addresses, as a runtime `set` without
    /// `replace_allowed_ips` does.
    pub fn add_allowed_ips(&mut self, nets: impl IntoIterator<Item = Prefix>) {
        let mut all = self.allowed_ips.nets().to_vec();
        all.extend(nets);
        self.allowed_ips = AllowedIps::new(all);
    }

    /// Replace the dialled endpoint, or clear it to roam.
    pub fn set_endpoint(&mut self, endpoint: Option<SocketAddr>) {
        self.endpoint = endpoint;
    }

    /// Replace the persistent keepalive interval.
    pub fn set_persistent_keepalive(&mut self, interval: Option<Duration>) {
        self.persistent_keepalive = interval;
    }

    /// Send an empty packet every `interval`, even with nothing to send.
    ///
    /// A peer is silent until it has something to say, and silence is what a NAT
    /// forgets first: the mapping was usually created by *our* outbound packet,
    /// so a peer behind one it did not create is unreachable until it speaks.
    /// With an interval the peer keeps talking, and the mapping stays warm.
    ///
    /// The interval is local policy and is never negotiated. It changes only the
    /// timing of packets the peer is already allowed to send, never their
    /// contents or their authenticity, so two ends may disagree about it freely.
    #[must_use]
    pub fn with_persistent_keepalive(mut self, interval: Duration) -> Self {
        self.persistent_keepalive = Some(interval);
        self
    }

    /// Traffic-analysis shaping machines for **this** peer's tunnel.
    ///
    /// Shaping is per-tunnel, not per-device: the machines observe one peer's
    /// sent and received packets, and a block holds only that peer's queue. Off
    /// unless machines are installed here.
    #[must_use]
    pub fn with_shaping(mut self, machines: Vec<Machine>) -> Self {
        self.shaping = machines;
        self
    }

    /// A human-readable name, for logs and configuration round-trips.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The peer's public identity — the KEM key, and the signing key if one is
    /// required.
    #[must_use]
    pub fn identity(&self) -> &PeerIdentity {
        &self.identity
    }

    /// The addresses this peer is responsible for.
    #[must_use]
    pub fn allowed_ips(&self) -> &AllowedIps {
        &self.allowed_ips
    }

    /// The configured address, if the peer is dialled rather than roaming.
    #[must_use]
    pub fn endpoint(&self) -> Option<SocketAddr> {
        self.endpoint
    }

    /// The configured keepalive interval, if the peer must hold a path open.
    #[must_use]
    pub fn persistent_keepalive(&self) -> Option<Duration> {
        self.persistent_keepalive
    }

    /// The shaping machines for this peer's tunnel.
    #[must_use]
    pub fn shaping(&self) -> &[Machine] {
        &self.shaping
    }
}
