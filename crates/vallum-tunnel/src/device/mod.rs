// SPDX-License-Identifier: Apache-2.0

//! The transport: peers, cryptokey routing, and the per-peer handshake driver.
//!
//! P1 through P6.2 built parts that each work — and are tested — in isolation: a
//! handshake, an epoch axis, a cookie gate, a shaping machine. The device is what
//! finally drives all of them at once, from real events, for a table of peers,
//! and it is where the *integration* bugs live. That is why it is a crate with a
//! gate of its own.
//!
//! # Sans-IO
//!
//! There is no socket, no TUN device, and no clock in here. A caller feeds
//! [`Event`]s in and takes [`Action`]s out:
//!
//! ```text
//!   UDP datagram ─┐                                   ┌─ send this datagram
//!   IP packet    ─┼─▶  Device::handle  ──▶ Vec<Action> ─┼─ deliver this IP packet
//!   timer tick   ─┘   (clock, rng)                     └─ a session was established
//! ```
//!
//! That is not stylistic. It is what makes a two-host interop test possible *in
//! memory* — no network namespaces, no root, no sleeping — and it is what lets a
//! whole transport be replayed byte for byte when the RNG is deterministic.
//!
//! # Rules the device enforces
//!
//! 1. **The admission gate runs before any KEM work.** [`admit_handshake`] is two
//!    MACs; the decapsulation it protects is the most expensive thing in the
//!    protocol. Under load, a handshake without a valid `mac2` gets a cookie
//!    reply and nothing else.
//! 2. **The peer hint resolves; it never authenticates.** A hint is sealed but
//!    forgeable by anyone who knows our public key, so it *selects* a peer and
//!    [`responder_accept`] then *checks* it. A forged hint cannot produce a
//!    session under the wrong peer; it fails at the initiator's confirmation.
//! 3. **A timestamp is checked on arrival and committed only after the initiator
//!    proves the key.** Committing early would turn one forged `InitHello` into a
//!    permanent lockout for that peer.
//! 4. **An endpoint is learned only from authenticated traffic.** An `InitHello`
//!    is answered at the address it came from, but the peer's endpoint is not
//!    *updated* until `InitConf` or an opened data packet proves the peer's key.
//!    Otherwise anyone could redirect a peer by sending a junk handshake.
//! 5. **An inbound packet's source address is checked against the peer's
//!    `allowed_ips`.** Encrypting under a session key proves *who* sent a packet,
//!    not *which address* it may claim.
//! 6. **Every index a peer owns is mapped to exactly one peer.** A superseded
//!    epoch keeps its own index, so a straggler is demultiplexed to the right
//!    receiver instead of guessed at.
//! 7. **A repeated initiation is answered from the cache, byte for byte.** Both
//!    ends retransmit on their own timers, and if they fire together the responder
//!    must not answer the same initiation with a *new* index: the initiator's
//!    confirmation would then name an index the responder had already discarded,
//!    and the handshake would stall until both sides gave up. Reusing the response
//!    costs no decapsulation and cannot amplify, because it is smaller than the
//!    message that asks for it.
//!
//! # Simultaneous handshakes
//!
//! Two hosts with traffic for each other will start handshakes at the same time.
//! Neither can simply prefer its own attempt or the peer's: if both prefer their
//! own, both play initiator and both `RespHello`s are discarded, and the tunnel
//! re-collides on every retry. The device breaks the tie **by static public
//! key**: on receiving an `InitHello` while we are initiating, the side with the
//! lexicographically smaller KEM public key keeps its attempt and the other
//! abandons its own and answers. The rule is symmetric, so the two ends always
//! agree, and it depends only on public keys.
//!
//! # Losing the third message
//!
//! The handshake's last message is the only one whose loss is not self-healing:
//! by then the initiator is established and has no reason to repeat anything, so
//! a dropped `InitConf` would leave the responder waiting until the initiator's
//! rekey timer fired two minutes later. The initiator therefore retains its
//! `InitConf` and resends it until any authenticated packet arrives from the
//! responder. A duplicate is harmless — by then the responder has no state for
//! that index and drops it.
//!
//! The cost of that recovery is one lost packet, and it is worth stating plainly:
//! the initiator considers itself established as soon as it has sent the
//! confirmation, so it releases whatever it was holding for the peer at that
//! moment. If the confirmation is lost, that first data packet arrives before the
//! responder has keys and is dropped. It is not buffered, because "hold packets
//! for a peer with no session" is exactly the unbounded queue an attacker would
//! like us to have. The loss is the same one WireGuard takes, and the transport
//! protocol above recovers it.
//!
//! # What this does *not* do
//!
//! Nothing here is a *defence* against an on-path attacker; that is what the
//! proofs are for. And one residual cost is documented rather than hidden: an
//! attacker who has observed an `InitHello` knows the initiator's index and can
//! make it do two decapsulations per forged `RespHello`. The work is bounded —
//! one outstanding handshake, and the initiator's own send rate is the ceiling —
//! but not free. Closing it needs a wire change (an op-A-keyed tag checked before
//! decapsulation) and is recorded as a follow-up rather than smuggled in here.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use vallum_core::cookie::{
    admit_handshake, build_cookie_reply, mac1 as compute_mac1, read_cookie_reply,
    sign_with_cookies, Admission, CookieSecret, COOKIE_ROTATION_SECONDS, COOKIE_SIZE, MAC_SIZE,
};
use vallum_core::handshake::{
    initiator_hello_with_psk, initiator_process_resp, peer_hint, responder_accept_with_psk,
    responder_identify, responder_process_conf, verify_resp_tag, ResponderState, SessionKeys,
    RESP_TAG_SIZE,
};
use vallum_core::identity::StaticIdentity;
use vallum_core::keys::{Role, COUNTER_SIZE, NONCE_SIZE};
use vallum_core::session::Session;
use vallum_core::shaping::{Action as ShapingAction, Effect, Event as ShapingEvent, Shaper};
use vallum_core::timer::{TimerAction, Timers, REKEY_ATTEMPT_TIME_MS, REKEY_TIMEOUT_MS};
use vallum_core::timestamp::{Tai64n, Tai64nGuard};
use vallum_core::wire::{
    tag, Message, MessageBuilder, MessageType, HEADER_LEN, INDEX_SIZE, MAX_DATA_MESSAGE,
};
use vallum_core::{PAYLOAD_LEN_SIZE, PEER_HINT_SIZE};
use vallum_crypto::suite::CryptoSuite;
use vallum_crypto::KemPublicKey;
use vallum_crypto::SharedSecret;

use crate::error::ConfigError;
use crate::peer::{PeerConfig, PeerId};
use crate::rng::Randomness;
use crate::routing::{packet_destination, packet_source, AllowedIps, Prefix};

mod data;
mod datagram;
mod handshake;
mod routing;
mod state;
mod timer;

#[cfg(test)]
mod tests;

use state::{keepalive_millis, Handshake, Peer};

/// The most packets held for one peer while it has no usable session, or while a
/// shaping machine is holding its queue.
///
/// A tunnel that queues without bound is a memory-exhaustion bug with a friendly
/// name. Past these limits the incoming packet is dropped and counted, which is
/// what a link does with a full buffer.
pub const MAX_QUEUED_PACKETS: usize = 256;

/// See [`MAX_QUEUED_PACKETS`].
pub const MAX_QUEUED_BYTES: usize = 4 * 1024 * 1024;

/// The most padding packets one shaper effect may inject in a burst.
///
/// A machine is data, and a machine that asks for 65 535 packets is either a
/// mistake or a self-inflicted flood. The burst is clamped rather than trusted.
pub const MAX_INJECTION_BURST: u16 = 64;

/// One clock reading.
///
/// The transport needs two notions of time and they are not interchangeable.
/// Everything that must be *reproducible* — rekey deadlines, keepalive timers,
/// retention windows, block windows — uses `monotonic_ms`, which is why none of
/// them can be perturbed by a clock step. The handshake timestamp is the
/// exception: `Tai64n` is a *wall* clock because it has to be comparable between
/// two hosts, and that is the only reason a wall clock appears at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Clock {
    /// Milliseconds from a monotonic source. Never moves backwards.
    pub monotonic_ms: u64,
    /// The current wall-clock time, as stamped into a new `InitHello`.
    pub wall: Tai64n,
}

impl Clock {
    /// A reading.
    #[must_use]
    pub fn new(monotonic_ms: u64, wall: Tai64n) -> Self {
        Self { monotonic_ms, wall }
    }
}

/// Something the transport must react to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A datagram arrived from the network, from `source`.
    ///
    /// The address is untrusted: it is what the packet *claims*, and it is not
    /// believed until a message proving the peer's key arrives from it.
    Datagram {
        /// Where the datagram appeared to come from.
        source: SocketAddr,
        /// The datagram itself.
        bytes: Vec<u8>,
    },
    /// A plaintext layer-3 packet arrived from the local interface.
    OutboundIp {
        /// The packet, as read from the interface.
        packet: Vec<u8>,
    },
    /// Time has passed; evaluate timers and release anything held.
    ///
    /// Any event runs the timer pass; a bare tick is what a caller sends when
    /// nothing else happened and it wants deadlines evaluated.
    Tick,
}

/// Something the transport wants done.
///
/// Every action is the caller's to perform. The device never performs I/O, so a
/// dropped action is a dropped packet, and a test can consume the actions
/// directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send these bytes to this address over UDP.
    Send {
        /// The destination.
        destination: SocketAddr,
        /// The datagram.
        bytes: Vec<u8>,
    },
    /// Write this plaintext layer-3 packet to the local interface.
    Deliver {
        /// The packet.
        packet: Vec<u8>,
    },
    /// A handshake completed and a session is live.
    ///
    /// Diagnostic: the device has already installed the keys. A caller uses it to
    /// log, or to assert progress in a test.
    Established {
        /// Which peer.
        peer: PeerId,
        /// The epoch the session is now at. `0` for a first handshake.
        epoch: u64,
        /// Which end we were in the handshake that produced it.
        role: Role,
    },
}

/// Per-peer counters, for telemetry or assertions in a test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PeerStats {
    /// Data packets sealed and handed to the caller to send.
    pub sent: u64,
    /// Plaintext packets handed to the caller to deliver.
    pub delivered: u64,
    /// Packets dropped rather than sent (queue full, no address, seal failure).
    pub dropped: u64,
    /// Datagrams that were authenticated and then rejected — a bad tag, a
    /// replayed counter, a source outside `allowed_ips`, a failed confirmation.
    pub rejected: u64,
    /// Packets currently held awaiting a session or a shaping window.
    pub queued: usize,
    /// Wire bytes sent for this peer.
    pub tx_bytes: u64,
    /// Wire bytes received for this peer.
    pub rx_bytes: u64,
    /// When the last handshake completed, if one has.
    pub last_handshake: Option<vallum_core::Tai64n>,
}

// ── the device ───────────────────────────────────────────────────────

/// A peer table and the handshake driver over it.
pub struct Device {
    suite: Arc<dyn CryptoSuite>,
    identity: StaticIdentity,
    peers: Vec<Peer>,
    /// Session/handshake index → peer. Every index a peer currently owns is in
    /// here, and nothing else is.
    index: HashMap<u32, PeerId>,
    next_index: u32,
    cookie_secret: CookieSecret,
    cookie_rotated_ms: u64,
    under_load: bool,
    now_ms: u64,
}

impl core::fmt::Debug for Device {
    /// Redacting: the suite is reported by id, our own identity is not printed at
    /// all, and the cookie secret never appears. Peer state is `Debug` because
    /// every key inside it is already behind a redacting type.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Device")
            .field("suite_id", &self.suite_id())
            .field("peers", &self.peers)
            .field("indices", &self.index.len())
            .field("under_load", &self.under_load)
            .field("now_ms", &self.now_ms)
            .finish_non_exhaustive()
    }
}

impl Device {
    /// A device with a peer table.
    ///
    /// `configs` are validated as a whole: overlapping addresses and duplicate
    /// identities are refused rather than resolved, because either one makes
    /// routing depend on configuration order.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] if two peers claim the same address, or the same identity
    /// is configured twice.
    pub fn new(
        suite: Arc<dyn CryptoSuite>,
        identity: StaticIdentity,
        configs: Vec<PeerConfig>,
        rng: &mut dyn Randomness,
        now_ms: u64,
    ) -> Result<Self, ConfigError> {
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);

        let mut device = Self {
            suite,
            identity,
            peers: Vec::with_capacity(configs.len()),
            index: HashMap::new(),
            // Zero is reserved: a cookie reply carries `sender_index = 0` because
            // it belongs to no session.
            next_index: 1,
            cookie_secret: CookieSecret::new(&seed),
            cookie_rotated_ms: now_ms,
            under_load: false,
            now_ms,
        };
        for config in configs {
            device.add_peer(config)?;
        }
        Ok(device)
    }

    /// Add a peer, returning its handle.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] as [`Device::new`].
    pub fn add_peer(&mut self, config: PeerConfig) -> Result<PeerId, ConfigError> {
        for existing in &self.peers {
            // The wire identity is the KEM key. The PSK and the signing
            // expectation are policy attached to that identity, not part of
            // it: two entries with the same KEM key are the same peer.
            if existing.config.identity().kem().as_bytes() == config.identity().kem().as_bytes() {
                return Err(ConfigError::DuplicatePeer {
                    existing: existing.config.name().to_owned(),
                    duplicate: config.name().to_owned(),
                });
            }
            if let Some(network) = existing.config.allowed_ips().overlaps(config.allowed_ips()) {
                return Err(ConfigError::OverlappingAllowedIps {
                    first: existing.config.name().to_owned(),
                    second: config.name().to_owned(),
                    network,
                });
            }
        }

        let hint = peer_hint(&*self.suite, config.identity().kem());
        let id = PeerId::from_index(self.peers.len());
        self.peers.push(Peer::new(config, hint, self.now_ms));
        Ok(id)
    }

    /// How many peers are configured.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peers.iter().filter(|peer| !peer.removed).count()
    }

    /// A peer's configuration.
    #[must_use]
    pub fn peer(&self, id: PeerId) -> Option<&PeerConfig> {
        self.peers
            .get(id.index())
            .filter(|peer| !peer.removed)
            .map(|peer| &peer.config)
    }

    /// Every peer and its handle, in configuration order.
    ///
    /// What a management interface enumerates, and what a test uses to reach a
    /// peer it did not itself add.
    pub fn peers(&self) -> impl Iterator<Item = (PeerId, &PeerConfig)> {
        self.peers
            .iter()
            .enumerate()
            .filter(|(_, peer)| !peer.removed)
            .map(|(index, peer)| (PeerId::from_index(index), &peer.config))
    }

    /// A peer's current address: configured, or learned by roaming.
    #[must_use]
    pub fn endpoint(&self, id: PeerId) -> Option<SocketAddr> {
        self.peers
            .get(id.index())
            .filter(|peer| !peer.removed)
            .and_then(|peer| peer.endpoint)
    }

    /// Set a peer's address explicitly, as a management interface would.
    pub fn set_endpoint(&mut self, id: PeerId, endpoint: Option<SocketAddr>) {
        if let Some(peer) = self.peers.get_mut(id.index()) {
            if !peer.removed {
                peer.endpoint = endpoint;
            }
        }
    }

    /// Remove a peer at runtime.
    ///
    /// The table is append-only so a [`PeerId`] never comes to mean a different
    /// peer; removal marks the slot dead and clears everything that could still
    /// route to it.
    pub fn remove_peer(&mut self, id: PeerId) {
        let index = id.index();
        let Some(peer) = self.peers.get_mut(index) else {
            return;
        };
        if peer.removed {
            return;
        }
        peer.removed = true;
        let indices = std::mem::take(&mut peer.indices);
        for index in indices {
            self.index.remove(&index);
        }
        peer.session = None;
        peer.handshake = Handshake::Idle;
        peer.pending.clear();
        peer.pending_bytes = 0;
        peer.pending_conf = None;
        peer.previous_own_index = None;
        peer.next_keepalive_ms = None;
    }

    /// Remove every peer, as `replace_peers` does.
    pub fn remove_all_peers(&mut self) {
        for index in 0..self.peers.len() {
            self.remove_peer(PeerId::from_index(index));
        }
    }

    /// Replace a peer's allowed addresses, refusing an overlap.
    ///
    /// # Errors
    ///
    /// [`ConfigError::OverlappingAllowedIps`] if another active peer claims any
    /// of them; routing must never depend on configuration order.
    pub fn set_allowed_ips(&mut self, id: PeerId, nets: Vec<Prefix>) -> Result<(), ConfigError> {
        let index = id.index();
        let Some(peer) = self.peers.get(index) else {
            return Err(ConfigError::UnknownPeer);
        };
        if peer.removed {
            return Err(ConfigError::UnknownPeer);
        }
        let candidate = AllowedIps::new(nets.clone());
        for (other_index, other) in self.peers.iter().enumerate() {
            if other_index == index || other.removed {
                continue;
            }
            if let Some(network) = other.config.allowed_ips().overlaps(&candidate) {
                return Err(ConfigError::OverlappingAllowedIps {
                    first: other.config.name().to_owned(),
                    second: peer.config.name().to_owned(),
                    network,
                });
            }
        }
        self.peers[index].config.set_allowed_ips(nets);
        Ok(())
    }

    /// Append allowed addresses, refusing an overlap.
    ///
    /// # Errors
    ///
    /// [`ConfigError::OverlappingAllowedIps`] if another active peer claims any
    /// of them.
    pub fn add_allowed_ips(&mut self, id: PeerId, nets: Vec<Prefix>) -> Result<(), ConfigError> {
        let index = id.index();
        let Some(peer) = self.peers.get(index) else {
            return Err(ConfigError::UnknownPeer);
        };
        if peer.removed {
            return Err(ConfigError::UnknownPeer);
        }
        let mut candidate = peer.config.allowed_ips().nets().to_vec();
        candidate.extend(nets.clone());
        let candidate = AllowedIps::new(candidate);
        for (other_index, other) in self.peers.iter().enumerate() {
            if other_index == index || other.removed {
                continue;
            }
            if let Some(network) = other.config.allowed_ips().overlaps(&candidate) {
                return Err(ConfigError::OverlappingAllowedIps {
                    first: other.config.name().to_owned(),
                    second: peer.config.name().to_owned(),
                    network,
                });
            }
        }
        self.peers[index].config.add_allowed_ips(nets);
        Ok(())
    }

    /// Find a peer by its KEM public key, as the UAPI does.
    #[must_use]
    pub fn peer_by_kem(&self, kem: &[u8]) -> Option<PeerId> {
        self.peers()
            .find(|(_, config)| config.identity().kem().as_bytes() == kem)
            .map(|(id, _)| id)
    }

    /// Whether this device's identity carries a signing half.
    #[must_use]
    pub fn has_signing(&self) -> bool {
        self.identity.signing_public().is_some()
    }

    /// Replace a peer's configured PSK. The current session keeps running; the
    /// next handshake uses the new value.
    pub fn set_preshared_key(&mut self, id: PeerId, psk: Option<SharedSecret>) {
        let index = id.index();
        let Some(peer) = self.peers.get_mut(index) else {
            return;
        };
        if peer.removed {
            return;
        }
        peer.config.set_preshared_key(psk);
        // An in-flight handshake was started under the old value and cannot
        // complete; the next attempt uses the new one.
        peer.handshake = Handshake::Idle;
        self.remap(index);
    }

    /// Replace a peer's persistent keepalive interval.
    pub fn set_keepalive(&mut self, id: PeerId, interval: Option<Duration>) {
        let index = id.index();
        let Some(peer) = self.peers.get_mut(index) else {
            return;
        };
        if peer.removed {
            return;
        }
        peer.config.set_persistent_keepalive(interval);
        peer.next_keepalive_ms =
            interval.map(|interval| self.now_ms.saturating_add(keepalive_millis(interval)));
    }

    /// Replace the device's own identity. Every session and handshake is torn
    /// down: they were authenticated as the old key.
    pub fn set_identity(&mut self, identity: StaticIdentity) {
        self.identity = identity;
        for index in 0..self.peers.len() {
            if self.peers[index].removed {
                continue;
            }
            let indices = std::mem::take(&mut self.peers[index].indices);
            for index in indices {
                self.index.remove(&index);
            }
            self.peers[index].session = None;
            self.peers[index].handshake = Handshake::Idle;
            self.peers[index].pending_conf = None;
            self.peers[index].previous_own_index = None;
            self.peers[index].pending.clear();
            self.peers[index].pending_bytes = 0;
        }
    }

    /// Whether a peer has a live session.
    #[must_use]
    pub fn is_established(&self, id: PeerId) -> bool {
        self.peers.get(id.index()).is_some_and(Peer::is_established)
    }

    /// A peer's current epoch, if it has a session.
    #[must_use]
    pub fn epoch(&self, id: PeerId) -> Option<u64> {
        self.peers
            .get(id.index())
            .and_then(|peer| peer.session.as_ref().map(Session::epoch))
    }

    /// Whether a handshake is in flight for a peer.
    #[must_use]
    pub fn handshake_in_flight(&self, id: PeerId) -> bool {
        self.peers
            .get(id.index())
            .is_some_and(|peer| peer.timers.handshake_in_flight())
    }

    /// Counters for a peer.
    #[must_use]
    pub fn stats(&self, id: PeerId) -> Option<PeerStats> {
        self.peers.get(id.index()).and_then(|peer| {
            (!peer.removed).then_some(PeerStats {
                sent: peer.sent,
                delivered: peer.delivered,
                dropped: peer.dropped,
                rejected: peer.rejected,
                queued: peer.pending.len(),
                tx_bytes: peer.tx_bytes,
                rx_bytes: peer.rx_bytes,
                last_handshake: peer.last_handshake,
            })
        })
    }

    /// Tell the device whether it is under load.
    ///
    /// Under load, an `InitHello` without a valid `mac2` is answered with a cookie
    /// and dropped, so the KEM work is deferred until the sender proves it can
    /// receive at its claimed address. This is the caller's signal because only
    /// the caller knows what its machine looks like.
    pub fn set_under_load(&mut self, under_load: bool) {
        self.under_load = under_load;
    }

    /// The device's own identity, for a control plane that exports a public line.
    #[must_use]
    pub fn identity(&self) -> &StaticIdentity {
        &self.identity
    }

    /// A peer's short fingerprint: the same 8-byte hint the wire uses.
    #[must_use]
    pub fn fingerprint(&self, id: PeerId) -> Option<[u8; PEER_HINT_SIZE]> {
        self.peers
            .get(id.index())
            .filter(|peer| !peer.removed)
            .map(|peer| peer.hint)
    }

    /// The suite id this device speaks.
    #[must_use]
    pub fn suite_id(&self) -> u16 {
        self.suite.suite_id()
    }

    /// Our own public KEM key — what peers must configure.
    #[must_use]
    pub fn public_key(&self) -> &KemPublicKey {
        self.identity.public()
    }

    /// React to one event and run the timer pass.
    ///
    /// Always returns the actions to perform, in order. An empty vector is the
    /// common case and means "nothing to do".
    #[must_use]
    pub fn handle(&mut self, clock: Clock, event: Event, rng: &mut dyn Randomness) -> Vec<Action> {
        self.now_ms = clock.monotonic_ms;
        let mut out = Vec::new();
        match event {
            Event::Datagram { source, bytes } => {
                self.on_datagram(clock, source, &bytes, rng, &mut out);
            }
            Event::OutboundIp { packet } => {
                self.on_outbound_ip(clock, packet, rng, &mut out);
            }
            Event::Tick => {}
        }
        self.on_tick(clock, rng, &mut out);
        out
    }

    /// Run the timer pass. Equivalent to [`Device::handle`] with [`Event::Tick`].
    #[must_use]
    pub fn poll(&mut self, clock: Clock, rng: &mut dyn Randomness) -> Vec<Action> {
        self.handle(clock, Event::Tick, rng)
    }
}
