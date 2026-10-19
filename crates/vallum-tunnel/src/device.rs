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
    initiator_hello, initiator_process_resp, peer_hint, responder_accept, responder_identify,
    responder_process_conf, ResponderState, SessionKeys,
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

use crate::error::ConfigError;
use crate::peer::{PeerConfig, PeerId};
use crate::rng::Randomness;
use crate::routing::{packet_destination, packet_source};

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
}

// ── per-peer runtime state ───────────────────────────────────────────

/// An in-flight handshake we are driving as the initiator.
///
/// The handshake is stored as its *inputs* rather than its outputs.
/// [`InitiatorState`] is consumed by [`initiator_process_resp`], so keeping it
/// would mean a single forged `RespHello` ends the attempt. Keeping the seed lets
/// the state be rebuilt — byte-identically — whenever it is needed, and makes a
/// failed `RespHello` a dropped packet instead of a lost handshake.
#[derive(Debug)]
struct Initiating {
    sender_index: u32,
    seed: [u8; 32],
    timestamp: Tai64n,
    /// The `mac1` of the `InitHello` we sent. A cookie reply is keyed by it, so it
    /// has to be retained to read the answer to our own request.
    mac1: [u8; MAC_SIZE],
    /// The `mac2` cookie, once one has been issued for our address.
    cookie: Option<[u8; COOKIE_SIZE]>,
    /// The framed `InitHello` itself, so a retransmission never re-encapsulates.
    init_hello: Vec<u8>,
}

/// An in-flight handshake we are answering.
#[derive(Debug)]
struct Responding {
    state: ResponderState,
    /// The address the `InitHello` came from. `RespHello` goes back there, but the
    /// peer's endpoint is not *committed* to it until the initiator proves its
    /// key.
    source: SocketAddr,
}

/// Which handshake, if any, is in flight for a peer.
#[derive(Debug)]
enum Handshake {
    /// Nothing outstanding.
    Idle,
    /// We sent an `InitHello` and are waiting for a `RespHello`.
    Initiating(Box<Initiating>),
    /// We answered an `InitHello` and are waiting for an `InitConf`.
    Responding(Box<Responding>),
}

impl Handshake {
    /// The index this handshake reserved, if any.
    fn index(&self) -> Option<u32> {
        match self {
            Self::Idle => None,
            Self::Initiating(init) => Some(init.sender_index),
            Self::Responding(resp) => Some(resp.state.sender_index()),
        }
    }
}

/// The initiator's `InitConf`, retained so it can be retransmitted until the
/// responder proves it has the session. See the module docs.
#[derive(Debug)]
struct PendingConf {
    bytes: Vec<u8>,
    first_ms: u64,
    last_ms: u64,
}

/// One peer's live state.
#[derive(Debug)]
struct Peer {
    config: PeerConfig,
    /// The hint we resolve inbound `InitHello`s by, precomputed because it
    /// depends only on the peer's static public key.
    hint: [u8; PEER_HINT_SIZE],
    endpoint: Option<SocketAddr>,
    session: Option<Session>,
    /// The index of the epoch retained receive-only, kept so it can be unmapped
    /// when that epoch is erased.
    previous_own_index: Option<u32>,
    handshake: Handshake,
    timers: Timers,
    timestamp_guard: Tai64nGuard,
    shaper: Shaper,
    blocked_until: Option<u64>,
    /// When the peer's *persistent* keepalive is next due, if it has one.
    ///
    /// Separate from [`Timers`] on purpose: the reactive keepalive there answers
    /// silence we caused, while this one is due on a fixed schedule whether or
    /// not anybody spoke. `None` means the peer has none configured.
    next_keepalive_ms: Option<u64>,
    pending: VecDeque<Vec<u8>>,
    pending_bytes: usize,
    pending_conf: Option<PendingConf>,
    /// Every index currently routing to this peer, so the map can be rebuilt
    /// without leaking a stale entry on every rekey.
    indices: Vec<u32>,
    sent: u64,
    delivered: u64,
    dropped: u64,
    rejected: u64,
}

impl Peer {
    fn new(config: PeerConfig, hint: [u8; PEER_HINT_SIZE], now_ms: u64) -> Self {
        let shaper = Shaper::new(config.shaping().to_vec());
        // A configured endpoint is where we dial; roaming may replace it later,
        // but only with an address authenticated traffic arrived from.
        let endpoint = config.endpoint();
        let next_keepalive_ms = config
            .persistent_keepalive()
            .map(|interval| now_ms.saturating_add(keepalive_millis(interval)));
        Self {
            config,
            hint,
            endpoint,
            session: None,
            previous_own_index: None,
            handshake: Handshake::Idle,
            timers: Timers::new(now_ms),
            timestamp_guard: Tai64nGuard::new(),
            shaper,
            blocked_until: None,
            next_keepalive_ms,
            pending: VecDeque::new(),
            pending_bytes: 0,
            pending_conf: None,
            indices: Vec::new(),
            sent: 0,
            delivered: 0,
            dropped: 0,
            rejected: 0,
        }
    }

    /// Whether a session is installed.
    fn is_established(&self) -> bool {
        self.session.is_some()
    }
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
            if existing.config.identity() == config.identity() {
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
        self.peers.len()
    }

    /// A peer's configuration.
    #[must_use]
    pub fn peer(&self, id: PeerId) -> Option<&PeerConfig> {
        self.peers.get(id.index()).map(|peer| &peer.config)
    }

    /// Every peer and its handle, in configuration order.
    ///
    /// What a management interface enumerates, and what a test uses to reach a
    /// peer it did not itself add.
    pub fn peers(&self) -> impl Iterator<Item = (PeerId, &PeerConfig)> {
        self.peers
            .iter()
            .enumerate()
            .map(|(index, peer)| (PeerId::from_index(index), &peer.config))
    }

    /// A peer's current address: configured, or learned by roaming.
    #[must_use]
    pub fn endpoint(&self, id: PeerId) -> Option<SocketAddr> {
        self.peers.get(id.index()).and_then(|peer| peer.endpoint)
    }

    /// Set a peer's address explicitly, as a management interface would.
    pub fn set_endpoint(&mut self, id: PeerId, endpoint: Option<SocketAddr>) {
        if let Some(peer) = self.peers.get_mut(id.index()) {
            peer.endpoint = endpoint;
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
        self.peers.get(id.index()).map(|peer| PeerStats {
            sent: peer.sent,
            delivered: peer.delivered,
            dropped: peer.dropped,
            rejected: peer.rejected,
            queued: peer.pending.len(),
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

    // ── inbound ──────────────────────────────────────────────────────

    fn on_datagram(
        &mut self,
        clock: Clock,
        source: SocketAddr,
        bytes: &[u8],
        rng: &mut dyn Randomness,
        out: &mut Vec<Action>,
    ) {
        let Ok(message) = Message::parse(bytes) else {
            return;
        };
        if message.header().suite_id != self.suite.suite_id() {
            return;
        }
        match message.message_type() {
            MessageType::InitHello => {
                self.on_init_hello(clock, source, &message, bytes, rng, out);
            }
            MessageType::RespHello => self.on_resp_hello(clock, source, bytes, out),
            MessageType::InitConf => self.on_init_conf(clock, source, bytes, out),
            MessageType::Data => self.on_data(clock, source, bytes, out),
            MessageType::CookieReply => self.on_cookie_reply(&message, out),
            // Identity documents travel out of band: P3 carries the signature
            // inline in the handshake, so a device has nothing to do with a
            // standalone document and must not guess what to do with one.
            MessageType::IdentityDoc => {}
        }
    }

    fn on_init_hello(
        &mut self,
        clock: Clock,
        source: SocketAddr,
        message: &Message<'_>,
        bytes: &[u8],
        rng: &mut dyn Randomness,
        out: &mut Vec<Action>,
    ) {
        let suite = Arc::clone(&self.suite);
        let now = clock.monotonic_ms;
        let client = client_bytes(source);

        // (1) The admission gate. Two MACs and no KEM work, before anything
        //     expensive touches an unauthenticated datagram.
        let admission = match admit_handshake(
            &*suite,
            message,
            self.identity.public().as_bytes(),
            &client,
            self.under_load,
            Some(&self.cookie_secret),
        ) {
            Ok(admission) => admission,
            Err(_) => return,
        };
        match admission {
            Admission::Accept => {}
            Admission::NeedCookie => {
                self.send_cookie_reply(&*suite, message, source, &client, rng, out);
                return;
            }
            // No `mac1`, a wrong `mac1`, or a wrong `mac2`: drop in silence. The
            // responder has not been told anything it should believe yet.
            Admission::NoMac1 | Admission::BadMac1 | Admission::BadMac2 => return,
        }

        // (2) Decapsulate op A and read the confidential, unauthenticated hint.
        let Ok(info) = responder_identify(&*suite, &self.identity, bytes) else {
            return;
        };
        let Some(index) = self.peer_with_hint(info.peer_hint()) else {
            return;
        };

        // (3) A *different* peer's configured endpoint must not disagree with the
        //     hint: that is either a misconfiguration the operator needs to see,
        //     or a spoof aimed at the wrong peer. Either way, refuse.
        if let Some(owner) = self.peer_owning_endpoint(source) {
            if owner != PeerId::from_index(index) {
                return;
            }
        }

        // (4) The timestamp, read-only. Committing here would let one forged
        //     `InitHello` lock the real peer out forever, because the guard would
        //     then reject the peer's own, genuine retransmission.
        let stamp = Tai64n::from_bytes(*info.timestamp());
        if self.peers[index].timestamp_guard.check(stamp).is_err() {
            return;
        }

        // (5) A repeated initiation is answered from the cache. The initiator
        //     retransmits the *same* `InitHello` — same index, same bytes — so the
        //     answer it already has is still the right answer. Reusing it matters
        //     for more than cost: if the two ends retransmit on the same tick, a
        //     fresh answer would move us to a new index while the initiator's
        //     confirmation still named the old one, and the handshake would stall
        //     until both sides gave up. A cached reply also does no decapsulation,
        //     and cannot amplify: it is smaller than the message that asks for it.
        if let Handshake::Responding(resp) = &self.peers[index].handshake {
            if resp.state.peer_index() == info.sender_index() {
                let resp_hello = resp.state.resp_hello().to_vec();
                out.push(Action::Send {
                    destination: source,
                    bytes: resp_hello,
                });
                return;
            }
        }

        // (6) Simultaneous initiation: exactly one side may answer, and the
        //     smaller public key keeps its own attempt.
        if matches!(self.peers[index].handshake, Handshake::Initiating(_)) {
            if self.identity.public().as_bytes()
                < self.peers[index].config.identity().kem().as_bytes()
            {
                return;
            }
            self.peers[index].handshake = Handshake::Idle;
            self.remap(index);
        }

        // (7) Answer. Allocating the index *before* `responder_accept` reserves it
        //     against reuse while the handshake is outstanding.
        let own_index = self.alloc_index();
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        let accepted = responder_accept(
            &*suite,
            &self.identity,
            self.peers[index].config.identity(),
            &info,
            own_index,
            &seed,
        );
        let Ok((resp_hello, state)) = accepted else {
            return;
        };

        self.peers[index].handshake = Handshake::Responding(Box::new(Responding { state, source }));
        // A new initiation is a new transcript: begin a fresh attempt run, so a
        // responder that once gave up on an older one is not dead to this caller.
        self.peers[index].timers.begin_handshake(now);
        self.remap(index);
        // The reply goes to where the `InitHello` came from — the only address we
        // have — but the peer's endpoint is not committed until `InitConf`.
        out.push(Action::Send {
            destination: source,
            bytes: resp_hello,
        });
    }

    /// Answer an `InitHello` that carried no `mac2` while under load.
    fn send_cookie_reply(
        &mut self,
        suite: &dyn CryptoSuite,
        message: &Message<'_>,
        source: SocketAddr,
        client: &[u8],
        rng: &mut dyn Randomness,
        out: &mut Vec<Action>,
    ) {
        let Some(mac1) = message
            .get(tag::MAC1)
            .and_then(|value| <[u8; MAC_SIZE]>::try_from(value).ok())
        else {
            return;
        };
        let Ok(cookie) = self.cookie_secret.cookie(suite, client) else {
            return;
        };
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill(&mut nonce);
        let Ok(reply) = build_cookie_reply(suite, message.sender_index(), &mac1, &nonce, &cookie)
        else {
            return;
        };
        out.push(Action::Send {
            destination: source,
            bytes: reply,
        });
    }

    fn on_cookie_reply(&mut self, message: &Message<'_>, out: &mut Vec<Action>) {
        let suite = Arc::clone(&self.suite);

        // The index is in the clear so the right outstanding handshake can be
        // found; the cookie itself only opens under that handshake's `mac1`.
        let Ok(index) = message.require_array::<INDEX_SIZE>(tag::RECEIVER_INDEX) else {
            return;
        };
        let index = u32::from_be_bytes(index);

        let Some(peer_id) = self.index.get(&index).copied() else {
            return;
        };
        let peer_index = peer_id.index();
        let Handshake::Initiating(init) = &self.peers[peer_index].handshake else {
            return;
        };
        let mac1 = init.mac1;
        let Ok((request_index, cookie)) = read_cookie_reply(&*suite, message, &mac1) else {
            return;
        };
        if request_index != index {
            return;
        }

        if let Handshake::Initiating(init) = &mut self.peers[peer_index].handshake {
            init.cookie = Some(cookie);
        }
        // Retry immediately with `mac2`: the cookie was issued precisely because
        // the first attempt could not be admitted. The target stays the address we
        // dialled, never the reply's source — a cookie reply carries no
        // authenticated address, so believing it would be a redirection
        // primitive.
        self.resend_init_hello(peer_index, out);
    }

    fn on_resp_hello(
        &mut self,
        clock: Clock,
        source: SocketAddr,
        bytes: &[u8],
        out: &mut Vec<Action>,
    ) {
        let suite = Arc::clone(&self.suite);
        let now = clock.monotonic_ms;

        let Ok(receiver) = Message::parse(bytes)
            .and_then(|message| message.require_array::<INDEX_SIZE>(tag::RECEIVER_INDEX))
        else {
            return;
        };
        let receiver = u32::from_be_bytes(receiver);
        let Some(peer_id) = self.index.get(&receiver).copied() else {
            return;
        };
        let index = peer_id.index();
        if !matches!(self.peers[index].handshake, Handshake::Initiating(_)) {
            return;
        }

        // Rebuild the state from the stored inputs and consume it. On failure the
        // inputs go back, so a forged `RespHello` costs a bounded amount of work
        // instead of ending the handshake.
        let handshake = core::mem::replace(&mut self.peers[index].handshake, Handshake::Idle);
        let Handshake::Initiating(init) = handshake else {
            return;
        };
        let rebuilt = initiator_hello(
            &*suite,
            &self.identity,
            self.peers[index].config.identity(),
            init.sender_index,
            *init.timestamp.as_bytes(),
            &init.seed,
        );
        let Ok((_, state)) = rebuilt else {
            self.peers[index].handshake = Handshake::Initiating(init);
            return;
        };

        match initiator_process_resp(&*suite, state, &self.identity, bytes) {
            Ok((init_conf, keys)) => {
                // The responder has proven the key, so the address it answered
                // from is now trustworthy for this peer.
                self.peers[index].endpoint = Some(source);
                self.install_session(index, &keys, Role::Initiator, clock, out);
                out.push(Action::Send {
                    destination: source,
                    bytes: init_conf.clone(),
                });
                self.peers[index].pending_conf = Some(PendingConf {
                    bytes: init_conf,
                    first_ms: now,
                    last_ms: now,
                });
            }
            Err(_) => {
                self.peers[index].rejected += 1;
                self.peers[index].handshake = Handshake::Initiating(init);
            }
        }
    }

    fn on_init_conf(
        &mut self,
        clock: Clock,
        source: SocketAddr,
        bytes: &[u8],
        out: &mut Vec<Action>,
    ) {
        let suite = Arc::clone(&self.suite);

        let Ok(receiver) = Message::parse(bytes)
            .and_then(|message| message.require_array::<INDEX_SIZE>(tag::RECEIVER_INDEX))
        else {
            return;
        };
        let receiver = u32::from_be_bytes(receiver);
        let Some(peer_id) = self.index.get(&receiver).copied() else {
            return;
        };
        let index = peer_id.index();

        let handshake = core::mem::replace(&mut self.peers[index].handshake, Handshake::Idle);
        let Handshake::Responding(resp) = handshake else {
            // A duplicate: the initiator retransmitted an `InitConf` we already
            // processed. Nothing to do, and nothing to complain about.
            return;
        };

        let timestamp = Tai64n::from_bytes(*resp.state.timestamp());
        match responder_process_conf(&*suite, resp.state, bytes) {
            Ok(keys) => {
                // The initiator has now proven the key, so its timestamp may be
                // committed and its address believed.
                self.peers[index].timestamp_guard.commit(timestamp);
                self.peers[index].endpoint = Some(source);
                self.install_session(index, &keys, Role::Responder, clock, out);
            }
            Err(_) => {
                // Consumed and rejected. The initiator's own retransmission, or its
                // `InitConf` resend, will drive a fresh attempt.
                self.peers[index].rejected += 1;
                self.remap(index);
            }
        }
    }

    fn on_data(&mut self, clock: Clock, source: SocketAddr, bytes: &[u8], out: &mut Vec<Action>) {
        let suite = Arc::clone(&self.suite);
        let Ok(message) = Message::parse(bytes) else {
            return;
        };
        let Some(peer_id) = self.index.get(&message.sender_index()).copied() else {
            return;
        };
        let index = peer_id.index();

        let opened = match self.peers[index].session.as_mut() {
            Some(session) => session.open(&*suite, bytes),
            None => return,
        };
        let Ok(plaintext) = opened else {
            self.peers[index].rejected += 1;
            return;
        };

        // Authenticated, so the address is now good, and the responder has proven
        // it holds the session — nothing left to retransmit.
        self.peers[index].endpoint = Some(source);
        self.peers[index].pending_conf = None;
        self.peers[index].timers.on_received(clock.monotonic_ms);

        if plaintext.is_empty() {
            // A keepalive, or a shaping machine's padding packet.
            return;
        }

        // The anti-spoofing check. Encrypting under the session key proves *who*
        // sent the packet; it says nothing about which address that peer may
        // claim. Only a source inside the peer's `allowed_ips` is accepted.
        let source_ip = packet_source(&plaintext);
        if !source_ip.is_some_and(|ip| self.peers[index].config.allowed_ips().contains(&ip)) {
            self.peers[index].rejected += 1;
            return;
        }

        self.peers[index].delivered += 1;
        out.push(Action::Deliver { packet: plaintext });
    }

    // ── outbound ─────────────────────────────────────────────────────

    fn on_outbound_ip(
        &mut self,
        clock: Clock,
        packet: Vec<u8>,
        rng: &mut dyn Randomness,
        out: &mut Vec<Action>,
    ) {
        let Some(destination) = packet_destination(&packet) else {
            return;
        };
        let Some(index) = self.route(&destination) else {
            return;
        };

        if self.peers[index].session.is_none() {
            // No session yet: hold the packet and start one. The packet goes out
            // as soon as the handshake completes, which is what makes the first
            // ping of a tunnel work instead of being discarded.
            self.enqueue(index, packet);
            self.start_handshake(index, clock, rng, out);
            return;
        }
        if self.peers[index].blocked_until.is_some() {
            self.enqueue(index, packet);
            return;
        }
        self.send_normal(index, &packet, clock, rng, out);
    }

    // ── timers ───────────────────────────────────────────────────────

    fn on_tick(&mut self, clock: Clock, rng: &mut dyn Randomness, out: &mut Vec<Action>) {
        let now = clock.monotonic_ms;

        if now.saturating_sub(self.cookie_rotated_ms) >= COOKIE_ROTATION_SECONDS * 1000 {
            let mut seed = [0u8; 32];
            rng.fill(&mut seed);
            self.cookie_secret.rotate(&seed);
            self.cookie_rotated_ms = now;
        }

        for index in 0..self.peers.len() {
            self.tick_peer(index, clock, rng, out);
        }
    }

    fn tick_peer(
        &mut self,
        index: usize,
        clock: Clock,
        rng: &mut dyn Randomness,
        out: &mut Vec<Action>,
    ) {
        let now = clock.monotonic_ms;

        // (1) A shaping block whose window has closed releases its queue.
        let released = match self.peers[index].blocked_until {
            Some(deadline) if now >= deadline => {
                self.peers[index].blocked_until = None;
                true
            }
            _ => false,
        };
        if released {
            let draw = rng.draw_u64();
            let effects = self.peers[index].shaper.handle(ShapingEvent::Timeout, draw);
            self.apply_effects(index, effects, clock, out);
        }

        // (2) A superseded epoch that has aged out loses its index.
        let expired = self.peers[index]
            .session
            .as_mut()
            .is_some_and(|session| session.expire_previous(now));
        if expired {
            self.peers[index].previous_own_index = None;
            self.remap(index);
        }

        // (3) Retransmit the initiator's `InitConf` until the responder answers.
        self.retransmit_conf(index, now, out);

        // (4) A *persistent* keepalive, if the peer has one due. It goes first
        //     because it is the one keepalive that must happen on schedule: with
        //     a session it is an empty data packet, and with none it is a dial —
        //     a peer behind a mapping it did not create is reachable only if we
        //     speak first.
        let persistent = self.persistent_keepalive(index, clock, rng, out);

        // (5) The rekey/keepalive/expiry state machine. The reactive keepalive
        //     stands down when the persistent one just went out: they are both an
        //     empty packet, and two in one tick is one more than the path needs.
        match self.peers[index].timers.poll(now) {
            TimerAction::None => {}
            TimerAction::SendKeepalive if persistent => {}
            TimerAction::SendKeepalive => self.send_keepalive(index, clock, rng, out),
            TimerAction::StartHandshake => self.start_handshake(index, clock, rng, out),
            TimerAction::RetransmitHandshake => self.retransmit_handshake(index, clock, out),
            TimerAction::GiveUp => self.abandon_handshake(index),
            TimerAction::Expire => self.tear_down(index, now),
        }

        // (6) Anything held for a session that is now usable.
        self.flush(index, clock, rng, out);
    }

    /// Send the peer's persistent keepalive if its interval has elapsed.
    ///
    /// Returns whether a keepalive actually went out, so the reactive keepalive
    /// can stand down for this tick.
    ///
    /// With a session, "keepalive" is the same empty data packet the reactive
    /// timer sends, shaped identically. Without one, it is a request to
    /// *establish*: an idle peer with nowhere to send is exactly the peer a NAT
    /// forgets, and dialling is the only thing that can fix that. A peer with no
    /// endpoint to dial is left alone, because there is nobody to dial.
    fn persistent_keepalive(
        &mut self,
        index: usize,
        clock: Clock,
        rng: &mut dyn Randomness,
        out: &mut Vec<Action>,
    ) -> bool {
        let now = clock.monotonic_ms;
        let Some(interval) = self.peers[index].config.persistent_keepalive() else {
            return false;
        };
        match self.peers[index].next_keepalive_ms {
            Some(due) if now >= due => {}
            _ => return false,
        }
        self.peers[index].next_keepalive_ms = Some(now.saturating_add(keepalive_millis(interval)));

        // A spent key must not carry traffic, and a keepalive is traffic. The
        // expiry rule is `Timers`' own — the state machine below is about to act
        // on it — so a keepalive never goes out on a key it has already rejected.
        if self.peers[index].timers.is_expired(now) {
            return false;
        }

        if self.peers[index].is_established() {
            self.send_keepalive(index, clock, rng, out);
            true
        } else {
            self.start_handshake(index, clock, rng, out);
            false
        }
    }

    /// Resend the initiator's `InitConf` until an authenticated packet arrives.
    fn retransmit_conf(&mut self, index: usize, now: u64, out: &mut Vec<Action>) {
        let Some(conf) = &mut self.peers[index].pending_conf else {
            return;
        };
        // Stop after the same window the handshake retransmissions use: a
        // responder that has not answered by then is not going to, and the rekey
        // path will pick it up.
        if now.saturating_sub(conf.first_ms) >= REKEY_ATTEMPT_TIME_MS {
            self.peers[index].pending_conf = None;
            return;
        }
        if now.saturating_sub(conf.last_ms) < REKEY_TIMEOUT_MS {
            return;
        }
        conf.last_ms = now;

        let (Some(endpoint), Some(conf)) = (
            self.peers[index].endpoint,
            self.peers[index].pending_conf.as_ref(),
        ) else {
            return;
        };
        out.push(Action::Send {
            destination: endpoint,
            bytes: conf.bytes.clone(),
        });
    }

    // ── handshake driving ────────────────────────────────────────────

    /// Begin a handshake with `peer`, if one is not already in flight.
    fn start_handshake(
        &mut self,
        index: usize,
        clock: Clock,
        rng: &mut dyn Randomness,
        out: &mut Vec<Action>,
    ) {
        if !matches!(self.peers[index].handshake, Handshake::Idle) {
            return;
        }
        // No address to dial: the peer must call us. Common for a roaming peer
        // whose endpoint has not been learned yet.
        let Some(endpoint) = self.peers[index].endpoint else {
            return;
        };
        let suite = Arc::clone(&self.suite);

        let sender_index = self.alloc_index();
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        let timestamp = clock.wall;

        let built = initiator_hello(
            &*suite,
            &self.identity,
            self.peers[index].config.identity(),
            sender_index,
            *timestamp.as_bytes(),
            &seed,
        );
        let Ok((init_hello, _)) = built else {
            return;
        };

        // `mac1` is keyed by the *responder's* public key and proves only that we
        // know it. That is its purpose: it costs an attacker nothing to compute,
        // and it lets the responder filter junk before spending a cookie.
        let peer_public = self.peers[index]
            .config
            .identity()
            .kem()
            .as_bytes()
            .to_vec();
        let Ok(mac1) = compute_mac1(&*suite, &peer_public, &init_hello) else {
            return;
        };
        let Ok(framed) = attach_cookies(&*suite, &init_hello, &peer_public, None) else {
            return;
        };

        self.peers[index].handshake = Handshake::Initiating(Box::new(Initiating {
            sender_index,
            seed,
            timestamp,
            mac1,
            cookie: None,
            init_hello,
        }));
        self.peers[index].timers.begin_handshake(clock.monotonic_ms);
        self.remap(index);

        out.push(Action::Send {
            destination: endpoint,
            bytes: framed,
        });
    }

    fn retransmit_handshake(&mut self, index: usize, clock: Clock, out: &mut Vec<Action>) {
        let now = clock.monotonic_ms;
        match &self.peers[index].handshake {
            Handshake::Initiating(_) => {
                self.resend_init_hello(index, out);
                self.peers[index].timers.on_handshake_sent(now);
            }
            Handshake::Responding(resp) => {
                let (source, resp_hello) = (resp.source, resp.state.resp_hello().to_vec());
                out.push(Action::Send {
                    destination: source,
                    bytes: resp_hello,
                });
                self.peers[index].timers.on_handshake_sent(now);
            }
            Handshake::Idle => {}
        }
    }

    /// Resend the stored `InitHello` for a peer.
    ///
    /// The address is the peer's committed endpoint, never an inbound datagram's
    /// source: a retransmission must not be redirectable by an attacker.
    fn resend_init_hello(&mut self, index: usize, out: &mut Vec<Action>) {
        let suite = Arc::clone(&self.suite);
        let Some(endpoint) = self.peers[index].endpoint else {
            return;
        };
        let peer_public = self.peers[index]
            .config
            .identity()
            .kem()
            .as_bytes()
            .to_vec();
        let Handshake::Initiating(init) = &self.peers[index].handshake else {
            return;
        };
        let Ok(framed) = attach_cookies(
            &*suite,
            &init.init_hello,
            &peer_public,
            init.cookie.as_ref(),
        ) else {
            return;
        };
        out.push(Action::Send {
            destination: endpoint,
            bytes: framed,
        });
    }

    /// Clear an in-flight handshake without touching an established session.
    fn abandon_handshake(&mut self, index: usize) {
        if !matches!(self.peers[index].handshake, Handshake::Idle) {
            self.peers[index].handshake = Handshake::Idle;
            self.remap(index);
        }
    }

    /// Drop a session whose key the timers have rejected.
    ///
    /// The timers must be told, or `Expire` outranks every other action forever:
    /// the session is already gone, but `poll` still reports expiry, which stops
    /// the rekey retransmitting and `start_handshake` from ever being reached
    /// again. A handshake already in flight is left alone — it keeps its own
    /// retransmission and give-up schedule.
    fn tear_down(&mut self, index: usize, now: u64) {
        self.peers[index].session = None;
        self.peers[index].previous_own_index = None;
        self.peers[index].pending_conf = None;
        self.peers[index].timers.on_torn_down(now);
        self.remap(index);
    }

    /// Install a completed handshake as the peer's live session.
    ///
    /// A first handshake establishes epoch `0`; every later one advances to the
    /// next epoch and retains the previous receiver for stragglers. The role is
    /// whichever end we were in *this* handshake, which is why a rekey may be
    /// initiated by either side.
    fn install_session(
        &mut self,
        index: usize,
        keys: &SessionKeys,
        role: Role,
        clock: Clock,
        out: &mut Vec<Action>,
    ) {
        let suite = Arc::clone(&self.suite);
        let peer_id = PeerId::from_index(index);
        let previous = self.peers[index].session.as_ref().map(Session::own_index);

        let epoch = match self.peers[index].session.as_mut() {
            Some(session) => match session.advance(&*suite, keys, role, clock.monotonic_ms) {
                Ok(epoch) => epoch,
                Err(_) => return,
            },
            None => match Session::establish(&*suite, keys, role) {
                Ok(session) => {
                    self.peers[index].session = Some(session);
                    0
                }
                Err(_) => return,
            },
        };

        self.peers[index].handshake = Handshake::Idle;
        self.peers[index].previous_own_index = previous;
        self.peers[index].timers.on_established(clock.monotonic_ms);
        self.remap(index);

        out.push(Action::Established {
            peer: peer_id,
            epoch,
            role,
        });
    }

    // ── data plane ───────────────────────────────────────────────────

    /// Seal one packet for a peer and emit it, applying whatever the shaper asks.
    fn send_normal(
        &mut self,
        index: usize,
        payload: &[u8],
        clock: Clock,
        rng: &mut dyn Randomness,
        out: &mut Vec<Action>,
    ) {
        let draw = rng.draw_u64();
        let effects = self.peers[index]
            .shaper
            .handle(ShapingEvent::NormalSent, draw);
        self.seal_and_send(index, payload, pad_target(&effects), clock, out);
        self.apply_effects(index, effects, clock, out);
    }

    /// Send an empty data packet.
    ///
    /// `TunnelSent` reaches the machines, so a keepalive is itself a shaped event
    /// rather than an invisible one — which is the whole point of a shaping
    /// defence, since an unshaped keepalive carries the timing signature the
    /// defense exists to blur.
    fn send_keepalive(
        &mut self,
        index: usize,
        clock: Clock,
        rng: &mut dyn Randomness,
        out: &mut Vec<Action>,
    ) {
        let draw = rng.draw_u64();
        let effects = self.peers[index]
            .shaper
            .handle(ShapingEvent::TunnelSent, draw);
        self.seal_and_send(index, &[], pad_target(&effects), clock, out);
        // A `Block` is deliberately not honoured here: a keepalive exists to hold
        // a path open, and a machine that held it would suppress the very traffic
        // that keeps the tunnel reachable. Injections still apply.
        for effect in effects {
            if let ShapingAction::Inject { count, size } = effect.action {
                self.inject(index, count, size, clock, out);
            }
        }
    }

    /// Act on a shaper's effects: hold the queue, or inject padding.
    fn apply_effects(
        &mut self,
        index: usize,
        effects: Vec<Effect>,
        clock: Clock,
        out: &mut Vec<Action>,
    ) {
        let now = clock.monotonic_ms;
        for effect in effects {
            match effect.action {
                ShapingAction::Block { timeout_ms } => {
                    let deadline = now.saturating_add(timeout_ms);
                    let peer = &mut self.peers[index];
                    peer.blocked_until =
                        Some(peer.blocked_until.map_or(deadline, |d| d.max(deadline)));
                }
                ShapingAction::Inject { count, size } => {
                    self.inject(index, count, size, clock, out);
                }
                // `Pad` has already been applied to the packet it named; a `Pad`
                // with no packet in hand has nothing to pad.
                ShapingAction::Pad { .. } => {}
            }
        }
    }

    /// Emit `count` padding packets carrying `size` sealed bytes each.
    fn inject(&mut self, index: usize, count: u16, size: u16, clock: Clock, out: &mut Vec<Action>) {
        // A machine is data; a machine that asks for 65 535 packets is a mistake
        // or a self-inflicted flood, so the burst is clamped here.
        let count = count.min(MAX_INJECTION_BURST);
        let target = usize::from(size);
        for _ in 0..count {
            if !self.seal_and_send(index, &[], Some(target), clock, out) {
                return;
            }
        }
    }

    /// The one place a data packet reaches the wire.
    ///
    /// Returns whether a packet went out. The pad target is clamped into the range
    /// the framing accepts: a machine that asks for an impossible size must not be
    /// able to blackhole the traffic it was meant to protect, and a packet already
    /// larger than its pad target simply cannot be padded down to it.
    fn seal_and_send(
        &mut self,
        index: usize,
        payload: &[u8],
        target: Option<usize>,
        clock: Clock,
        out: &mut Vec<Action>,
    ) -> bool {
        let suite = Arc::clone(&self.suite);
        let Some(endpoint) = self.peers[index].endpoint else {
            self.peers[index].dropped += 1;
            return false;
        };

        let floor = payload.len() + PAYLOAD_LEN_SIZE;
        let ceiling = self.max_pad_target();
        let Some(session) = self.peers[index].session.as_mut() else {
            self.peers[index].dropped += 1;
            return false;
        };
        let sealed = match target {
            Some(requested) => {
                let clamped = requested.clamp(floor, ceiling);
                match session.seal_padded(&*suite, payload, clamped) {
                    Ok(packet) => Ok(packet),
                    // Defensive: the clamp should make this unreachable. If it is
                    // reached, sending the packet at its natural size is better
                    // than dropping user traffic.
                    Err(_) => session.seal(&*suite, payload),
                }
            }
            None => session.seal(&*suite, payload),
        };
        let Ok(packet) = sealed else {
            self.peers[index].dropped += 1;
            return false;
        };

        self.peers[index].sent += 1;
        self.peers[index].timers.on_sent(clock.monotonic_ms);
        out.push(Action::Send {
            destination: endpoint,
            bytes: packet,
        });
        true
    }

    /// Hold a packet for a peer that cannot send yet.
    fn enqueue(&mut self, index: usize, packet: Vec<u8>) {
        if packet.is_empty() {
            return;
        }
        let peer = &mut self.peers[index];
        if peer.pending.len() >= MAX_QUEUED_PACKETS
            || peer.pending_bytes + packet.len() > MAX_QUEUED_BYTES
        {
            peer.dropped += 1;
            return;
        }
        peer.pending_bytes += packet.len();
        peer.pending.push_back(packet);
    }

    /// Send whatever has been held for a peer, stopping the moment a machine holds
    /// it again.
    fn flush(
        &mut self,
        index: usize,
        clock: Clock,
        rng: &mut dyn Randomness,
        out: &mut Vec<Action>,
    ) {
        loop {
            if self.peers[index].session.is_none() || self.peers[index].blocked_until.is_some() {
                return;
            }
            let Some(packet) = self.peers[index].pending.pop_front() else {
                return;
            };
            self.peers[index].pending_bytes -= packet.len();
            self.send_normal(index, &packet, clock, rng, out);
        }
    }

    // ── routing and index bookkeeping ────────────────────────────────

    /// The peer with the longest matching prefix for `destination`.
    ///
    /// Longest-prefix match, not first match: a `/32` host route must beat a
    /// `/24` subnet, or a peer given a single address could be shadowed by another
    /// peer's wider prefix.
    fn route(&self, destination: &IpAddr) -> Option<usize> {
        let mut best: Option<(u8, usize)> = None;
        for (index, peer) in self.peers.iter().enumerate() {
            let mut longest: Option<u8> = None;
            for net in peer.config.allowed_ips().nets() {
                if net.contains(destination) {
                    let prefix = net.prefix_len();
                    longest = Some(longest.map_or(prefix, |current| current.max(prefix)));
                }
            }
            if let Some(prefix) = longest {
                if best.is_none_or(|(best_prefix, _)| prefix > best_prefix) {
                    best = Some((prefix, index));
                }
            }
        }
        best.map(|(_, index)| index)
    }

    /// The peer, if any, whose *configured* endpoint is `source`.
    fn peer_owning_endpoint(&self, source: SocketAddr) -> Option<PeerId> {
        self.peers
            .iter()
            .position(|peer| peer.config.endpoint() == Some(source))
            .map(PeerId::from_index)
    }

    /// The peer whose precomputed hint matches.
    ///
    /// The hint is confidential but **not** authenticated, so a match here is a
    /// lookup, not a conclusion: [`responder_accept`] re-derives the hint for the
    /// chosen peer and refuses if they disagree. A collision costs a failed
    /// handshake, never a session under the wrong peer.
    fn peer_with_hint(&self, hint: &[u8; PEER_HINT_SIZE]) -> Option<usize> {
        self.peers.iter().position(|peer| &peer.hint == hint)
    }

    /// Reserve a session index that nothing else owns.
    fn alloc_index(&mut self) -> u32 {
        loop {
            let index = self.next_index;
            // Zero is reserved for cookie replies, which belong to no session.
            self.next_index = self.next_index.wrapping_add(1).max(1);
            if index != 0 && !self.index.contains_key(&index) {
                return index;
            }
        }
    }

    /// Rebuild this peer's entries in the index map from its current state.
    ///
    /// Called after *every* change to a session, a handshake, or a retained epoch,
    /// so the map is a projection of the peer table rather than a second source of
    /// truth that can drift.
    fn remap(&mut self, index: usize) {
        let peer_id = PeerId::from_index(index);
        for stale in self.peers[index].indices.drain(..) {
            self.index.remove(&stale);
        }
        let mut current = Vec::with_capacity(3);
        if let Some(session) = &self.peers[index].session {
            current.push(session.own_index());
        }
        if let Some(previous) = self.peers[index].previous_own_index {
            current.push(previous);
        }
        if let Some(handshake) = self.peers[index].handshake.index() {
            current.push(handshake);
        }
        for owned in &current {
            self.index.insert(*owned, peer_id);
        }
        self.peers[index].indices = current;
    }

    /// The largest sealed-plaintext length that still frames within
    /// [`MAX_DATA_MESSAGE`].
    fn max_pad_target(&self) -> usize {
        // header + COUNTER field (4 framing + 8 value) + DATA_CT field (4 framing)
        // + the target + the suite's tag.
        MAX_DATA_MESSAGE
            .saturating_sub(HEADER_LEN)
            .saturating_sub(4 + COUNTER_SIZE)
            .saturating_sub(4)
            .saturating_sub(self.suite.sizes().aead_tag)
    }
}

// ── helpers ──────────────────────────────────────────────────────────

/// Re-frame a message produced by the handshake with `mac1`, and `mac2` if a
/// cookie is available.
///
/// `vallum-core`'s handshake functions deliberately emit no MAC fields — a MAC is
/// a transport concern, and a handshake that baked one in could not be replayed
/// under a cookie. Adding them means re-framing: parse, copy the fields in order,
/// sign. The field order is preserved exactly, which matters because `mac1` is
/// computed over the fields *before* it.
fn attach_cookies(
    suite: &dyn CryptoSuite,
    message: &[u8],
    responder_public: &[u8],
    cookie: Option<&[u8; COOKIE_SIZE]>,
) -> Result<Vec<u8>, vallum_core::HandshakeError> {
    let parsed = Message::parse(message)?;
    let mut builder = MessageBuilder::new(parsed.header());
    for tag in parsed.tags() {
        if let Some(value) = parsed.get(tag) {
            builder.field(tag, value)?;
        }
    }
    sign_with_cookies(suite, &mut builder, responder_public, cookie)?;
    builder.finish()
}

/// The largest `Pad` target among a shaper's effects, if any.
///
/// The maximum, not the last: if two machines pad the same packet, the larger
/// target satisfies both size classes.
fn pad_target(effects: &[Effect]) -> Option<usize> {
    effects
        .iter()
        .filter_map(|effect| match effect.action {
            ShapingAction::Pad { target } => Some(usize::from(target)),
            _ => None,
        })
        .max()
}

/// A configured keepalive interval in milliseconds.
///
/// Floored at one so an interval of zero — which a caller can express with a
/// sub-millisecond `Duration` — cannot make the deadline permanent.
fn keepalive_millis(interval: Duration) -> u64 {
    u64::try_from(interval.as_millis())
        .unwrap_or(u64::MAX)
        .max(1)
}

/// A stable byte encoding of a socket address, used as the cookie's client key.
///
/// The encoding is the responder's alone — an initiator merely echoes the cookie
/// it is given — so any injective encoding works. Address and port are both
/// included, so a cookie is bound to the full endpoint and a NAT rebinding
/// correctly invalidates it.
fn client_bytes(address: SocketAddr) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(18);
    match address {
        SocketAddr::V4(v4) => {
            bytes.push(4);
            bytes.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            bytes.push(6);
            bytes.extend_from_slice(&v6.ip().octets());
        }
    }
    bytes.extend_from_slice(&address.port().to_be_bytes());
    bytes
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn client_encoding_distinguishes_address_and_port() {
        let a: SocketAddr = "10.0.0.1:1000".parse().unwrap();
        let b: SocketAddr = "10.0.0.1:1001".parse().unwrap();
        let c: SocketAddr = "10.0.0.2:1000".parse().unwrap();
        assert_ne!(client_bytes(a), client_bytes(b));
        assert_ne!(client_bytes(a), client_bytes(c));
        assert_ne!(client_bytes(a), client_bytes(c));
        // Same address and port, same encoding — the ciphertext is keyed by it.
        assert_eq!(client_bytes(a), client_bytes(a));
    }

    #[test]
    fn pad_target_takes_the_largest_of_several_machines() {
        let effects = vec![
            Effect {
                machine: 0,
                action: ShapingAction::Pad { target: 512 },
            },
            Effect {
                machine: 1,
                action: ShapingAction::Pad { target: 1400 },
            },
            Effect {
                machine: 2,
                action: ShapingAction::Block { timeout_ms: 10 },
            },
        ];
        assert_eq!(pad_target(&effects), Some(1400));
        assert_eq!(pad_target(&[]), None);
    }
}
