// SPDX-License-Identifier: Apache-2.0

//! Per-peer runtime state: the handshake slots, the session, the queue, timers.

use super::*;
use vallum_core::identity::{PeerIdentity, Validity};

// ── per-peer runtime state ───────────────────────────────────────────

/// An in-flight handshake we are driving as the initiator.
///
/// The handshake is stored as its *inputs* rather than its outputs.
/// [`InitiatorState`] is consumed by [`initiator_process_resp`], so keeping it
/// would mean a single forged `RespHello` ends the attempt. Keeping the seed lets
/// the state be rebuilt — byte-identically — whenever it is needed, and makes a
/// failed `RespHello` a dropped packet instead of a lost handshake.
#[derive(Debug)]
pub(super) struct Initiating {
    pub(super) sender_index: u32,
    pub(super) seed: [u8; 32],
    pub(super) timestamp: Tai64n,
    /// The `mac1` of the `InitHello` we sent. A cookie reply is keyed by it, so it
    /// has to be retained to read the answer to our own request.
    pub(super) mac1: [u8; MAC_SIZE],
    /// The `mac2` cookie, once one has been issued for our address.
    pub(super) cookie: Option<[u8; COOKIE_SIZE]>,
    /// The framed `InitHello` itself, so a retransmission never re-encapsulates.
    pub(super) init_hello: Vec<u8>,
    /// The op-A-keyed key a `RespHello` must carry a tag under (P6.8).
    ///
    /// Retained so a forged `RespHello` can be rejected **before** the state
    /// rebuild below, which costs an ephemeral keygen and an op-A
    /// encapsulation. Without it the tag would only save the two decapsulations
    /// that come after that rebuild.
    pub(super) resp_tag_key: [u8; RESP_TAG_SIZE],
}

/// An in-flight handshake we are answering.
#[derive(Debug)]
pub(super) struct Responding {
    pub(super) state: ResponderState,
    /// The address the `InitHello` came from. `RespHello` goes back there, but the
    /// peer's endpoint is not *committed* to it until the initiator proves its
    /// key.
    pub(super) source: SocketAddr,
}

/// Which handshake, if any, is in flight for a peer.
#[derive(Debug)]
pub(super) enum Handshake {
    /// Nothing outstanding.
    Idle,
    /// We sent an `InitHello` and are waiting for a `RespHello`.
    Initiating(Box<Initiating>),
    /// We answered an `InitHello` and are waiting for an `InitConf`.
    Responding(Box<Responding>),
}

impl Handshake {
    /// The index this handshake reserved, if any.
    pub(super) fn index(&self) -> Option<u32> {
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
pub(super) struct PendingConf {
    pub(super) bytes: Vec<u8>,
    pub(super) first_ms: u64,
    pub(super) last_ms: u64,
}

/// One peer's live state.
#[derive(Debug)]
pub(super) struct Peer {
    pub(super) config: PeerConfig,
    /// The hint we resolve inbound `InitHello`s by, precomputed because it
    /// depends only on the peer's static public key.
    pub(super) hint: [u8; PEER_HINT_SIZE],
    /// Identities still accepted during a rotation, with their hints and
    /// windows. Empty outside a rotation.
    pub(super) previous: Vec<([u8; PEER_HINT_SIZE], PeerIdentity, Option<Validity>)>,
    pub(super) endpoint: Option<SocketAddr>,
    pub(super) session: Option<Session>,
    /// The index of the epoch retained receive-only, kept so it can be unmapped
    /// when that epoch is erased.
    pub(super) previous_own_index: Option<u32>,
    pub(super) handshake: Handshake,
    pub(super) timers: Timers,
    pub(super) timestamp_guard: Tai64nGuard,
    pub(super) shaper: Shaper,
    pub(super) blocked_until: Option<u64>,
    /// When the peer's *persistent* keepalive is next due, if it has one.
    ///
    /// Separate from [`Timers`] on purpose: the reactive keepalive there answers
    /// silence we caused, while this one is due on a fixed schedule whether or
    /// not anybody spoke. `None` means the peer has none configured.
    pub(super) next_keepalive_ms: Option<u64>,
    pub(super) pending: VecDeque<Vec<u8>>,
    pub(super) pending_bytes: usize,
    pub(super) pending_conf: Option<PendingConf>,
    /// Every index currently routing to this peer, so the map can be rebuilt
    /// without leaking a stale entry on every rekey.
    pub(super) indices: Vec<u32>,
    pub(super) sent: u64,
    pub(super) delivered: u64,
    pub(super) dropped: u64,
    pub(super) rejected: u64,
    /// Wire bytes sent and received for this peer (G2 counters).
    pub(super) tx_bytes: u64,
    pub(super) rx_bytes: u64,
    /// When the last handshake completed, for `show`.
    pub(super) last_handshake: Option<Tai64n>,
    /// A runtime `remove` marks the peer dead rather than shifting the table,
    /// so a `PeerId` never comes to mean a different peer.
    pub(super) removed: bool,
}

impl Peer {
    /// The identity a hint matched: `0` is the current one, `n > 0` is the
    /// `n`th previous identity.
    pub(super) fn identity_at(&self, which: usize) -> &PeerIdentity {
        if which == 0 {
            self.config.identity()
        } else {
            &self.previous[which - 1].1
        }
    }

    /// The window the matched identity asserted, if any.
    pub(super) fn validity_at(&self, which: usize) -> Option<Validity> {
        if which == 0 {
            self.config.validity()
        } else {
            self.previous[which - 1].2
        }
    }

    /// Whether this peer accepts `kem`, now or during a rotation.
    pub(super) fn accepts_kem(&self, kem: &[u8]) -> bool {
        self.config.identity().kem().as_bytes() == kem
            || self
                .previous
                .iter()
                .any(|(_, identity, _)| identity.kem().as_bytes() == kem)
    }

    pub(super) fn new(config: PeerConfig, suite: &dyn CryptoSuite, now_ms: u64) -> Self {
        let hint = peer_hint(suite, config.identity().kem());
        let previous = config
            .previous_identities()
            .iter()
            .map(|accepted| {
                (
                    peer_hint(suite, accepted.identity().kem()),
                    accepted.identity().clone(),
                    accepted.validity(),
                )
            })
            .collect();
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
            previous,
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
            tx_bytes: 0,
            rx_bytes: 0,
            last_handshake: None,
            removed: false,
        }
    }

    /// Whether a session is installed.
    pub(super) fn is_established(&self) -> bool {
        self.session.is_some()
    }
}

/// A configured keepalive interval in milliseconds.
///
/// Floored at one so an interval of zero — which a caller can express with a
/// sub-millisecond `Duration` — cannot make the deadline permanent.
pub(super) fn keepalive_millis(interval: Duration) -> u64 {
    u64::try_from(interval.as_millis())
        .unwrap_or(u64::MAX)
        .max(1)
}
