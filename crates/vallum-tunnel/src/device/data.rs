// SPDX-License-Identifier: Apache-2.0

//! The data plane: seal, queue, flush, and the shaping side effects.

use super::*;

/// ADR-0019's reinit budget, keyed per peer and per device: at least this much
/// time between two reactive re-handshake offers to one peer, and between any
/// two device-wide. Stale-session traffic can trigger a handshake only at this
/// cadence.
pub(super) const PASSIVE_REINIT_INTERVAL_MS: u64 = 15_000;

/// The largest `Pad` target among a shaper's effects, if any.
///
/// The maximum, not the last: if two machines pad the same packet, the larger
/// target satisfies both size classes.
pub(super) fn pad_target(effects: &[Effect]) -> Option<usize> {
    effects
        .iter()
        .filter_map(|effect| match effect.action {
            ShapingAction::Pad { target } => Some(usize::from(target)),
            _ => None,
        })
        .max()
}

impl Device {
    pub(super) fn on_data(
        &mut self,
        clock: Clock,
        source: SocketAddr,
        bytes: &[u8],
        rng: &mut dyn Randomness,
        out: &mut Vec<Action>,
    ) {
        let suite = Arc::clone(&self.suite);
        let Ok(message) = Message::parse(bytes) else {
            self.dropped_malformed = self.dropped_malformed.saturating_add(1);
            return;
        };
        let Some(peer_id) = self.index.get(&message.sender_index()).copied() else {
            // The session this datagram belongs to is not in our table. After a
            // restart this is what every packet from a still-running peer looks
            // like, and it was previously indistinguishable from silence.
            self.dropped_unknown_index = self.dropped_unknown_index.saturating_add(1);
            // We cannot decrypt the packet and there is nothing to do with it,
            // but its shape alone can be trusted enough to be the trigger: it
            // parsed as a data message and carries an index that is not ours.
            // ADR-0019: it may mean a peer is trying to reach us and we are not,
            // so offer a reactive re-handshake, rate-limited.
            self.offer_passive_reinit(source, clock, rng, out);
            return;
        };
        let index = peer_id.index();

        let opened = match self.peers[index].session.as_mut() {
            Some(session) => session.open(&*suite, bytes),
            None => {
                self.peers[index].dropped_no_session += 1;
                return;
            }
        };
        let Ok(plaintext) = opened else {
            self.peers[index].rejected += 1;
            self.peers[index].dropped_replay += 1;
            return;
        };

        // Authenticated, so the address is now good, and the responder has proven
        // it holds the session — nothing left to retransmit.
        self.peers[index].endpoint = Some(source);
        self.peers[index].pending_conf = None;
        self.peers[index].rx_bytes = self.peers[index]
            .rx_bytes
            .saturating_add(bytes.len() as u64);
        self.peers[index].window.received = self.peers[index].window.received.saturating_add(1);
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
            self.peers[index].dropped_allowed_ips += 1;
            self.peers[index].last_rejected_source = source_ip;
            return;
        }

        self.peers[index].delivered += 1;
        out.push(Action::Deliver { packet: plaintext });
    }

    /// The passive side's reactive re-handshake offer, per ADR-0019.
    ///
    /// Traffic from `source` just landed with an index no session of ours names:
    /// from a peer's perspective our session has lapsed and theirs is alive, the
    /// mirror image of what [`Device::on_data`] handles above. We cannot decrypt
    /// anything, and the packet itself carries no proof of identity — so the
    /// whole defence is the rate limit: at most one offer per peer per
    /// [`PASSIVE_REINIT_INTERVAL_MS`], and at most one device-wide, so a flood
    /// of spoofed stale-session datagrams buys an attacker one handshake per
    /// interval, not one handshake per packet.
    ///
    /// The peer is chosen conservatively: a peer whose endpoint is exactly the
    /// datagram's source address, or — when the datagram matches no endpoint —
    /// the one sessionless peer whose endpoint has never been learned. Handshake
    /// completion and everything after goes through the full authenticated path.
    fn offer_passive_reinit(
        &mut self,
        source: SocketAddr,
        clock: Clock,
        rng: &mut dyn Randomness,
        out: &mut Vec<Action>,
    ) {
        let now = clock.monotonic_ms;
        // The device-wide gate first: nothing is offered while its interval is
        // running, whatever the per-peer state.
        if self
            .last_reinit_global_ms
            .is_some_and(|t| now.saturating_sub(t) < PASSIVE_REINIT_INTERVAL_MS)
        {
            return;
        }
        let available = |peer: &Peer| {
            peer.session.is_none()
                && peer
                    .last_reinit_ms
                    .is_none_or(|t| now.saturating_sub(t) >= PASSIVE_REINIT_INTERVAL_MS)
        };
        // A peer whose learned endpoint is the source; or, when nothing matches,
        // the unique peer with no endpoint to its name — a restart wiped it and
        // the roaming client has not re-learned its address yet, so there is
        // exactly one peer the datagram can belong to. A peer with a handshake
        // already in flight is skipped by start_handshake, but offering into it
        // would still burn the budget, so it is filtered out here.
        let maybe_peer = self
            .peers
            .iter()
            .position(|peer| peer.endpoint == Some(source) && available(peer))
            .or_else(|| {
                let mut candidates = self
                    .peers
                    .iter()
                    .enumerate()
                    .filter(|(_, peer)| peer.endpoint.is_none() && available(peer));
                let (index, _) = candidates.next()?;
                candidates.next().is_none().then_some(index)
            })
            .filter(|&index| matches!(self.peers[index].handshake, Handshake::Idle));
        let Some(index) = maybe_peer else {
            return;
        };
        self.last_reinit_global_ms = Some(now);
        self.peers[index].last_reinit_ms = Some(now);
        self.peers[index].reinit_offered = self.peers[index].reinit_offered.saturating_add(1);
        // The offer dials the address the stale datagram came from; that is not
        // committed as the peer's endpoint — see `start_handshake`.
        self.start_handshake(index, Some(source), clock, rng, out);
    }

    // ── outbound ─────────────────────────────────────────────────────

    pub(super) fn on_outbound_ip(
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
            self.start_handshake(index, None, clock, rng, out);
            return;
        }
        if self.peers[index].blocked_until.is_some() {
            self.enqueue(index, packet);
            return;
        }
        self.send_normal(index, &packet, clock, rng, out);
    }

    // ── timers ───────────────────────────────────────────────────────

    /// Seal one packet for a peer and emit it, applying whatever the shaper asks.
    pub(super) fn send_normal(
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
    pub(super) fn send_keepalive(
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
        self.rearm_shape_wake(index, clock);
    }

    /// Act on a shaper's effects: hold the queue, or inject padding.
    pub(super) fn apply_effects(
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
        // Every event fed to a machine restarts its armed interval, so the
        // deadline is recomputed here rather than only when one acts.
        self.rearm_shape_wake(index, clock);
    }

    /// Point the peer's shaping wake-up at `now` plus the shortest interval any
    /// armed machine asks for.
    ///
    /// The machines have no clock, so every event fed to one restarts its
    /// interval and the transport is what turns that into a deadline. Calling
    /// this after each [`Shaper::handle`] — not only when a machine acts — is
    /// what makes the constant-rate floor fill silence rather than add to
    /// traffic that is already moving.
    pub(super) fn rearm_shape_wake(&mut self, index: usize, clock: Clock) {
        let deadline = self.peers[index]
            .shaper
            .wake_after()
            .map(|interval| clock.monotonic_ms.saturating_add(interval));
        self.peers[index].shape_wake_ms = deadline;
    }

    /// Emit `count` padding packets carrying `size` sealed bytes each.
    pub(super) fn inject(
        &mut self,
        index: usize,
        count: u16,
        size: u16,
        clock: Clock,
        out: &mut Vec<Action>,
    ) {
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
    pub(super) fn seal_and_send(
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
        self.peers[index].window.sent = self.peers[index].window.sent.saturating_add(1);
        self.peers[index].tx_bytes = self.peers[index]
            .tx_bytes
            .saturating_add(packet.len() as u64);
        self.peers[index].timers.on_sent(clock.monotonic_ms);
        out.push(Action::Send {
            destination: endpoint,
            bytes: packet,
        });
        true
    }

    /// Hold a packet for a peer that cannot send yet.
    pub(super) fn enqueue(&mut self, index: usize, packet: Vec<u8>) {
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
    pub(super) fn flush(
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

    /// The largest sealed-plaintext length that still frames within
    /// [`MAX_DATA_MESSAGE`].
    pub(super) fn max_pad_target(&self) -> usize {
        // header + COUNTER field (4 framing + 8 value) + DATA_CT field (4 framing)
        // + the target + the suite's tag.
        MAX_DATA_MESSAGE
            .saturating_sub(HEADER_LEN)
            .saturating_sub(4 + COUNTER_SIZE)
            .saturating_sub(4)
            .saturating_sub(self.suite.sizes().aead_tag)
    }
}
