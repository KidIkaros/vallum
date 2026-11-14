// SPDX-License-Identifier: Apache-2.0

//! Timers: rekey, keepalive, and the per-peer tick.

use super::state::keepalive_millis;
use super::*;

impl Device {
    pub(super) fn on_tick(
        &mut self,
        clock: Clock,
        rng: &mut dyn Randomness,
        out: &mut Vec<Action>,
    ) {
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

    pub(super) fn tick_peer(
        &mut self,
        index: usize,
        clock: Clock,
        rng: &mut dyn Randomness,
        out: &mut Vec<Action>,
    ) {
        let now = clock.monotonic_ms;

        // (0) Turn the delivery window over, so the ratio describes recent
        //     traffic rather than everything since the process started.
        self.peers[index]
            .window
            .roll(now, crate::device::DELIVERY_WINDOW_MS);

        // (1) Time has passed for the shaping machines: a block whose window has
        //     closed releases its queue, and an armed wake-up gets its timeout.
        //     One `Timeout` covers both, because a machine that is blocked and
        //     armed at once would otherwise act twice on one clock reading.
        let block_closed = self.peers[index]
            .blocked_until
            .is_some_and(|deadline| now >= deadline);
        if block_closed {
            self.peers[index].blocked_until = None;
        }
        let wake_due = self.peers[index]
            .shape_wake_ms
            .is_some_and(|deadline| now >= deadline);
        if block_closed || wake_due {
            self.peers[index].shape_wake_ms = None;
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

        // (2b) Jitter, drawn once per session so peers that established
        //      together do not rekey, probe or retransmit in lockstep.
        seed_timer_jitter(&mut self.peers[index].timers, rng);

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
            TimerAction::StartHandshake => self.start_handshake(index, None, clock, rng, out),
            TimerAction::RetransmitHandshake => {
                self.retransmit_handshake(index, clock, out);
                let jitter = draw_up_to(rng, vallum_core::timer::REKEY_JITTER_MS);
                self.peers[index].timers.set_retransmit_offset(jitter);
            }
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
    pub(super) fn persistent_keepalive(
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
            self.start_handshake(index, None, clock, rng, out);
            false
        }
    }
}

/// A uniform draw in `0..=max`. The device owns the randomness; `vallum-core`
/// has none, so every timer offset is drawn here and handed in.
fn draw_up_to(rng: &mut dyn Randomness, max: u64) -> u64 {
    rng.draw_u64() % (max + 1)
}

/// Give a session's timers the offsets they are still missing.
///
/// Rekey spread and idle-keepalive jitter belong to an established session;
/// the retransmit jitter belongs to a handshake in flight. Each is drawn once
/// and kept until the session (or handshake) changes.
fn seed_timer_jitter(timers: &mut Timers, rng: &mut dyn Randomness) {
    use vallum_core::timer::{KEEPALIVE_JITTER_MS, REKEY_JITTER_MS, REKEY_SPREAD_MS};

    if timers.is_established() {
        if timers.rekey_offset().is_none() {
            timers.set_rekey_offset(draw_up_to(rng, REKEY_SPREAD_MS));
        }
        if timers.keepalive_offset().is_none() {
            timers.set_keepalive_offset(draw_up_to(rng, KEEPALIVE_JITTER_MS));
        }
    }
    if timers.handshake_in_flight() && timers.retransmit_offset().is_none() {
        timers.set_retransmit_offset(draw_up_to(rng, REKEY_JITTER_MS));
    }
}
