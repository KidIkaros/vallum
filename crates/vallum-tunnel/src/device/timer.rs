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
            self.start_handshake(index, clock, rng, out);
            false
        }
    }
}
