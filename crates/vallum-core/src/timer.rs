// SPDX-License-Identifier: Apache-2.0

//! Rekey, keepalive, and expiry policy.
//!
//! A tunnel that never replaces its keys is a tunnel whose keys are worth
//! stealing: an attacker who recovers one key reads everything from that point
//! until the peer disconnects, which may be forever. These are the deadlines
//! that bound a key's useful life.
//!
//! Nothing here reads a clock. Every entry point takes a caller-supplied
//! `now` in milliseconds from a **monotonic** source, which is what makes the
//! whole state machine testable and reproducible — and what keeps
//! `vallum-core` free of a time dependency it would otherwise have to fake in
//! tests.
//!
//! The numbers are WireGuard's, and they interact deliberately:
//!
//! | deadline | value | why |
//! |----------|-------|-----|
//! | [`KEEPALIVE_TIMEOUT_MS`] | 10 s | silence from a peer we spoke to means a NAT binding may be gone |
//! | [`REKEY_AFTER_TIME_MS`] | 120 s | start a fresh handshake well before the key expires |
//! | [`REKEY_TIMEOUT_MS`] | 5 s | a handshake that drew no answer is retried |
//! | [`REKEY_ATTEMPT_TIME_MS`] | 90 s | after this long of trying, give up rather than churn |
//! | [`REJECT_AFTER_TIME_MS`] | 180 s | the key is spent; stop using it even if the rekey failed |
//!
//! The rekey starts at 120 s and the key dies at 180 s, so a handshake has 60 s
//! — twelve [`REKEY_TIMEOUT_MS`] intervals — to complete before traffic stops.
//! That margin is the point: running out of key must be the peer's fault, not a
//! scheduling coincidence.

/// Idle time before a keepalive is sent, in milliseconds.
pub const KEEPALIVE_TIMEOUT_MS: u64 = 10_000;

/// Age at which a session should be rekeyed, in milliseconds.
pub const REKEY_AFTER_TIME_MS: u64 = 120_000;

/// Time to wait for an answer to a handshake before retrying, in milliseconds.
pub const REKEY_TIMEOUT_MS: u64 = 5_000;

/// Time to keep retrying a handshake before giving up, in milliseconds.
pub const REKEY_ATTEMPT_TIME_MS: u64 = 90_000;

/// Age at which a session's key must not be used, in milliseconds.
pub const REJECT_AFTER_TIME_MS: u64 = 180_000;

/// How far a session's rekey may be spread past [`REKEY_AFTER_TIME_MS`], in
/// milliseconds.
///
/// Without this, a fleet that enrolled together - or rebooted together -
/// rekeys in the same instant, forever: the rekey trigger was exactly
/// `established_at + 120 s` with no spread, so a thousand clients that booted
/// together sent a thousand initiations to the server in the same second. The
/// server's reassembly table holds sixteen concurrent handshakes
/// (`MAX_REASSEMBLIES`), so the herd evicts entries and the handshakes that
/// lose their entry never complete.
///
/// The spread is bounded so the margin survives it. The rekey starts no later
/// than 120 s + 20 s, the key is spent at 180 s, and the handshake has at
/// least forty seconds - eight [`REKEY_TIMEOUT_MS`] intervals - to complete.
/// The margin was the point of the numbers above: running out of key must be
/// the peer's fault, not a scheduling coincidence.
///
/// The randomness is the caller's, as with [`REKEY_JITTER_MS`]: `vallum-core`
/// has no RNG.
pub const REKEY_SPREAD_MS: u64 = 20_000;

/// Maximum jitter the caller should add to [`KEEPALIVE_TIMEOUT_MS`], in
/// milliseconds.
///
/// Peers with identical keepalive intervals synchronize idle probes behind
/// NATs and relays. The caller supplies the randomness — `vallum-core` has no
/// RNG — and it lands in `0..=KEEPALIVE_JITTER_MS`.
pub const KEEPALIVE_JITTER_MS: u64 = 2_000;

/// Maximum jitter the caller should add to [`REKEY_TIMEOUT_MS`], in
/// milliseconds.
///
/// A responder rekeys all its peers on the same schedule, so without jitter a
/// fleet synchronises into bursts. The caller supplies the randomness —
/// `vallum-core` has no RNG — and it lands in `0..=REKEY_JITTER_MS`.
pub const REKEY_JITTER_MS: u64 = 333;

/// How many handshakes we may have outstanding before giving up.
pub const MAX_HANDSHAKE_ATTEMPTS: u32 = 2;

/// What the transport loop should do on its next tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerAction {
    /// Nothing is due.
    None,
    /// Send a data packet with an empty payload to keep a NAT binding alive.
    SendKeepalive,
    /// Begin a fresh handshake for this session.
    StartHandshake,
    /// Send the outstanding handshake again.
    RetransmitHandshake,
    /// Stop trying: the session has failed to rekey for too long. The caller may
    /// tear the session down and start again on demand.
    GiveUp,
    /// The key is past [`REJECT_AFTER_TIME_MS`]; stop using it, immediately.
    Expire,
}

/// The rekey/keepalive state for one peer session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timers {
    now: u64,
    established_at: Option<u64>,
    /// How far this session's rekey is spread, in milliseconds. Drawn once per
    /// session by the caller, and cleared when the session changes.
    rekey_offset: Option<u64>,
    /// How far this session's idle keepalive is jittered past [`KEEPALIVE_TIMEOUT_MS`],
    /// in milliseconds. Drawn by the caller and cleared when the session changes.
    keepalive_offset: Option<u64>,
    /// How far handshake retransmissions are jittered past [`REKEY_TIMEOUT_MS`],
    /// in milliseconds. Drawn by the caller and cleared when a handshake settles or fails.
    retransmit_offset: Option<u64>,
    last_sent: u64,
    last_received: u64,
    attempts: Option<Attempts>,
}

/// An in-flight handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Attempts {
    /// When the first attempt of this run was made.
    first: u64,
    /// When the most recent attempt was made.
    last: u64,
    /// How many attempts have been made.
    count: u32,
}

impl Timers {
    /// A fresh, unestablished session.
    #[must_use]
    pub fn new(now: u64) -> Self {
        Self {
            now,
            established_at: None,
            rekey_offset: None,
            keepalive_offset: None,
            retransmit_offset: None,
            last_sent: now,
            last_received: now,
            attempts: None,
        }
    }

    /// A session that just completed its handshake.
    #[must_use]
    pub fn established(now: u64) -> Self {
        let mut timers = Self::new(now);
        timers.on_established(now);
        timers
    }

    /// Record that a handshake completed.
    pub fn on_established(&mut self, now: u64) {
        self.now = now;
        self.established_at = Some(now);
        // A new session draws a new spread and jitter offsets, so a peer that
        // rekeys repeatedly does not synchronize probes on the same beat.
        self.rekey_offset = None;
        self.keepalive_offset = None;
        self.retransmit_offset = None;
        self.attempts = None;
    }

    /// Whether this session is established.
    #[must_use]
    pub fn is_established(&self) -> bool {
        self.established_at.is_some()
    }

    /// The spread applied to this session's rekey, if one has been drawn.
    #[must_use]
    pub fn rekey_offset(&self) -> Option<u64> {
        self.rekey_offset
    }

    /// Record the spread for this session's rekey.
    ///
    /// The caller owns the randomness; this only records it, so that the
    /// rekey trigger can be moved without shortening the key's life.
    pub fn set_rekey_offset(&mut self, offset: u64) {
        self.rekey_offset = Some(offset.min(REKEY_SPREAD_MS));
    }

    /// The jitter offset applied to this session's idle keepalive probe, if drawn.
    #[must_use]
    pub fn keepalive_offset(&self) -> Option<u64> {
        self.keepalive_offset
    }

    /// Record caller-supplied jitter for idle keepalive probes, bounded to
    /// [`KEEPALIVE_JITTER_MS`].
    pub fn set_keepalive_offset(&mut self, offset: u64) {
        self.keepalive_offset = Some(offset.min(KEEPALIVE_JITTER_MS));
    }

    /// The jitter offset applied to handshake retransmissions, if drawn.
    #[must_use]
    pub fn retransmit_offset(&self) -> Option<u64> {
        self.retransmit_offset
    }

    /// Record caller-supplied jitter for handshake retransmissions, bounded to
    /// [`REKEY_JITTER_MS`].
    pub fn set_retransmit_offset(&mut self, offset: u64) {
        self.retransmit_offset = Some(offset.min(REKEY_JITTER_MS));
    }

    /// Record that the device tore down the session because its key expired.
    ///
    /// Expiry outranks everything in [`poll`](Self::poll). A device that removed
    /// the session but left `established_at` in place would therefore be told to
    /// expire forever: no retransmission, no new handshake, a peer that is dead
    /// until the process restarts. Once the spent session is gone there is nothing
    /// left to expire, so this clears the session clock and the idle clock.
    ///
    /// An attempt run that is still in flight is **kept**: the key is spent, but a
    /// replacement handshake may already be halfway through, and it must be allowed
    /// to finish or to give up on its own schedule.
    pub fn on_torn_down(&mut self, now: u64) {
        self.now = now;
        self.established_at = None;
        self.rekey_offset = None;
        self.keepalive_offset = None;
        // With no session, "we spoke and heard nothing" is meaningless; leaving
        // the old times in place would fire a useless reactive keepalive every
        // tick, because a failed send cannot advance `last_sent`.
        self.last_sent = now;
        self.last_received = now;
    }

    /// Record that we sent a data packet.
    pub fn on_sent(&mut self, now: u64) {
        self.now = now;
        self.last_sent = now;
    }

    /// Record that we received a data packet.
    pub fn on_received(&mut self, now: u64) {
        self.now = now;
        self.last_received = now;
    }

    /// Begin a **new** handshake run, with a fresh attempt budget.
    ///
    /// [`poll`](Self::poll) deliberately leaves a spent run in place when it
    /// returns [`TimerAction::GiveUp`], so the device stays quiet until something
    /// asks for a handshake again. That something — user traffic, or a persistent
    /// keepalive — must start a run whose first attempt counts as the first, not
    /// as one more on a budget that is already exhausted. Without this, a peer
    /// that once gave up could never come back: the first message of every later
    /// run would be abandoned by the very next `poll`.
    pub fn begin_handshake(&mut self, now: u64) {
        self.now = now;
        self.attempts = Some(Attempts {
            first: now,
            last: now,
            count: 1,
        });
    }

    /// Record that we sent a handshake (a retransmission of one we began).
    ///
    /// A *new* run begins with [`begin_handshake`](Self::begin_handshake), not
    /// with this: a run that ended in [`TimerAction::GiveUp`] leaves its count
    /// behind on purpose, and continuing it would abandon the new run at once.
    pub fn on_handshake_sent(&mut self, now: u64) {
        self.now = now;
        self.attempts = Some(match self.attempts {
            Some(previous) => Attempts {
                first: previous.first,
                last: now,
                count: previous.count.saturating_add(1),
            },
            None => Attempts {
                first: now,
                last: now,
                count: 1,
            },
        });
    }

    /// Record that a handshake failed outright — the peer answered and was
    /// rejected. This clears the outstanding attempt so the next `poll` may
    /// start a fresh run rather than retransmitting a known-bad message.
    pub fn on_handshake_failed(&mut self) {
        self.attempts = None;
        self.retransmit_offset = None;
    }

    /// Whether a handshake is outstanding.
    #[must_use]
    pub fn handshake_in_flight(&self) -> bool {
        self.attempts.is_some()
    }

    /// How many handshake attempts the current run has made.
    #[must_use]
    pub fn attempts(&self) -> u32 {
        self.attempts.map_or(0, |a| a.count)
    }

    /// Whether the session's key is past [`REJECT_AFTER_TIME_MS`].
    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool {
        self.established_at
            .is_some_and(|established| now.saturating_sub(established) >= REJECT_AFTER_TIME_MS)
    }

    /// What to do at `now`.
    ///
    /// `now` must be monotonic; a clock that moves backwards can only delay an
    /// action, never take one twice, because every comparison saturates.
    #[must_use]
    pub fn poll(&mut self, now: u64) -> TimerAction {
        self.now = now;

        // Expiry outranks everything: a spent key must not carry traffic even
        // while a rekey is in flight.
        if self.is_expired(now) {
            return TimerAction::Expire;
        }

        if let Some(attempts) = self.attempts {
            let waiting = now.saturating_sub(attempts.last);
            if attempts.count >= MAX_HANDSHAKE_ATTEMPTS
                && now.saturating_sub(attempts.first) >= REKEY_ATTEMPT_TIME_MS
            {
                return TimerAction::GiveUp;
            }
            let retransmit_wait = REKEY_TIMEOUT_MS + self.retransmit_offset.unwrap_or(0);
            if waiting >= retransmit_wait {
                return TimerAction::RetransmitHandshake;
            }
            return TimerAction::None;
        }

        if let Some(established) = self.established_at {
            // The spread moves the rekey later, never earlier: the key's life
            // is not shortened by it.
            let offset = self.rekey_offset.unwrap_or(0);
            if now.saturating_sub(established) >= REKEY_AFTER_TIME_MS + offset {
                return TimerAction::StartHandshake;
            }
        }

        // We spoke and heard nothing back: the path may have gone idle. Send an
        // empty data packet to find out, or to hold a NAT binding open.
        let keepalive_wait = KEEPALIVE_TIMEOUT_MS + self.keepalive_offset.unwrap_or(0);
        if self.last_sent > self.last_received
            && now.saturating_sub(self.last_sent) >= keepalive_wait
        {
            return TimerAction::SendKeepalive;
        }

        TimerAction::None
    }

    /// The retransmission delay to use, given caller-supplied `jitter`.
    ///
    /// Add the result to the moment the last handshake was sent. The caller owns
    /// the randomness; this only bounds it, so no fleet rekeys in lockstep.
    #[must_use]
    pub fn retransmit_delay(jitter: u64) -> u64 {
        REKEY_TIMEOUT_MS + jitter % (REKEY_JITTER_MS + 1)
    }

    /// The keepalive delay to use, given caller-supplied `jitter`.
    ///
    /// Add the result to `last_sent` when spreading idle keepalive probes in `0..=KEEPALIVE_JITTER_MS`.
    #[must_use]
    pub fn keepalive_delay(jitter: u64) -> u64 {
        KEEPALIVE_TIMEOUT_MS + jitter % (KEEPALIVE_JITTER_MS + 1)
    }

    /// The session rekey delay to use, given caller-supplied `spread`.
    ///
    /// Add the result to `established_at` when spreading session rekeys in `0..=REKEY_SPREAD_MS`.
    #[must_use]
    pub fn rekey_delay(spread: u64) -> u64 {
        REKEY_AFTER_TIME_MS + spread % (REKEY_SPREAD_MS + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_session_wants_nothing() {
        let mut timers = Timers::new(0);
        assert_eq!(timers.poll(0), TimerAction::None);
        assert_eq!(timers.poll(KEEPALIVE_TIMEOUT_MS - 1), TimerAction::None);
    }

    #[test]
    fn sending_without_hearing_back_triggers_a_keepalive() {
        let mut timers = Timers::established(0);
        timers.on_sent(1_000);
        assert_eq!(
            timers.poll(1_000 + KEEPALIVE_TIMEOUT_MS - 1),
            TimerAction::None
        );
        assert_eq!(
            timers.poll(1_000 + KEEPALIVE_TIMEOUT_MS),
            TimerAction::SendKeepalive
        );

        // Hearing back resets the idle clock.
        timers.on_received(20_000);
        assert_eq!(
            timers.poll(20_000 + KEEPALIVE_TIMEOUT_MS - 1),
            TimerAction::None
        );
    }

    #[test]
    fn a_session_rekeys_at_one_twenty_seconds() {
        let mut timers = Timers::established(0);
        timers.on_received(1);
        assert_eq!(timers.poll(REKEY_AFTER_TIME_MS - 1), TimerAction::None);
        assert_eq!(
            timers.poll(REKEY_AFTER_TIME_MS),
            TimerAction::StartHandshake
        );
    }

    #[test]
    fn a_rekey_spread_moves_the_trigger_later_not_earlier() {
        let mut timers = Timers::established(0);
        timers.on_received(1);
        timers.set_rekey_offset(20_000);
        assert_eq!(
            timers.poll(REKEY_AFTER_TIME_MS),
            TimerAction::None,
            "the spread delays the rekey; it must not bring it forward"
        );
        assert_eq!(
            timers.poll(REKEY_AFTER_TIME_MS + 20_000),
            TimerAction::StartHandshake
        );
    }

    #[test]
    fn a_rekey_spread_never_eats_the_margin() {
        // The whole point of the 60 s between the rekey (120 s) and the spent
        // key (180 s) is that running out of key is the peer's fault. The
        // spread may delay the rekey, so it must leave the margin intact.
        let mut timers = Timers::established(0);
        timers.set_rekey_offset(REKEY_SPREAD_MS);
        let rekey_at = REKEY_AFTER_TIME_MS + REKEY_SPREAD_MS;
        assert!(
            REJECT_AFTER_TIME_MS - rekey_at >= 8 * REKEY_TIMEOUT_MS,
            "at least eight retransmit intervals must remain: {} ms left",
            REJECT_AFTER_TIME_MS - rekey_at
        );
    }

    #[test]
    fn a_rekey_spread_is_bounded_by_the_caller() {
        let mut timers = Timers::established(0);
        timers.set_rekey_offset(u64::MAX);
        assert_eq!(timers.rekey_offset(), Some(REKEY_SPREAD_MS));
    }

    #[test]
    fn a_new_session_draws_a_new_spread() {
        let mut timers = Timers::established(0);
        timers.set_rekey_offset(5_000);
        timers.on_established(1_000);
        assert_eq!(timers.rekey_offset(), None);
    }

    #[test]
    fn a_key_expires_at_one_eighty_seconds_even_mid_rekey() {
        let mut timers = Timers::established(0);
        timers.on_handshake_sent(REKEY_AFTER_TIME_MS);
        assert_eq!(
            timers.poll(REJECT_AFTER_TIME_MS - 1),
            TimerAction::RetransmitHandshake,
            "the rekey is being retried"
        );
        assert_eq!(
            timers.poll(REJECT_AFTER_TIME_MS),
            TimerAction::Expire,
            "expiry outranks the rekey"
        );
    }

    #[test]
    fn an_unanswered_first_handshake_is_retransmitted_then_given_up() {
        // A session that never established: there is no key to expire, so the
        // give-up timer is what ends the attempt.
        let mut timers = Timers::new(0);
        timers.on_handshake_sent(1_000);
        assert_eq!(
            timers.poll(1_000 + REKEY_TIMEOUT_MS),
            TimerAction::RetransmitHandshake
        );

        timers.on_handshake_sent(1_000 + REKEY_TIMEOUT_MS);
        assert_eq!(timers.attempts(), 2);
        assert_eq!(
            timers.poll(1_000 + REKEY_ATTEMPT_TIME_MS),
            TimerAction::GiveUp
        );

        // A failed handshake clears the run, so the caller may start over.
        timers.on_handshake_failed();
        assert_eq!(timers.attempts(), 0);
        assert_eq!(
            timers.poll(1_000 + REKEY_ATTEMPT_TIME_MS),
            TimerAction::None,
            "nothing is due until the caller sends a handshake"
        );
    }

    #[test]
    fn tearing_down_a_spent_session_lets_the_rekey_finish() {
        let mut timers = Timers::established(0);
        timers.begin_handshake(REKEY_AFTER_TIME_MS);
        assert_eq!(timers.poll(REJECT_AFTER_TIME_MS), TimerAction::Expire);

        // The device removes the spent session. What remains is the rekey in
        // flight, which is overdue and must be retried — not expired again.
        timers.on_torn_down(REJECT_AFTER_TIME_MS);
        assert_eq!(
            timers.poll(REJECT_AFTER_TIME_MS + 1),
            TimerAction::RetransmitHandshake,
            "expiry must not repeat now the session is gone"
        );

        // Recording that retry puts the run back on its normal schedule.
        timers.on_handshake_sent(REJECT_AFTER_TIME_MS + 1);
        assert_eq!(
            timers.poll(REJECT_AFTER_TIME_MS + 2),
            TimerAction::None,
            "nothing is due again until the retransmit interval elapses"
        );
    }

    #[test]
    fn a_new_run_after_giving_up_is_not_abandoned_immediately() {
        let mut timers = Timers::new(0);
        timers.begin_handshake(1_000);
        timers.on_handshake_sent(1_000 + REKEY_TIMEOUT_MS);
        assert_eq!(
            timers.poll(1_000 + REKEY_ATTEMPT_TIME_MS),
            TimerAction::GiveUp
        );

        // The spent run stays in place, so the device keeps quiet rather than
        // churning: `poll` reports the same give-up until something asks again.
        assert_eq!(
            timers.poll(200_000),
            TimerAction::GiveUp,
            "a spent run is still spent"
        );

        // A new run starts from attempt one. Without this, the first message of
        // every later run would be abandoned by the very next `poll`.
        timers.begin_handshake(200_000);
        assert_eq!(timers.attempts(), 1);
        assert_eq!(timers.poll(200_000), TimerAction::None);
        assert_eq!(
            timers.poll(200_000 + REKEY_TIMEOUT_MS),
            TimerAction::RetransmitHandshake,
            "the new run retransmits instead of giving up"
        );
    }

    #[test]
    fn an_established_session_expires_rather_than_giving_up() {
        // A rekey that runs the full `REKEY_ATTEMPT_TIME_MS` from 120 s would
        // reach 210 s, past `REJECT_AFTER_TIME_MS` at 180 s. Expiry must win:
        // the key is spent whether or not a replacement arrived.
        let mut timers = Timers::established(0);
        timers.on_handshake_sent(REKEY_AFTER_TIME_MS);
        assert_eq!(timers.poll(210_000), TimerAction::Expire);
    }

    #[test]
    fn an_established_key_never_calls_give_up() {
        let mut timers = Timers::established(0);
        for now in [0, 60_000, REKEY_AFTER_TIME_MS, REJECT_AFTER_TIME_MS + 1] {
            assert_ne!(timers.poll(now), TimerAction::GiveUp, "at {now}");
        }
    }

    #[test]
    fn a_backwards_clock_cannot_double_fire() {
        let mut timers = Timers::new(0);
        timers.on_established(0);
        timers.on_received(1);
        timers.on_sent(10_000);
        assert_eq!(
            timers.poll(10_000 + KEEPALIVE_TIMEOUT_MS),
            TimerAction::SendKeepalive
        );
        // Clock jumps back: nothing is due, and nothing underflows.
        assert_eq!(timers.poll(0), TimerAction::None);
    }

    #[test]
    fn retransmit_jitter_stays_in_range() {
        assert_eq!(Timers::retransmit_delay(0), REKEY_TIMEOUT_MS);
        assert_eq!(
            Timers::retransmit_delay(REKEY_JITTER_MS),
            REKEY_TIMEOUT_MS + REKEY_JITTER_MS
        );
        for jitter in [1, 100, REKEY_JITTER_MS + 1, u64::MAX] {
            let delay = Timers::retransmit_delay(jitter);
            assert!(
                (REKEY_TIMEOUT_MS..=REKEY_TIMEOUT_MS + REKEY_JITTER_MS).contains(&delay),
                "jitter {jitter} gave {delay}"
            );
        }
    }

    #[test]
    fn keepalive_and_rekey_delays_stay_in_range() {
        assert_eq!(Timers::keepalive_delay(0), KEEPALIVE_TIMEOUT_MS);
        assert_eq!(
            Timers::keepalive_delay(KEEPALIVE_JITTER_MS),
            KEEPALIVE_TIMEOUT_MS + KEEPALIVE_JITTER_MS
        );
        for jitter in [1, 750, KEEPALIVE_JITTER_MS + 1, u64::MAX] {
            let delay = Timers::keepalive_delay(jitter);
            assert!(
                (KEEPALIVE_TIMEOUT_MS..=KEEPALIVE_TIMEOUT_MS + KEEPALIVE_JITTER_MS)
                    .contains(&delay),
                "keepalive jitter {jitter} gave {delay}"
            );
        }

        assert_eq!(Timers::rekey_delay(0), REKEY_AFTER_TIME_MS);
        assert_eq!(
            Timers::rekey_delay(REKEY_SPREAD_MS),
            REKEY_AFTER_TIME_MS + REKEY_SPREAD_MS
        );
        for spread in [1, 5_000, REKEY_SPREAD_MS + 1, u64::MAX] {
            let delay = Timers::rekey_delay(spread);
            assert!(
                (REKEY_AFTER_TIME_MS..=REKEY_AFTER_TIME_MS + REKEY_SPREAD_MS).contains(&delay),
                "rekey spread {spread} gave {delay}"
            );
        }
    }

    #[test]
    fn keepalive_and_retransmit_offsets_delay_poll_and_clear_on_lifecycle() {
        let mut timers = Timers::established(0);
        timers.set_keepalive_offset(u64::MAX);
        assert_eq!(timers.keepalive_offset(), Some(KEEPALIVE_JITTER_MS));
        timers.set_keepalive_offset(1_250);
        timers.on_received(50);
        timers.on_sent(100);

        assert_eq!(
            timers.poll(100 + KEEPALIVE_TIMEOUT_MS + 1_249),
            TimerAction::None
        );
        assert_eq!(
            timers.poll(100 + KEEPALIVE_TIMEOUT_MS + 1_250),
            TimerAction::SendKeepalive
        );

        timers.on_torn_down(20_000);
        assert_eq!(timers.keepalive_offset(), None);

        timers.begin_handshake(20_000);
        timers.set_retransmit_offset(u64::MAX);
        assert_eq!(timers.retransmit_offset(), Some(REKEY_JITTER_MS));
        timers.set_retransmit_offset(200);
        assert_eq!(
            timers.poll(20_000 + REKEY_TIMEOUT_MS + 199),
            TimerAction::None
        );
        assert_eq!(
            timers.poll(20_000 + REKEY_TIMEOUT_MS + 200),
            TimerAction::RetransmitHandshake
        );

        timers.on_handshake_failed();
        assert_eq!(timers.retransmit_offset(), None);

        timers.set_keepalive_offset(900);
        timers.set_retransmit_offset(150);
        timers.on_established(30_000);
        assert_eq!(timers.keepalive_offset(), None);
        assert_eq!(timers.retransmit_offset(), None);
    }
}
