// SPDX-License-Identifier: Apache-2.0

//! TAI64N timestamps and the handshake-replay guard.
//!
//! WireGuard's `InitHello` carries a 12-byte timestamp, and the responder
//! refuses any timestamp that is not newer than the newest one it has seen from
//! that peer. That is what stops an on-path attacker from capturing a handshake
//! and replaying it later: the replayed timestamp is no longer new.
//!
//! # The hazard this module is written around
//!
//! An `InitHello` is **not authenticated**. Anyone can encapsulate to the
//! responder's public KEM key, so anyone can mint a well-formed `InitHello` with
//! any timestamp they like — including one far in the future.
//!
//! So the high-water mark must never be advanced by an unauthenticated message.
//! If it were, a single forged `InitHello` bearing the year 3000 would lock the
//! peer out permanently. The guard therefore separates the two operations:
//!
//! - [`Tai64nGuard::check`] is cheap, read-only, and safe to run on arrival. It
//!   rejects stamps that cannot be fresh.
//! - [`Tai64nGuard::commit`] advances the mark, and is only sound **after the
//!   initiator has been authenticated** — i.e. once their key confirmation
//!   verifies. A forged stamp never gets that far.
//!
//! Flooding with fresh-looking stamps is not this mechanism's problem;
//! `mac1`/`mac2` cookies are ([`crate::cookie`]). Timestamps stop replay *after
//! the fact*; cookies stop the flood *in flight*. Both are needed.
//!
//! # What "TAI64N" means here
//!
//! The encoding is WireGuard's: a 64-bit TAI64 second count (Unix seconds plus
//! the TAI64 epoch offset `2⁶²`) and a 32-bit nanosecond count, both big-endian.
//! Like WireGuard, this implementation does **not** apply leap seconds, so the
//! seconds field tracks Unix time and is monotone rather than a true TAI
//! conversion. For a replay guard, monotonicity is the only property that
//! matters.

use core::fmt;

use crate::wire::TIMESTAMP_SIZE;

/// The TAI64 epoch offset: `2⁶²`. Added to a Unix second count.
const TAI64_OFFSET: u64 = 0x4000_0000_0000_0000;

/// A 12-byte TAI64N timestamp.
///
/// `Ord` compares numerically: all three fields are big-endian, so byte-wise
/// order and time order agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tai64n([u8; TIMESTAMP_SIZE]);

impl Tai64n {
    /// The encoded size, in bytes.
    pub const SIZE: usize = TIMESTAMP_SIZE;

    /// The all-zero stamp, as used by the frozen test vectors.
    pub const ZERO: Self = Self([0; TIMESTAMP_SIZE]);

    /// Wrap raw wire bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; TIMESTAMP_SIZE]) -> Self {
        Self(bytes)
    }

    /// The wire bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; TIMESTAMP_SIZE] {
        &self.0
    }

    /// Build from a Unix second count and nanoseconds.
    ///
    /// `nanos` is not range-checked: a value ≥ 10⁹ still orders correctly
    /// against a stamp with the same second count, and the guard only needs
    /// ordering.
    #[must_use]
    pub fn from_unix(unix_secs: u64, nanos: u32) -> Self {
        let tai = TAI64_OFFSET.wrapping_add(unix_secs);
        let mut out = [0u8; TIMESTAMP_SIZE];
        out[..8].copy_from_slice(&tai.to_be_bytes());
        out[8..].copy_from_slice(&nanos.to_be_bytes());
        Self(out)
    }

    /// The raw 64-bit seconds field, as stored (including the TAI64 offset).
    #[must_use]
    pub fn seconds(&self) -> u64 {
        u64::from_be_bytes([
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7],
        ])
    }

    /// The 32-bit nanoseconds field.
    #[must_use]
    pub fn nanos(&self) -> u32 {
        u32::from_be_bytes([self.0[8], self.0[9], self.0[10], self.0[11]])
    }

    /// The Unix second count, undoing the TAI64 offset.
    #[must_use]
    pub fn unix_seconds(&self) -> u64 {
        self.seconds().wrapping_sub(TAI64_OFFSET)
    }

    /// The current time, from the host clock.
    ///
    /// This is the one place in `vallum-core` that reads a clock. It exists so
    /// the daemon has something to put in `InitHello`; every test drives the
    /// timestamps explicitly instead.
    ///
    /// # Errors
    ///
    /// [`TimestampError::Clock`] if the host clock is before the Unix epoch,
    /// where there is no sensible stamp to send.
    pub fn now() -> Result<Self, TimestampError> {
        let elapsed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| TimestampError::Clock)?;
        Ok(Self::from_unix(elapsed.as_secs(), elapsed.subsec_nanos()))
    }
}

impl fmt::Display for Tai64n {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TAI64N({}.{:09})", self.unix_seconds(), self.nanos())
    }
}

/// A timestamp failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampError {
    /// The stamp is not newer than the newest one already committed — almost
    /// certainly a replayed handshake.
    Stale,
    /// The host clock could not produce a timestamp.
    Clock,
}

impl fmt::Display for TimestampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stale => f.write_str("TimestampError: timestamp is not newer than the last one"),
            Self::Clock => f.write_str("TimestampError: host clock is unusable"),
        }
    }
}

impl std::error::Error for TimestampError {}

/// Rejects a replayed handshake by timestamp monotonicity.
///
/// One guard per peer. See the module docs for why [`Tai64nGuard::check`] and
/// [`Tai64nGuard::commit`] are separate.
#[derive(Debug, Clone, Default)]
pub struct Tai64nGuard {
    latest: Option<Tai64n>,
}

impl Tai64nGuard {
    /// A guard that has committed nothing.
    #[must_use]
    pub fn new() -> Self {
        Self { latest: None }
    }

    /// The newest committed stamp.
    #[must_use]
    pub fn latest(&self) -> Option<Tai64n> {
        self.latest
    }

    /// Whether `stamp` could be fresh: strictly newer than the newest committed.
    ///
    /// Cheap and read-only, so it can run on arrival, before any KEM work.
    ///
    /// # Errors
    ///
    /// [`TimestampError::Stale`] if `stamp` is not strictly newer.
    pub fn check(&self, stamp: Tai64n) -> Result<(), TimestampError> {
        match self.latest {
            Some(latest) if stamp <= latest => Err(TimestampError::Stale),
            _ => Ok(()),
        }
    }

    /// Advance the high-water mark to `stamp` if it is newer.
    ///
    /// **Only call this for a handshake whose initiator you have authenticated**,
    /// i.e. after their key confirmation verifies — see the module docs. Calling
    /// it on receipt turns a single forged `InitHello` into a permanent lockout.
    ///
    /// Monotone: an older `stamp` is ignored rather than moving the mark
    /// backwards.
    pub fn commit(&mut self, stamp: Tai64n) {
        if self.latest.is_none_or(|latest| stamp > latest) {
            self.latest = Some(stamp);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn encoding_is_wireguards() {
        // 1970-01-01T00:00:00Z is the TAI64 epoch offset with no nanos.
        let t = Tai64n::from_unix(0, 0);
        assert_eq!(t.as_bytes(), &[0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        // 2024-01-01T00:00:00Z = 1704067200 Unix seconds.
        let t = Tai64n::from_unix(1_704_067_200, 500);
        assert_eq!(t.unix_seconds(), 1_704_067_200);
        assert_eq!(t.nanos(), 500);
        assert_eq!(t.seconds(), 0x4000_0000_0000_0000 + 1_704_067_200);
    }

    #[test]
    fn ordering_matches_time_order() {
        let a = Tai64n::from_unix(100, 0);
        let b = Tai64n::from_unix(100, 1);
        let c = Tai64n::from_unix(101, 0);
        assert!(a < b && b < c && a < c);
        assert_eq!(Tai64n::ZERO, Tai64n::from_bytes([0; TIMESTAMP_SIZE]));
        // The all-zero stamp is before any real stamp: `ZERO` is only a vector
        // placeholder, never a valid "now".
        assert!(Tai64n::ZERO < a);
    }

    #[test]
    fn a_repeat_is_stale_but_a_newer_stamp_is_not() {
        let mut guard = Tai64nGuard::new();
        let first = Tai64n::from_unix(1_000, 0);
        assert_eq!(guard.check(first), Ok(()));
        guard.commit(first);

        assert_eq!(guard.check(first), Err(TimestampError::Stale));
        assert_eq!(
            guard.check(Tai64n::from_unix(999, 0)),
            Err(TimestampError::Stale)
        );
        assert_eq!(guard.check(Tai64n::from_unix(1_000, 1)), Ok(()));
        assert_eq!(guard.latest(), Some(first));
    }

    #[test]
    fn commit_is_monotone() {
        let mut guard = Tai64nGuard::new();
        guard.commit(Tai64n::from_unix(10, 0));
        guard.commit(Tai64n::from_unix(5, 0));
        assert_eq!(guard.latest(), Some(Tai64n::from_unix(10, 0)));
    }

    #[test]
    fn an_unchecked_stamp_cannot_lock_the_peer_out() {
        // The exact attack the split API exists to prevent: a forged InitHello
        // bearing a far-future stamp is *checked* (and looks fresh) but the
        // handshake fails, so it is never committed.
        let mut guard = Tai64nGuard::new();
        let forged = Tai64n::from_unix(u64::MAX / 2, 0);
        assert_eq!(guard.check(forged), Ok(()));
        // ...no commit: the handshake never authenticated.
        assert_eq!(guard.latest(), None);

        let honest = Tai64n::from_unix(1_000, 0);
        assert_eq!(guard.check(honest), Ok(()));
        guard.commit(honest);
        assert_eq!(guard.latest(), Some(honest));
    }
}
