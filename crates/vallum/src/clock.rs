// SPDX-License-Identifier: Apache-2.0

//! Where the transport's two clocks come from.
//!
//! [`vallum_tunnel::Clock`] carries a monotonic millisecond count *and* a
//! `Tai64n` wall stamp, and P6.3 keeps them apart on purpose: the monotonic clock
//! drives every deadline that must be reproducible and is never stepped, while
//! the wall clock appears in exactly one place — a fresh `InitHello` — because a
//! timestamp is the one thing that must be comparable between two hosts.
//!
//! Both come from here. A daemon uses [`SystemClock`]; a test uses [`MockClock`],
//! which is what makes the in-process gate deterministic.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use vallum_core::Tai64n;

/// The daemon's clock, and a test's.
pub trait TimeSource: Send + Sync + 'static {
    /// Milliseconds from a monotonic source. Never moves backwards.
    fn monotonic_ms(&self) -> u64;

    /// The current wall-clock time.
    fn wall(&self) -> Tai64n;
}

/// The host clock.
///
/// The monotonic origin is *this process's start*, not the Unix epoch: nothing
/// compares a monotonic reading across hosts, and anchoring it to the process
/// keeps it far from any value that could be confused with a wall time.
#[derive(Debug)]
pub struct SystemClock {
    start: Instant,
}

impl SystemClock {
    /// Anchor the monotonic clock at now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeSource for SystemClock {
    fn monotonic_ms(&self) -> u64 {
        // Truncating a `u128` of milliseconds: a process would have to run for
        // 584 million years to overflow the `u64`, and saturating is the right
        // failure if it somehow did.
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn wall(&self) -> Tai64n {
        // The host clock is the only source of a `Tai64n` in the daemon. If it
        // is before the Unix epoch there is no sensible stamp; sending `ZERO`
        // makes the peer see a stale timestamp and refuse the handshake, which
        // is the correct outcome and is visible in the log rather than silent.
        Tai64n::now().unwrap_or(Tai64n::ZERO)
    }
}

/// A clock a test sets by hand.
///
/// Both fields are set explicitly rather than derived, because a test sometimes
/// needs the wall clock to be *behind* the peer's while the monotonic clock
/// advances — that is how a replayed handshake is expressed.
#[derive(Debug, Default)]
pub struct MockClock {
    monotonic_ms: AtomicU64,
    unix_secs: AtomicU64,
    nanos: AtomicU64,
}

impl MockClock {
    /// A clock at monotonic `0` and Unix `0`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set both readings.
    pub fn set(&self, monotonic_ms: u64, unix_secs: u64, nanos: u32) {
        self.monotonic_ms.store(monotonic_ms, Ordering::Relaxed);
        self.unix_secs.store(unix_secs, Ordering::Relaxed);
        self.nanos.store(u64::from(nanos), Ordering::Relaxed);
    }

    /// Advance the monotonic clock, leaving the wall clock alone.
    pub fn advance(&self, delta_ms: u64) {
        self.monotonic_ms.fetch_add(delta_ms, Ordering::Relaxed);
    }

    /// Advance the wall clock by whole seconds.
    pub fn advance_wall(&self, delta_secs: u64) {
        self.unix_secs.fetch_add(delta_secs, Ordering::Relaxed);
    }
}

impl TimeSource for MockClock {
    fn monotonic_ms(&self) -> u64 {
        self.monotonic_ms.load(Ordering::Relaxed)
    }

    fn wall(&self) -> Tai64n {
        Tai64n::from_unix(
            self.unix_secs.load(Ordering::Relaxed),
            u32::try_from(self.nanos.load(Ordering::Relaxed)).unwrap_or(0),
        )
    }
}
