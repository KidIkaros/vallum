// SPDX-License-Identifier: Apache-2.0

//! The sliding-window replay filter.
//!
//! A tunnel reorders and drops packets by design — UDP guarantees neither order
//! nor delivery — so "reject anything not exactly one more than the last" is
//! wrong. The filter remembers the last [`REPLAY_WINDOW`] counters and accepts
//! each at most once.
//!
//! # The caller's obligation
//!
//! **This filter must only ever see counters that an AEAD tag has already
//! authenticated.** Feeding it an attacker-chosen counter lets an off-path
//! adversary advance the window past real packets — a denial of service that
//! costs the attacker nothing more than forged packets.
//!
//! That obligation is not left to the caller's discipline:
//! [`Receiver::open`](crate::data::Receiver::open) is the only thing in Vallum
//! that owns a filter, and it calls [`ReplayFilter::accept`] strictly after
//! `aead_open` returns success. The filter type is public only so its algorithm
//! can be tested directly.

use crate::data::REJECT_AFTER_MESSAGES;
use crate::error::DataError;

/// Width of the replay window, in packets.
pub const REPLAY_WINDOW: u64 = 256;

/// The window as a bitmap of 64-bit words.
const WINDOW_WORDS: usize = (REPLAY_WINDOW / 64) as usize;

/// Sliding-window replay filter for one receiving key.
///
/// Tracks `next` — one past the highest counter accepted — and a bitmap of the
/// counters below it. Bit `i` set means `next - 1 - i` has been accepted.
#[derive(Clone, PartialEq, Eq)]
pub struct ReplayFilter {
    next: u64,
    window: [u64; WINDOW_WORDS],
}

impl Default for ReplayFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayFilter {
    /// A fresh filter that has accepted nothing.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next: 0,
            window: [0; WINDOW_WORDS],
        }
    }

    /// One past the highest counter accepted so far.
    #[must_use]
    pub fn next(&self) -> u64 {
        self.next
    }

    /// Record `counter`, or reject it as a replay.
    ///
    /// Call this **only** with an authenticated counter: see the module docs.
    ///
    /// # Errors
    ///
    /// [`DataError::Replay`] if `counter` was already accepted or has fallen out
    /// of the window; [`DataError::CounterExhausted`] if it is at or beyond
    /// [`REJECT_AFTER_MESSAGES`], where the key's lifetime ends.
    pub fn accept(&mut self, counter: u64) -> Result<(), DataError> {
        // The key has a hard message ceiling. Refusing past it here — rather
        // than trusting the sender to stop — keeps `next` bounded, so the
        // `counter + 1` below can never overflow and the bitmap arithmetic can
        // never leave its defined range.
        if counter >= REJECT_AFTER_MESSAGES {
            return Err(DataError::CounterExhausted { counter });
        }

        // Anything at or below `next - REPLAY_WINDOW` is too old to place in the
        // bitmap. Written as a subtraction-free comparison so a small `next`
        // cannot underflow.
        if counter.saturating_add(REPLAY_WINDOW) <= self.next {
            return Err(DataError::Replay {
                counter,
                next: self.next,
            });
        }

        if counter < self.next {
            // Inside the window: the bit says whether we already saw it.
            let offset = (self.next - counter - 1) as usize;
            let (word, bit) = (offset / 64, offset % 64);
            let mask = 1u64 << bit;
            if self.window[word] & mask != 0 {
                return Err(DataError::Replay {
                    counter,
                    next: self.next,
                });
            }
            self.window[word] |= mask;
            return Ok(());
        }

        // At or ahead of `next`: slide the window forward and mark it.
        let shift = counter - self.next + 1;
        if shift >= REPLAY_WINDOW {
            self.window = [0; WINDOW_WORDS];
        } else {
            shift_window(&mut self.window, shift as usize);
        }
        self.next = counter + 1;
        self.window[0] |= 1;
        Ok(())
    }
}

impl core::fmt::Debug for ReplayFilter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ReplayFilter(next {}, {} of {} window bits set)",
            self.next,
            self.window.iter().map(|w| w.count_ones()).sum::<u32>(),
            REPLAY_WINDOW
        )
    }
}

/// Shift the bitmap left by `shift` bits — toward *higher* bit indices, which is
/// the direction an accepted counter's position moves as `next` advances.
///
/// Bit `p` lives in word `p / 64` at bit `p % 64`, so a left shift by
/// `64·word_shift + bit_shift` sends word `i`'s bits to word `i + word_shift`,
/// with the top `bit_shift` bits overflowing into the word above.
///
/// `shift` must be in `1..REPLAY_WINDOW`.
fn shift_window(window: &mut [u64; WINDOW_WORDS], shift: usize) {
    let word_shift = shift / 64;
    let bit_shift = shift % 64;
    let mut out = [0u64; WINDOW_WORDS];

    for (i, &word) in window.iter().enumerate() {
        if word == 0 {
            continue;
        }
        let low = i + word_shift;
        if low < WINDOW_WORDS {
            out[low] |= word << bit_shift;
        }
        if bit_shift > 0 {
            let high = low + 1;
            if high < WINDOW_WORDS {
                out[high] |= word >> (64 - bit_shift);
            }
        }
    }

    *window = out;
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn in_order_counters_are_accepted_once() {
        let mut f = ReplayFilter::new();
        for counter in 0..(REPLAY_WINDOW * 3) {
            assert_eq!(f.accept(counter), Ok(()), "counter {counter}");
        }
        assert_eq!(f.next(), REPLAY_WINDOW * 3);
    }

    #[test]
    fn a_repeat_is_rejected() {
        let mut f = ReplayFilter::new();
        f.accept(5).unwrap();
        assert_eq!(
            f.accept(5),
            Err(DataError::Replay {
                counter: 5,
                next: 6
            })
        );
    }

    #[test]
    fn out_of_order_within_the_window_is_accepted() {
        let mut f = ReplayFilter::new();
        f.accept(100).unwrap();
        // Everything in [100 - 255, 99] is still placeable.
        for counter in (0..100).rev() {
            assert_eq!(f.accept(counter), Ok(()), "counter {counter}");
        }
        // ...but each only once.
        assert!(f.accept(99).is_err());
        assert_eq!(f.next(), 101);
    }

    #[test]
    fn counters_below_the_window_are_too_old() {
        let mut f = ReplayFilter::new();
        f.accept(REPLAY_WINDOW + 10).unwrap();
        assert!(f.accept(10).is_err(), "10 is below the window floor");
        assert!(f.accept(11).is_err(), "11 is the window floor itself");
        assert_eq!(f.accept(12), Ok(()), "12 is the oldest in-window counter");
    }

    #[test]
    fn a_large_jump_clears_the_window() {
        let mut f = ReplayFilter::new();
        f.accept(1).unwrap();
        f.accept(REPLAY_WINDOW * 4).unwrap();
        assert!(f.accept(1).is_err(), "the pre-jump counter is long gone");
        assert_eq!(
            f.accept(REPLAY_WINDOW * 4),
            Err(DataError::Replay {
                counter: REPLAY_WINDOW * 4,
                next: REPLAY_WINDOW * 4 + 1,
            })
        );
    }

    #[test]
    fn window_edges_are_exact() {
        // Boundary sweep around every word transition, with a sparse pattern, so
        // an off-by-one in the bit arithmetic shows up.
        let mut f = ReplayFilter::new();
        let base = 1000u64;
        f.accept(base).unwrap();
        for delta in [1u64, 63, 64, 65, 127, 128, 129, 255] {
            let counter = base + delta;
            assert_eq!(f.accept(counter), Ok(()), "delta {delta}");
            assert!(f.accept(counter).is_err(), "delta {delta} replayed");
        }
    }

    #[test]
    fn the_highest_counter_survives_a_slide() {
        let mut f = ReplayFilter::new();
        f.accept(0).unwrap();
        f.accept(1).unwrap();
        f.accept(64).unwrap();
        // Slide far enough that the old bits land in the right words.
        assert!(f.accept(1).is_err());
        assert!(f.accept(0).is_err());
        assert!(f.accept(64).is_err());
    }

    #[test]
    fn the_message_ceiling_is_enforced() {
        let mut f = ReplayFilter::new();
        assert_eq!(
            f.accept(REJECT_AFTER_MESSAGES),
            Err(DataError::CounterExhausted {
                counter: REJECT_AFTER_MESSAGES
            })
        );
        // A peer that ignores the ceiling cannot push `next` into overflow.
        assert_eq!(
            f.accept(u64::MAX),
            Err(DataError::CounterExhausted { counter: u64::MAX })
        );
        assert_eq!(f.next(), 0);
    }
}
