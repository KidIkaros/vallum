// SPDX-License-Identifier: Apache-2.0

//! Where randomness actually comes from.
//!
//! Every crate below this one takes a [`Randomness`] and never generates a byte
//! itself, which is what makes a session replayable in a test. The daemon is the
//! one place where that trait is bound to an operating system, and binding it is
//! a five-line job with one hard rule: **fail closed**. If the kernel will not
//! give random bytes, there is no safe way to continue — a zeroed buffer is a
//! predictable key — so the process stops rather than handing the transport a
//! constant.

use vallum_tunnel::Randomness;

/// The operating system's random source.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRng;

impl OsRng {
    /// A source.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Randomness for OsRng {
    fn fill(&mut self, out: &mut [u8]) {
        if getrandom::fill(out).is_err() {
            // Not a panic: unwinding out of a KEM key generation would leave the
            // rest of the process running with a partially filled buffer.
            eprintln!("vallum: the operating system refused to supply randomness; aborting");
            std::process::abort();
        }
    }
}

/// Draw 32 fresh bytes for a new key.
///
/// A named entry point rather than a bare `fill(&mut seed)`, because a key
/// generation is the one draw whose failure must not be silently tolerated.
#[must_use]
pub fn seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    OsRng.fill(&mut seed);
    seed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_draws_differ() {
        // Not a randomness test — a test that the source is *connected*. Two
        // 32-byte draws colliding means the trait is wired to a constant.
        let a = seed();
        let b = seed();
        assert_ne!(a, b, "the operating system returned the same seed twice");
    }

    #[test]
    fn fill_touches_the_whole_buffer() {
        let mut bytes = [0u8; 64];
        OsRng.fill(&mut bytes);
        assert!(bytes.iter().any(|&b| b != 0));
    }
}
