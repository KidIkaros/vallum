// SPDX-License-Identifier: Apache-2.0

//! Where randomness enters the transport.
//!
//! The same rule as [`vallum_core`]: the crate holds no generator, so a test can
//! replay a session byte for byte and the transport cannot quietly grow a
//! dependency on a global RNG. The device asks for bytes; the caller decides
//! where they come from.
//!
//! The traffic is small and infrequent — one 32-byte seed per handshake
//! attempt, one nonce per cookie reply, one `u64` per shaping event, one seed per
//! cookie-secret rotation — so an implementation is free to be conservative. It
//! only has to be unpredictable, which is exactly what a caller can supply and
//! this crate cannot verify.

/// A source of unpredictable bytes.
///
/// Implementations must not be predictable to an observer and must not repeat
/// across calls. A deterministic implementation is acceptable **only** in tests,
/// where reproducibility is the point.
pub trait Randomness {
    /// Fill `out` with random bytes.
    fn fill(&mut self, out: &mut [u8]);

    /// One uniformly random `u64`.
    ///
    /// A default built on [`Randomness::fill`], because a uniform byte string is
    /// a uniform integer and a separate method would invite an implementation
    /// that is uniform-looking but biased.
    fn draw_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill(&mut bytes);
        u64::from_le_bytes(bytes)
    }
}

impl<R: Randomness + ?Sized> Randomness for &mut R {
    fn fill(&mut self, out: &mut [u8]) {
        (**self).fill(out);
    }
}

impl<R: Randomness + ?Sized> Randomness for Box<R> {
    fn fill(&mut self, out: &mut [u8]) {
        (**self).fill(out);
    }
}
