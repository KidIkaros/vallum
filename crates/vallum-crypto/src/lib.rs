// SPDX-License-Identifier: Apache-2.0

//! # vallum-crypto
//!
//! The cryptographic **boundary** for Vallum, a hybrid post-quantum layer-3
//! tunnel.
//!
//! This crate is deliberately dependency-free and contains no cryptographic
//! implementations. It defines the single interface — [`CryptoSuite`] — through
//! which Vallum reaches *any* crypto provider, plus the protocol-level
//! constructions ([`derive_kem_key`], [`transcript_hash`]) that must not depend
//! on a particular provider.
//!
//! A provider lives behind an adapter. Vallum ships one for
//! `origin-crypto-sdk` (`vallum-crypto-sdk`); the author's future from-scratch
//! cryptography becomes a second adapter implementing the same trait, validated
//! by the same contract tests (`vallum-crypto-contract`).
//!
//! ## Layout
//!
//! - [`suite`] — the [`CryptoSuite`] trait, byte-oriented newtypes, and wire
//!   sizes.
//! - [`kem`] — the protocol combiner and transcript hash.
//! - [`error`] — Vallum-owned error types.
//!
//! ## Invariants
//!
//! 1. No provider type crosses the boundary; only bytes and Vallum newtypes do.
//! 2. The hybrid-leg list is a *Vallum* constant; a suite supplies operations
//!    and sizes, and the protocol asserts the leg set.
//! 3. The suite id is folded into the transcript, so downgrade is detectable.
//! 4. Byte-exact contract tests at the boundary freeze behaviour; a provider
//!    swap that changes a byte fails CI.

#![forbid(unsafe_code)]

pub mod error;
pub mod kem;
pub mod suite;

pub use error::{AeadError, KdfError, KemError, SigError, SuiteError};
pub use kem::{
    derive_combined_key, derive_kem_key, frame, transcript_hash, KEM_INFO, TRANSCRIPT_INFO,
};
pub use suite::{
    Ciphertext, CryptoSuite, Encapsulation, KemPublicKey, KemRole, KemSecretKey, LegKind,
    SharedSecret, SignPublicKey, SignSecretKey, WireSizes, KEM_ENCAPS_RANDOMNESS,
};

/// Best-effort memory scrub the optimizer is unlikely to elide.
///
/// Safe (no `unsafe`): zeroes the bytes and then forces the compiler to treat
/// the buffer as observable via [`core::hint::black_box`].
pub(crate) fn scrub(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        *byte = 0;
    }
    core::hint::black_box(buf);
}
