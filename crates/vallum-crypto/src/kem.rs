// SPDX-License-Identifier: Apache-2.0

//! Vallum's protocol-level hybrid combiner and transcript hash.
//!
//! # Why this lives in Vallum, not the SDK
//!
//! The [SDK](https://docs.rs/origin-crypto-sdk) also ships a hybrid-KEM
//! combiner (`origin_crypto_sdk::kem::hybrid::combine_shared_secrets`), but that
//! is a *library convenience* for SDK consumers (e.g. Stoa). Vallum's combiner
//! is a **protocol rule**: it must run on the abstract [`CryptoSuite`] KDF so it
//! survives having the SDK swapped out.
//!
//! The two share the same underlying idea — HKDF-SHA3-256 over the concatenated
//! leg secrets — but are deliberately *not* byte-identical: the SDK binds a
//! caller-supplied context plus the raw ciphertexts into the salt, whereas
//! Vallum binds the handshake transcript (which already contains the
//! ciphertexts) and uses its own domain label. Neither depends on the other.
//!
//! # Construction
//!
//! ```text
//! TR = hash("vallum/transcript/v1", suite_id ‖ InitHello ‖ RespHello)
//! K  = KDF(salt = TR, ikm = ss_1 ‖ ss_2 ‖ … ‖ ss_n, info = "vallum/kem/v1", out)
//! ```
//!
//! Because `TR` hashes the exact handshake bytes, it transitively binds every
//! ciphertext already — no separate ciphertext binding is needed at the
//! combiner. Ever input is length-framed, so concatenation is unambiguous.
//!
//! The combiner lemma is: if at least one leg is IND-CCA, `K` is unpredictable
//! to a polynomial adversary unless the KDF fails as a dual-PRF with
//! adversarially-influenced IKM. See the plan's §7 obligation 1.

use crate::error::KdfError;
use crate::suite::{CryptoSuite, SharedSecret};

/// HKDF `info` label for the KEM key schedule.
pub const KEM_INFO: &[u8] = b"vallum/kem/v1";

/// Hash domain for the handshake transcript.
pub const TRANSCRIPT_INFO: &[u8] = b"vallum/transcript/v1";

/// Concatenate `parts` with big-endian `u32` length prefixes.
///
/// Length framing makes the encoding unambiguous: `["ab", "c"]` and
/// `["a", "bc"]` produce different outputs.
pub fn frame(parts: &[&[u8]]) -> Vec<u8> {
    let total: usize = parts.iter().map(|p| 4 + p.len()).sum();
    let mut out = Vec::with_capacity(total);
    for part in parts {
        let len = u32::try_from(part.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// Combine the per-leg shared secrets into a session key, binding `transcript`.
///
/// `legs` must be in the suite's combiner order.
///
/// # Errors
///
/// [`KdfError`] if `legs` is empty or the suite's KDF fails.
pub fn derive_kem_key<S: CryptoSuite + ?Sized>(
    suite: &S,
    transcript: &[u8],
    legs: &[SharedSecret],
    out: &mut [u8],
) -> Result<(), KdfError> {
    if legs.is_empty() {
        return Err(KdfError::new("no hybrid-combiner legs"));
    }
    if out.is_empty() {
        return Err(KdfError::new("empty output buffer"));
    }

    let mut ikm = Vec::with_capacity(32 * legs.len());
    for ss in legs {
        ikm.extend_from_slice(ss.as_bytes());
    }

    let result = suite.kdf(transcript, &ikm, KEM_INFO, out);

    crate::scrub(&mut ikm);
    result
}

/// Hash the handshake transcript: `suite_id ‖ messages`.
///
/// `suite_id` is hashed first so that a downgrade to a different suite changes
/// every derived key — a forced-suite attack is *detected*, not merely
/// not-offered.
pub fn transcript_hash<S: CryptoSuite + ?Sized>(
    suite: &S,
    suite_id: u16,
    messages: &[&[u8]],
) -> [u8; 32] {
    let id = suite_id.to_be_bytes();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(messages.len() + 1);
    parts.push(&id);
    parts.extend_from_slice(messages);

    let framed = frame(&parts);
    suite.hash(TRANSCRIPT_INFO, &framed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_is_unambiguous() {
        assert_ne!(frame(&[b"ab", b"c"]), frame(&[b"a", b"bc"]));
        assert_ne!(frame(&[b"", b"a"]), frame(&[b"a", b""]));
    }

    #[test]
    fn frame_is_stable() {
        // Frozen encoding — u32 big-endian length prefixes.
        assert_eq!(frame(&[b"hi"]), vec![0, 0, 0, 2, b'h', b'i']);
    }
}
