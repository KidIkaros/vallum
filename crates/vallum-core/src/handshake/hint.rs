// SPDX-License-Identifier: Apache-2.0

//! The sealed peer hint carried in `InitHello`.
//!
//! One actor: resolving a responder to a configured peer before the peer is
//! authenticated. The hint is confidential, not authenticated — see
//! [`peer_hint`] and [`hint_crypt`].

use vallum_crypto::{frame, CryptoSuite, KemPublicKey, SharedSecret};

use crate::error::HandshakeError;
use crate::keys::NONCE_SIZE;

// ── peer hint (P6) ───────────────────────────────────────────────────

/// Length of the peer hint, in bytes.
///
/// Eight bytes is a birthday bound of 2^32 peers and a negligible false-match
/// rate for any real deployment, while adding only 44 bytes to `InitHello`. A
/// hint is never *trusted* — the transport resolves it to a configured peer and
/// [`responder_accept`] checks the two agree — so a collision costs one wasted
/// attempt, not a wrong session.
pub const PEER_HINT_SIZE: usize = 8;

/// Hash domain for the hint value.
const PEER_HINT_DOMAIN: &[u8] = b"vallum/peer-hint/v1";
/// Salt for the key that seals the hint.
const PEER_HINT_SALT: &[u8] = b"vallum/peer-hint/seal/v1";
/// Label for the key that seals the hint.
const PEER_HINT_KEY_INFO: &[u8] = b"vallum/peer-hint/key/v1";

/// The peer hint for a static KEM public key.
///
/// A short fingerprint of the *key*, not of a name: the responder derives it
/// from each peer's configured public key, so the hint needs no extra
/// configuration and no registry. It fingerprints a public value, which is
/// exactly why it is sealed rather than sent as a bare truncation — an
/// unsealed hint would let a passive observer confirm which configured peer is
/// connecting, and even recover the key by brute force over a small peer set.
#[must_use]
pub fn peer_hint(suite: &dyn CryptoSuite, public: &KemPublicKey) -> [u8; PEER_HINT_SIZE] {
    let digest = suite.hash(
        PEER_HINT_DOMAIN,
        &frame(&[&suite.suite_id().to_be_bytes(), public.as_bytes()]),
    );
    let mut hint = [0u8; PEER_HINT_SIZE];
    hint.copy_from_slice(&digest[..PEER_HINT_SIZE]);
    hint
}

/// Derive the key and nonce that seal a peer hint from op A's shared secrets.
///
/// Both endpoints can compute this, and — the entire point — both can do so
/// before the peer is identified: the initiator from the encapsulation it just
/// made, the responder from the decapsulation it just did with its own static
/// secret.
///
/// The hint is **confidential, not authenticated**. Anyone who knows the
/// responder's public key can encapsulate op A and so derive this key; the seal
/// stops a passive observer from reading *who is talking* and nothing more. What
/// authenticates a peer is op C plus the confirmations, not this.
///
/// Op A's randomness is MEX-bound and per-handshake, so the key is unique and the
/// nonce need not be on the wire.
pub(super) fn hint_crypt(
    suite: &dyn CryptoSuite,
    legs: &[SharedSecret],
) -> Result<([u8; 32], [u8; NONCE_SIZE]), HandshakeError> {
    let parts: Vec<&[u8]> = legs.iter().map(|leg| &leg.as_bytes()[..]).collect();
    let mut out = [0u8; 32 + NONCE_SIZE];
    suite
        .kdf(PEER_HINT_SALT, &frame(&parts), PEER_HINT_KEY_INFO, &mut out)
        .map_err(HandshakeError::Kdf)?;

    let mut key = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&out[32..]);
    Ok((key, nonce))
}

