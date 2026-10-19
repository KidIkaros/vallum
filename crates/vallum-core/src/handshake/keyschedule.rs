// SPDX-License-Identifier: Apache-2.0

//! The key schedule and its transcript stages.
//!
//! This is the "how the keys are made" half of the handshake, split from the
//! message steps in [`super`] so each file serves one actor: the schedule is a
//! pure function of the transcript and the three shared secrets, and nothing in
//! it parses or builds a message.

use vallum_crypto::{
    derive_kem_key, frame, transcript_hash, CryptoSuite, KemSecretKey, SharedSecret, SignPublicKey,
    KEM_ENCAPS_RANDOMNESS,
};

use crate::error::HandshakeError;
use crate::identity::verify_transcript;

// ── domain separation ────────────────────────────────────────────────

/// Salt for deriving per-handshake sub-seeds from the caller's seed.
const HANDSHAKE_SALT: &[u8] = b"vallum/handshake/v1";
/// Fresh seed for the initiator's ephemeral KEM key pair.
pub(super) const EPH_SEED_INFO: &[u8] = b"vallum/handshake/eph/v1";
/// Fresh salt for op A's MEX-bound randomness.
pub(super) const A_FRESH_INFO: &[u8] = b"vallum/handshake/a-fresh/v1";
/// Fresh seed for op B's plain encapsulation randomness.
pub(super) const B_FRESH_INFO: &[u8] = b"vallum/handshake/b-fresh/v1";
/// Fresh salt for op C's MEX-bound randomness.
pub(super) const C_FRESH_INFO: &[u8] = b"vallum/handshake/c-fresh/v1";
/// MEX: bind a static secret into encapsulation randomness.
const MEX_INFO: &[u8] = b"vallum/mex/v1";
/// Transcript stage 1 — the initiator's `InitHello` fields.
const TR_INIT_DOMAIN: &[u8] = b"vallum/tr/init/v1";
/// Transcript stage 2 — the responder's `RespHello` core fields.
const TR_RESP_DOMAIN: &[u8] = b"vallum/tr/resp/v1";
/// Transcript stage 3 — binds the responder's confirmation value.
const TR_CONF_DOMAIN: &[u8] = b"vallum/tr/conf/v1";
/// Hash domain for the UKS-mitigation pre-shared key.
const PSK_DOMAIN: &[u8] = b"vallum/psk/v1";
/// Mix the psk into the handshake root.
const PSK_MIX_INFO: &[u8] = b"vallum/psk-mix/v1";
/// Initiator key-confirmation value.
const CONFIRM_I_INFO: &[u8] = b"vallum/confirm/init/v1";
/// Responder key-confirmation value.
const CONFIRM_R_INFO: &[u8] = b"vallum/confirm/resp/v1";
/// Hash domain for comparing confirmation values.
const CONFIRM_CMP_DOMAIN: &[u8] = b"vallum/confirm-cmp/v1";
/// Mix a configured per-peer PSK into the schedule (G1).
const CONFIG_PSK_INFO: &[u8] = b"vallum/config-psk/v1";

// ── helpers ──────────────────────────────────────────────────────────

/// Derive a per-handshake 32-byte sub-seed under its own domain label.
pub(super) fn derive_seed(
    suite: &dyn CryptoSuite,
    seed: &[u8; 32],
    info: &[u8],
) -> Result<[u8; 32], HandshakeError> {
    let mut out = [0u8; 32];
    suite
        .kdf(HANDSHAKE_SALT, seed, info, &mut out)
        .map_err(HandshakeError::Kdf)?;
    Ok(out)
}

pub(super) fn mex_randomness(
    suite: &dyn CryptoSuite,
    static_secret: &KemSecretKey,
    fresh: &[u8; 32],
) -> Result<[u8; KEM_ENCAPS_RANDOMNESS], HandshakeError> {
    let mut out = [0u8; KEM_ENCAPS_RANDOMNESS];
    suite
        .kdf(fresh, static_secret.as_bytes(), MEX_INFO, &mut out)
        .map_err(HandshakeError::Kdf)?;
    Ok(out)
}

/// Transcript stage 1 — binds the initiator's `InitHello` fields.
pub(super) fn transcript_init(
    suite: &dyn CryptoSuite,
    suite_id: u16,
    sender_index: u32,
    ephemeral_pk: &[u8],
    static_ct: &[u8],
    timestamp: &[u8],
) -> [u8; 32] {
    transcript_hash(
        suite,
        suite_id,
        &[
            TR_INIT_DOMAIN,
            &sender_index.to_be_bytes(),
            ephemeral_pk,
            static_ct,
            timestamp,
        ],
    )
}

/// Transcript stage 2 — binds the responder's `RespHello` core fields onto
/// stage 1.
///
/// This is the value the key schedule is salted with, and what the responder's
/// confirmation commits to.
pub(super) fn transcript_resp(
    suite: &dyn CryptoSuite,
    suite_id: u16,
    transcript_init: &[u8; 32],
    sender_index: u32,
    ephemeral_ct: &[u8],
    static_ct: &[u8],
) -> [u8; 32] {
    transcript_hash(
        suite,
        suite_id,
        &[
            TR_RESP_DOMAIN,
            &transcript_init[..],
            &sender_index.to_be_bytes(),
            ephemeral_ct,
            static_ct,
        ],
    )
}

/// Transcript stage 3 — binds the responder's confirmation onto stage 2.
///
/// PQ-WireGuard's running hash chain has the same shape (`H10 = H(H9 ‖ zero)`):
/// the responder's confirmation commits to the transcript *before* it, and the
/// initiator's confirmation commits to the transcript that includes it.
pub(super) fn transcript_conf(
    suite: &dyn CryptoSuite,
    suite_id: u16,
    transcript_resp: &[u8; 32],
    confirm_responder: &[u8],
) -> [u8; 32] {
    transcript_hash(
        suite,
        suite_id,
        &[TR_CONF_DOMAIN, &transcript_resp[..], confirm_responder],
    )
}

/// The key-schedule half: `KEY` plus the responder's confirmation value.
///
/// `legs` must be in the suite's combiner order on both sides: `A ‖ B ‖ C`. The
/// responder recovers A by decapsulation rather than encapsulation, but the order
/// is identical, which is what makes the two derivations agree.
pub(super) fn schedule(
    suite: &dyn CryptoSuite,
    transcript_resp: &[u8; 32],
    legs: &[SharedSecret],
    initiator_static: &[u8],
    responder_static: &[u8],
    preshared_key: Option<&SharedSecret>,
) -> Result<(SharedSecret, SharedSecret), HandshakeError> {
    let mut root = [0u8; 32];
    derive_kem_key(suite, transcript_resp, legs, &mut root).map_err(HandshakeError::Kdf)?;

    // UKS mitigation: both static public keys are *public*, so this psk is not a
    // secret on its own. It is mixed as HKDF `ikm` with the root as salt, i.e. as
    // PRK = HMAC(key = root, msg = psk), which can only add entropy — an attacker
    // who does not know both keys cannot reproduce it, so an unknown-key-share
    // attack diverges the keys and becomes *detectable*.
    let psk = suite.hash(PSK_DOMAIN, &frame(&[initiator_static, responder_static]));

    let mut key = [0u8; 32];
    suite
        .kdf(&root, &psk, PSK_MIX_INFO, &mut key)
        .map_err(HandshakeError::Kdf)?;
    let key = SharedSecret::new(key);

    // A configured per-peer PSK (G1), if any. Mixed after the UKS psk, so the
    // default `None` path is byte-identical to every existing vector. It is an
    // extra secret both ends already hold; a mismatch diverges the confirmation
    // and the handshake fails, which is the only observable effect.
    let key = match preshared_key {
        Some(psk) => {
            let mut mixed = [0u8; 32];
            suite
                .kdf(key.as_bytes(), psk.as_bytes(), CONFIG_PSK_INFO, &mut mixed)
                .map_err(HandshakeError::Kdf)?;
            SharedSecret::new(mixed)
        }
        None => key,
    };

    // The responder's confirmation: only a party that derived `key` can produce
    // it, and deriving `key` requires decapsulating op A.
    let mut confirm_responder = [0u8; 32];
    suite
        .kdf(
            key.as_bytes(),
            transcript_resp,
            CONFIRM_R_INFO,
            &mut confirm_responder,
        )
        .map_err(HandshakeError::Kdf)?;

    Ok((key, SharedSecret::new(confirm_responder)))
}

/// The initiator's confirmation — proves the initiator derived `key`, which
/// requires ops B *and* C.
pub(super) fn confirm_initiator(
    suite: &dyn CryptoSuite,
    key: &SharedSecret,
    transcript_conf: &[u8; 32],
) -> Result<SharedSecret, HandshakeError> {
    let mut out = [0u8; 32];
    suite
        .kdf(key.as_bytes(), transcript_conf, CONFIRM_I_INFO, &mut out)
        .map_err(HandshakeError::Kdf)?;
    Ok(SharedSecret::new(out))
}

/// Verify a fixed-size value against ours.
///
/// Comparing digests (rather than a bespoke constant-time loop) is sound here:
/// both sides hash a value the protocol already binds, and equality of the
/// digests is exactly equality of the inputs. A timing signal on a hash
/// comparison reveals nothing about the value itself.
pub(super) fn verify_value(suite: &dyn CryptoSuite, expected: &[u8], got: &[u8]) -> bool {
    suite.hash(CONFIRM_CMP_DOMAIN, got) == suite.hash(CONFIRM_CMP_DOMAIN, expected)
}

/// Verify a peer's confirmation value against ours.
pub(super) fn verify_confirmation(
    suite: &dyn CryptoSuite,
    expected: &SharedSecret,
    got: &[u8],
) -> bool {
    verify_value(suite, expected.as_bytes(), got)
}

/// The fail-closed identity-signature rule.
///
/// | peer signing key | `IDENTITY_SIG` | outcome |
/// |---|---|---|
/// | `Some(pk)` | present | must verify |
/// | `Some(_)` | absent | [`HandshakeError::IdentityMissing`] |
/// | `None` | present | [`HandshakeError::IdentityUnexpected`] |
/// | `None` | absent | accept |
///
/// The requirement comes from local configuration, never from the wire, so
/// stripping the field cannot downgrade a session that expects one.
pub(super) fn check_identity_signature(
    suite: &dyn CryptoSuite,
    suite_id: u16,
    domain: &[u8],
    transcript: &[u8; 32],
    expected: Option<&SignPublicKey>,
    signature: Option<&[u8]>,
) -> Result<(), HandshakeError> {
    match (expected, signature) {
        (Some(pk), Some(sig)) => {
            if verify_transcript(suite, pk, domain, suite_id, transcript, sig) {
                Ok(())
            } else {
                Err(HandshakeError::IdentityInvalid)
            }
        }
        (Some(_), None) => Err(HandshakeError::IdentityMissing),
        (None, Some(_)) => Err(HandshakeError::IdentityUnexpected),
        (None, None) => Ok(()),
    }
}
