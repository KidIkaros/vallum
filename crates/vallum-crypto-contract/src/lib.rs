// SPDX-License-Identifier: Apache-2.0

//! # vallum-crypto-contract
//!
//! The suite-agnostic contract for Vallum's cryptographic boundary.
//!
//! [`run_contract`] exercises every operation a [`CryptoSuite`] must provide and
//! panics if any invariant is violated. It is defined **only** in terms of the
//! trait — this crate does not depend on any provider — so it can be run
//! unchanged against a new adapter (including the author's future from-scratch
//! cryptography). A provider swap that breaks the contract fails CI loudly.
//!
//! What is checked:
//!
//! 1. **Sizes** — reported sizes are self-consistent, and produced keys and
//!    ciphertexts match them.
//! 2. **KEM keygen** — deterministic from a seed, and static/ephemeral roles are
//!    domain-separated.
//! 3. **KEM round-trip** — encaps then decaps recovers every leg's secret.
//! 4. **Tamper rejection** — a modified ciphertext never yields the original
//!    secret.
//! 5. **Combiner** — deterministic, transcript-binding, and rejects empty input.
//! 6. **Transcript** — binds the suite id and the message framing.
//! 7. **AEAD** — seal/open round-trip, and rejection of wrong key, nonce, AD, and
//!    a forged tag (the committing property).
//! 8. **Signatures** — verify accepts a good signature and rejects a wrong
//!    message, a tampered signature, and a wrong key.

// The contract panics on violation by design — its callers are tests.
#![allow(clippy::expect_used)]

use vallum_crypto::{
    derive_kem_key, transcript_hash, CryptoSuite, Encapsulation, KemPublicKey, KemRole,
    KemSecretKey, LegKind, SharedSecret, WireSizes, KEM_ENCAPS_RANDOMNESS,
};

/// Assert that a suite provides the leg kinds Vallum's combiner expects.
///
/// The default suite must be the tri-hybrid, in the canonical order.
pub fn assert_default_legs<S: CryptoSuite + ?Sized>(suite: &S) {
    let legs = suite.leg_kinds();
    assert_eq!(
        legs,
        &[LegKind::X25519, LegKind::NtruPrime761, LegKind::MlKem768],
        "default suite leg set/order drifted"
    );
}

/// Run the full boundary contract against `suite`. Panics on any violation.
pub fn run_contract<S: CryptoSuite + ?Sized>(suite: &S) {
    check_sizes(suite);
    check_kem_keygen(suite);
    let (_pk, sk, enc, dec) = check_kem_roundtrip(suite);
    check_kem_tamper(suite, &sk, &enc);
    check_combiner(suite, &dec);
    check_transcript(suite);
    check_aead(suite);
    check_signatures(suite);
}

fn check_sizes<S: CryptoSuite + ?Sized>(suite: &S) {
    let sizes: WireSizes = suite.sizes();
    let legs = suite.leg_kinds();

    assert_eq!(
        sizes.leg_count,
        legs.len(),
        "leg_count vs leg_kinds mismatch"
    );
    assert!(sizes.leg_count >= 2, "a hybrid suite must have >= 2 legs");
    assert_eq!(sizes.shared_secret, 32, "shared-secret size");
    assert_eq!(sizes.hash, 32, "hash size");
    assert_eq!(sizes.aead_key, 32, "AEAD key size");
    assert_eq!(sizes.aead_nonce, 24, "AEAD nonce size");
    assert_eq!(sizes.aead_tag, 32, "AEAD tag size");
    assert!(sizes.kem_pk > 0, "kem_pk");
    assert!(sizes.kem_sk > 0, "kem_sk");
    assert!(sizes.kem_ct > 0, "kem_ct");
}

fn check_kem_keygen<S: CryptoSuite + ?Sized>(suite: &S) {
    let sizes = suite.sizes();
    let seed = [0x5Au8; 32];

    let (pk_a, sk_a) = suite
        .kem_keygen(&seed, KemRole::Static)
        .expect("kem_keygen");
    let (pk_b, _) = suite
        .kem_keygen(&seed, KemRole::Static)
        .expect("kem_keygen");
    assert_eq!(
        pk_a.as_bytes(),
        pk_b.as_bytes(),
        "keygen is not deterministic from a seed"
    );

    assert_eq!(pk_a.len(), sizes.kem_pk, "public-key size");
    assert_eq!(sk_a.len(), sizes.kem_sk, "secret-key size");

    // Static and ephemeral derivations must not collide.
    let (pk_e, _) = suite
        .kem_keygen(&seed, KemRole::Ephemeral)
        .expect("kem_keygen");
    assert_ne!(
        pk_a.as_bytes(),
        pk_e.as_bytes(),
        "static/ephemeral role separation missing"
    );
}

fn check_kem_roundtrip<S: CryptoSuite + ?Sized>(
    suite: &S,
) -> (KemPublicKey, KemSecretKey, Encapsulation, Vec<SharedSecret>) {
    let sizes = suite.sizes();
    let legs = suite.leg_kinds();
    let (pk, sk) = suite
        .kem_keygen(&[0x5Au8; 32], KemRole::Static)
        .expect("kem_keygen");

    let randomness: [u8; KEM_ENCAPS_RANDOMNESS] = [0x3Cu8; KEM_ENCAPS_RANDOMNESS];

    // Encapsulation is a pure function of (pk, randomness).
    let enc = suite.kem_encaps(&pk, &randomness).expect("kem_encaps");
    let enc_again = suite.kem_encaps(&pk, &randomness).expect("kem_encaps");
    assert_eq!(
        enc.ciphertext.as_bytes(),
        enc_again.ciphertext.as_bytes(),
        "encaps is not deterministic"
    );
    for (a, b) in enc
        .shared_secrets
        .iter()
        .zip(enc_again.shared_secrets.iter())
    {
        assert_eq!(
            a.as_bytes(),
            b.as_bytes(),
            "encaps secrets not deterministic"
        );
    }

    // Distinct randomness must change the ciphertext.
    let other = suite
        .kem_encaps(&pk, &[0x3Du8; KEM_ENCAPS_RANDOMNESS])
        .expect("kem_encaps");
    assert_ne!(
        enc.ciphertext.as_bytes(),
        other.ciphertext.as_bytes(),
        "encapsulation ignores the supplied randomness"
    );

    assert_eq!(enc.leg_count(), legs.len(), "encaps leg count");
    assert_eq!(enc.ciphertext.len(), sizes.kem_ct, "ciphertext size");

    // The wire form round-trips: decapsulating the raw bytes recovers every leg.
    let dec = suite
        .kem_decaps(&sk, enc.ciphertext.as_bytes())
        .expect("kem_decaps");
    assert_eq!(dec.len(), legs.len(), "decaps leg count");
    for (i, (a, b)) in enc.shared_secrets.iter().zip(dec.iter()).enumerate() {
        assert_eq!(a.as_bytes(), b.as_bytes(), "leg {i} secret mismatch");
    }

    (pk, sk, enc, dec)
}

fn check_kem_tamper<S: CryptoSuite + ?Sized>(suite: &S, sk: &KemSecretKey, enc: &Encapsulation) {
    let bytes = enc.ciphertext.as_bytes();
    let mut tampered = bytes.to_vec();
    tampered[0] ^= 1;
    let dec = suite
        .kem_decaps(sk, &tampered)
        .expect("kem_decaps of tampered ciphertext");
    assert!(
        dec.iter()
            .zip(enc.shared_secrets.iter())
            .any(|(a, b)| a.as_bytes() != b.as_bytes()),
        "tampering the ciphertext did not change any recovered secret"
    );

    // A wrong-length ciphertext must be rejected, not silently truncated.
    assert!(
        suite.kem_decaps(sk, &bytes[..bytes.len() - 1]).is_err(),
        "short ciphertext accepted"
    );
}

fn check_combiner<S: CryptoSuite + ?Sized>(suite: &S, legs: &[vallum_crypto::SharedSecret]) {
    let mut k1 = [0u8; 32];
    derive_kem_key(suite, b"TR", legs, &mut k1).expect("derive_kem_key");
    assert_ne!(k1, [0u8; 32], "combiner produced all-zero key");

    let mut k2 = [0u8; 32];
    derive_kem_key(suite, b"TR", legs, &mut k2).expect("derive_kem_key");
    assert_eq!(k1, k2, "combiner is not deterministic");

    let mut k3 = [0u8; 32];
    derive_kem_key(suite, b"other-transcript", legs, &mut k3).expect("derive_kem_key");
    assert_ne!(k1, k3, "combiner ignores the transcript");

    assert!(
        derive_kem_key(suite, b"TR", &[], &mut k1).is_err(),
        "combiner accepted zero legs"
    );
}

fn check_transcript<S: CryptoSuite + ?Sized>(suite: &S) {
    let id = suite.suite_id();
    let t1 = transcript_hash(suite, id, &[b"InitHello", b"RespHello"]);
    assert_ne!(t1, [0u8; 32], "transcript hash is zero");

    let t2 = transcript_hash(suite, id.wrapping_add(1), &[b"InitHello", b"RespHello"]);
    assert_ne!(t1, t2, "transcript ignores the suite id");

    let t3 = transcript_hash(suite, id, &[b"InitHello", b"RespHello!"]);
    assert_ne!(t1, t3, "transcript ignores message contents");

    // Length framing: ["InitHello","RespHello"] must differ from the concatenation.
    let t4 = transcript_hash(suite, id, &[b"InitHelloRespHello"]);
    assert_ne!(t1, t4, "transcript framing is ambiguous");
}

fn check_aead<S: CryptoSuite + ?Sized>(suite: &S) {
    let sizes = suite.sizes();
    let key = [7u8; 32];
    let nonce = [9u8; 24];
    let ad = b"vallum/ad";

    let ct = suite
        .aead_seal(&key, &nonce, ad, b"hello world")
        .expect("seal");
    assert_eq!(ct.len(), 11 + sizes.aead_tag, "AEAD ciphertext+tag size");

    let pt = suite.aead_open(&key, &nonce, ad, &ct).expect("open");
    assert_eq!(pt, b"hello world", "AEAD round-trip");

    assert!(
        suite.aead_open(&key, &nonce, b"vallum/AD", &ct).is_err(),
        "wrong associated data accepted"
    );
    assert!(
        suite.aead_open(&[8u8; 32], &nonce, ad, &ct).is_err(),
        "wrong key accepted"
    );
    let mut wrong_nonce = nonce;
    wrong_nonce[0] ^= 1;
    assert!(
        suite.aead_open(&key, &wrong_nonce, ad, &ct).is_err(),
        "wrong nonce accepted"
    );

    let mut forged = ct.clone();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    assert!(
        suite.aead_open(&key, &nonce, ad, &forged).is_err(),
        "forged tag accepted"
    );
}

fn check_signatures<S: CryptoSuite + ?Sized>(suite: &S) {
    let sizes = suite.sizes();
    let (pk, sk) = suite.sign_keygen(&[0x11u8; 32]).expect("sign_keygen");
    assert!(
        pk.len() > 32 && pk.len() <= sizes.sign_pk_max,
        "hybrid public-key size out of range"
    );

    let msg = b"vallum/transcript";
    let sig = suite.sign(&sk, msg).expect("sign");
    assert!(sig.len() <= sizes.sign_sig_max, "signature size");
    assert!(suite.verify(&pk, msg, &sig), "valid signature rejected");

    assert!(
        !suite.verify(&pk, b"vallum/transcripT", &sig),
        "wrong message accepted"
    );

    let mut tampered = sig.clone();
    tampered[0] ^= 1;
    assert!(
        !suite.verify(&pk, msg, &tampered),
        "tampered signature accepted"
    );

    let mut wrong_pk = pk.as_bytes().to_vec();
    wrong_pk[0] ^= 1;
    let wrong_pk = vallum_crypto::SignPublicKey::new(wrong_pk);
    assert!(
        !suite.verify(&wrong_pk, msg, &sig),
        "wrong public key accepted"
    );
}
