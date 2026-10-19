// SPDX-License-Identifier: Apache-2.0

//! Adapter-level checks for the hybrid signature path.
//!
//! The generic contract (`vallum-crypto-contract`) sweeps every byte of a
//! signature and requires the verdict to flip. This file adds the part only the
//! adapter can know: the *layout*. The SDK's wire format is
//! `[u32 BE falcon_len][falcon][64-byte ed25519]`, so each half can be broken on
//! its own — which is the concrete meaning of "both must verify" for the shipped
//! suite.

#![allow(clippy::expect_used)]

use vallum_crypto::{CryptoSuite, SignPublicKey};
use vallum_crypto_sdk::SdkSuite;

const SEED: [u8; 32] = [0x5Au8; 32];
const MSG: &[u8] = b"vallum/identity/resp/v1";

fn falcon_len(sig: &[u8]) -> usize {
    u32::from_be_bytes([sig[0], sig[1], sig[2], sig[3]]) as usize
}

#[test]
fn both_halves_must_verify() {
    let suite = SdkSuite::tri_hybrid();
    let (pk, sk) = suite.sign_keygen(&SEED).expect("sign_keygen");
    let sig = suite.sign(&sk, MSG).expect("sign");

    assert!(
        suite.verify(&pk, MSG, &sig),
        "valid hybrid signature rejected"
    );

    // The format is `[falcon_len][falcon][ed25519]`; check it is what we think.
    let flen = falcon_len(&sig);
    assert!(
        flen > 0 && 4 + flen + 64 == sig.len(),
        "unexpected wire layout"
    );

    // Break the Falcon half alone.
    let mut falcon_broken = sig.clone();
    falcon_broken[4 + flen / 2] ^= 0x80;
    assert!(
        !suite.verify(&pk, MSG, &falcon_broken),
        "a signature with a broken Falcon component was accepted"
    );

    // Break the Ed25519 half alone.
    let mut ed_broken = sig.clone();
    let last = ed_broken.len() - 1;
    ed_broken[last] ^= 0x80;
    assert!(
        !suite.verify(&pk, MSG, &ed_broken),
        "a signature with a broken Ed25519 component was accepted"
    );

    // Break the length prefix: decoding must fail, not panic or truncate.
    let mut len_broken = sig.clone();
    len_broken[0] ^= 0x01;
    assert!(!suite.verify(&pk, MSG, &len_broken));

    // A valid Falcon half with the *wrong* Ed25519 message binding still fails.
    assert!(!suite.verify(&pk, b"other", &sig));

    // The public key is Ed25519 (32 B) followed by the Falcon key.
    let mut wrong_pk = pk.as_bytes().to_vec();
    wrong_pk[0] ^= 1;
    assert!(!suite.verify(&SignPublicKey::new(wrong_pk), MSG, &sig));
}

#[test]
fn the_same_seed_yields_the_same_identity_on_every_suite() {
    // The signing identity is the peer's *name*, not a property of the KEM legs,
    // so every suite in this adapter derives the same hybrid signing key from a
    // seed. (The KEM halves differ; see the contract tests.)
    let a = SdkSuite::tri_hybrid().sign_keygen(&SEED).expect("tri");
    let b = SdkSuite::x25519_sntrup761()
        .sign_keygen(&SEED)
        .expect("weaker suite");
    assert_eq!(a.0.as_bytes(), b.0.as_bytes());
}
