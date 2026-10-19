// SPDX-License-Identifier: Apache-2.0

//! Constant-time check for `ChaCha20Blake3` open.
//!
//! The first cut of this harness compared a valid ciphertext against one with a
//! flipped tag and reported `max t ≈ +275`. That is **not** a tag-comparison
//! leak: the implementation computes the MAC, compares in constant time, and
//! only then runs ChaCha over the plaintext, so the success path does strictly
//! more work than the failure path. The outcome (accepted vs rejected) is
//! public — the peer answers or it does not — so that difference is benign.
//!
//! A useful harness must hold the post-verification work constant and vary only
//! the thing under test. Three benchmarks, with three different jobs:
//!
//! 1. `aead_tag_compare` — **the real test.** Both messages are invalid; the
//!    only difference is *where* the tag first differs (first byte vs last).
//!    An early-exit comparison leaks here; a constant-time one does not.
//! 2. `aead_failure_causes` — both invalid, one from a wrong key and one from a
//!    flipped ciphertext body. The failure path should not care which.
//! 3. `aead_success_vs_failure` — the *informational* measurement. It is
//!    expected to differ, for the reason above, and `scripts/ct.sh` does not
//!    treat it as a failure. Recording it keeps the benign difference visible
//!    instead of hiding it behind a better-chosen class.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::hint::black_box;

use dudect_bencher::rand::RngExt;
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use origin_crypto_sdk::chacha20_blake3::ChaCha20Blake3;

/// Plaintext size: large enough that the ChaCha pass on the success path is a
/// visible fraction of the work, which is what makes benchmark 3 informative.
const PT_LEN: usize = 1_024;

/// Samples per class.
const SAMPLES: usize = 5_000;

const AD: &[u8] = b"vallum/ct/aead";

fn fixture(rng: &mut BenchRng) -> ([u8; 32], [u8; 24], Vec<u8>) {
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 24];
    rng.fill(&mut key[..]);
    rng.fill(&mut nonce[..]);
    let mut pt = vec![0u8; PT_LEN];
    rng.fill(pt.as_mut_slice());
    let ct = ChaCha20Blake3::encrypt(&key, &nonce, &pt, AD).expect("seal");
    (key, nonce, ct)
}

fn flip(bytes: &[u8], index: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[index] ^= 1;
    out
}

/// Both invalid; only the position of the first differing tag byte varies.
fn aead_tag_compare(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (key, nonce, ct) = fixture(rng);
    let tag_start = ct.len() - 32;

    let mut inputs = Vec::with_capacity(SAMPLES);
    let mut classes = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        if rng.random::<bool>() {
            // First tag byte differs: an early-exit compare stops at once.
            inputs.push(flip(&ct, tag_start));
            classes.push(Class::Left);
        } else {
            // Last tag byte differs: an early-exit compare runs to the end.
            inputs.push(flip(&ct, ct.len() - 1));
            classes.push(Class::Right);
        }
    }

    for (class, ct) in classes.into_iter().zip(inputs) {
        runner.run_one(class, || {
            let _ = black_box(ChaCha20Blake3::decrypt(&key, &nonce, &ct, AD));
        });
    }
}

/// Both invalid; the *cause* of the failure differs.
fn aead_failure_causes(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (key, nonce, ct) = fixture(rng);
    let mut wrong = key;
    wrong[0] ^= 1;
    let body_flipped = flip(&ct, 0);

    let mut inputs = Vec::with_capacity(SAMPLES);
    let mut classes = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        if rng.random::<bool>() {
            inputs.push((wrong, ct.clone()));
            classes.push(Class::Left);
        } else {
            inputs.push((key, body_flipped.clone()));
            classes.push(Class::Right);
        }
    }

    for (class, (key, ct)) in classes.into_iter().zip(inputs) {
        runner.run_one(class, || {
            let _ = black_box(ChaCha20Blake3::decrypt(&key, &nonce, &ct, AD));
        });
    }
}

/// Informational: the expected success-vs-failure difference. Not a gate.
fn aead_success_vs_failure(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (key, nonce, ct) = fixture(rng);
    let broken = flip(&ct, ct.len() - 1);

    let mut inputs = Vec::with_capacity(SAMPLES);
    let mut classes = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        if rng.random::<bool>() {
            inputs.push(ct.clone());
            classes.push(Class::Left);
        } else {
            inputs.push(broken.clone());
            classes.push(Class::Right);
        }
    }

    for (class, ct) in classes.into_iter().zip(inputs) {
        runner.run_one(class, || {
            let _ = black_box(ChaCha20Blake3::decrypt(&key, &nonce, &ct, AD));
        });
    }
}

ctbench_main!(
    aead_tag_compare,
    aead_failure_causes,
    aead_success_vs_failure
);
