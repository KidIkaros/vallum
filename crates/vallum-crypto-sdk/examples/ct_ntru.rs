// SPDX-License-Identifier: Apache-2.0

//! Constant-time check for the custom sntrup761 decapsulation.
//!
//! This is the one primitive in the suite that Vallum's author wrote from
//! scratch, and the one whose failure path is a decryption-failure oracle if it
//! branches. The SDK's own source says the CCA fallback is arithmetic (`mask =
//! all_match - 1`, `r ^ (mask & (r ^ rho))`) and that no branch may depend on
//! the outcome; this harness tests that claim from the outside.
//!
//! Two classes, each a plausible leak site:
//!
//! 1. **A malformed ciphertext** — the implicit-rejection path. If the
//!    re-encryption comparison or the fallback select branched on the result,
//!    this is where it would show.
//! 2. **A ciphertext for a different key** — a decapsulation that cannot
//!    succeed. It reaches the same fallback through a different input shape.
//!
//! Read the result as DudeCT states it: a small `max t` is absence of evidence
//! under *these* classes, not proof of constant-time behaviour.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::hint::black_box;

use dudect_bencher::rand::RngExt;
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use origin_crypto_sdk::drbg::ChaCha20Rng;
use origin_crypto_sdk::pqc::ntru_prime::{Ciphertext, NtruPrime, PrivateKey};

/// How many timed samples each class contributes. DudeCT crops the runtime
/// distributions, so this is comfortably more than it needs while keeping the
/// input set small.
const SAMPLES: usize = 2_000;

/// A key pair and one valid ciphertext for it.
fn fixture(seed: u8) -> (Ciphertext, PrivateKey) {
    let (pk, sk) = NtruPrime::generate_keypair_from_seed(&[seed; 32]);
    let mut rng = ChaCha20Rng::from_seed([seed.wrapping_add(0x80); 32]);
    let (ct, _) = NtruPrime::encapsulate(&pk, &mut rng);
    (ct, sk)
}

/// A ciphertext that will fail the re-encryption check: one bit flipped.
fn bitflip(ct: &Ciphertext, rng: &mut BenchRng) -> Ciphertext {
    let mut broken = *ct;
    let index = rng.random_range(0..broken.len());
    broken[index] ^= 1 << rng.random_range(0..8);
    broken
}

fn ntru_decaps_bitflip(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (ct, sk) = fixture(0x11);

    let mut inputs = Vec::with_capacity(SAMPLES);
    let mut classes = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        if rng.random::<bool>() {
            inputs.push(ct);
            classes.push(Class::Left);
        } else {
            inputs.push(bitflip(&ct, rng));
            classes.push(Class::Right);
        }
    }

    for (class, ct) in classes.into_iter().zip(inputs) {
        runner.run_one(class, || {
            let _ = black_box(NtruPrime::decapsulate(&ct, &sk));
        });
    }
}

fn ntru_decaps_wrong_key(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (ct, sk) = fixture(0x22);
    let (foreign_ct, _) = fixture(0x33);

    let mut inputs = Vec::with_capacity(SAMPLES);
    let mut classes = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        if rng.random::<bool>() {
            inputs.push(ct);
            classes.push(Class::Left);
        } else {
            inputs.push(foreign_ct);
            classes.push(Class::Right);
        }
    }

    for (class, ct) in classes.into_iter().zip(inputs) {
        runner.run_one(class, || {
            let _ = black_box(NtruPrime::decapsulate(&ct, &sk));
        });
    }
}

ctbench_main!(ntru_decaps_bitflip, ntru_decaps_wrong_key);
