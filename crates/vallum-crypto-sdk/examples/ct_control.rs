// SPDX-License-Identifier: Apache-2.0

//! The positive control for the constant-time harness.
//!
//! A timing harness that never reports a leak proves nothing: it may be too
//! noisy, the classes may not differ, or the optimizer may have removed the
//! work. This benchmark is *deliberately* variable-time — an early-return byte
//! comparison — and must report a leak. If it does not, no result from
//! `ct_ntru` or `ct_aead` is trusted, and `scripts/ct.sh` fails.
//!
//! `black_box` on the index is load-bearing: without it LLVM is entitled to
//! turn the loop into a `memcmp` or a vector compare, and the control would
//! stop controlling for the thing it exists to control for.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::hint::black_box;

use dudect_bencher::rand::RngExt;
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};

const LEN: usize = 64;

#[inline(never)]
fn leaky_eq(a: &[u8; LEN], b: &[u8; LEN]) -> bool {
    for i in 0..LEN {
        if a[black_box(i)] != b[black_box(i)] {
            return false;
        }
    }
    true
}

fn rand_bytes(rng: &mut BenchRng) -> [u8; LEN] {
    let mut out = [0u8; LEN];
    rng.fill(&mut out[..]);
    out
}

fn control(runner: &mut CtRunner, rng: &mut BenchRng) {
    // 20 000 pairs is enough for dudect to separate a real early-exit branch;
    // more samples only lengthen the run.
    let mut inputs = Vec::with_capacity(20_000);
    let mut classes = Vec::with_capacity(20_000);

    for _ in 0..20_000 {
        let a = rand_bytes(rng);
        if rng.random::<bool>() {
            // Left: equal, so the loop runs to the end.
            inputs.push((a, a));
            classes.push(Class::Left);
        } else {
            // Right: differs early, so the loop returns almost immediately.
            let mut b = a;
            b[6] ^= 0x01;
            inputs.push((a, b));
            classes.push(Class::Right);
        }
    }

    for (class, (a, b)) in classes.into_iter().zip(inputs) {
        runner.run_one(class, || {
            black_box(leaky_eq(&a, &b));
        });
    }
}

ctbench_main!(control);
