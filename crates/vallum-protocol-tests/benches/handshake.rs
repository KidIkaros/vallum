// SPDX-License-Identifier: Apache-2.0

//! The handshake, measured per stage and per suite.
//!
//! These are correctness-first numbers: the gate for every phase was "does it
//! verify", and this is the first place the cost is written down. The shapes to
//! watch are the KEM operations — `initiator_hello` and `responder_accept` do
//! encapsulations, `initiator_process_resp` does two decapsulations — and the
//! signed variant, where Falcon dominates.
//!
//! The seeds are fixed, so a rerun on the same machine is comparable, and the
//! frozen vectors in `tests/interop.rs` describe exactly these messages.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use vallum_core::{
    initiator_hello, initiator_process_resp, responder_process_conf, responder_process_init,
    PeerIdentity, StaticIdentity,
};
use vallum_crypto_sdk::SdkSuite;

const TIMESTAMP: [u8; 12] = [
    0x40, 0x00, 0x00, 0x00, 0x67, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78,
];

const I_STATIC: [u8; 32] = [0x11; 32];
const R_STATIC: [u8; 32] = [0x22; 32];
const I_SEED: [u8; 32] = [0x33; 32];
const R_SEED: [u8; 32] = [0x44; 32];

fn identities(suite: &SdkSuite, signing: bool) -> (StaticIdentity, StaticIdentity) {
    if signing {
        (
            StaticIdentity::generate_with_signing(suite, &I_STATIC).expect("initiator"),
            StaticIdentity::generate_with_signing(suite, &R_STATIC).expect("responder"),
        )
    } else {
        (
            StaticIdentity::generate(suite, &I_STATIC).expect("initiator"),
            StaticIdentity::generate(suite, &R_STATIC).expect("responder"),
        )
    }
}

fn bench_suite(c: &mut Criterion, suite: SdkSuite, label: &str, signing: bool) {
    let (initiator, responder) = identities(&suite, signing);
    let i_peer = PeerIdentity::from_identity(&initiator);
    let r_peer = PeerIdentity::from_identity(&responder);

    let (init_hello, _) =
        initiator_hello(&suite, &initiator, &r_peer, 1, TIMESTAMP, &I_SEED).expect("hello");
    let (resp_hello, _) =
        responder_process_init(&suite, &responder, &i_peer, &init_hello, 2, &R_SEED)
            .expect("response");

    let mut group = c.benchmark_group(format!("handshake/{label}"));

    group.bench_function("initiator_hello", |b| {
        b.iter(|| {
            black_box(
                initiator_hello(&suite, &initiator, &r_peer, 1, TIMESTAMP, &I_SEED).expect("hello"),
            );
        });
    });

    // `responder_identify` is the decapsulation-only first half, and
    // `responder_accept` the encapsulation half, so the two are separable.
    group.bench_function("responder_identify", |b| {
        b.iter(|| {
            black_box(responder_process_init_identify(
                &suite,
                &responder,
                &init_hello,
            ))
        });
    });

    let info = responder_process_init_identify(&suite, &responder, &init_hello).expect("info");
    group.bench_function("responder_accept", |b| {
        b.iter(|| {
            black_box(
                vallum_core::responder_accept(&suite, &responder, &i_peer, &info, 2, &R_SEED)
                    .expect("accept"),
            );
        });
    });

    group.bench_function("initiator_process_resp", |b| {
        b.iter_batched(
            || {
                initiator_hello(&suite, &initiator, &r_peer, 1, TIMESTAMP, &I_SEED)
                    .expect("hello")
                    .1
            },
            |state| {
                black_box(
                    initiator_process_resp(&suite, state, &initiator, &resp_hello)
                        .expect("process"),
                );
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("full_exchange", |b| {
        b.iter(|| {
            let (ih, state) =
                initiator_hello(&suite, &initiator, &r_peer, 1, TIMESTAMP, &I_SEED).expect("hello");
            let (rh, r_state) =
                responder_process_init(&suite, &responder, &i_peer, &ih, 2, &R_SEED)
                    .expect("response");
            let (ic, _i_keys) =
                initiator_process_resp(&suite, state, &initiator, &rh).expect("process");
            black_box(responder_process_conf(&suite, r_state, &ic).expect("confirm"));
        });
    });

    group.finish();
}

/// `responder_identify` without the `responder_accept` half.
fn responder_process_init_identify(
    suite: &SdkSuite,
    responder: &StaticIdentity,
    init_hello: &[u8],
) -> Result<vallum_core::InitHelloInfo, vallum_core::HandshakeError> {
    vallum_core::responder_identify(suite, responder, init_hello)
}

fn benches(c: &mut Criterion) {
    for (id, label) in [
        (0x0001u16, "x25519-sntrup761"),
        (0x0002, "x25519-mlkem768"),
        (0x0003, "tri-hybrid"),
    ] {
        let Ok(suite) = SdkSuite::from_id(id) else {
            continue; // not compiled in
        };
        bench_suite(c, suite, label, false);
    }

    // The signed tri-hybrid: Falcon-1024 is the cost that matters here, and it
    // is why the P3 artefact caches keygen.
    if let Ok(suite) = SdkSuite::from_id(0x0003) {
        bench_suite(c, suite, "tri-hybrid-signed", true);
    }
}

criterion_group! {
    name = handshake;
    config = Criterion::default().sample_size(20);
    targets = benches
}
criterion_main!(handshake);
