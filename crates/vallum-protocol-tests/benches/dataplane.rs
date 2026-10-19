// SPDX-License-Identifier: Apache-2.0

//! The data plane: seal and open at the sizes a tunnel actually carries.
//!
//! Three payload sizes — a small packet, a typical one, and the largest an
//! inner MTU of 1380 allows — plus the padded seal that P5's shaping machines
//! use. The keys come from a real handshake, so the schedule is the one the
//! protocol uses and not a shortcut.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use vallum_core::data::{establish, Receiver, Sender};
use vallum_core::keys::Role;
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

/// The largest inner payload a 1380-byte MTU can carry in one data message.
const MAX_PAYLOAD: usize = 1380;

fn sessions(suite: &SdkSuite) -> (Sender, Receiver) {
    let initiator = StaticIdentity::generate(suite, &I_STATIC).expect("initiator");
    let responder = StaticIdentity::generate(suite, &R_STATIC).expect("responder");
    let i_peer = PeerIdentity::from_identity(&initiator);
    let r_peer = PeerIdentity::from_identity(&responder);

    let (init_hello, state) =
        initiator_hello(suite, &initiator, &r_peer, 1, TIMESTAMP, &I_SEED).expect("hello");
    let (resp_hello, r_state) =
        responder_process_init(suite, &responder, &i_peer, &init_hello, 2, &R_SEED)
            .expect("response");
    let (init_conf, i_keys) =
        initiator_process_resp(suite, state, &initiator, &resp_hello).expect("process");
    let r_keys = responder_process_conf(suite, r_state, &init_conf).expect("confirm");

    let (sender, _) = establish(suite, &i_keys, Role::Initiator).expect("initiator data keys");
    let (_, receiver) = establish(suite, &r_keys, Role::Responder).expect("responder data keys");
    (sender, receiver)
}

fn benches(c: &mut Criterion) {
    let Ok(suite) = SdkSuite::from_id(0x0003) else {
        return;
    };
    let (mut sender, mut receiver) = sessions(&suite);

    for size in [64usize, 512, MAX_PAYLOAD] {
        let payload = vec![0x5Au8; size];

        let mut group = c.benchmark_group(format!("seal/{size}"));
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function("seal", |b| {
            b.iter(|| black_box(sender.seal(&suite, black_box(&payload)).expect("seal")));
        });
        group.finish();

        let mut group = c.benchmark_group(format!("open/{size}"));
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function("open", |b| {
            b.iter_batched(
                || sender.seal(&suite, &payload).expect("seal"),
                |packet| black_box(receiver.open(&suite, &packet).expect("open")),
                BatchSize::SmallInput,
            );
        });
        group.finish();
    }

    // The padded seal P5 uses to close the length channel: every packet becomes
    // the same on-wire size, which costs the padding.
    let payload = vec![0x5Au8; 512];
    let mut group = c.benchmark_group("seal_padded/1400");
    group.throughput(Throughput::Bytes(1_400));
    group.bench_function("seal_padded", |b| {
        b.iter(|| black_box(sender.seal_padded(&suite, &payload, 1_400).expect("seal")));
    });
    group.finish();
}

criterion_group! {
    name = dataplane;
    config = Criterion::default().sample_size(50);
    targets = benches
}
criterion_main!(dataplane);
