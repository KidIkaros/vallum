#![no_main]

//! The epoch demultiplexer a rekey creates, on arbitrary bytes.
//!
//! `Session::open` is what receives every data packet, and a rekey is the only
//! thing that makes it hold *two* epochs at once: the current one, and the
//! superseded one retained receive-only so packets still in flight keep opening.
//! That makes this the state a live tunnel spends real time in, and it is fed by
//! the network — the first thing an unauthenticated peer reaches after a
//! handshake that an attacker may have replayed. The invariants:
//!
//! * arbitrary bytes never panic, and never open;
//! * a packet sealed under *either* retained epoch still opens, so the fuzz
//!   corpus cannot pass by rejecting everything;
//! * once the retention window closes, the superseded epoch's straggler is
//!   refused rather than silently accepted — that erasure is the post-compromise
//!   guarantee (`docs/proof/ratchet-pcs.md`).
//!
//! The fixture is a key schedule, not a handshake: two sessions derive the same
//! epochs from fixed keys, so the target exercises the epoch axis at thousands of
//! inputs a second instead of paying a KEM per input.

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use vallum_core::session::{Session, RETAIN_PREVIOUS_EPOCH_MS};
use vallum_core::{Role, SessionKeys};
use vallum_crypto::SharedSecret;
use vallum_crypto_sdk::SdkSuite;

/// One IPv4-ish packet, so the sealed shape matches what the data plane carries.
const PLAINTEXT: &[u8] = &[
    0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 10, 7, 0, 2, 10, 7, 0,
    1, 0x30, 0x39, 0x30, 0x39, 0x00, 0x08, 0x00, 0x00,
];

struct Fixture {
    suite: SdkSuite,
    /// Our epoch-n keys: what the initiator derives from handshake n.
    mine: [SessionKeys; 2],
    /// The peer's view of the same epochs, with the indices swapped: a sender
    /// stamps the recipient's index, so this is what makes a sealed packet
    /// addressed to us.
    theirs: [SessionKeys; 2],
}

fn keys(tag: u8, epoch: Option<u64>) -> SessionKeys {
    SessionKeys {
        transcript: [tag; 32],
        key: SharedSecret::new([tag.wrapping_add(0x40); 32]),
        confirm_initiator: SharedSecret::new([tag; 32]),
        confirm_responder: SharedSecret::new([tag.wrapping_add(1); 32]),
        own_index: u32::from(tag) + 0x1000,
        peer_index: u32::from(tag) + 0x2000,
        epoch,
    }
}

fn swapped(mut keys: SessionKeys) -> SessionKeys {
    core::mem::swap(&mut keys.own_index, &mut keys.peer_index);
    keys
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let suite = SdkSuite::from_id(0x0002).expect("the ML-KEM suite is compiled in");
        // The first handshake is the pre-negotiation epoch, the rekey an agreed
        // one: both branches of `advance`'s epoch choice are exercised.
        let first = keys(0x11, None);
        let second = keys(0x22, Some(1));
        Fixture {
            suite,
            mine: [first.clone(), second.clone()],
            theirs: [swapped(first), swapped(second)],
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let Fixture {
        suite,
        mine,
        theirs,
    } = fixture();

    let mut us = Session::establish(suite, &mine[0], Role::Initiator).expect("epoch 0");
    let mut them = Session::establish(suite, &theirs[0], Role::Responder).expect("peer epoch 0");

    // A packet under the first epoch, sealed before the rekey.
    let straggler = them.seal(suite, PLAINTEXT).expect("seal at epoch 0");

    us.advance(suite, &mine[1], Role::Initiator, 1_000)
        .expect("advance");
    them.advance(suite, &theirs[1], Role::Responder, 1_000)
        .expect("peer advance");
    assert_eq!(us.epoch(), 1);
    assert_eq!(us.previous_epoch(), Some(0), "the superseded epoch is retained");

    // The whole point of retention: a packet sealed under the old epoch still
    // opens, and it is the only epoch that can answer it.
    assert_eq!(
        us.open(suite, &straggler).expect("the retained epoch opens"),
        PLAINTEXT
    );

    // And the current epoch works, so a session that answered only stragglers
    // would still fail here.
    let current = them.seal(suite, PLAINTEXT).expect("seal at epoch 1");
    assert_eq!(
        us.open(suite, &current).expect("the current epoch opens"),
        PLAINTEXT
    );

    // Arbitrary bytes: never a panic, and never accepted. The session has both
    // epochs live, so this is the demultiplexer's full state.
    assert!(us.open(suite, data).is_err(), "arbitrary bytes opened");
    assert!(them.open(suite, data).is_err(), "arbitrary bytes opened");

    // Erasure is bounded: past the window the straggler must be refused. This is
    // the property the retention exists to serve, so it is asserted rather than
    // assumed.
    assert!(us.expire_previous(1_000 + RETAIN_PREVIOUS_EPOCH_MS));
    assert!(us.open(suite, &straggler).is_err(), "an erased epoch still opened");
});
