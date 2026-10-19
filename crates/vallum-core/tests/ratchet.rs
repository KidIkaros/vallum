// SPDX-License-Identifier: Apache-2.0

//! P4 gate tests: the epoch axis, and erasure-based post-compromise security.
//!
//! The gate is *"post-compromise security after an epoch advance, bounded and
//! erasure-based"*. Because Vallum's epoch is keyed by a **fresh handshake**
//! rather than by a symmetric chain, the PCS claim is a statement about key
//! independence, and the tests state it that way:
//!
//! 1. **Advance agrees.** Both ends advance to the same epoch from their own
//!    halves of one new handshake, and traffic flows in both directions.
//! 2. **No epoch from the old root opens new traffic.** An attacker holding
//!    epoch *n*'s root and transcript, with the correct recipient index and the
//!    correct epoch number, opens nothing from epoch *n+1*. This is the PCS
//!    claim, tested against the strongest attacker the model allows.
//! 3. **The epoch is bound into the key.** Reusing the *same* handshake for two
//!    epochs still yields traffic neither epoch can read.
//! 4. **Erasure is bounded and complete.** Stragglers open inside the retention
//!    window, are still replay-checked, and are rejected once the window closes
//!    — the point at which the superseded key is erased.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use vallum_core::{
    establish_epoch, initiator_hello, initiator_process_resp, responder_process_conf,
    responder_process_init, DataError, PeerIdentity, Role, Session, SessionKeys, StaticIdentity,
    RETAIN_PREVIOUS_EPOCH_MS,
};
use vallum_crypto_sdk::SdkSuite;

const TS: [u8; 12] = [
    0x40, 0x00, 0x00, 0x00, 0x67, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78,
];
const I_IDX: u32 = 0x1111_1111;
const R_IDX: u32 = 0x2222_2222;
const I_IDX2: u32 = 0x1111_3333;
const R_IDX2: u32 = 0x2222_4444;

/// Both ends' keys from one handshake.
struct Pair {
    init: SessionKeys,
    resp: SessionKeys,
}

/// One full exchange with caller-chosen indices and randomness.
fn handshake(
    suite: &SdkSuite,
    initiator: &StaticIdentity,
    responder: &StaticIdentity,
    i_idx: u32,
    r_idx: u32,
    i_seed: [u8; 32],
    r_seed: [u8; 32],
) -> Pair {
    let peer_r = PeerIdentity::from_identity(responder);
    let peer_i = PeerIdentity::from_identity(initiator);

    let (init_hello, i_state) =
        initiator_hello(suite, initiator, &peer_r, i_idx, TS, &i_seed).expect("InitHello");
    let (resp_hello, r_state) =
        responder_process_init(suite, responder, &peer_i, &init_hello, r_idx, &r_seed)
            .expect("RespHello");
    let (init_conf, init) =
        initiator_process_resp(suite, i_state, initiator, &resp_hello).expect("InitConf");
    let resp = responder_process_conf(suite, r_state, &init_conf).expect("verify InitConf");

    assert_eq!(init.transcript, resp.transcript);
    Pair { init, resp }
}

/// A session pair at epoch 0, plus the keys that produced it.
struct Established {
    initiator: Session,
    responder: Session,
    keys: Pair,
}

fn establish(
    suite: &SdkSuite,
    initiator: &StaticIdentity,
    responder: &StaticIdentity,
) -> Established {
    let keys = handshake(
        suite, initiator, responder, I_IDX, R_IDX, [0xA1; 32], [0xB1; 32],
    );
    let i = Session::establish(suite, &keys.init, Role::Initiator).expect("initiator session");
    let r = Session::establish(suite, &keys.resp, Role::Responder).expect("responder session");
    Established {
        initiator: i,
        responder: r,
        keys,
    }
}

/// A second, independent handshake between the same two peers.
fn rekey(suite: &SdkSuite, initiator: &StaticIdentity, responder: &StaticIdentity) -> Pair {
    handshake(
        suite, initiator, responder, I_IDX2, R_IDX2, [0xA2; 32], [0xB2; 32],
    )
}

// ── 1. advance agrees ────────────────────────────────────────────────

#[test]
fn both_ends_advance_to_the_same_epoch_and_talk() {
    let suite = SdkSuite::tri_hybrid();
    let i_id = StaticIdentity::generate(&suite, &[0x11; 32]).expect("identity");
    let r_id = StaticIdentity::generate(&suite, &[0x22; 32]).expect("identity");

    let mut pair = establish(&suite, &i_id, &r_id);
    assert_eq!(pair.initiator.epoch(), 0);
    assert_eq!(pair.responder.epoch(), 0);

    // Epoch 0 works in both directions.
    let ct = pair.initiator.seal(&suite, b"epoch zero").expect("seal");
    assert_eq!(
        pair.responder.open(&suite, &ct).expect("open"),
        b"epoch zero"
    );

    // Advance both ends from one new handshake.
    let fresh = rekey(&suite, &i_id, &r_id);
    assert_eq!(
        pair.initiator
            .advance(&suite, &fresh.init, Role::Initiator, 1_000)
            .expect("advance"),
        1
    );
    assert_eq!(
        pair.responder
            .advance(&suite, &fresh.resp, Role::Responder, 1_000)
            .expect("advance"),
        1
    );

    assert_eq!(pair.initiator.epoch(), 1);
    assert_eq!(pair.responder.epoch(), 1);
    // The new handshake's indices replace the old ones.
    assert_eq!(pair.initiator.own_index(), I_IDX2);
    assert_eq!(pair.initiator.peer_index(), R_IDX2);

    let ct = pair.initiator.seal(&suite, b"epoch one").expect("seal");
    assert_eq!(
        pair.responder.open(&suite, &ct).expect("open"),
        b"epoch one"
    );
    let ct = pair.responder.seal(&suite, b"back").expect("seal");
    assert_eq!(pair.initiator.open(&suite, &ct).expect("open"), b"back");
}

#[test]
fn many_epochs_stay_monotonic_and_separated() {
    let suite = SdkSuite::tri_hybrid();
    let i_id = StaticIdentity::generate(&suite, &[0x11; 32]).expect("identity");
    let r_id = StaticIdentity::generate(&suite, &[0x22; 32]).expect("identity");

    let mut pair = establish(&suite, &i_id, &r_id);
    for round in 1u8..=6 {
        let fresh = handshake(
            &suite,
            &i_id,
            &r_id,
            I_IDX + u32::from(round),
            R_IDX + u32::from(round),
            [0xA0 | round; 32],
            [0xB0 | round; 32],
        );
        assert_eq!(
            pair.initiator
                .advance(&suite, &fresh.init, Role::Initiator, u64::from(round))
                .expect("advance"),
            u64::from(round)
        );
        assert_eq!(
            pair.responder
                .advance(&suite, &fresh.resp, Role::Responder, u64::from(round))
                .expect("advance"),
            u64::from(round)
        );

        let ct = pair.initiator.seal(&suite, &[round; 8]).expect("seal");
        assert_eq!(pair.responder.open(&suite, &ct).expect("open"), &[round; 8]);
        // Retention never compounds: only the epoch just left is held.
        assert_eq!(pair.responder.previous_epoch(), Some(u64::from(round) - 1));
    }
}

// ── 2. PCS: no epoch derived from the old root opens new traffic ─────

#[test]
fn no_epoch_from_the_old_root_opens_next_epoch_traffic() {
    let suite = SdkSuite::tri_hybrid();
    let i_id = StaticIdentity::generate(&suite, &[0x11; 32]).expect("identity");
    let r_id = StaticIdentity::generate(&suite, &[0x22; 32]).expect("identity");

    let mut pair = establish(&suite, &i_id, &r_id);
    let stolen = pair.keys.resp.clone(); // the attacker's copy of epoch 0

    // Both ends rekey to epoch 1 from a fresh handshake.
    let fresh = rekey(&suite, &i_id, &r_id);
    pair.initiator
        .advance(&suite, &fresh.init, Role::Initiator, 0)
        .expect("advance");
    pair.responder
        .advance(&suite, &fresh.resp, Role::Responder, 0)
        .expect("advance");

    let secret = b"traffic after compromise";
    let ct = pair.initiator.seal(&suite, secret).expect("seal");
    assert_eq!(
        pair.responder.open(&suite, &ct).expect("legitimate peer"),
        secret
    );

    // The strongest attacker the model allows: it holds epoch 0's root and
    // transcript, it knows the *new* recipient index (it can read packet
    // headers), and it guesses the epoch number. None of it opens the packet —
    // the key came from a fresh hybrid exchange, not from anything it holds.
    let new_rx_index = pair.responder.own_index();
    let new_tx_index = pair.responder.peer_index();
    for epoch in 0u64..4 {
        let (_, mut receiver) = establish_epoch(
            &suite,
            &stolen.key,
            &stolen.transcript,
            epoch,
            Role::Responder,
            new_rx_index,
            new_tx_index,
        )
        .expect("attacker schedule");
        assert!(
            matches!(receiver.open(&suite, &ct), Err(DataError::Aead(_))),
            "epoch {epoch} derived from the compromised root opened new traffic"
        );
    }
}

#[test]
fn a_compromised_epoch_does_not_yield_the_next_epoch_keys() {
    let suite = SdkSuite::tri_hybrid();
    let i_id = StaticIdentity::generate(&suite, &[0x11; 32]).expect("identity");
    let r_id = StaticIdentity::generate(&suite, &[0x22; 32]).expect("identity");

    let pair = establish(&suite, &i_id, &r_id);

    // The ratchet root is *not* a function of the previous root: a new handshake
    // with fresh ephemeral randomness produces an unrelated KEY, and the epoch
    // folds in on top of that.
    let fresh = rekey(&suite, &i_id, &r_id);
    assert_ne!(
        pair.keys.init.key.as_bytes(),
        fresh.init.key.as_bytes(),
        "a fresh handshake must not reproduce the session root"
    );
    assert_ne!(pair.keys.init.transcript, fresh.init.transcript);
}

// ── 3. the epoch is bound into the key ───────────────────────────────

#[test]
fn the_same_handshake_keyed_at_two_epochs_does_not_cross_decrypt() {
    let suite = SdkSuite::tri_hybrid();
    let i_id = StaticIdentity::generate(&suite, &[0x11; 32]).expect("identity");
    let r_id = StaticIdentity::generate(&suite, &[0x22; 32]).expect("identity");

    let keys = handshake(&suite, &i_id, &r_id, I_IDX, R_IDX, [0xA1; 32], [0xB1; 32]);
    let mut epoch0 = Session::establish(&suite, &keys.init, Role::Initiator).expect("epoch 0");
    let mut peer = Session::establish(&suite, &keys.resp, Role::Responder).expect("peer");

    // Advance using the *same* SessionKeys: only the epoch number differs.
    epoch0
        .advance(&suite, &keys.init, Role::Initiator, 0)
        .expect("advance");
    let ct = epoch0.seal(&suite, b"epoch one only").expect("seal");

    // The peer is still at epoch 0 with the same handshake root, and cannot open
    // it: the epoch counter is folded into the key, so a repeated epoch value
    // would be the only way to forge this.
    assert!(matches!(peer.open(&suite, &ct), Err(DataError::Aead(_))));

    // Advancing the peer to the same epoch makes it readable.
    peer.advance(&suite, &keys.resp, Role::Responder, 0)
        .expect("advance");
    assert_eq!(peer.open(&suite, &ct).expect("open"), b"epoch one only");
}

// ── 4. erasure is bounded and complete ───────────────────────────────

#[test]
fn stragglers_open_inside_the_window_and_are_erased_after_it() {
    let suite = SdkSuite::tri_hybrid();
    let i_id = StaticIdentity::generate(&suite, &[0x11; 32]).expect("identity");
    let r_id = StaticIdentity::generate(&suite, &[0x22; 32]).expect("identity");

    let mut pair = establish(&suite, &i_id, &r_id);

    // A packet sealed under epoch 0, still in flight when the rekey happens.
    let straggler = pair.initiator.seal(&suite, b"late").expect("seal");

    let fresh = rekey(&suite, &i_id, &r_id);
    let rekey_at = 5_000;
    pair.initiator
        .advance(&suite, &fresh.init, Role::Initiator, rekey_at)
        .expect("advance");
    pair.responder
        .advance(&suite, &fresh.resp, Role::Responder, rekey_at)
        .expect("advance");

    assert_eq!(pair.responder.previous_epoch(), Some(0));
    // Inside the window: the straggler still opens, through the retained epoch.
    assert_eq!(
        pair.responder.open(&suite, &straggler).expect("straggler"),
        b"late"
    );
    // And it is still replay-checked there.
    assert!(matches!(
        pair.responder.open(&suite, &straggler),
        Err(DataError::Replay { .. })
    ));

    // Not yet due: the retention window has not closed.
    assert!(!pair
        .responder
        .expire_previous(rekey_at + RETAIN_PREVIOUS_EPOCH_MS - 1));
    assert!(pair.responder.retains_previous());

    // Due: erased, and the straggler now fails — the superseded key is gone.
    assert!(pair
        .responder
        .expire_previous(rekey_at + RETAIN_PREVIOUS_EPOCH_MS));
    assert!(!pair.responder.retains_previous());
    assert_eq!(pair.responder.previous_epoch(), None);
    assert!(pair.responder.open(&suite, &straggler).is_err());

    // Current-epoch traffic is unaffected by the erasure.
    let ct = pair.initiator.seal(&suite, b"current").expect("seal");
    assert_eq!(pair.responder.open(&suite, &ct).expect("open"), b"current");
}

#[test]
fn retiring_the_previous_epoch_is_immediate() {
    let suite = SdkSuite::tri_hybrid();
    let i_id = StaticIdentity::generate(&suite, &[0x11; 32]).expect("identity");
    let r_id = StaticIdentity::generate(&suite, &[0x22; 32]).expect("identity");

    let mut pair = establish(&suite, &i_id, &r_id);
    let straggler = pair.initiator.seal(&suite, b"late").expect("seal");

    let fresh = rekey(&suite, &i_id, &r_id);
    pair.responder
        .advance(&suite, &fresh.resp, Role::Responder, 0)
        .expect("advance");

    assert!(pair.responder.retire_previous());
    assert!(!pair.responder.retire_previous());
    assert!(pair.responder.open(&suite, &straggler).is_err());
}
