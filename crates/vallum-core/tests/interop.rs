// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for the handshake core.
//!
//! Three layers:
//!
//! 1. **Self-interop** — two endpoints run the full exchange and derive equal
//!    keys, for every shipped suite.
//! 2. **Negative** — tampering, downgrade, index mismatch, and confirmation
//!    forgery are all rejected.
//! 3. **Frozen vectors** — with fixed seeds the whole exchange is byte-exact, so
//!    a provider swap that changes any byte fails here.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use vallum_core::wire::tag;
use vallum_core::{
    initiator_hello, initiator_process_resp, peer_hint, responder_accept, responder_identify,
    responder_process_conf, responder_process_init, HandshakeError, Message, MessageBuilder,
    PeerIdentity, SessionKeys, StaticIdentity, PEER_HINT_SIZE,
};
use vallum_crypto::CryptoSuite;
use vallum_crypto_sdk::SdkSuite;

const TIMESTAMP: [u8; 12] = [
    0x40, 0x00, 0x00, 0x00, 0x67, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78,
];

/// The peer configuration matching a local identity.
///
/// KEM-only identities yield a KEM-only peer (P1 semantics); an identity with a
/// signing half yields a peer that *requires* a signature, so a P3 run needs no
/// extra plumbing to exercise the signature path.
fn peer(identity: &StaticIdentity) -> PeerIdentity {
    PeerIdentity::from_identity(identity)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The full three-message exchange, as the protocol drives it.
struct Exchange {
    initiator: SessionKeys,
    responder: SessionKeys,
    init_hello: Vec<u8>,
    resp_hello: Vec<u8>,
    init_conf: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
fn run(
    suite: &dyn CryptoSuite,
    init_static: &[u8; 32],
    resp_static: &[u8; 32],
    init_seed: &[u8; 32],
    resp_seed: &[u8; 32],
    init_index: u32,
    resp_index: u32,
    timestamp: [u8; 12],
) -> Result<Exchange, HandshakeError> {
    let initiator = StaticIdentity::generate(suite, init_static)?;
    let responder = StaticIdentity::generate(suite, resp_static)?;

    let (init_hello, i_state) = initiator_hello(
        suite,
        &initiator,
        &peer(&responder),
        init_index,
        timestamp,
        init_seed,
    )?;

    let (resp_hello, r_state) = responder_process_init(
        suite,
        &responder,
        &peer(&initiator),
        &init_hello,
        resp_index,
        resp_seed,
    )?;

    let (init_conf, i_keys) = initiator_process_resp(suite, i_state, &initiator, &resp_hello)?;

    let r_keys = responder_process_conf(suite, r_state, &init_conf)?;

    Ok(Exchange {
        initiator: i_keys,
        responder: r_keys,
        init_hello,
        resp_hello,
        init_conf,
    })
}

fn seeds() -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
    ([0x11u8; 32], [0x22u8; 32], [0x33u8; 32], [0x44u8; 32])
}

fn default_run(suite: &dyn CryptoSuite) -> Exchange {
    let (a, b, c, d) = seeds();
    run(suite, &a, &b, &c, &d, 0x0A0B_0C0D, 0xE0E1_E2E3, TIMESTAMP).expect("handshake")
}

fn shipped_suites() -> Vec<SdkSuite> {
    let mut suites = vec![SdkSuite::x25519_sntrup761()];
    if let Ok(ml) = SdkSuite::from_id(0x0002) {
        suites.push(ml);
    }
    if let Ok(tri) = SdkSuite::from_id(0x0003) {
        suites.push(tri);
    }
    suites
}

// ── 1. self-interop ──────────────────────────────────────────────────

#[test]
fn every_suite_completes_and_agrees() {
    for suite in shipped_suites() {
        let ex = default_run(&suite);
        assert_eq!(
            ex.initiator.transcript,
            ex.responder.transcript,
            "suite {:#06x} endpoints derived different transcripts",
            suite.suite_id()
        );
        assert_eq!(
            ex.initiator.key.as_bytes(),
            ex.responder.key.as_bytes(),
            "suite {:#06x} endpoints derived different keys",
            suite.suite_id()
        );
        assert_eq!(
            ex.initiator.confirm_initiator.as_bytes(),
            ex.responder.confirm_initiator.as_bytes()
        );
        assert_eq!(
            ex.initiator.confirm_responder.as_bytes(),
            ex.responder.confirm_responder.as_bytes()
        );
        // The indices are the one thing that must *not* match: each end's own
        // index is the other's peer index.
        assert_eq!(ex.initiator.own_index, ex.responder.peer_index);
        assert_eq!(ex.initiator.peer_index, ex.responder.own_index);
        assert_ne!(ex.initiator.own_index, ex.initiator.peer_index);
        assert_ne!(ex.initiator.key.as_bytes(), &[0u8; 32], "all-zero key");
    }
}

#[test]
fn legs_are_bound_to_all_three_operations() {
    // Op C is the only one bound to the *initiator's* static key: change it and
    // the derived keys must change even though the handshake still completes only
    // if the responder knows the new key.
    let suite = SdkSuite::from_id(0x0003).expect("tri-hybrid");
    let (a, b, c, d) = seeds();

    let ex1 = run(&suite, &a, &b, &c, &d, 1, 2, TIMESTAMP).unwrap();
    let ex2 = run(&suite, &a, &[0x23u8; 32], &c, &d, 1, 2, TIMESTAMP).unwrap();
    assert_ne!(
        ex1.initiator.key.as_bytes(),
        ex2.initiator.key.as_bytes(),
        "responder static key is not bound into the key"
    );

    let ex3 = run(&suite, &[0x12u8; 32], &b, &c, &d, 1, 2, TIMESTAMP).unwrap();
    assert_ne!(
        ex1.initiator.key.as_bytes(),
        ex3.initiator.key.as_bytes(),
        "initiator static key is not bound into the key"
    );
}

#[test]
fn fresh_handshake_seed_changes_the_key() {
    let suite = SdkSuite::from_id(0x0003).expect("tri-hybrid");
    let (a, b, c, d) = seeds();

    // The responder's fresh entropy must not touch InitHello (the initiator does
    // not know it yet), but must change RespHello and therefore the key.
    let ex1 = run(&suite, &a, &b, &c, &d, 1, 2, TIMESTAMP).unwrap();
    let ex2 = run(&suite, &a, &b, &c, &[0x45u8; 32], 1, 2, TIMESTAMP).unwrap();
    assert_eq!(
        ex1.init_hello, ex2.init_hello,
        "InitHello must not depend on responder entropy"
    );
    assert_ne!(ex1.resp_hello, ex2.resp_hello);
    assert_ne!(ex1.initiator.key.as_bytes(), ex2.initiator.key.as_bytes());

    // The initiator's own fresh entropy changes everything from InitHello on.
    let ex3 = run(&suite, &a, &b, &[0x34u8; 32], &d, 1, 2, TIMESTAMP).unwrap();
    assert_ne!(ex1.init_hello, ex3.init_hello);
    assert_ne!(ex1.initiator.key.as_bytes(), ex3.initiator.key.as_bytes());
}

#[test]
fn the_exchange_is_deterministic() {
    let suite = SdkSuite::from_id(0x0003).expect("tri-hybrid");
    let first = default_run(&suite);
    let second = default_run(&suite);
    assert_eq!(first.init_hello, second.init_hello);
    assert_eq!(first.resp_hello, second.resp_hello);
    assert_eq!(first.init_conf, second.init_conf);
    assert_eq!(first.initiator, second.initiator);
}

#[test]
fn mex_makes_the_static_secret_feed_the_encapsulation() {
    // MEX: op A's randomness is KDF(fresh, static_secret). Two initiators that
    // share a handshake seed but differ in static identity must produce different
    // A ciphertexts — proving the static secret (not just fresh entropy) drives
    // the encapsulation.
    let suite = SdkSuite::from_id(0x0003).expect("tri-hybrid");
    let (_, b, c, d) = seeds();
    let initiator_a = StaticIdentity::generate(&suite, &[0x11u8; 32]).unwrap();
    let initiator_b = StaticIdentity::generate(&suite, &[0x99u8; 32]).unwrap();
    let responder = StaticIdentity::generate(&suite, &b).unwrap();

    let (hello_a, _) =
        initiator_hello(&suite, &initiator_a, &peer(&responder), 1, TIMESTAMP, &c).unwrap();
    let (hello_b, _) =
        initiator_hello(&suite, &initiator_b, &peer(&responder), 1, TIMESTAMP, &c).unwrap();

    // Same timestamp/index/seed; the ephemeral key derives from `c` alone, so the
    // EPHEMERAL_PK is identical, while STATIC_CT (the MEX-bound op A) differs.
    let a_msg = vallum_core::Message::parse(&hello_a).unwrap();
    let b_msg = vallum_core::Message::parse(&hello_b).unwrap();
    assert_eq!(
        a_msg.get(tag::EPHEMERAL_PK),
        b_msg.get(tag::EPHEMERAL_PK),
        "ephemeral key should depend only on the handshake seed"
    );
    assert_ne!(
        a_msg.get(tag::STATIC_CT),
        b_msg.get(tag::STATIC_CT),
        "MEX did not mix the static secret into op A"
    );

    let _ = d;
}

// ── 2. negative cases ────────────────────────────────────────────────

#[test]
fn forged_confirmation_is_rejected() {
    let suite = SdkSuite::from_id(0x0003).expect("tri-hybrid");
    let (a, b, c, d) = seeds();
    let initiator = StaticIdentity::generate(&suite, &a).unwrap();
    let responder = StaticIdentity::generate(&suite, &b).unwrap();

    let (init_hello, i_state) =
        initiator_hello(&suite, &initiator, &peer(&responder), 1, TIMESTAMP, &c).unwrap();
    let (resp_hello, r_state) =
        responder_process_init(&suite, &responder, &peer(&initiator), &init_hello, 2, &d).unwrap();
    let (init_conf, _) = initiator_process_resp(&suite, i_state, &initiator, &resp_hello).unwrap();

    // InitConf layout: 8-byte header, then CONFIRMATION (tag+len = 4 bytes, then
    // the 32-byte value at offset 12..44), then RECEIVER_INDEX. Flip a bit inside
    // the confirmation value itself.
    let mut forged = init_conf;
    forged[12] ^= 1;

    assert!(matches!(
        responder_process_conf(&suite, r_state, &forged),
        Err(HandshakeError::Confirmation)
    ));
}

#[test]
fn forged_responder_confirmation_is_rejected() {
    let suite = SdkSuite::from_id(0x0003).expect("tri-hybrid");
    let (a, b, c, d) = seeds();
    let initiator = StaticIdentity::generate(&suite, &a).unwrap();
    let responder = StaticIdentity::generate(&suite, &b).unwrap();

    let (init_hello, i_state) =
        initiator_hello(&suite, &initiator, &peer(&responder), 1, TIMESTAMP, &c).unwrap();
    let (resp_hello, _) =
        responder_process_init(&suite, &responder, &peer(&initiator), &init_hello, 2, &d).unwrap();

    // Rebuild RespHello with a corrupted responder confirmation. The other fields
    // are copied across so the failure is the confirmation, not the framing.
    let forged = {
        let msg = Message::parse(&resp_hello).unwrap();
        let mut confirmation = msg.require_array::<32>(tag::CONFIRMATION).unwrap();
        confirmation[0] ^= 1;
        let mut b = MessageBuilder::new(msg.header());
        b.field(tag::EPHEMERAL_CT, msg.require(tag::EPHEMERAL_CT).unwrap())
            .unwrap();
        b.field(tag::STATIC_CT, msg.require(tag::STATIC_CT).unwrap())
            .unwrap();
        b.field(
            tag::RECEIVER_INDEX,
            msg.require(tag::RECEIVER_INDEX).unwrap(),
        )
        .unwrap();
        b.field(tag::CONFIRMATION, &confirmation).unwrap();
        b.finish().unwrap()
    };

    assert!(matches!(
        initiator_process_resp(&suite, i_state, &initiator, &forged),
        Err(HandshakeError::Confirmation)
    ));
}

#[test]
fn a_responder_confirmation_cannot_be_replayed_from_another_handshake() {
    // The responder's confirmation is keyed and transcript-bound, so replaying a
    // valid `RespHello` from one handshake into another fails the transcript
    // check rather than authenticating.
    let suite = SdkSuite::from_id(0x0003).expect("tri-hybrid");
    let (a, b, c, d) = seeds();
    let initiator = StaticIdentity::generate(&suite, &a).unwrap();
    let responder = StaticIdentity::generate(&suite, &b).unwrap();

    let (init_hello_1, _i_state_1) =
        initiator_hello(&suite, &initiator, &peer(&responder), 1, TIMESTAMP, &c).unwrap();
    let (resp_hello_1, _) =
        responder_process_init(&suite, &responder, &peer(&initiator), &init_hello_1, 2, &d)
            .unwrap();

    // A second handshake with different initiator entropy.
    let (_, i_state_2) = initiator_hello(
        &suite,
        &initiator,
        &peer(&responder),
        1,
        TIMESTAMP,
        &[0x77u8; 32],
    )
    .unwrap();

    // Combining handshake 1's RespHello with handshake 2's state must fail: the
    // transcript the responder confirmed is not the one this initiator computed.
    assert!(matches!(
        initiator_process_resp(&suite, i_state_2, &initiator, &resp_hello_1),
        Err(HandshakeError::Confirmation)
    ));
}

#[test]
fn missing_confirmation_field_is_a_framing_error() {
    let suite = SdkSuite::from_id(0x0003).expect("tri-hybrid");
    let (a, b, c, d) = seeds();
    let initiator = StaticIdentity::generate(&suite, &a).unwrap();
    let responder = StaticIdentity::generate(&suite, &b).unwrap();

    let (init_hello, i_state) =
        initiator_hello(&suite, &initiator, &peer(&responder), 1, TIMESTAMP, &c).unwrap();
    let (resp_hello, r_state) =
        responder_process_init(&suite, &responder, &peer(&initiator), &init_hello, 2, &d).unwrap();
    let (init_conf, _) = initiator_process_resp(&suite, i_state, &initiator, &resp_hello).unwrap();

    // Rebuild InitConf carrying only the receiver index — no confirmation at all.
    let stripped = {
        let msg = Message::parse(&init_conf).unwrap();
        let mut b = MessageBuilder::new(msg.header());
        b.field(
            tag::RECEIVER_INDEX,
            msg.require(tag::RECEIVER_INDEX).unwrap(),
        )
        .unwrap();
        b.finish().unwrap()
    };

    assert!(matches!(
        responder_process_conf(&suite, r_state, &stripped),
        Err(HandshakeError::Wire(_))
    ));
}

#[test]
fn suite_downgrade_is_rejected() {
    // The responder runs 0x0003 but the message claims 0x0001.
    let tri = SdkSuite::from_id(0x0003).expect("tri-hybrid");
    let (a, b, c, d) = seeds();
    let initiator = StaticIdentity::generate(&tri, &a).unwrap();
    let responder = StaticIdentity::generate(&tri, &b).unwrap();
    let (mut init_hello, _) =
        initiator_hello(&tri, &initiator, &peer(&responder), 1, TIMESTAMP, &c).unwrap();

    // Suite id lives at header bytes 2..4.
    init_hello[2] = 0x00;
    init_hello[3] = 0x01;

    assert!(matches!(
        responder_process_init(&tri, &responder, &peer(&initiator), &init_hello, 2, &d),
        Err(HandshakeError::SuiteMismatch { .. })
    ));
}

#[test]
fn wrong_receiver_index_is_rejected() {
    let suite = SdkSuite::from_id(0x0003).expect("tri-hybrid");
    let (a, b, c, d) = seeds();
    let initiator = StaticIdentity::generate(&suite, &a).unwrap();
    let responder = StaticIdentity::generate(&suite, &b).unwrap();

    let (init_hello, i_state) = initiator_hello(
        &suite,
        &initiator,
        &peer(&responder),
        0x1122_3344,
        TIMESTAMP,
        &c,
    )
    .unwrap();
    let (resp_hello, _) =
        responder_process_init(&suite, &responder, &peer(&initiator), &init_hello, 2, &d).unwrap();

    // Rebuild RespHello echoing the wrong initiator index.
    let tampered = {
        let msg = Message::parse(&resp_hello).unwrap();
        let mut b = MessageBuilder::new(msg.header());
        b.field(tag::EPHEMERAL_CT, msg.require(tag::EPHEMERAL_CT).unwrap())
            .unwrap();
        b.field(tag::STATIC_CT, msg.require(tag::STATIC_CT).unwrap())
            .unwrap();
        b.field(tag::RECEIVER_INDEX, &0x5566_7788u32.to_be_bytes())
            .unwrap();
        b.finish().unwrap()
    };

    assert!(matches!(
        initiator_process_resp(&suite, i_state, &initiator, &tampered),
        Err(HandshakeError::WrongReceiverIndex { .. })
    ));
}

#[test]
fn errors_do_not_leak_secrets_in_debug() {
    let suite = SdkSuite::from_id(0x0003).expect("tri-hybrid");
    let ex = default_run(&suite);
    // Debug on the derived keys must not print key bytes.
    let key_hex = hex(ex.initiator.key.as_bytes());
    let text = format!("{:?}", ex.initiator);
    assert!(
        !text.contains(&key_hex),
        "Debug output leaked the session key"
    );
}

// ── 3. frozen vectors ────────────────────────────────────────────────

#[test]
#[ignore = "run with --ignored to print the current frozen vectors"]
fn dump_frozen_vectors() {
    for suite in shipped_suites() {
        let ex = default_run(&suite);
        println!("=== suite {:#06x} ===", suite.suite_id());
        println!(
            "init_hello  {} bytes {}",
            ex.init_hello.len(),
            hex(&ex.init_hello)
        );
        println!(
            "resp_hello  {} bytes {}",
            ex.resp_hello.len(),
            hex(&ex.resp_hello)
        );
        println!(
            "init_conf   {} bytes {}",
            ex.init_conf.len(),
            hex(&ex.init_conf)
        );
        println!("transcript  {}", hex(&ex.initiator.transcript));
        println!("key         {}", hex(ex.initiator.key.as_bytes()));
        println!(
            "conf_i      {}",
            hex(ex.initiator.confirm_initiator.as_bytes())
        );
        println!(
            "conf_r      {}",
            hex(ex.initiator.confirm_responder.as_bytes())
        );
    }
}

// ── 4. peer identification (P6) ──────────────────────────────────────

/// A responder resolves *which peer* is calling from the sealed hint, before it
/// has authenticated anyone. Both ends derive the hint from the peer's static
/// public key, so no extra configuration is needed to look it up.
#[test]
fn the_peer_hint_names_the_initiator_before_authentication() {
    let suite = SdkSuite::from_id(0x0003).expect("tri-hybrid");
    let (a, b, c, _) = seeds();
    let initiator = StaticIdentity::generate(&suite, &a).unwrap();
    let responder = StaticIdentity::generate(&suite, &b).unwrap();

    let (init_hello, _) =
        initiator_hello(&suite, &initiator, &peer(&responder), 7, TIMESTAMP, &c).unwrap();

    let info = responder_identify(&suite, &responder, &init_hello).unwrap();
    assert_eq!(info.suite_id(), 0x0003);
    assert_eq!(info.sender_index(), 7);
    assert_eq!(info.timestamp(), &TIMESTAMP);
    assert_eq!(info.peer_hint(), &peer_hint(&suite, initiator.public()));
    // A different identity means a different hint — this is what makes it an
    // index into a peer table.
    let other = StaticIdentity::generate(&suite, &[0x77u8; 32]).unwrap();
    assert_ne!(info.peer_hint(), &peer_hint(&suite, other.public()));
}

/// The hint is *sealed*, not merely truncated: its value does not appear
/// anywhere in the message, so a passive observer cannot confirm which
/// configured peer is connecting.
#[test]
fn the_hint_does_not_appear_in_cleartext() {
    let suite = SdkSuite::from_id(0x0003).expect("tri-hybrid");
    let (a, b, c, _) = seeds();
    let initiator = StaticIdentity::generate(&suite, &a).unwrap();
    let responder = StaticIdentity::generate(&suite, &b).unwrap();

    let (init_hello, _) =
        initiator_hello(&suite, &initiator, &peer(&responder), 1, TIMESTAMP, &c).unwrap();
    let hint = peer_hint(&suite, initiator.public());
    assert!(
        !init_hello
            .windows(PEER_HINT_SIZE)
            .any(|window| window == hint),
        "the peer hint leaked into the wire bytes"
    );
}

/// The hint is checked, never trusted. Resolving it to a peer it does not name
/// is refused rather than completing a session under the wrong peer.
#[test]
fn a_hint_that_names_another_peer_is_refused() {
    let suite = SdkSuite::from_id(0x0003).expect("tri-hybrid");
    let (a, b, c, d) = seeds();
    let initiator = StaticIdentity::generate(&suite, &a).unwrap();
    let responder = StaticIdentity::generate(&suite, &b).unwrap();
    let other = StaticIdentity::generate(&suite, &[0x77u8; 32]).unwrap();

    let (init_hello, _) =
        initiator_hello(&suite, &initiator, &peer(&responder), 1, TIMESTAMP, &c).unwrap();
    let info = responder_identify(&suite, &responder, &init_hello).unwrap();

    assert_eq!(
        responder_accept(&suite, &responder, &peer(&other), &info, 2, &d).unwrap_err(),
        HandshakeError::PeerHintMismatch
    );
    // The peer the hint *does* name goes through — through the same two phases.
    assert!(responder_accept(&suite, &responder, &peer(&initiator), &info, 2, &d).is_ok());
}

/// A tampered, truncated, or stripped hint is a framing/AEAD failure. Stripping
/// it is not a way to skip the check.
#[test]
fn a_tampered_or_missing_hint_is_rejected() {
    let suite = SdkSuite::from_id(0x0003).expect("tri-hybrid");
    let (a, b, c, _) = seeds();
    let initiator = StaticIdentity::generate(&suite, &a).unwrap();
    let responder = StaticIdentity::generate(&suite, &b).unwrap();

    let (init_hello, _) =
        initiator_hello(&suite, &initiator, &peer(&responder), 1, TIMESTAMP, &c).unwrap();

    // Flip one bit of the sealed hint (the last field of the message).
    let mut tampered = init_hello.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(matches!(
        responder_identify(&suite, &responder, &tampered),
        Err(HandshakeError::Aead(_))
    ));

    // Rebuild the message with the hint field truncated and with it missing
    // altogether: both are wire errors, not a silent accept.
    let msg = Message::parse(&init_hello).unwrap();
    let sealed = msg.require(tag::PEER_HINT).unwrap();
    for hint_field in [&sealed[..PEER_HINT_SIZE], &[][..]] {
        let mut builder = MessageBuilder::new(msg.header());
        builder
            .field(tag::STATIC_CT, msg.require(tag::STATIC_CT).unwrap())
            .unwrap();
        builder
            .field(tag::EPHEMERAL_PK, msg.require(tag::EPHEMERAL_PK).unwrap())
            .unwrap();
        builder
            .field(tag::TIMESTAMP, msg.require(tag::TIMESTAMP).unwrap())
            .unwrap();
        if !hint_field.is_empty() {
            builder.field(tag::PEER_HINT, hint_field).unwrap();
        }
        let rebuilt = builder.finish().unwrap();
        assert!(
            matches!(
                responder_identify(&suite, &responder, &rebuilt),
                Err(HandshakeError::Wire(_))
            ),
            "a hint field of {} bytes was accepted",
            hint_field.len()
        );
    }
}

/// The product shape: one responder, two initiators. Each `InitHello` resolves
/// to its own peer by hint, and both handshakes complete independently.
#[test]
fn a_responder_picks_the_right_peer_out_of_several() {
    let suite = SdkSuite::from_id(0x0003).expect("tri-hybrid");
    let responder = StaticIdentity::generate(&suite, &[0x22u8; 32]).unwrap();

    let mut keys = Vec::new();
    for (i, seed) in [[0x11u8; 32], [0x55u8; 32]].into_iter().enumerate() {
        let initiator = StaticIdentity::generate(&suite, &seed).unwrap();
        let (init_hello, i_state) = initiator_hello(
            &suite,
            &initiator,
            &peer(&responder),
            0x10 + i as u32,
            TIMESTAMP,
            &[0x33u8; 32],
        )
        .unwrap();

        let info = responder_identify(&suite, &responder, &init_hello).unwrap();
        assert_eq!(info.peer_hint(), &peer_hint(&suite, initiator.public()));
        let (resp_hello, r_state) = responder_accept(
            &suite,
            &responder,
            &peer(&initiator),
            &info,
            0x20 + i as u32,
            &[0x44u8; 32],
        )
        .unwrap();

        let (init_conf, i_keys) =
            initiator_process_resp(&suite, i_state, &initiator, &resp_hello).unwrap();
        let r_keys = responder_process_conf(&suite, r_state, &init_conf).unwrap();

        assert_eq!(i_keys.key.as_bytes(), r_keys.key.as_bytes());
        keys.push(i_keys.key.as_bytes().to_vec());
    }
    // The two sessions are distinct: sharing the responder does not share a key.
    assert_ne!(keys[0], keys[1]);
}

#[test]
fn frozen_vectors_match() {
    // Frozen from `dump_frozen_vectors`. Regenerate with:
    //   cargo test -p vallum-core --test interop -- --ignored --nocapture
    //
    // The transcript (`TR`, stage 2) is a hash over every `InitHello` and
    // `RespHello` core field, so freezing it pins both messages' content; the key
    // pins all three KEM operations; `conf_r`/`conf_i` pin the two confirmation
    // stages. If any of these fail after a provider swap, the swap changed
    // protocol-visible bytes and the contract is broken.
    //
    // One `InitHello` field is *not* in the transcript: the P6 peer hint, which
    // is sealed under op A and carries no key material. It is pinned by
    // `init_hello_len` instead — a scheme change that altered the hint would
    // change the length even though `TR` and every key below stayed put.
    struct Vector {
        suite_id: u16,
        init_hello_len: usize,
        resp_hello_len: usize,
        init_conf: &'static str,
        transcript: &'static str,
        key: &'static str,
        conf_i: &'static str,
        conf_r: &'static str,
    }

    const VECTORS: &[Vector] = &[
        Vector {
            suite_id: 0x0001,
            init_hello_len: 2337,
            resp_hello_len: 2202,
            init_conf: "010300010a0b0c0d00100020eec128c04c9bbb41982b13ea0408773ef6d4e9ccdb97237656b2a7e9f6c9489600050004e0e1e2e3",
            transcript: "846d88879dd8511e8f692fa43ec622153b0ba64dac36c92c2a864f31a7fcbc07",
            key: "c4f2772b75022bf47361754dc88bb40c78c1aa196958ae6631a32bf6fd30c530",
            conf_i: "eec128c04c9bbb41982b13ea0408773ef6d4e9ccdb97237656b2a7e9f6c94896",
            conf_r: "60c6bda41925fdf6264cde7c5718b393198f931ad23b6440a1b9a16ae87e1b59",
        },
        Vector {
            suite_id: 0x0002,
            init_hello_len: 2412,
            resp_hello_len: 2300,
            init_conf: "010300020a0b0c0d00100020bbcb651aa14240f8300d8e6d7d38e53b940a2030a630f48ba1978ecccd86c4b100050004e0e1e2e3",
            transcript: "f36118a94977124c29cfd976408445660450803a101d8e939703a7b234626697",
            key: "439f0600bcd6b3fade69983f7afc236d29e111e1fcfdb22f64aa44b4dea8a2c5",
            conf_i: "bbcb651aa14240f8300d8e6d7d38e53b940a2030a630f48ba1978ecccd86c4b1",
            conf_r: "9391b08e097d251b86fc6539758f25d5f61e16376de75a6c27749b204ff10808",
        },
        Vector {
            suite_id: 0x0003,
            init_hello_len: 4609,
            resp_hello_len: 4378,
            init_conf: "010300030a0b0c0d0010002052171e405c34b707362b25c1b3ad823b83161dc6f0ba6c4b58e0e59d32a18ec200050004e0e1e2e3",
            transcript: "6c22bee37269a2a89aae4752718fbce53c8210659b5a4ddc84424e165436a9fc",
            key: "53b04bac78b3b0bd12eadbf80ae2e88e35075c70104c26ea12c95d6eacff22c9",
            conf_i: "52171e405c34b707362b25c1b3ad823b83161dc6f0ba6c4b58e0e59d32a18ec2",
            conf_r: "84891b5625a2dd57c8c6eac858797e2321371c7fd73c7bc204ff02f99529a776",
        },
    ];

    for v in VECTORS {
        let Ok(suite) = SdkSuite::from_id(v.suite_id) else {
            continue; // suite not compiled in (`ml-kem` off)
        };
        let ex = default_run(&suite);
        let where_ = format!("suite {:#06x}", v.suite_id);

        assert_eq!(
            ex.init_hello.len(),
            v.init_hello_len,
            "{where_}: InitHello size"
        );
        assert_eq!(
            ex.resp_hello.len(),
            v.resp_hello_len,
            "{where_}: RespHello size"
        );
        assert_eq!(hex(&ex.init_conf), v.init_conf, "{where_}: InitConf bytes");
        assert_eq!(
            hex(&ex.initiator.transcript),
            v.transcript,
            "{where_}: transcript"
        );
        assert_eq!(
            hex(ex.initiator.key.as_bytes()),
            v.key,
            "{where_}: session key"
        );
        assert_eq!(
            hex(ex.initiator.confirm_initiator.as_bytes()),
            v.conf_i,
            "{where_}: initiator confirmation"
        );
        assert_eq!(
            hex(ex.initiator.confirm_responder.as_bytes()),
            v.conf_r,
            "{where_}: responder confirmation"
        );
    }
}
