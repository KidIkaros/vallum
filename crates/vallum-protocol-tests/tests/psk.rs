// SPDX-License-Identifier: Apache-2.0

//! A configured per-peer PSK (G1).
//!
//! The PSK is mixed into the key schedule, never sent on the wire. The default
//! `None` path must be byte-identical to every existing vector; a mismatch must
//! fail the responder's confirmation, not produce a usable session.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use vallum_core::{
    initiator_hello_with_psk, initiator_process_resp, responder_process_conf,
    responder_process_init_with_psk, HandshakeError, PeerIdentity, SessionKeys, StaticIdentity,
};
use vallum_crypto::{CryptoSuite, SharedSecret};
use vallum_crypto_sdk::SdkSuite;

const TIMESTAMP: [u8; 12] = [
    0x40, 0x00, 0x00, 0x00, 0x67, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78,
];

fn psk(byte: u8) -> SharedSecret {
    SharedSecret::new([byte; 32])
}

fn peer(identity: &StaticIdentity) -> PeerIdentity {
    PeerIdentity::from_identity(identity)
}

struct Exchange {
    initiator: SessionKeys,
    responder: SessionKeys,
    init_hello: Vec<u8>,
    resp_hello: Vec<u8>,
}

/// `initiator_psk` is what the initiator configured for the responder;
/// `responder_psk` is what the responder configured for the initiator.
fn run(
    suite: &dyn CryptoSuite,
    initiator_psk: Option<&SharedSecret>,
    responder_psk: Option<&SharedSecret>,
) -> Result<Exchange, HandshakeError> {
    let initiator = StaticIdentity::generate(suite, &[0x11; 32])?;
    let responder = StaticIdentity::generate(suite, &[0x22; 32])?;

    let (init_hello, i_state) = initiator_hello_with_psk(
        suite,
        &initiator,
        &peer(&responder),
        0x0A0B_0C0D,
        TIMESTAMP,
        &[0x33; 32],
        initiator_psk,
    )?;
    let (resp_hello, r_state) = responder_process_init_with_psk(
        suite,
        &responder,
        &peer(&initiator),
        &init_hello,
        0xE0E1_E2E3,
        &[0x44; 32],
        responder_psk,
    )?;
    let (init_conf, i_keys) = initiator_process_resp(suite, i_state, &initiator, &resp_hello)?;
    let r_keys = responder_process_conf(suite, r_state, &init_conf)?;

    Ok(Exchange {
        initiator: i_keys,
        responder: r_keys,
        init_hello,
        resp_hello,
    })
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

#[test]
fn a_matching_psk_produces_the_same_keys() {
    for suite in shipped_suites() {
        let key = psk(0xA5);
        let exchange = run(&suite, Some(&key), Some(&key)).expect("a matching PSK");
        // `own_index`/`peer_index` are mirrored by design; everything else must
        // agree.
        assert_eq!(
            exchange.initiator.transcript, exchange.responder.transcript,
            "suite {suite:?}"
        );
        assert_eq!(
            exchange.initiator.key, exchange.responder.key,
            "suite {suite:?}"
        );
        assert_eq!(
            exchange.initiator.confirm_initiator, exchange.responder.confirm_initiator,
            "suite {suite:?}"
        );
        assert_eq!(
            exchange.initiator.confirm_responder, exchange.responder.confirm_responder,
            "suite {suite:?}"
        );
    }
}

#[test]
fn a_mismatched_psk_fails_the_confirmation() {
    let suite = SdkSuite::tri_hybrid();
    let result = run(&suite, Some(&psk(0x01)), Some(&psk(0x02)));
    assert!(
        matches!(result, Err(HandshakeError::Confirmation)),
        "a different PSK must not produce a session"
    );
}

#[test]
fn a_one_sided_psk_fails() {
    let suite = SdkSuite::tri_hybrid();
    assert!(matches!(
        run(&suite, Some(&psk(0x03)), None),
        Err(HandshakeError::Confirmation)
    ));
    assert!(matches!(
        run(&suite, None, Some(&psk(0x03))),
        Err(HandshakeError::Confirmation)
    ));
}

#[test]
fn the_psk_never_appears_on_the_wire() {
    let suite = SdkSuite::tri_hybrid();
    let key = psk(0xC7);
    let exchange = run(&suite, Some(&key), Some(&key)).expect("a matching PSK");
    for message in [&exchange.init_hello, &exchange.resp_hello] {
        assert!(
            !message.windows(32).any(|window| window == key.as_bytes()),
            "the PSK was found in a handshake message"
        );
    }
}

#[test]
fn the_psk_does_not_change_init_hello() {
    // The PSK is a key-schedule input, not a message field: the initiator's
    // first message must be byte-identical with and without one.
    let suite = SdkSuite::tri_hybrid();
    let plain = run(&suite, None, None).expect("no PSK");
    let key = psk(0x5A);
    let with_psk = run(&suite, Some(&key), Some(&key)).expect("with PSK");
    assert_eq!(plain.init_hello, with_psk.init_hello);
    assert_ne!(plain.resp_hello, with_psk.resp_hello);
}
