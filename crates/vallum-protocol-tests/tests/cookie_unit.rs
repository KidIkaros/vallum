#![allow(clippy::expect_used, clippy::unwrap_used)]

use vallum_core::cookie::*;
use vallum_core::wire::{
    tag, Message, MessageBuilder, MessageHeader, MessageType, PROTOCOL_VERSION,
};
use vallum_core::{HandshakeError, NONCE_SIZE};
use vallum_crypto::CryptoSuite;
use vallum_crypto_sdk::SdkSuite;

const PK: &[u8] = b"a responder static public key";
const MSG: &[u8] = b"an InitHello with the cookie fields removed";

fn suite() -> SdkSuite {
    SdkSuite::tri_hybrid()
}

#[test]
fn mac1_is_a_function_of_the_public_key_and_the_message() {
    let s = suite();
    let a = mac1(&s, PK, MSG).unwrap();
    assert_eq!(a, mac1(&s, PK, MSG).unwrap(), "deterministic");
    assert_ne!(a, mac1(&s, b"another key", MSG).unwrap());
    assert_ne!(a, mac1(&s, PK, b"another message").unwrap());
}

#[test]
fn mac1_needs_no_secret_but_mac2_does() {
    // `mac1` is computable from public data alone — that is its purpose, and
    // why it must never be mistaken for authentication. `mac2` is the layer
    // that actually costs an attacker: without the secret it cannot be
    // produced.
    let s = suite();
    let secret = CookieSecret::new(&[1u8; 32]);
    let attacker_secret = CookieSecret::new(&[2u8; 32]);

    let honest = mac2(&s, &secret.cookie(&s, b"addr").unwrap(), MSG).unwrap();
    let forged = mac2(&s, &attacker_secret.cookie(&s, b"addr").unwrap(), MSG).unwrap();
    assert_ne!(honest, forged);
    assert!(!secret.verify_mac2(&s, b"addr", MSG, &forged).unwrap());
    assert!(secret.verify_mac2(&s, b"addr", MSG, &honest).unwrap());
}

#[test]
fn a_cookie_validates_only_for_its_own_address() {
    let s = suite();
    let secret = CookieSecret::new(&[3u8; 32]);
    let cookie = secret.cookie(&s, b"10.0.0.1:51820").unwrap();
    let m = mac2(&s, &cookie, MSG).unwrap();

    assert!(secret.verify_mac2(&s, b"10.0.0.1:51820", MSG, &m).unwrap());
    assert!(!secret.verify_mac2(&s, b"10.0.0.2:51820", MSG, &m).unwrap());
    assert!(!secret
        .verify_mac2(&s, b"10.0.0.1:51820", b"other message", &m)
        .unwrap());
    assert!(
        !secret
            .verify_mac2(&s, b"10.0.0.1:51820", MSG, &[0u8; 16])
            .unwrap(),
        "an all-zero mac2 is not valid"
    );
    assert!(
        !secret
            .verify_mac2(&s, b"10.0.0.1:51820", MSG, &[0u8; 17])
            .unwrap(),
        "the wrong length is invalid, not an error"
    );
}

#[test]
fn rotation_keeps_the_previous_cookie_valid_but_not_older_ones() {
    let s = suite();
    let mut secret = CookieSecret::new(&[1u8; 32]);
    let old = mac2(&s, &secret.cookie(&s, b"addr").unwrap(), MSG).unwrap();

    secret.rotate(&[2u8; 32]);
    let new = mac2(&s, &secret.cookie(&s, b"addr").unwrap(), MSG).unwrap();
    assert_ne!(old, new, "the cookie changed");

    assert!(
        secret.verify_mac2(&s, b"addr", MSG, &old).unwrap(),
        "a reply already in flight still validates"
    );
    assert!(secret.verify_mac2(&s, b"addr", MSG, &new).unwrap());

    secret.rotate(&[3u8; 32]);
    assert!(
        !secret.verify_mac2(&s, b"addr", MSG, &old).unwrap(),
        "two rotations back is gone"
    );
    assert!(secret.verify_mac2(&s, b"addr", MSG, &new).unwrap());
}

#[test]
fn a_cookie_reply_round_trips_and_is_bound_to_the_request() {
    let s = suite();
    let request_mac1 = mac1(&s, PK, MSG).unwrap();
    let nonce = [7u8; NONCE_SIZE];
    let cookie = [9u8; COOKIE_SIZE];

    let sealed = seal_cookie_reply(&s, &request_mac1, &nonce, &cookie).unwrap();
    assert_eq!(
        open_cookie_reply(&s, &request_mac1, &nonce, &sealed).unwrap(),
        cookie
    );

    // A reply for another request's mac1 does not open.
    let other_mac1 = mac1(&s, b"another key", MSG).unwrap();
    assert!(open_cookie_reply(&s, &other_mac1, &nonce, &sealed).is_err());
    // Nor does it open under another nonce.
    let other_nonce = [8u8; NONCE_SIZE];
    assert!(open_cookie_reply(&s, &request_mac1, &other_nonce, &sealed).is_err());
    // Nor does a truncated reply.
    assert!(open_cookie_reply(&s, &request_mac1, &nonce, &sealed[..sealed.len() - 1]).is_err());
}

#[test]
fn a_cookie_reply_round_trips_through_the_wire() {
    let s = suite();
    let request_mac1 = mac1(&s, PK, MSG).unwrap();
    let nonce = [7u8; NONCE_SIZE];
    let cookie = [9u8; COOKIE_SIZE];
    let request_index = 0xDEAD_BEEF;

    let bytes = build_cookie_reply(&s, request_index, &request_mac1, &nonce, &cookie).unwrap();

    // The wire form is small and fixed: a requester must not be able to make
    // the responder emit more than it received (no reflection amplifier).
    assert!(bytes.len() < 128, "a cookie reply is {} bytes", bytes.len());

    let msg = Message::parse(&bytes).unwrap();
    assert_eq!(msg.message_type(), MessageType::CookieReply);
    assert_eq!(
        msg.sender_index(),
        0,
        "a cookie reply belongs to no session"
    );

    let (index, got) = read_cookie_reply(&s, &msg, &request_mac1).unwrap();
    assert_eq!(index, request_index, "the request index is echoed");
    assert_eq!(got, cookie);
}

#[test]
fn a_cookie_reply_is_unreadable_without_our_own_request() {
    let s = suite();
    let ours = mac1(&s, PK, MSG).unwrap();
    let theirs = mac1(&s, b"another key", MSG).unwrap();
    let nonce = [7u8; NONCE_SIZE];

    let bytes = build_cookie_reply(&s, 1, &theirs, &nonce, &[9u8; COOKIE_SIZE]).unwrap();
    let msg = Message::parse(&bytes).unwrap();

    // A reply issued for someone else's request does not open under ours:
    // the cookie is bound to the request that asked for it.
    assert!(matches!(
        read_cookie_reply(&s, &msg, &ours),
        Err(HandshakeError::Aead(_))
    ));
    assert!(read_cookie_reply(&s, &msg, &theirs).is_ok());
}

#[test]
fn a_cookie_reply_asserts_its_type_and_suite() {
    let s = suite();
    let mac = mac1(&s, PK, MSG).unwrap();
    let bytes = build_cookie_reply(&s, 1, &mac, &[7u8; NONCE_SIZE], &[9u8; COOKIE_SIZE]).unwrap();
    let msg = Message::parse(&bytes).unwrap();
    assert!(msg.expect_type(MessageType::CookieReply).is_ok());
    assert!(msg.expect_suite(s.suite_id()).is_ok());

    // A reply whose suite id was rewritten is refused before any AEAD work.
    let mut forged = bytes.clone();
    forged[2..4].copy_from_slice(&0x0099u16.to_be_bytes());
    let forged = Message::parse(&forged).unwrap();
    assert!(matches!(
        read_cookie_reply(&s, &forged, &mac),
        Err(HandshakeError::SuiteMismatch { .. })
    ));

    // And a data message is not a cookie reply.
    let mut b = MessageBuilder::new(MessageHeader {
        version: PROTOCOL_VERSION,
        message_type: MessageType::Data,
        suite_id: s.suite_id(),
        sender_index: 0,
    });
    b.field(tag::COUNTER, &1u64.to_be_bytes()).unwrap();
    b.field(tag::DATA_CT, b"ct").unwrap();
    let data_bytes = b.finish().unwrap();
    let data = Message::parse(&data_bytes).unwrap();
    assert!(matches!(
        read_cookie_reply(&s, &data, &mac),
        Err(HandshakeError::WrongMessageType { .. })
    ));
}

#[test]
fn a_truncated_cookie_reply_is_a_framing_error_not_a_panic() {
    let s = suite();
    let mac = mac1(&s, PK, MSG).unwrap();
    let bytes = build_cookie_reply(&s, 1, &mac, &[7u8; NONCE_SIZE], &[9u8; COOKIE_SIZE]).unwrap();
    let msg = Message::parse(&bytes).unwrap();

    // Drop each field in turn and confirm the reader reports a missing field
    // rather than unwrapping one.
    for missing in [tag::RECEIVER_INDEX, tag::COOKIE_NONCE, tag::COOKIE_CT] {
        let mut rebuilt = MessageBuilder::new(MessageHeader {
            version: PROTOCOL_VERSION,
            message_type: MessageType::CookieReply,
            suite_id: s.suite_id(),
            sender_index: 0,
        });
        for t in [tag::RECEIVER_INDEX, tag::COOKIE_NONCE, tag::COOKIE_CT] {
            if t != missing {
                rebuilt.field(t, msg.require(t).unwrap()).unwrap();
            }
        }
        let short_bytes = rebuilt.finish().unwrap();
        let short = Message::parse(&short_bytes).unwrap();
        assert!(
            matches!(
                read_cookie_reply(&s, &short, &mac),
                Err(HandshakeError::Wire(_))
            ),
            "missing field {missing:#06x} should be a framing error"
        );
    }
}
