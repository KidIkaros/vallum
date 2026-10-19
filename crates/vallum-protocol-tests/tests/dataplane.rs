// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for the transport data plane.
//!
//! The data plane is where the handshake stops being a proof obligation and
//! starts being a product: packets that must open exactly once, on exactly one
//! endpoint, under exactly one key. These tests drive a real P1 handshake and
//! then attack the resulting session.
//!
//! Four layers:
//!
//! 1. **Lifecycle** — a completed handshake becomes a working, bidirectional
//!    data plane, and a data packet is never mistaken for a handshake message.
//! 2. **Key isolation** — committing-AEAD boundary behaviour: no cross-session,
//!    cross-epoch, or cross-direction opening, whatever the header claims.
//! 3. **Replay** — reorder is fine; duplication and ageing are not.
//! 4. **Anti-flood** — the `mac1`/`mac2` admission gate and the cookie reply.
//!
//! See `docs/proof/committing-aead-multikey.md` for what this does and does not
//! establish.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use vallum_core::cookie::{
    admit_handshake, build_cookie_reply, mac1, mac2, open_cookie_reply, read_cookie_reply,
    seal_cookie_reply, sign_with_cookies, Admission, CookieSecret, COOKIE_SIZE, MAC_SIZE,
};
use vallum_core::wire::tag;
use vallum_core::{
    establish, establish_epoch, initiator_hello, initiator_process_resp, responder_process_conf,
    responder_process_init, DataError, HandshakeError, Message, MessageBuilder, MessageHeader,
    MessageType, PeerIdentity, Receiver, Role, Sender, SessionKeys, StaticIdentity, NONCE_SIZE,
    PAYLOAD_LEN_SIZE, PROTOCOL_VERSION, REPLAY_WINDOW,
};
use vallum_crypto::CryptoSuite;
use vallum_crypto_sdk::SdkSuite;

const TIMESTAMP: [u8; 12] = [
    0x40, 0x00, 0x00, 0x00, 0x67, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78,
];

const INIT_INDEX: u32 = 0x0A0B_0C0D;
const RESP_INDEX: u32 = 0xE0E1_E2E3;

/// The peer configuration matching a local identity.
fn peer(identity: &StaticIdentity) -> PeerIdentity {
    PeerIdentity::from_identity(identity)
}

/// A live session: both endpoints, both directions.
struct Live {
    suite: SdkSuite,
    init_keys: SessionKeys,
    resp_keys: SessionKeys,
    a_send: Sender,
    a_recv: Receiver,
    b_send: Sender,
    b_recv: Receiver,
}

impl Live {
    fn new() -> Self {
        Self::from_seeds([0x11u8; 32], [0x22u8; 32], [0x33u8; 32], [0x44u8; 32])
    }

    /// Run a complete handshake and expand both directions from it.
    fn from_seeds(
        init_static: [u8; 32],
        resp_static: [u8; 32],
        init_seed: [u8; 32],
        resp_seed: [u8; 32],
    ) -> Self {
        let suite = SdkSuite::tri_hybrid();

        let initiator = StaticIdentity::generate(&suite, &init_static).expect("initiator identity");
        let responder = StaticIdentity::generate(&suite, &resp_static).expect("responder identity");

        let (init_hello, i_state) = initiator_hello(
            &suite,
            &initiator,
            &peer(&responder),
            INIT_INDEX,
            TIMESTAMP,
            &init_seed,
        )
        .expect("InitHello");

        let (resp_hello, r_state) = responder_process_init(
            &suite,
            &responder,
            &peer(&initiator),
            &init_hello,
            RESP_INDEX,
            &resp_seed,
        )
        .expect("RespHello");

        let (init_conf, init_keys) =
            initiator_process_resp(&suite, i_state, &initiator, &resp_hello).expect("InitConf");
        let resp_keys =
            responder_process_conf(&suite, r_state, &init_conf).expect("responder accepts");

        let (a_send, a_recv) = establish(&suite, &init_keys, Role::Initiator).expect("initiator");
        let (b_send, b_recv) = establish(&suite, &resp_keys, Role::Responder).expect("responder");

        Self {
            suite,
            init_keys,
            resp_keys,
            a_send,
            a_recv,
            b_send,
            b_recv,
        }
    }
}

/// Re-frame a packet with a counter the sender never sealed, keeping the
/// ciphertext and tag bytes so only the counter has changed.
fn rebuild_with_counter(packet: &[u8], counter: u64) -> Vec<u8> {
    let parsed = Message::parse(packet).unwrap();
    let ciphertext = parsed.require(tag::DATA_CT).unwrap();
    let mut builder = MessageBuilder::new(parsed.header());
    builder.field(tag::COUNTER, &counter.to_be_bytes()).unwrap();
    builder.field(tag::DATA_CT, ciphertext).unwrap();
    builder.finish().unwrap()
}

// ── 1. lifecycle ─────────────────────────────────────────────────────

#[test]
fn a_completed_handshake_becomes_a_working_data_plane() {
    let mut live = Live::new();

    for i in 0..8u32 {
        let payload = format!("initiator packet {i}").into_bytes();
        let packet = live.a_send.seal(&live.suite, &payload).expect("seal");
        assert_eq!(
            live.b_recv.open(&live.suite, &packet).expect("open"),
            payload
        );
    }

    for i in 0..8u32 {
        let payload = format!("responder packet {i}").into_bytes();
        let packet = live.b_send.seal(&live.suite, &payload).expect("seal");
        assert_eq!(
            live.a_recv.open(&live.suite, &packet).expect("open"),
            payload
        );
    }

    // The two directions keep independent counters — neither end's sequence
    // number is observable from, or entangled with, the other's.
    assert_eq!(live.a_send.counter(), 8);
    assert_eq!(live.b_send.counter(), 8);
    assert_eq!(live.a_recv.next_counter(), 8);
    assert_eq!(live.b_recv.next_counter(), 8);
}

#[test]
fn both_endpoints_agree_the_session_is_the_same_one() {
    let live = Live::new();

    assert_eq!(live.init_keys.transcript, live.resp_keys.transcript);
    assert_eq!(live.init_keys.key, live.resp_keys.key);

    // The index roles are mirrored, which is what makes the direction check
    // meaningful rather than accidental.
    assert_eq!(live.init_keys.own_index, INIT_INDEX);
    assert_eq!(live.init_keys.peer_index, RESP_INDEX);
    assert_eq!(live.resp_keys.own_index, RESP_INDEX);
    assert_eq!(live.resp_keys.peer_index, INIT_INDEX);
}

#[test]
fn a_data_packet_is_a_data_message_and_nothing_else() {
    let suite = SdkSuite::tri_hybrid();
    let mut live = Live::new();
    let packet = live.a_send.seal(&suite, b"hello").unwrap();

    let message = Message::parse(&packet).unwrap();
    assert_eq!(message.message_type(), MessageType::Data);
    assert!(message.expect_suite(suite.suite_id()).is_ok());
    // The header names the *recipient*, not the sender.
    assert_eq!(message.header().sender_index, RESP_INDEX);
    assert!(message.get(tag::COUNTER).is_some());
    assert!(message.get(tag::DATA_CT).is_some());

    // And the handshake path refuses it, so a data packet can never be fed to
    // the state machine as an InitHello.
    let responder = StaticIdentity::generate(&suite, &[0x22u8; 32]).unwrap();
    let initiator = StaticIdentity::generate(&suite, &[0x11u8; 32]).unwrap();
    assert!(matches!(
        responder_process_init(
            &suite,
            &responder,
            &peer(&initiator),
            &packet,
            RESP_INDEX,
            &[0x44u8; 32],
        ),
        Err(HandshakeError::WrongMessageType { .. })
    ));
}

#[test]
fn a_keepalive_is_an_empty_payload_of_a_known_size() {
    let mut live = Live::new();
    let packet = live.a_send.seal(&live.suite, &[]).unwrap();

    // 8-byte header, COUNTER (4-byte tag + u64), DATA_CT (4-byte tag + 32-byte
    // AEAD tag + the 2-byte payload-length prefix). A fixed, minimal,
    // unremarkable packet — the point of a keepalive is that it reveals only
    // that a session exists.
    assert_eq!(packet.len(), 8 + 12 + 4 + 32 + PAYLOAD_LEN_SIZE);
    assert_eq!(live.b_recv.open(&live.suite, &packet).unwrap(), b"");
    assert_eq!(
        live.b_recv.next_counter(),
        1,
        "a keepalive is a real packet"
    );
}

// ── 2. key isolation (committing-AEAD boundary) ──────────────────────

#[test]
fn a_packet_only_opens_in_the_direction_it_was_sealed() {
    // A packet fed back to the endpoint that sealed it is refused, caught twice
    // over: the directions hold different keys, and the header names only the
    // recipient.
    let mut live = Live::new();
    let from_a = live.a_send.seal(&live.suite, b"a").unwrap();
    let from_b = live.b_send.seal(&live.suite, b"b").unwrap();

    assert_eq!(live.b_recv.open(&live.suite, &from_a).unwrap(), b"a");
    assert_eq!(live.a_recv.open(&live.suite, &from_b).unwrap(), b"b");

    assert!(matches!(
        live.a_recv.open(&live.suite, &from_a),
        Err(DataError::WrongIndex { .. })
    ));
    assert!(matches!(
        live.b_recv.open(&live.suite, &from_b),
        Err(DataError::WrongIndex { .. })
    ));
}

#[test]
fn the_two_directions_do_not_share_a_key() {
    // Both receivers below expect the index `b_send` stamps, so the index guard
    // is out of the way and only the key can decide.
    let mut live = Live::new();
    let packet = live.b_send.seal(&live.suite, b"b speaking").unwrap();

    // A receiver holding the responder's *sending* half — which is what an
    // initiator receives under — opens it. This is `a_recv`'s wiring, rebuilt
    // here explicitly so the roles are visible.
    let (_, mut right) = establish_epoch(
        &live.suite,
        &live.resp_keys.key,
        &live.resp_keys.transcript,
        0,
        Role::Initiator,
        INIT_INDEX,
        RESP_INDEX,
    )
    .unwrap();
    assert_eq!(right.open(&live.suite, &packet).unwrap(), b"b speaking");

    // A receiver holding the responder's *receiving* half does not, even wired
    // to expect the very same index.
    let (_, mut wrong) = establish_epoch(
        &live.suite,
        &live.resp_keys.key,
        &live.resp_keys.transcript,
        0,
        Role::Responder,
        INIT_INDEX,
        RESP_INDEX,
    )
    .unwrap();
    let packet = live.b_send.seal(&live.suite, b"b speaking again").unwrap();
    assert!(matches!(
        wrong.open(&live.suite, &packet),
        Err(DataError::Aead(_))
    ));
}

#[test]
fn another_session_cannot_open_our_packets() {
    // Two independent handshakes with the same suite, endpoints, and indices.
    // Only the handshake entropy differs. The eavesdropper is aliased to our own
    // index, so nothing but the key can refuse the packet.
    let mut live = Live::new();
    let other = Live::from_seeds([0x11u8; 32], [0x22u8; 32], [0x55u8; 32], [0x66u8; 32]);

    let (_, mut aliased) = establish_epoch(
        &live.suite,
        &other.resp_keys.key,
        &other.resp_keys.transcript,
        0,
        Role::Responder,
        RESP_INDEX,
        INIT_INDEX,
    )
    .unwrap();

    let packet = live.a_send.seal(&live.suite, b"top secret").unwrap();
    assert!(
        matches!(aliased.open(&live.suite, &packet), Err(DataError::Aead(_))),
        "a different session's key must not open this packet"
    );
}

#[test]
fn another_epoch_cannot_open_our_packets() {
    // A ratchet step changes neither the indices nor the transcript, only the
    // epoch root. The epoch is bound into the key derivation, so a packet from
    // one epoch must not open under the next — the property P4's forward
    // secrecy depends on.
    let live = Live::new();

    let (mut epoch0_send, _) = establish_epoch(
        &live.suite,
        &live.init_keys.key,
        &live.init_keys.transcript,
        0,
        Role::Initiator,
        INIT_INDEX,
        RESP_INDEX,
    )
    .unwrap();
    let (_, mut epoch1_recv) = establish_epoch(
        &live.suite,
        &live.init_keys.key,
        &live.init_keys.transcript,
        1,
        Role::Responder,
        RESP_INDEX,
        INIT_INDEX,
    )
    .unwrap();

    let packet = epoch0_send.seal(&live.suite, b"epoch zero").unwrap();
    assert!(matches!(
        epoch1_recv.open(&live.suite, &packet),
        Err(DataError::Aead(_))
    ));
}

#[test]
fn a_packet_with_a_foreign_suite_id_is_refused() {
    let mut live = Live::new();
    let mut packet = live.a_send.seal(&live.suite, b"payload").unwrap();

    // Relabel the packet as suite 0x0001. The suite id is bound both in the
    // header and, through the header, in the associated data.
    packet[2..4].copy_from_slice(&0x0001u16.to_be_bytes());
    assert!(live.b_recv.open(&live.suite, &packet).is_err());
}

#[test]
fn a_tampered_tag_ciphertext_or_counter_is_rejected() {
    let mut live = Live::new();
    let packet = live.a_send.seal(&live.suite, b"payload").unwrap();

    // The tag.
    let mut flipped = packet.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    assert!(matches!(
        live.b_recv.open(&live.suite, &flipped),
        Err(DataError::Aead(_))
    ));

    // The first ciphertext byte: 8-byte header, then the COUNTER TLV (4-byte
    // tag/length header + u64), then the DATA_CT TLV's 4-byte header.
    let mut flipped = packet.clone();
    flipped[8 + 4 + 8 + 4] ^= 0x01;
    assert!(matches!(
        live.b_recv.open(&live.suite, &flipped),
        Err(DataError::Aead(_))
    ));

    // The counter, rebuilt so the framing stays valid.
    let forged = rebuild_with_counter(&packet, 0xDEAD_BEEF);
    assert!(matches!(
        live.b_recv.open(&live.suite, &forged),
        Err(DataError::Aead(_))
    ));

    // Nothing above moved the window, and the genuine packet still opens.
    assert_eq!(live.b_recv.next_counter(), 0);
    assert_eq!(live.b_recv.open(&live.suite, &packet).unwrap(), b"payload");
    assert_eq!(live.b_recv.next_counter(), 1);
}

// ── 3. replay ────────────────────────────────────────────────────────

#[test]
fn reordered_packets_all_open_and_duplicates_do_not() {
    let mut live = Live::new();

    let packets: Vec<Vec<u8>> = (0..16u32)
        .map(|i| {
            live.a_send
                .seal(&live.suite, format!("p{i}").as_bytes())
                .unwrap()
        })
        .collect();

    // Delivered back to front: the window has to tolerate reordering, which on
    // a real network is the normal case, not the exception.
    for (i, packet) in packets.iter().enumerate().rev() {
        assert_eq!(
            live.b_recv.open(&live.suite, packet).unwrap(),
            format!("p{i}").into_bytes()
        );
    }
    assert_eq!(live.b_recv.next_counter(), 16);

    // And now every one of them, a second time.
    for (i, packet) in packets.iter().enumerate() {
        assert_eq!(
            live.b_recv.open(&live.suite, packet),
            Err(DataError::Replay {
                counter: i as u64,
                next: 16,
            }),
        );
    }
}

#[test]
fn a_counter_may_not_be_reused_after_it_ages_out_of_the_window() {
    let mut live = Live::new();

    // Hold one packet back, then let the sender run far ahead. The held packet
    // is still authentic — the window, not the tag, is what makes it stale.
    let held = live.a_send.seal(&live.suite, b"held").unwrap();
    let beyond = REPLAY_WINDOW + 16;
    for i in 0..beyond {
        let packet = live
            .a_send
            .seal(&live.suite, format!("later {i}").as_bytes())
            .unwrap();
        live.b_recv.open(&live.suite, &packet).unwrap();
    }
    assert_eq!(live.b_recv.next_counter(), beyond + 1);

    assert!(matches!(
        live.b_recv.open(&live.suite, &held),
        Err(DataError::Replay { counter: 0, .. })
    ));
}

#[test]
fn a_forged_counter_cannot_advance_the_window() {
    // The attack that decides the order inside `open`: claim a counter so high
    // that every honest packet which follows looks stale. Verifying the tag
    // before consulting the window is what stops it.
    let mut live = Live::new();

    let honest = live.a_send.seal(&live.suite, b"honest").unwrap();
    let template = live.a_send.seal(&live.suite, b"template").unwrap();
    let forged = rebuild_with_counter(&template, 1 << 40);

    assert!(matches!(
        live.b_recv.open(&live.suite, &forged),
        Err(DataError::Aead(_))
    ));
    assert_eq!(live.b_recv.next_counter(), 0, "the window stayed put");

    // And the honest packet is still deliverable.
    assert_eq!(live.b_recv.open(&live.suite, &honest).unwrap(), b"honest");
}

// ── 4. anti-flood admission ──────────────────────────────────────────

/// Build an `InitHello`-shaped message that carries the cookie fields, using the
/// same helper the protocol itself uses.
fn signed_hello(
    suite: &SdkSuite,
    responder_pk: &[u8],
    cookie: Option<&[u8; COOKIE_SIZE]>,
) -> Vec<u8> {
    let mut builder = MessageBuilder::new(MessageHeader {
        version: PROTOCOL_VERSION,
        message_type: MessageType::InitHello,
        suite_id: suite.suite_id(),
        sender_index: INIT_INDEX,
    });
    builder
        .field(tag::EPHEMERAL_PK, b"a placeholder ephemeral key")
        .unwrap();
    builder.field(tag::TIMESTAMP, &TIMESTAMP).unwrap();
    sign_with_cookies(suite, &mut builder, responder_pk, cookie).unwrap();
    builder.finish().unwrap()
}

#[test]
fn the_admission_gate_costs_nothing_before_it_admits() {
    let suite = SdkSuite::tri_hybrid();
    let responder = StaticIdentity::generate(&suite, &[0x22u8; 32]).unwrap();
    let responder_pk = responder.public().as_bytes();
    let client = b"203.0.113.7:51820";

    // A correctly signed message is admitted without any KEM work.
    let good = signed_hello(&suite, responder_pk, None);
    assert_eq!(
        admit_handshake(
            &suite,
            &Message::parse(&good).unwrap(),
            responder_pk,
            client,
            false,
            None,
        )
        .unwrap(),
        Admission::Accept
    );

    // No mac1 at all.
    let mut builder = MessageBuilder::new(MessageHeader {
        version: PROTOCOL_VERSION,
        message_type: MessageType::InitHello,
        suite_id: suite.suite_id(),
        sender_index: INIT_INDEX,
    });
    builder.field(tag::EPHEMERAL_PK, b"unsigned").unwrap();
    let unsigned = builder.finish().unwrap();
    assert_eq!(
        admit_handshake(
            &suite,
            &Message::parse(&unsigned).unwrap(),
            responder_pk,
            client,
            false,
            None,
        )
        .unwrap(),
        Admission::NoMac1
    );

    // A mac1 computed for a different responder.
    let wrong = signed_hello(&suite, b"somebody else's static key", None);
    assert_eq!(
        admit_handshake(
            &suite,
            &Message::parse(&wrong).unwrap(),
            responder_pk,
            client,
            false,
            None,
        )
        .unwrap(),
        Admission::BadMac1
    );

    // A tampered field invalidates mac1, because mac1 covers the message. Flip
    // the first byte of the ephemeral key's value.
    let mut tampered = signed_hello(&suite, responder_pk, None);
    tampered[8 + 4] ^= 0x01;
    assert_eq!(
        admit_handshake(
            &suite,
            &Message::parse(&tampered).unwrap(),
            responder_pk,
            client,
            false,
            None,
        )
        .unwrap(),
        Admission::BadMac1
    );
}

#[test]
fn under_load_without_a_cookie_gets_a_cookie_and_nothing_more() {
    let suite = SdkSuite::tri_hybrid();
    let responder = StaticIdentity::generate(&suite, &[0x22u8; 32]).unwrap();
    let responder_pk = responder.public().as_bytes();
    let client = b"203.0.113.7:51820";
    let secret = CookieSecret::new(&[0x55u8; 32]);

    // Under load, mac1 alone is not enough: an attacker can compute mac1 too.
    let no_cookie = signed_hello(&suite, responder_pk, None);
    assert_eq!(
        admit_handshake(
            &suite,
            &Message::parse(&no_cookie).unwrap(),
            responder_pk,
            client,
            true,
            Some(&secret),
        )
        .unwrap(),
        Admission::NeedCookie
    );

    // Fail closed: under load with no cookie facility configured, refuse.
    assert_eq!(
        admit_handshake(
            &suite,
            &Message::parse(&no_cookie).unwrap(),
            responder_pk,
            client,
            true,
            None,
        )
        .unwrap(),
        Admission::NeedCookie
    );
}

#[test]
fn a_cookie_is_bound_to_the_client_address() {
    let suite = SdkSuite::tri_hybrid();
    let responder = StaticIdentity::generate(&suite, &[0x22u8; 32]).unwrap();
    let responder_pk = responder.public().as_bytes();
    let secret = CookieSecret::new(&[0x55u8; 32]);

    let client = b"203.0.113.7:51820";
    let cookie = secret.cookie(&suite, client).unwrap();

    let with_cookie = signed_hello(&suite, responder_pk, Some(&cookie));
    let message = Message::parse(&with_cookie).unwrap();

    // The address it was issued for: admitted.
    assert_eq!(
        admit_handshake(&suite, &message, responder_pk, client, true, Some(&secret)).unwrap(),
        Admission::Accept
    );

    // The same packet from somewhere else: refused. This is what makes the
    // cookie a proof of return reachability rather than a bearer token — an
    // attacker who steals a cookie still cannot use it.
    assert_eq!(
        admit_handshake(
            &suite,
            &message,
            responder_pk,
            b"198.51.100.9:51820",
            true,
            Some(&secret),
        )
        .unwrap(),
        Admission::BadMac2
    );
}

/// The whole point of P6's framing: the responder hands out a cookie, and the
/// requester's *retry* — with that cookie as `mac2` — is admitted. Both ends
/// never share a key except through the sealed reply.
#[test]
fn a_cookie_reply_turns_a_refusal_into_a_retry_that_is_admitted() {
    let suite = SdkSuite::tri_hybrid();
    let responder = StaticIdentity::generate(&suite, &[0x22u8; 32]).unwrap();
    let responder_pk = responder.public().as_bytes();
    let client = b"203.0.113.7:51820";
    let secret = CookieSecret::new(&[0x55u8; 32]);

    // 1. Under load, the initiator's first try carries no mac2 and is refused.
    let first = signed_hello(&suite, responder_pk, None);
    let first = Message::parse(&first).unwrap();
    let mac1_of_first = <[u8; MAC_SIZE]>::try_from(first.require(tag::MAC1).unwrap()).unwrap();
    assert_eq!(
        admit_handshake(&suite, &first, responder_pk, client, true, Some(&secret)).unwrap(),
        Admission::NeedCookie
    );

    // 2. The responder answers with a cookie, sealed for that request. The
    //    request's own index comes back so the initiator knows which handshake
    //    it is for, and the mac1 keys the reply so nobody else can read it.
    let nonce = [0x9Au8; NONCE_SIZE];
    let cookie = secret.cookie(&suite, client).unwrap();
    let reply = build_cookie_reply(
        &suite,
        first.sender_index(),
        &mac1_of_first,
        &nonce,
        &cookie,
    )
    .unwrap();

    // 3. The initiator (which kept its mac1 and nonce) reads it back.
    let reply = Message::parse(&reply).unwrap();
    let (index, received) = read_cookie_reply(&suite, &reply, &mac1_of_first).unwrap();
    assert_eq!(index, INIT_INDEX, "the echoed index names the retry");
    assert_eq!(received, cookie);

    // 4. The retry carries mac2 and is admitted.
    let retry = signed_hello(&suite, responder_pk, Some(&received));
    assert_eq!(
        admit_handshake(
            &suite,
            &Message::parse(&retry).unwrap(),
            responder_pk,
            client,
            true,
            Some(&secret),
        )
        .unwrap(),
        Admission::Accept
    );

    // ...but only from the address the cookie was issued to.
    assert_eq!(
        admit_handshake(
            &suite,
            &Message::parse(&retry).unwrap(),
            responder_pk,
            b"198.51.100.9:51820",
            true,
            Some(&secret),
        )
        .unwrap(),
        Admission::BadMac2
    );
}

#[test]
fn a_cookie_keeps_working_across_a_rotation_but_not_forever() {
    let suite = SdkSuite::tri_hybrid();
    let client = b"203.0.113.7:51820";

    let mut secret = CookieSecret::new(&[0x55u8; 32]);
    let issued = secret.cookie(&suite, client).unwrap();

    let mut builder = MessageBuilder::new(MessageHeader {
        version: PROTOCOL_VERSION,
        message_type: MessageType::InitHello,
        suite_id: suite.suite_id(),
        sender_index: INIT_INDEX,
    });
    builder.field(tag::EPHEMERAL_PK, b"placeholder").unwrap();
    let input = builder.mac2_input();

    let stale_proof = mac2(&suite, &issued, &input).unwrap();
    assert!(secret
        .verify_mac2(&suite, client, &input, &stale_proof)
        .unwrap());

    // Rotate: a cookie computed under the previous secret must still verify, or
    // every rotation would drop the handshakes in flight.
    secret.rotate(&[0x66u8; 32]);
    assert!(secret
        .verify_mac2(&suite, client, &input, &stale_proof)
        .unwrap());

    let current = secret.cookie(&suite, client).unwrap();
    let fresh = mac2(&suite, &current, &input).unwrap();
    assert!(secret.verify_mac2(&suite, client, &input, &fresh).unwrap());

    // A second rotation retires the original for good — the overlap is one
    // rotation wide, not unbounded.
    secret.rotate(&[0x77u8; 32]);
    assert!(!secret
        .verify_mac2(&suite, client, &input, &stale_proof)
        .unwrap());

    let current = secret.cookie(&suite, client).unwrap();
    let fresh = mac2(&suite, &current, &input).unwrap();
    assert!(secret.verify_mac2(&suite, client, &input, &fresh).unwrap());
}

#[test]
fn a_cookie_reply_is_readable_only_with_the_request_it_answers() {
    let suite = SdkSuite::tri_hybrid();
    let secret = CookieSecret::new(&[0x55u8; 32]);
    let client = b"203.0.113.7:51820";
    let cookie = secret.cookie(&suite, client).unwrap();

    let request_mac1: [u8; MAC_SIZE] = mac1(&suite, b"responder pk", b"the request").unwrap();
    let nonce = [0x42u8; 24];
    let sealed = seal_cookie_reply(&suite, &request_mac1, &nonce, &cookie).unwrap();

    assert_eq!(
        open_cookie_reply(&suite, &request_mac1, &nonce, &sealed).unwrap(),
        cookie
    );

    // An eavesdropper who saw the reply but not the request cannot open it: the
    // key is a function of that request's mac1.
    let other_mac1: [u8; MAC_SIZE] = mac1(&suite, b"responder pk", b"a different request").unwrap();
    assert!(open_cookie_reply(&suite, &other_mac1, &nonce, &sealed).is_err());
    assert!(open_cookie_reply(&suite, &request_mac1, &[0x43u8; 24], &sealed).is_err());
}

#[test]
fn the_parser_reproduces_exactly_what_the_sender_covered() {
    // The responder recomputes mac1 over the *parsed* fields, so any asymmetry
    // between what the sender covered and what the parser exposes would show up
    // as a spurious rejection. Build, serialise, re-parse, compare.
    let suite = SdkSuite::tri_hybrid();
    let responder_pk = b"a responder static public key";
    let cookie = CookieSecret::new(&[0x55u8; 32])
        .cookie(&suite, b"203.0.113.7:51820")
        .unwrap();
    let bytes = signed_hello(&suite, responder_pk, Some(&cookie));

    let message = Message::parse(&bytes).unwrap();
    let expected_mac1 = mac1(&suite, responder_pk, &message.mac1_input()).unwrap();
    assert_eq!(message.get(tag::MAC1).unwrap(), expected_mac1);
    assert!(message.get(tag::MAC2).is_some());

    // And the gate that consumes it agrees.
    assert_eq!(
        admit_handshake(
            &suite,
            &message,
            responder_pk,
            b"203.0.113.7:51820",
            true,
            Some(&CookieSecret::new(&[0x55u8; 32])),
        )
        .unwrap(),
        Admission::Accept
    );
}
