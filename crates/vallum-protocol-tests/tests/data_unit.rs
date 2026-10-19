#![allow(clippy::expect_used, clippy::unwrap_used)]

use vallum_core::data::*;
use vallum_core::data::{test_associated_data, test_nonce};
use vallum_core::wire::MessageHeader;
use vallum_core::wire::{tag, Message, MessageBuilder, MessageType, HEADER_LEN, PROTOCOL_VERSION};
use vallum_core::{DataError, Role, SessionKeys, COUNTER_SIZE, NONCE_PREFIX_SIZE};
use vallum_crypto::{CryptoSuite, SharedSecret};
use vallum_crypto_sdk::SdkSuite;

const OWN: u32 = 0x1111_1111;
const PEER: u32 = 0x2222_2222;

fn session(transcript: [u8; 32], key: [u8; 32]) -> SessionKeys {
    SessionKeys {
        transcript,
        key: SharedSecret::new(key),
        confirm_initiator: SharedSecret::new([1u8; 32]),
        confirm_responder: SharedSecret::new([2u8; 32]),
        own_index: OWN,
        peer_index: PEER,
    }
}

/// The state a completed handshake leaves behind, wired as a real pair with
/// mirrored indices: `(suite, a_send, a_recv, b_send, b_recv)`.
///
/// `a` is the initiator: its own index is [`OWN`] and the peer's is [`PEER`].
/// `b` is the responder, so its own index is [`PEER`] and its peer's is
/// [`OWN`] — which is exactly what makes `a`'s packets addressable by `b`.
fn pair() -> (SdkSuite, Sender, Receiver, Sender, Receiver) {
    let suite = SdkSuite::tri_hybrid();

    let a = session([7u8; 32], [9u8; 32]);
    let mut b = session([7u8; 32], [9u8; 32]);
    b.own_index = PEER;
    b.peer_index = OWN;

    let (a_send, a_recv) = establish(&suite, &a, Role::Initiator).unwrap();
    let (b_send, b_recv) = establish(&suite, &b, Role::Responder).unwrap();
    (suite, a_send, a_recv, b_send, b_recv)
}

/// Rebuild a packet with the same header, counter, and ciphertext bytes, but
/// a chosen counter. Used to forge a counter that the tag does not cover.
fn rebuild_with_counter(packet: &[u8], counter: u64) -> Vec<u8> {
    let parsed = Message::parse(packet).unwrap();
    let ciphertext = parsed.require(tag::DATA_CT).unwrap();
    let mut builder = MessageBuilder::new(parsed.header());
    builder.field(tag::COUNTER, &counter.to_be_bytes()).unwrap();
    builder.field(tag::DATA_CT, ciphertext).unwrap();
    builder.finish().unwrap()
}

#[test]
fn a_packet_round_trips_in_each_direction() {
    let (suite, mut a_send, mut a_recv, mut b_send, mut b_recv) = pair();

    let packet = a_send.seal(&suite, b"an inner IP packet").unwrap();
    assert_eq!(b_recv.open(&suite, &packet).unwrap(), b"an inner IP packet");

    let packet = b_send.seal(&suite, b"the reply").unwrap();
    assert_eq!(a_recv.open(&suite, &packet).unwrap(), b"the reply");
}

#[test]
fn a_packet_only_opens_in_the_direction_it_was_sealed() {
    let (suite, mut a_send, mut a_recv, mut b_send, mut b_recv) = pair();

    let from_a = a_send.seal(&suite, b"from a").unwrap();
    let from_b = b_send.seal(&suite, b"from b").unwrap();

    assert_eq!(b_recv.open(&suite, &from_a).unwrap(), b"from a");
    assert_eq!(a_recv.open(&suite, &from_b).unwrap(), b"from b");

    // Feeding a packet back to the endpoint that sealed it is refused. It is
    // caught twice over: the directions use different keys, and a data
    // packet names its *recipient*, so the index is already wrong here.
    assert!(matches!(
        a_recv.open(&suite, &from_a),
        Err(DataError::WrongIndex { .. })
    ));
    assert!(matches!(
        b_recv.open(&suite, &from_b),
        Err(DataError::WrongIndex { .. })
    ));
}

#[test]
fn the_two_directions_do_not_share_a_key() {
    // Move the index guard out of the way so only the key can decide: build a
    // receiver that holds the responder's *receiving* key but expects the
    // index the responder's sender stamps.
    let (suite, _, _, mut b_send, _) = pair();
    let (_, mut receiver_for_b) = establish_epoch(
        &suite,
        &SharedSecret::new([9u8; 32]),
        &[7u8; 32],
        0,
        Role::Responder,
        OWN,
        PEER,
    )
    .unwrap();

    let packet = b_send.seal(&suite, b"b speaking").unwrap();
    assert!(matches!(
        receiver_for_b.open(&suite, &packet),
        Err(DataError::Aead(_))
    ));
}

#[test]
fn another_session_cannot_open_our_packets() {
    // The eavesdropper is given the index `a` addresses, so the packet gets
    // past demultiplexing and only the key can stop it.
    let (suite, mut a_send, _, _, _) = pair();
    let (_, mut eavesdropper) = establish_epoch(
        &suite,
        &SharedSecret::new([0xBBu8; 32]),
        &[0xAAu8; 32],
        0,
        Role::Responder,
        PEER,
        OWN,
    )
    .unwrap();

    let packet = a_send.seal(&suite, b"secret").unwrap();
    assert!(matches!(
        eavesdropper.open(&suite, &packet),
        Err(DataError::Aead(_))
    ));
}

#[test]
fn a_keepalive_is_an_empty_payload() {
    let (suite, mut a_send, _, _, mut b_recv) = pair();
    let packet = a_send.seal(&suite, &[]).unwrap();
    assert_eq!(b_recv.open(&suite, &packet).unwrap(), b"");
    // 8-byte header + COUNTER TLV (4 + 8) + DATA_CT TLV (4 + tag), where the
    // sealed plaintext is just the 2-byte length prefix.
    assert_eq!(packet.len(), HEADER_LEN + 12 + 4 + 32 + PAYLOAD_LEN_SIZE);
    assert_eq!(b_recv.next_counter(), 1, "a keepalive consumes a counter");
}

#[test]
fn padding_hides_the_payload_length_and_is_recovered_exactly() {
    let (suite, mut a_send, _, _, mut b_recv) = pair();

    // Two payloads of very different lengths, padded to one target, produce
    // ciphertexts of the same size — which is the whole point.
    let short = a_send.seal_padded(&suite, b"x", 512).unwrap();
    let long = a_send.seal_padded(&suite, &[0xAB; 400], 512).unwrap();
    assert_eq!(short.len(), long.len(), "same target, same on-wire size");

    // The receiver recovers each payload without its padding.
    assert_eq!(b_recv.open(&suite, &short).unwrap(), b"x");
    assert_eq!(b_recv.open(&suite, &long).unwrap(), vec![0xAB; 400]);

    // A target exactly big enough needs no padding at all.
    let exact = a_send
        .seal_padded(&suite, b"abc", 3 + PAYLOAD_LEN_SIZE)
        .unwrap();
    assert_eq!(b_recv.open(&suite, &exact).unwrap(), b"abc");

    // A target that cannot hold the payload is refused, and burns no counter.
    let before = a_send.counter();
    assert_eq!(
        a_send.seal_padded(&suite, b"abc", 3 + PAYLOAD_LEN_SIZE - 1),
        Err(DataError::PaddingTooSmall {
            payload: 3,
            target: 3 + PAYLOAD_LEN_SIZE - 1,
        })
    );
    assert_eq!(a_send.counter(), before);
}

#[test]
fn a_forged_length_prefix_fails_the_tag() {
    let (suite, mut a_send, _, _, mut b_recv) = pair();
    let packet = a_send.seal_padded(&suite, b"payload", 128).unwrap();

    // The pre-image is `u16 len ‖ payload ‖ zeros` inside DATA_CT, so the
    // first two ciphertext bytes are the encrypted length prefix. Flip one:
    // the padding scheme must not degrade into a malleable length field.
    let ct_at = HEADER_LEN + 4 + COUNTER_SIZE + 4;
    let mut forged = packet.clone();
    forged[ct_at] ^= 0x01;
    assert!(matches!(
        b_recv.open(&suite, &forged),
        Err(DataError::Aead(_))
    ));
    assert_eq!(b_recv.next_counter(), 0, "no forgery moved the window");
}

#[test]
fn the_counter_is_authenticated_so_a_forgery_cannot_move_the_window() {
    let (suite, mut a_send, _, _, mut b_recv) = pair();
    let honest = a_send.seal(&suite, b"one").unwrap();
    let other = a_send.seal(&suite, b"two").unwrap();

    // Re-label the real ciphertext with a counter the sender never sealed.
    let forged = rebuild_with_counter(&other, 0xDEAD_BEEF);
    assert!(matches!(
        b_recv.open(&suite, &forged),
        Err(DataError::Aead(_))
    ));
    assert_eq!(b_recv.next_counter(), 0, "the window did not move");

    // The genuine packets still open, at their genuine counters.
    assert_eq!(b_recv.open(&suite, &honest).unwrap(), b"one");
    assert_eq!(b_recv.open(&suite, &other).unwrap(), b"two");
    assert_eq!(b_recv.next_counter(), 2);
}

#[test]
fn a_tampered_tag_or_ciphertext_is_rejected() {
    let (suite, mut a_send, _, _, mut b_recv) = pair();
    let packet = a_send.seal(&suite, b"payload").unwrap();

    let mut flipped_tag = packet.clone();
    let last = flipped_tag.len() - 1;
    flipped_tag[last] ^= 0x01;
    assert!(matches!(
        b_recv.open(&suite, &flipped_tag),
        Err(DataError::Aead(_))
    ));

    // The COUNTER field is first and DATA_CT second, so the first
    // ciphertext byte sits just past both TLV headers.
    let ct_at = HEADER_LEN + 4 + COUNTER_SIZE + 4;
    let mut flipped_ct = packet.clone();
    flipped_ct[ct_at] ^= 0x01;
    assert!(matches!(
        b_recv.open(&suite, &flipped_ct),
        Err(DataError::Aead(_))
    ));

    assert_eq!(b_recv.next_counter(), 0, "no forgery moved the window");
    assert_eq!(b_recv.open(&suite, &packet).unwrap(), b"payload");
}

#[test]
fn a_packet_for_another_session_is_refused_before_any_crypto() {
    let (suite, mut a_send, _, _, mut b_recv) = pair();
    let mut packet = a_send.seal(&suite, b"payload").unwrap();
    packet[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    assert_eq!(
        b_recv.open(&suite, &packet),
        Err(DataError::WrongIndex {
            expected: PEER,
            got: 0xDEAD_BEEF,
        })
    );
}

#[test]
fn a_foreign_suite_id_on_the_wire_is_refused() {
    let (suite, mut a_send, _, _, mut b_recv) = pair();
    let mut packet = a_send.seal(&suite, b"payload").unwrap();
    packet[2..4].copy_from_slice(&0x0001u16.to_be_bytes());
    assert!(b_recv.open(&suite, &packet).is_err());
}

#[test]
fn a_handshake_message_is_not_a_data_message() {
    let (suite, _, _, _, mut b_recv) = pair();
    let header = MessageHeader {
        version: PROTOCOL_VERSION,
        message_type: MessageType::InitHello,
        suite_id: suite.suite_id(),
        sender_index: OWN,
    };
    let mut builder = MessageBuilder::new(header);
    builder.field(tag::COUNTER, &7u64.to_be_bytes()).unwrap();
    builder.field(tag::DATA_CT, &[0u8; 32]).unwrap();
    let bytes = builder.finish().unwrap();
    assert!(matches!(
        b_recv.open(&suite, &bytes),
        Err(DataError::Wire(_))
    ));
}

#[test]
fn a_spent_key_refuses_to_seal_again() {
    let (suite, mut a_send, _, _, _) = pair();

    // Crossing the rekey threshold is a request, not a failure.
    a_send.force_counter(REKEY_AFTER_MESSAGES - 1);
    assert!(!a_send.needs_rekey());
    a_send
        .seal(&suite, b"the last one before the request")
        .unwrap();
    assert_eq!(a_send.counter(), REKEY_AFTER_MESSAGES);
    assert!(a_send.needs_rekey(), "now the caller must rekey");

    // Crossing the rejection threshold is a hard stop.
    a_send.force_counter(REJECT_AFTER_MESSAGES);
    assert_eq!(
        a_send.seal(&suite, b"one too many"),
        Err(DataError::CounterExhausted {
            counter: REJECT_AFTER_MESSAGES
        })
    );
    assert_eq!(a_send.counter(), REJECT_AFTER_MESSAGES, "no counter burned");
}

#[test]
fn the_nonce_is_the_prefix_then_the_counter() {
    let prefix = [0xABu8; NONCE_PREFIX_SIZE];
    let built = test_nonce(&prefix, 0x0102_0304_0506_0708);
    assert_eq!(built[..NONCE_PREFIX_SIZE], prefix);
    assert_eq!(
        built[NONCE_PREFIX_SIZE..],
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    );
    // Big-endian, so nonces sort with counters.
    assert!(test_nonce(&prefix, 1) > test_nonce(&prefix, 0));
}

#[test]
fn the_associated_data_is_the_header_then_the_counter() {
    let header = MessageHeader {
        version: PROTOCOL_VERSION,
        message_type: MessageType::Data,
        suite_id: 0x0003,
        sender_index: 0x0A0B_0C0D,
    };
    let ad = test_associated_data(&header, 0x1234);
    assert_eq!(&ad[..HEADER_LEN], &header.encode());
    assert_eq!(&ad[HEADER_LEN..], &[0, 0, 0, 0, 0, 0, 0x12, 0x34]);
    assert_eq!(ad.len(), HEADER_LEN + COUNTER_SIZE);
}
