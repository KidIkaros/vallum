// SPDX-License-Identifier: Apache-2.0

//! The data plane: sealing and opening transport packets.
//!
//! Once the handshake completes, both ends hold `KEY`. Each direction then gets
//! its own AEAD key and nonce prefix ([`crate::keys`]), and every tunnelled
//! layer-3 packet becomes one data message:
//!
//! ```text
//! ┌─────────┬──────────┬────────────┬────────────────┐
//! │ version │ type=0x04│  suite_id  │ recipient index│   8-byte header
//! └─────────┴──────────┴────────────┴────────────────┘
//! ┌──────────────┬─────────────────────────────┐
//! │ COUNTER (u64)│ CIPHERTEXT ‖ TAG            │
//! └──────────────┴─────────────────────────────┘
//! ```
//!
//! # What is authenticated, and where
//!
//! The AEAD's associated data is the **header plus the counter**. That binds the
//! protocol version, the message type, the suite id, the recipient index, and
//! the counter to every packet — so a packet cannot be re-aimed at another
//! session, replayed under a different counter, or relabelled as another suite
//! without the tag failing.
//!
//! The transcript and the epoch are *not* in the associated data. They are bound
//! into the AEAD key instead ([`DataKeys`]), which costs nothing per packet. So
//! all of `{transcript, epoch, suite, counter, recipient}` are bound to every
//! packet, at the price of 16 bytes of associated data.
//!
//! # Counter discipline
//!
//! Nonce uniqueness rests on two facts: the nonce is `prefix ‖ counter` with a
//! per-direction prefix, and the counter never repeats under one key.
//! [`Sender`] enforces the second by refusing to seal at
//! [`REJECT_AFTER_MESSAGES`], and asks for a rekey at [`REKEY_AFTER_MESSAGES`].
//! Both are far below 2⁶⁴, so the ceiling exists to bound a key's lifetime (and
//! so the P4 ratchet's post-compromise interval), **not** to protect the nonce
//! space from overflowing.

use vallum_crypto::{CryptoSuite, SharedSecret};

use crate::error::DataError;
use crate::handshake::SessionKeys;
use crate::keys::{
    DataKeys, DirectionalKey, Role, COUNTER_SIZE, DATA_KEY_SIZE, NONCE_PREFIX_SIZE, NONCE_SIZE,
};
use crate::replay::ReplayFilter;
use crate::wire::{
    tag, Message, MessageBuilder, MessageHeader, MessageType, HEADER_LEN, PROTOCOL_VERSION,
};

/// Ask for a fresh handshake once this many packets have been sealed under one
/// key.
///
/// Reaching it is not an error: the tunnel keeps working until the new handshake
/// lands. It bounds how long a compromised key stays useful.
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 48;

/// Refuse to seal at this many packets under one key. The key is spent.
///
/// Twice [`REKEY_AFTER_MESSAGES`], so a peer that ignores the rekey request
/// still has room to keep talking while one is in flight.
pub const REJECT_AFTER_MESSAGES: u64 = 1 << 49;

/// Seals outbound transport packets under one directional key.
#[derive(Debug)]
pub struct Sender {
    suite_id: u16,
    /// The **recipient's** session index. Data packets name the recipient so it
    /// can demux without trusting the source address.
    peer_index: u32,
    key: DirectionalKey,
    epoch: u64,
    counter: u64,
}

impl Sender {
    /// The number of packets sealed under this key so far.
    #[must_use]
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// The epoch this key belongs to.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The recipient's session index that outbound packets name.
    #[must_use]
    pub fn peer_index(&self) -> u32 {
        self.peer_index
    }

    /// Whether the caller should begin a fresh handshake at its next
    /// opportunity.
    #[must_use]
    pub fn needs_rekey(&self) -> bool {
        self.counter >= REKEY_AFTER_MESSAGES
    }

    /// Seal one transport packet.
    ///
    /// `plaintext` is a bare layer-3 packet. An empty payload is a keepalive:
    /// the protocol has no separate message for it, exactly as in WireGuard.
    ///
    /// # Errors
    ///
    /// - [`DataError::CounterExhausted`] if the key reached
    ///   [`REJECT_AFTER_MESSAGES`].
    /// - [`DataError::Aead`] if the suite's seal fails.
    /// - [`DataError::Wire`] if the framed packet exceeds the size cap.
    pub fn seal<S: CryptoSuite + ?Sized>(
        &mut self,
        suite: &S,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, DataError> {
        if self.counter >= REJECT_AFTER_MESSAGES {
            return Err(DataError::CounterExhausted {
                counter: self.counter,
            });
        }

        let counter = self.counter;
        let header = self.header();
        let ad = associated_data(&header, counter);
        let nonce = nonce(self.key.nonce_prefix(), counter);
        let ciphertext = suite.aead_seal(self.key.key(), &nonce, &ad, plaintext)?;

        let mut builder = MessageBuilder::new(header);
        builder.field(tag::COUNTER, &counter.to_be_bytes())?;
        builder.field(tag::DATA_CT, &ciphertext)?;
        let packet = builder.finish()?;

        // Only on success: a failed seal must not burn a counter value, or a
        // caller retrying in a loop would advance to the ceiling for nothing.
        self.counter += 1;
        Ok(packet)
    }

    fn header(&self) -> MessageHeader {
        MessageHeader {
            version: PROTOCOL_VERSION,
            message_type: MessageType::Data,
            suite_id: self.suite_id,
            sender_index: self.peer_index,
        }
    }
}

/// Opens inbound transport packets under one directional key, dropping replays.
#[derive(Debug)]
pub struct Receiver {
    suite_id: u16,
    /// Our own session index; a data packet must name it.
    own_index: u32,
    key: DirectionalKey,
    epoch: u64,
    filter: ReplayFilter,
}

impl Receiver {
    /// The epoch this key belongs to.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Our own session index; an inbound packet must name it.
    #[must_use]
    pub fn own_index(&self) -> u32 {
        self.own_index
    }

    /// One past the highest counter accepted so far.
    #[must_use]
    pub fn next_counter(&self) -> u64 {
        self.filter.next()
    }

    /// Open one transport packet.
    ///
    /// # Errors
    ///
    /// - [`DataError::Wire`] if the packet is not a well-formed data message.
    /// - [`DataError::WrongIndex`] if it names another session.
    /// - [`DataError::Aead`] if the tag does not verify.
    /// - [`DataError::Replay`] if the (authenticated) counter was already
    ///   accepted or has aged out of the window.
    /// - [`DataError::CounterExhausted`] if the counter is past the key's
    ///   ceiling.
    pub fn open<S: CryptoSuite + ?Sized>(
        &mut self,
        suite: &S,
        packet: &[u8],
    ) -> Result<Vec<u8>, DataError> {
        let message = Message::parse(packet)?;
        message.expect_type(MessageType::Data)?;
        message.expect_suite(self.suite_id)?;

        let sender_index = message.sender_index();
        if sender_index != self.own_index {
            return Err(DataError::WrongIndex {
                expected: self.own_index,
                got: sender_index,
            });
        }

        let counter = u64::from_be_bytes(message.require_array::<COUNTER_SIZE>(tag::COUNTER)?);
        let ciphertext = message.require(tag::DATA_CT)?;

        // The associated data is rebuilt from the *parsed* header, so it is
        // exactly what the sender authenticated (or the tag fails).
        let ad = associated_data(&message.header(), counter);
        let nonce = nonce(self.key.nonce_prefix(), counter);
        let plaintext = suite.aead_open(self.key.key(), &nonce, &ad, ciphertext)?;

        // Ordering is the whole point: the tag has now verified, so `counter` is
        // a value the peer really sent. Letting a forged counter reach the
        // window would let an off-path attacker push it forward and drop real
        // traffic.
        self.filter.accept(counter)?;
        Ok(plaintext)
    }
}

/// Establish the data plane for one endpoint from a finished handshake.
///
/// `role` is which end we are. The indices come from [`SessionKeys`], and the
/// role decides which directional key sends — so neither the direction pair nor
/// the index pair can be miswired by a caller.
///
/// # Errors
///
/// [`DataError::Kdf`] if the suite's key schedule fails or its AEAD geometry is
/// not the shape the data plane assumes.
pub fn establish<S: CryptoSuite + ?Sized>(
    suite: &S,
    session: &SessionKeys,
    role: Role,
) -> Result<(Sender, Receiver), DataError> {
    establish_epoch(
        suite,
        &session.key,
        &session.transcript,
        0,
        role,
        session.own_index,
        session.peer_index,
    )
}

/// As [`establish`], but from an arbitrary epoch root and index pair.
///
/// The epoch axis's low-level entry point. [`crate::session::Session`] is the
/// intended caller: it installs epoch `0` from a handshake and each later epoch
/// from a **new** handshake's result ([`crate::session::Session::advance`]).
///
/// Reusing an `epoch` value with a different root is a protocol error the key
/// schedule cannot detect — the caller owns epoch monotonicity. [`Session`] is
/// what discharges that obligation.
///
/// [`Session`]: crate::session::Session
///
/// # Errors
///
/// As [`establish`].
pub fn establish_epoch<S: CryptoSuite + ?Sized>(
    suite: &S,
    epoch_root: &SharedSecret,
    transcript: &[u8; 32],
    epoch: u64,
    role: Role,
    own_index: u32,
    peer_index: u32,
) -> Result<(Sender, Receiver), DataError> {
    let suite_id = suite.suite_id();
    let keys = DataKeys::derive(suite, epoch_root, transcript, epoch)?;
    let (sending, receiving) = keys.split(role);

    Ok((
        Sender {
            suite_id,
            peer_index,
            key: sending,
            epoch,
            counter: 0,
        },
        Receiver {
            suite_id,
            own_index,
            key: receiving,
            epoch,
            filter: ReplayFilter::new(),
        },
    ))
}

/// The associated data for a data packet: its header followed by its counter.
fn associated_data(header: &MessageHeader, counter: u64) -> Vec<u8> {
    let mut ad = Vec::with_capacity(HEADER_LEN + COUNTER_SIZE);
    ad.extend_from_slice(&header.encode());
    ad.extend_from_slice(&counter.to_be_bytes());
    ad
}

/// Build the 24-byte nonce: the per-key prefix followed by the counter.
fn nonce(prefix: &[u8; NONCE_PREFIX_SIZE], counter: u64) -> [u8; NONCE_SIZE] {
    let mut out = [0u8; NONCE_SIZE];
    out[..NONCE_PREFIX_SIZE].copy_from_slice(prefix);
    out[NONCE_PREFIX_SIZE..].copy_from_slice(&counter.to_be_bytes());
    out
}

// The nonce is exactly a prefix plus a counter; if these ever diverge the
// `copy_from_slice` above would panic rather than silently truncate.
const _: () = assert!(NONCE_PREFIX_SIZE + COUNTER_SIZE == NONCE_SIZE);
const _: () = assert!(DATA_KEY_SIZE == 32);

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::wire::MessageHeader;
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
        // 8-byte header + COUNTER TLV (4 + 8) + DATA_CT TLV (4 + tag).
        assert_eq!(packet.len(), HEADER_LEN + 12 + 4 + 32);
        assert_eq!(b_recv.next_counter(), 1, "a keepalive consumes a counter");
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
        a_send.counter = REKEY_AFTER_MESSAGES - 1;
        assert!(!a_send.needs_rekey());
        a_send
            .seal(&suite, b"the last one before the request")
            .unwrap();
        assert_eq!(a_send.counter(), REKEY_AFTER_MESSAGES);
        assert!(a_send.needs_rekey(), "now the caller must rekey");

        // Crossing the rejection threshold is a hard stop.
        a_send.counter = REJECT_AFTER_MESSAGES;
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
        let built = nonce(&prefix, 0x0102_0304_0506_0708);
        assert_eq!(built[..NONCE_PREFIX_SIZE], prefix);
        assert_eq!(
            built[NONCE_PREFIX_SIZE..],
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
        // Big-endian, so nonces sort with counters.
        assert!(nonce(&prefix, 1) > nonce(&prefix, 0));
    }

    #[test]
    fn the_associated_data_is_the_header_then_the_counter() {
        let header = MessageHeader {
            version: PROTOCOL_VERSION,
            message_type: MessageType::Data,
            suite_id: 0x0003,
            sender_index: 0x0A0B_0C0D,
        };
        let ad = associated_data(&header, 0x1234);
        assert_eq!(&ad[..HEADER_LEN], &header.encode());
        assert_eq!(&ad[HEADER_LEN..], &[0, 0, 0, 0, 0, 0, 0x12, 0x34]);
        assert_eq!(ad.len(), HEADER_LEN + COUNTER_SIZE);
    }
}
