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
//! # The sealed plaintext carries its own length
//!
//! Every sealed payload is
//!
//! ```text
//! u16 BE true length ‖ payload ‖ zero padding
//! ```
//!
//! and this sits **inside** the AEAD, so the padding is authenticated and the
//! true length cannot be forged, truncated, or extended without the tag failing.
//! What an observer sees is the ciphertext's length — which is now a *chosen*
//! quantity, not a leak of the payload's size. That is the hook the P5 shaping
//! machine pads into: [`Sender::seal_padded`] fixes the pre-image to a target
//! size, and [`Receiver::open`] returns the payload without the padding.
//!
//! The prefix costs two bytes per packet and is always present, so enabling a
//! shaping machine later is a policy change with no wire change. Payloads are
//! capped at [`crate::wire::MAX_DATA_MESSAGE`], far below 2¹⁶, so the prefix's
//! width is never the binding constraint.
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

/// Bytes of length prefix at the front of every sealed payload.
///
/// See the module docs: the prefix is inside the AEAD, and the padding after the
/// payload is what a shaping machine chooses.
pub const PAYLOAD_LEN_SIZE: usize = 2;

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
    /// The packet carries no padding beyond the length prefix. A shaping machine
    /// that wants a chosen on-wire size uses [`Self::seal_padded`].
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
        self.seal_padded(suite, plaintext, plaintext.len() + PAYLOAD_LEN_SIZE)
    }

    /// Seal one transport packet with the sealed plaintext exactly `target`
    /// bytes long, padding with zeros as required.
    ///
    /// `target` is the length of the *pre-image* — length prefix plus payload
    /// plus padding — so both peers (and an observer) see a ciphertext of the
    /// same size whatever the payload was. Use it to give every packet in a
    /// class the same on-wire length; see the P5 shaping machine.
    ///
    /// # Errors
    ///
    /// - [`DataError::PaddingTooSmall`] if `target` cannot hold the length prefix
    ///   and the payload.
    /// - [`DataError::Wire`] if the payload does not fit the length prefix, or
    ///   the framed packet exceeds the size cap.
    /// - [`DataError::CounterExhausted`] as [`Self::seal`].
    /// - [`DataError::Aead`] as [`Self::seal`].
    pub fn seal_padded<S: CryptoSuite + ?Sized>(
        &mut self,
        suite: &S,
        plaintext: &[u8],
        target: usize,
    ) -> Result<Vec<u8>, DataError> {
        let needed = plaintext.len() + PAYLOAD_LEN_SIZE;
        if target < needed {
            return Err(DataError::PaddingTooSmall {
                payload: plaintext.len(),
                target,
            });
        }
        if self.counter >= REJECT_AFTER_MESSAGES {
            return Err(DataError::CounterExhausted {
                counter: self.counter,
            });
        }

        let mut pre_image = vec![0u8; target];
        let len = u16::try_from(plaintext.len()).map_err(|_| {
            DataError::Wire(format!(
                "payload of {} bytes does not fit the {PAYLOAD_LEN_SIZE}-byte length prefix",
                plaintext.len()
            ))
        })?;
        pre_image[..PAYLOAD_LEN_SIZE].copy_from_slice(&len.to_be_bytes());
        pre_image[PAYLOAD_LEN_SIZE..needed].copy_from_slice(plaintext);
        // The rest is already zero: the padding.

        let counter = self.counter;
        let header = self.header();
        let ad = associated_data(&header, counter);
        let nonce = nonce(self.key.nonce_prefix(), counter);
        let ciphertext = suite.aead_seal(self.key.key(), &nonce, &ad, &pre_image)?;

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
    /// - [`DataError::Wire`] if the packet is not a well-formed data message, or
    ///   its authenticated length prefix describes a payload larger than the
    ///   decrypted pre-image.
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
        let pre_image = suite.aead_open(self.key.key(), &nonce, &ad, ciphertext)?;

        // Ordering is the whole point: the tag has now verified, so `counter` is
        // a value the peer really sent. Letting a forged counter reach the
        // window would let an off-path attacker push it forward and drop real
        // traffic.
        self.filter.accept(counter)?;

        // The prefix is inside the AEAD, so it is as authentic as the payload;
        // the padding after it is discarded.
        strip_padding(&pre_image)
    }
}

/// Recover the payload from a decrypted pre-image: `u16 BE length ‖ payload ‖
/// zero padding`.
fn strip_padding(pre_image: &[u8]) -> Result<Vec<u8>, DataError> {
    let Some(prefix) = pre_image.get(..PAYLOAD_LEN_SIZE) else {
        return Err(DataError::Wire(format!(
            "sealed payload is {} bytes, shorter than the {PAYLOAD_LEN_SIZE}-byte \
             length prefix",
            pre_image.len()
        )));
    };
    let len = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));

    // Checked against what actually decrypted, so a length field that claims
    // more than the AEAD returned is a framing error, not a panic.
    let padding = &pre_image[PAYLOAD_LEN_SIZE..];
    let Some(payload) = padding.get(..len) else {
        return Err(DataError::Wire(format!(
            "length prefix claims {len} bytes, pre-image holds {}",
            padding.len()
        )));
    };

    Ok(payload.to_vec())
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

#[cfg(feature = "test-internals")]
impl Sender {
    /// Force the send counter, for the exhaustion tests in the external test
    /// component. Test-only: the feature is never enabled by a library build.
    pub fn force_counter(&mut self, counter: u64) {
        self.counter = counter;
    }
}

#[cfg(feature = "test-internals")]
#[must_use]
pub fn test_nonce(prefix: &[u8; NONCE_PREFIX_SIZE], counter: u64) -> [u8; NONCE_SIZE] {
    nonce(prefix, counter)
}

#[cfg(feature = "test-internals")]
#[must_use]
pub fn test_associated_data(header: &MessageHeader, counter: u64) -> Vec<u8> {
    associated_data(header, counter)
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
