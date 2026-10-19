// SPDX-License-Identifier: Apache-2.0

//! Self-describing TLV framing for handshake messages.
//!
//! Every handshake message is an 8-byte fixed header followed by zero or more
//! tag/length/value fields:
//!
//! ```text
//! ┌─────────┬──────────┬────────────┬───────────────┐
//! │ version │ msg_type │  suite_id  │  sender_index │   8-byte header
//! │   u8    │    u8    │  u16 (BE)  │    u32 (BE)   │
//! └─────────┴──────────┴────────────┴───────────────┘
//! then, repeated:
//! ┌─────────┬─────────┬──────────────────┐
//! │   tag   │   len   │       value      │   len ≤ 65535
//! │ u16(BE) │ u16(BE) │    len bytes     │
//! └─────────┴─────────┴──────────────────┘
//! ```
//!
//! TLV means the parser never needs the suite's size table — a suite that adds
//! or reorders legs still parses — while the protocol can still *assert* the
//! lengths it expects. Unknown tags are tolerated by the parser and simply
//! unread by this version, which is what lets P2 add WireGuard-style cookies
//! (`mac1`/`mac2`) without a format break.
//!
//! Two rules make the encoding unambiguous and safe:
//!
//! 1. **No duplicate tags** — a repeated tag is rejected outright, so a field
//!    can never be shadowed by a later one.
//! 2. **A hard size cap** — a message over [`MAX_HANDSHAKE_MESSAGE`] is refused
//!    on both build and parse, so a handshake is never split across IP
//!    fragments. Nothing relies on fragmentation.

use crate::error::HandshakeError;

/// The protocol version this build speaks.
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Length of a handshake header, in bytes.
pub const HEADER_LEN: usize = 8;

/// Hard cap on a single handshake message, in bytes.
///
/// The largest message the default tri-hybrid suite produces is well under this
/// (about 4.6 KiB). A handshake that does not fit is a protocol error, never a
/// fragmentation opportunity.
pub const MAX_HANDSHAKE_MESSAGE: usize = 16 * 1024;

/// Hard cap on a single data message, in bytes.
///
/// Deliberately the same value as [`MAX_HANDSHAKE_MESSAGE`]. A tunnelled
/// layer-3 packet is MTU-bounded — comfortably under 2 KiB — so this cap is a
/// memory bound against a hostile peer, not a fragmentation budget. One parser
/// and one cap for both planes means there is no second framing implementation
/// to get subtly wrong.
pub const MAX_DATA_MESSAGE: usize = MAX_HANDSHAKE_MESSAGE;

/// Length of a TAI64N timestamp, as in WireGuard.
pub const TIMESTAMP_SIZE: usize = 12;

/// Length of a session index on the wire.
pub const INDEX_SIZE: usize = 4;

/// Length of a key-confirmation value.
pub const CONFIRMATION_SIZE: usize = 32;

/// Handshake message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// Initiator → responder: static ciphertext, ephemeral key, timestamp.
    InitHello,
    /// Responder → initiator: ephemeral ciphertext, static ciphertext.
    RespHello,
    /// Initiator → responder: explicit key confirmation.
    InitConf,
    /// Either direction: an encrypted transport packet (P2).
    Data,
    /// A detached identity document (P3): a signed KEM ↔ signing key binding.
    ///
    /// Not a handshake message — it rides the same framing so there is one
    /// parser and one set of caps, but it is never exchanged *inside* a
    /// handshake.
    IdentityDoc,
    /// Responder → initiator: a cookie for the source address (P6).
    ///
    /// Answers an `InitHello` that carried no valid `mac2` while the responder
    /// was under load. Not part of a handshake transcript: it is a retry
    /// instruction, and a session that never sees one is unaffected.
    CookieReply,
}

impl MessageType {
    /// The wire code for this type.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Self::InitHello => 0x01,
            Self::RespHello => 0x02,
            Self::InitConf => 0x03,
            Self::Data => 0x04,
            Self::IdentityDoc => 0x05,
            Self::CookieReply => 0x06,
        }
    }

    /// Parse a wire code.
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0x01 => Some(Self::InitHello),
            0x02 => Some(Self::RespHello),
            0x03 => Some(Self::InitConf),
            0x04 => Some(Self::Data),
            0x05 => Some(Self::IdentityDoc),
            0x06 => Some(Self::CookieReply),
            _ => None,
        }
    }

    /// A short name for diagnostics.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::InitHello => "InitHello",
            Self::RespHello => "RespHello",
            Self::InitConf => "InitConf",
            Self::Data => "Data",
            Self::IdentityDoc => "IdentityDoc",
            Self::CookieReply => "CookieReply",
        }
    }
}

/// TLV tags.
///
/// `0x0001..=0x0FFF` are core handshake fields, `0x0010..` are later-phase
/// additions, and `0x8000..` is reserved for future use.
pub mod tag {
    /// A ciphertext to a peer's **static** KEM key.
    pub const STATIC_CT: u16 = 0x0001;
    /// A ciphertext to a peer's **ephemeral** KEM key.
    pub const EPHEMERAL_CT: u16 = 0x0002;
    /// The sender's hybrid KEM ephemeral public key.
    pub const EPHEMERAL_PK: u16 = 0x0003;
    /// TAI64N timestamp ([`super::TIMESTAMP_SIZE`] bytes).
    pub const TIMESTAMP: u16 = 0x0004;
    /// The sender index this message replies to ([`super::INDEX_SIZE`] bytes, BE).
    pub const RECEIVER_INDEX: u16 = 0x0005;
    /// A data message's 64-bit packet counter (P2).
    pub const COUNTER: u16 = 0x0006;
    /// The sealed peer hint on an `InitHello` (P6).
    ///
    /// A short fingerprint of the initiator's static KEM public key, sealed so
    /// only the responder can read it. The responder needs it because op A is
    /// encapsulated to the responder's *own* static key and so says nothing
    /// about who sent it, while op C — the leg that names the initiator — cannot
    /// be built until the peer is known. See [`crate::handshake`].
    pub const PEER_HINT: u16 = 0x0007;
    /// A key-confirmation value ([`super::CONFIRMATION_SIZE`] bytes).
    pub const CONFIRMATION: u16 = 0x0010;
    /// A hybrid identity signature (P3).
    pub const IDENTITY_SIG: u16 = 0x0020;
    /// An identity document's label (P3).
    pub const IDENTITY_LABEL: u16 = 0x0021;
    /// A KEM public key inside an identity document (P3).
    pub const KEM_PUBLIC: u16 = 0x0022;
    /// A signing public key inside an identity document (P3).
    pub const SIGN_PUBLIC: u16 = 0x0023;
    /// WireGuard-style `mac1` cookie (P2).
    pub const MAC1: u16 = 0x0030;
    /// WireGuard-style `mac2` cookie (P2).
    pub const MAC2: u16 = 0x0031;
    /// A cookie reply's nonce ([`crate::keys::NONCE_SIZE`] bytes, P6).
    pub const COOKIE_NONCE: u16 = 0x0032;
    /// A cookie reply's sealed cookie ([`crate::cookie::COOKIE_SIZE`] plus the
    /// AEAD tag, P6).
    pub const COOKIE_CT: u16 = 0x0033;
    /// A data message's AEAD ciphertext, tag appended (P2).
    pub const DATA_CT: u16 = 0x0040;
}

/// Tags that a cookie MAC must not cover.
///
/// `mac1` and `mac2` are computed over the message *excluding* these fields —
/// see [`Message::mac1_input`]. Keeping the list in one place is what makes the
/// sender and receiver agree on the exact bytes.
pub const MAC_TAGS: [u16; 2] = [tag::MAC1, tag::MAC2];

/// A parsed 8-byte handshake header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageHeader {
    /// Protocol version.
    pub version: u8,
    /// Message type.
    pub message_type: MessageType,
    /// Suite id — bound into the transcript, so a downgrade changes every key.
    pub suite_id: u16,
    /// The sender's 32-bit session index.
    pub sender_index: u32,
}

impl MessageHeader {
    /// Encode to the fixed 8-byte form.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0] = self.version;
        out[1] = self.message_type.code();
        out[2..4].copy_from_slice(&self.suite_id.to_be_bytes());
        out[4..8].copy_from_slice(&self.sender_index.to_be_bytes());
        out
    }

    /// Decode from the fixed 8-byte form.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Wire`] if the buffer is too short or the message type
    /// is unknown.
    pub fn decode(buf: &[u8]) -> Result<Self, HandshakeError> {
        let head = buf.get(..HEADER_LEN).ok_or_else(|| {
            HandshakeError::Wire(format!("shorter than the {HEADER_LEN}-byte header"))
        })?;
        let message_type = MessageType::from_code(head[1]).ok_or_else(|| {
            HandshakeError::Wire(format!("unknown message type {:#04x}", head[1]))
        })?;
        Ok(Self {
            version: head[0],
            message_type,
            suite_id: u16::from_be_bytes([head[2], head[3]]),
            sender_index: u32::from_be_bytes([head[4], head[5], head[6], head[7]]),
        })
    }
}

/// Serialize a header plus TLV fields in order, skipping the tags in `exclude`.
///
/// Shared by [`MessageBuilder`] and [`Message`] so the bytes a cookie MAC covers
/// are constructed identically on both ends.
fn serialize_fields<T: AsRef<[u8]>>(
    header: MessageHeader,
    fields: &[(u16, T)],
    exclude: &[u16],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&header.encode());
    for (tag, value) in fields {
        if exclude.contains(tag) {
            continue;
        }
        let value = value.as_ref();
        // Bounded by the 65535 field limit: the builder validates on append and
        // the parser reads the length as a `u16`, so this cannot truncate.
        let len = value.len() as u16;
        out.extend_from_slice(&tag.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(value);
    }
    out
}

/// Builds a handshake or data message field by field.
#[derive(Debug)]
pub struct MessageBuilder {
    header: MessageHeader,
    fields: Vec<(u16, Vec<u8>)>,
}

impl MessageBuilder {
    /// Start a message.
    #[must_use]
    pub fn new(header: MessageHeader) -> Self {
        Self {
            header,
            fields: Vec::new(),
        }
    }

    /// Append one TLV field.
    ///
    /// The cookie fields are ordered, because a `mac1`/`mac2` is computed over
    /// the fields present when it is added ([`MessageBuilder::mac1_input`]): all
    /// other fields must come before `mac1`, and `mac2` must come after it.
    /// Trying to add them in any other order is an error rather than a message
    /// whose MAC the receiver would compute differently.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Wire`] if the value is longer than `u16::MAX` bytes,
    /// if the tag was already added (the parser rejects duplicates, so refusing
    /// to build one keeps every built message parseable), or if the cookie
    /// fields are out of order.
    pub fn field(&mut self, tag: u16, value: &[u8]) -> Result<&mut Self, HandshakeError> {
        u16::try_from(value.len()).map_err(|_| {
            HandshakeError::Wire(format!(
                "field {tag:#06x} is {} bytes, over the 65535 limit",
                value.len()
            ))
        })?;
        if self.fields.iter().any(|(t, _)| *t == tag) {
            return Err(HandshakeError::Wire(format!("duplicate tag {tag:#06x}")));
        }

        let is_mac1 = tag == tag::MAC1;
        let is_mac2 = tag == tag::MAC2;
        let has_mac1 = self.fields.iter().any(|(t, _)| *t == tag::MAC1);
        if is_mac2 && !has_mac1 {
            return Err(HandshakeError::Wire("mac2 must be added after mac1".into()));
        }
        if !is_mac1 && !is_mac2 && has_mac1 {
            return Err(HandshakeError::Wire(
                "no field may be added after mac1".into(),
            ));
        }

        self.fields.push((tag, value.to_vec()));
        Ok(self)
    }

    /// The bytes a `mac1` must cover: the header followed by every field so far
    /// **except** the cookie fields, in wire order.
    ///
    /// Call this once the non-cookie fields are in, before adding `mac1`.
    #[must_use]
    pub fn mac1_input(&self) -> Vec<u8> {
        self.serialize(&MAC_TAGS)
    }

    /// The bytes a `mac2` must cover: the header followed by every field so far
    /// **except** `mac2` itself, so the `mac1` already present is included.
    ///
    /// Call this after adding `mac1`, before adding `mac2`.
    #[must_use]
    pub fn mac2_input(&self) -> Vec<u8> {
        self.serialize(&[tag::MAC2])
    }

    /// Serialize header plus fields in order, skipping `exclude`.
    fn serialize(&self, exclude: &[u16]) -> Vec<u8> {
        serialize_fields(self.header, &self.fields, exclude)
    }

    /// Finish, returning the wire bytes.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Wire`] if the assembled message exceeds the size cap.
    pub fn finish(self) -> Result<Vec<u8>, HandshakeError> {
        let out = self.serialize(&[]);
        if out.len() > MAX_HANDSHAKE_MESSAGE {
            return Err(HandshakeError::Wire(format!(
                "message would be {} bytes, over the {MAX_HANDSHAKE_MESSAGE}-byte cap",
                out.len()
            )));
        }
        Ok(out)
    }
}

/// A parsed handshake message.
#[derive(Debug)]
pub struct Message<'a> {
    header: MessageHeader,
    fields: Vec<(u16, &'a [u8])>,
}

impl<'a> Message<'a> {
    /// Parse a handshake message.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Wire`] for a truncated header, a truncated or
    /// over-long field, a duplicate tag, or a message over the size cap;
    /// [`HandshakeError::VersionMismatch`] for an unexpected protocol version.
    pub fn parse(buf: &'a [u8]) -> Result<Self, HandshakeError> {
        if buf.len() > MAX_HANDSHAKE_MESSAGE {
            return Err(HandshakeError::Wire(format!(
                "message is {} bytes, over the {MAX_HANDSHAKE_MESSAGE}-byte cap",
                buf.len()
            )));
        }
        let header = MessageHeader::decode(buf)?;
        if header.version != PROTOCOL_VERSION {
            return Err(HandshakeError::VersionMismatch {
                expected: PROTOCOL_VERSION,
                got: header.version,
            });
        }

        let mut fields: Vec<(u16, &'a [u8])> = Vec::new();
        let mut pos = HEADER_LEN;
        while pos < buf.len() {
            // Bounded by `buf.len() <= MAX_HANDSHAKE_MESSAGE`, so `+ 4` cannot
            // overflow; a shorter tail is simply a truncated header.
            let Some(head) = buf.get(pos..pos + 4) else {
                return Err(HandshakeError::Wire("truncated TLV header".into()));
            };
            let tag = u16::from_be_bytes([head[0], head[1]]);
            let len = usize::from(u16::from_be_bytes([head[2], head[3]]));
            let start = pos + 4;
            let value = buf
                .get(start..)
                .and_then(|rest| rest.get(..len))
                .ok_or_else(|| {
                    HandshakeError::Wire(format!(
                        "field {tag:#06x} claims {len} bytes, past the end of the message"
                    ))
                })?;
            if fields.iter().any(|(t, _)| *t == tag) {
                return Err(HandshakeError::Wire(format!("duplicate tag {tag:#06x}")));
            }
            fields.push((tag, value));
            pos = start + len;
        }

        Ok(Self { header, fields })
    }

    /// The parsed header.
    #[must_use]
    pub fn header(&self) -> MessageHeader {
        self.header
    }

    /// The message type.
    #[must_use]
    pub fn message_type(&self) -> MessageType {
        self.header.message_type
    }

    /// The sender's session index.
    #[must_use]
    pub fn sender_index(&self) -> u32 {
        self.header.sender_index
    }

    /// Fetch a field, if present.
    #[must_use]
    pub fn get(&self, tag: u16) -> Option<&'a [u8]> {
        self.fields.iter().find(|(t, _)| *t == tag).map(|(_, v)| *v)
    }

    /// Fetch a required field.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Wire`] if the field is absent.
    pub fn require(&self, tag: u16) -> Result<&'a [u8], HandshakeError> {
        self.get(tag)
            .ok_or_else(|| HandshakeError::Wire(format!("missing required field {tag:#06x}")))
    }

    /// Fetch a required fixed-size field.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Wire`] if the field is absent or not exactly `N` bytes.
    pub fn require_array<const N: usize>(&self, tag: u16) -> Result<[u8; N], HandshakeError> {
        let value = self.require(tag)?;
        <[u8; N]>::try_from(value).map_err(|_| {
            HandshakeError::Wire(format!(
                "field {tag:#06x} must be {N} bytes, got {}",
                value.len()
            ))
        })
    }

    /// The number of fields carried.
    #[must_use]
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }

    /// The tags carried, in order.
    pub fn tags(&self) -> impl Iterator<Item = u16> + '_ {
        self.fields.iter().map(|(t, _)| *t)
    }

    /// The bytes a `mac1` must cover: the header followed by every field
    /// **except** the cookie fields, in wire order.
    ///
    /// This is the receiver's mirror of [`MessageBuilder::mac1_input`]. It is
    /// derived from the parsed fields, not from the raw buffer, so a peer cannot
    /// satisfy the cookie check by reordering fields: the reconstruction changes
    /// and the MAC fails.
    #[must_use]
    pub fn mac1_input(&self) -> Vec<u8> {
        serialize_fields(self.header, &self.fields, &MAC_TAGS)
    }

    /// The bytes a `mac2` must cover: the header followed by every field
    /// **except** `mac2` — so `mac1` is included, as the sender had it.
    #[must_use]
    pub fn mac2_input(&self) -> Vec<u8> {
        serialize_fields(self.header, &self.fields, &[tag::MAC2])
    }

    /// Assert the message type.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::WrongMessageType`] if it differs.
    pub fn expect_type(&self, expected: MessageType) -> Result<(), HandshakeError> {
        if self.header.message_type == expected {
            Ok(())
        } else {
            Err(HandshakeError::WrongMessageType {
                expected: expected.name(),
                got: self.header.message_type.code(),
            })
        }
    }

    /// Assert the suite id.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::SuiteMismatch`] if it differs.
    pub fn expect_suite(&self, expected: u16) -> Result<(), HandshakeError> {
        if self.header.suite_id == expected {
            Ok(())
        } else {
            Err(HandshakeError::SuiteMismatch {
                expected,
                got: self.header.suite_id,
            })
        }
    }

    /// Assert an echoed receiver index.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::WrongReceiverIndex`] if it differs.
    pub fn expect_receiver_index(&self, expected: u32) -> Result<(), HandshakeError> {
        let got = u32::from_be_bytes(self.require_array::<INDEX_SIZE>(tag::RECEIVER_INDEX)?);
        if got == expected {
            Ok(())
        } else {
            Err(HandshakeError::WrongReceiverIndex { expected, got })
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn header(message_type: MessageType) -> MessageHeader {
        MessageHeader {
            version: PROTOCOL_VERSION,
            message_type,
            suite_id: 0x0003,
            sender_index: 0xDEAD_BEEF,
        }
    }

    #[test]
    fn header_round_trips() {
        let h = header(MessageType::RespHello);
        assert_eq!(MessageHeader::decode(&h.encode()), Ok(h));
    }

    #[test]
    fn message_round_trips_with_unknown_tags_intact() {
        let mut b = MessageBuilder::new(header(MessageType::InitHello));
        b.field(tag::EPHEMERAL_PK, b"pk").unwrap();
        b.field(0x7777, b"future").unwrap(); // unknown tag: preserved, unread
        b.field(tag::TIMESTAMP, &[0u8; TIMESTAMP_SIZE]).unwrap();
        let bytes = b.finish().unwrap();

        let msg = Message::parse(&bytes).unwrap();
        assert_eq!(msg.message_type(), MessageType::InitHello);
        assert_eq!(msg.sender_index(), 0xDEAD_BEEF);
        assert_eq!(msg.get(tag::EPHEMERAL_PK), Some(&b"pk"[..]));
        assert_eq!(msg.get(0x7777), Some(&b"future"[..]));
        assert_eq!(msg.field_count(), 3);
    }

    #[test]
    fn empty_body_is_valid() {
        let bytes = MessageBuilder::new(header(MessageType::InitConf))
            .finish()
            .unwrap();
        assert_eq!(bytes.len(), HEADER_LEN);
        let msg = Message::parse(&bytes).unwrap();
        assert_eq!(msg.field_count(), 0);
    }

    #[test]
    fn duplicate_tag_is_rejected() {
        let mut b = MessageBuilder::new(header(MessageType::InitHello));
        b.field(tag::TIMESTAMP, &[0u8; TIMESTAMP_SIZE]).unwrap();
        let mut bytes = b.finish().unwrap();
        // Splice the same field in a second time.
        let dup = [
            &tag::TIMESTAMP.to_be_bytes()[..],
            &(12u16).to_be_bytes()[..],
            &[0u8; 12][..],
        ]
        .concat();
        bytes.extend_from_slice(&dup);
        assert!(matches!(
            Message::parse(&bytes),
            Err(HandshakeError::Wire(_))
        ));
    }

    #[test]
    fn truncated_field_is_rejected() {
        let mut b = MessageBuilder::new(header(MessageType::InitHello));
        b.field(tag::EPHEMERAL_PK, b"0123456789").unwrap();
        let mut bytes = b.finish().unwrap();
        bytes.truncate(bytes.len() - 3);
        assert!(matches!(
            Message::parse(&bytes),
            Err(HandshakeError::Wire(_))
        ));
    }

    #[test]
    fn truncated_header_is_rejected() {
        assert!(Message::parse(&[0, 1, 0]).is_err());
    }

    #[test]
    fn unknown_message_type_is_rejected() {
        let mut bytes = MessageBuilder::new(header(MessageType::InitHello))
            .finish()
            .unwrap();
        bytes[1] = 0x7F;
        assert!(matches!(
            Message::parse(&bytes),
            Err(HandshakeError::Wire(_))
        ));
    }

    #[test]
    fn wrong_version_is_rejected() {
        let mut bytes = MessageBuilder::new(header(MessageType::InitHello))
            .finish()
            .unwrap();
        bytes[0] = PROTOCOL_VERSION + 1;
        assert!(matches!(
            Message::parse(&bytes),
            Err(HandshakeError::VersionMismatch { .. })
        ));
    }

    #[test]
    fn oversize_message_is_rejected_on_build() {
        let mut b = MessageBuilder::new(header(MessageType::InitHello));
        b.field(tag::EPHEMERAL_PK, &vec![0u8; MAX_HANDSHAKE_MESSAGE])
            .unwrap();
        assert!(matches!(b.finish(), Err(HandshakeError::Wire(_))));
    }

    #[test]
    fn oversized_buffer_is_rejected_on_parse() {
        let buf = vec![0u8; MAX_HANDSHAKE_MESSAGE + 1];
        assert!(matches!(Message::parse(&buf), Err(HandshakeError::Wire(_))));
    }

    #[test]
    fn type_and_suite_and_index_assertions() {
        let mut b = MessageBuilder::new(header(MessageType::RespHello));
        b.field(tag::RECEIVER_INDEX, &42u32.to_be_bytes()).unwrap();
        let bytes = b.finish().unwrap();
        let msg = Message::parse(&bytes).unwrap();

        assert!(msg.expect_type(MessageType::RespHello).is_ok());
        assert!(matches!(
            msg.expect_type(MessageType::InitHello),
            Err(HandshakeError::WrongMessageType { .. })
        ));
        assert!(msg.expect_suite(0x0003).is_ok());
        assert!(matches!(
            msg.expect_suite(0x0001),
            Err(HandshakeError::SuiteMismatch { .. })
        ));
        assert!(msg.expect_receiver_index(42).is_ok());
        assert!(matches!(
            msg.expect_receiver_index(43),
            Err(HandshakeError::WrongReceiverIndex { .. })
        ));
    }

    #[test]
    fn require_array_checks_length() {
        let mut b = MessageBuilder::new(header(MessageType::InitHello));
        b.field(tag::TIMESTAMP, b"too short").unwrap();
        let bytes = b.finish().unwrap();
        let msg = Message::parse(&bytes).unwrap();
        assert!(msg.require_array::<TIMESTAMP_SIZE>(tag::TIMESTAMP).is_err());
        assert!(msg
            .require_array::<TIMESTAMP_SIZE>(tag::EPHEMERAL_PK)
            .is_err());
    }

    #[test]
    fn a_data_message_is_just_another_message_type() {
        assert_eq!(MessageType::Data.code(), 0x04);
        assert_eq!(MessageType::from_code(0x04), Some(MessageType::Data));
        let mut b = MessageBuilder::new(header(MessageType::Data));
        b.field(tag::COUNTER, &1u64.to_be_bytes()).unwrap();
        b.field(tag::DATA_CT, b"ciphertext").unwrap();
        let bytes = b.finish().unwrap();
        let msg = Message::parse(&bytes).unwrap();
        assert_eq!(msg.message_type(), MessageType::Data);
        assert_eq!(msg.get(tag::COUNTER), Some(&1u64.to_be_bytes()[..]));
    }

    /// The cookie MACs must cover the same bytes on both ends. `mac1_input`
    /// excludes both cookie fields; `mac2_input` excludes only `mac2`, so it
    /// commits to `mac1`.
    #[test]
    fn mac_inputs_exclude_the_right_fields() {
        let mut b = MessageBuilder::new(header(MessageType::InitHello));
        b.field(tag::EPHEMERAL_PK, b"pk").unwrap();
        let without_cookies = b.mac1_input();
        assert_eq!(
            without_cookies,
            b.mac2_input(),
            "with no cookies yet, both cover the same bytes"
        );
        assert_eq!(
            &without_cookies[..HEADER_LEN],
            &header(MessageType::InitHello).encode()
        );
        assert!(
            without_cookies.len() > HEADER_LEN,
            "the non-cookie fields are covered"
        );

        b.field(tag::MAC1, b"0123456789abcdef").unwrap();
        let with_mac1 = b.mac1_input();
        let with_mac1_for_mac2 = b.mac2_input();
        assert_eq!(with_mac1, without_cookies, "mac1 does not cover itself");
        assert_ne!(with_mac1_for_mac2, with_mac1, "mac2 must cover mac1");

        b.field(tag::MAC2, b"fedcba9876543210").unwrap();
        let bytes = b.finish().unwrap();
        let msg = Message::parse(&bytes).unwrap();
        // The receiver reconstructs exactly what the sender covered.
        assert_eq!(msg.mac1_input(), with_mac1);
        assert_eq!(msg.mac2_input(), with_mac1_for_mac2);
    }

    #[test]
    fn mac_inputs_follow_wire_order_not_tag_order() {
        // Field order is preserved, so a peer cannot rearrange fields and keep a
        // valid cookie by some accidental canonicalisation.
        let mut b = MessageBuilder::new(header(MessageType::InitHello));
        b.field(0x7000, b"first").unwrap();
        b.field(0x0100, b"second").unwrap();
        let forward = b.mac1_input();

        let mut b = MessageBuilder::new(header(MessageType::InitHello));
        b.field(0x0100, b"second").unwrap();
        b.field(0x7000, b"first").unwrap();
        assert_ne!(b.mac1_input(), forward);
    }

    #[test]
    fn cookie_fields_must_be_added_in_order() {
        // mac2 before mac1.
        let mut b = MessageBuilder::new(header(MessageType::InitHello));
        assert!(matches!(
            b.field(tag::MAC2, b"fedcba9876543210"),
            Err(HandshakeError::Wire(_))
        ));

        // Anything other than mac2 after mac1.
        let mut b = MessageBuilder::new(header(MessageType::InitHello));
        b.field(tag::MAC1, b"0123456789abcdef").unwrap();
        assert!(matches!(
            b.field(tag::EPHEMERAL_PK, b"too late"),
            Err(HandshakeError::Wire(_))
        ));
        // ...but mac2 is fine, and so is finishing.
        b.field(tag::MAC2, b"fedcba9876543210").unwrap();
        assert!(b.finish().is_ok());
    }

    #[test]
    fn a_duplicate_tag_is_refused_at_build_time_too() {
        // The parser rejects duplicates, so the builder must not be able to
        // produce a message the parser would refuse.
        let mut b = MessageBuilder::new(header(MessageType::InitHello));
        b.field(tag::EPHEMERAL_PK, b"pk").unwrap();
        assert!(matches!(
            b.field(tag::EPHEMERAL_PK, b"pk again"),
            Err(HandshakeError::Wire(_))
        ));
    }
}
