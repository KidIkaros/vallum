// SPDX-License-Identifier: Apache-2.0

//! Application-layer segmentation: the envelope that keeps a handshake off the
//! IP fragment path.
//!
//! [`wire`](crate::wire) caps a message at [`MAX_HANDSHAKE_MESSAGE`] and the
//! tri-hybrid `InitHello` uses a third of that: 4 609 bytes. A UDP datagram that
//! big is four IP fragments, and IP fragments that do not carry the transport
//! header are not something a NAT can translate — a NAPT has no port to rewrite
//! in fragments two through four, so it drops them. The handshake fails, the
//! tunnel never comes up, and the only symptom is silence on a link that was
//! otherwise healthy. The same applies to a stateful firewall that reassembles
//! and inspects, or one that simply discards fragments.
//!
//! This module is the envelope that removes that dependence. A logical *message*
//! larger than [`MAX_OUTER_DATAGRAM`] is cut into fragments, each one a
//! self-contained UDP datagram carrying the UDP header a NAT needs, and the
//! message layer is handed the reassembled bytes. Nothing above this module
//! knows the message travelled in pieces; nothing below it knows what the
//! pieces mean.
//!
//! # The envelope
//!
//! ```text
//! ┌─────────┬──────────┬─────────────┬──────────┬─────────┬──────────────┐
//! │ version │   0x07   │  message_id │  offset  │  total  │     data     │
//! │   u8    │    u8    │   u32 (BE)  │  u16(BE) │ u16(BE) │  ≤ 1 442 B   │
//! └─────────┴──────────┴─────────────┴──────────┴─────────┴──────────────┘
//! ```
//!
//! There is no checksum, no nonce and no MAC here, and that is deliberate: the
//! reassembled bytes are authenticated exactly as they would have been arriving
//! whole — `mac1` for a handshake, an AEAD tag for data — so a fragment is
//! untrusted input of the same standing as a whole datagram. An attacker who
//! injects or reorders fragments can delay a message but cannot forge one, and
//! cannot make a message mean something else.
//!
//! # Telling the two framings apart
//!
//! A *message* begins `01` (the protocol version) followed by a
//! [`MessageType`](vallum_core::wire::MessageType) code. No message type has the code
//! `0x07`, so `01 07` can only be a fragment and the receiver needs two bytes to
//! know which framing it has. [`vallum_core::wire::Message::parse`] refuses `0x07`, so
//! a fragment that reaches the message layer is dropped rather than misread —
//! there is no second parser to disagree with this one.
//!
//! [`offset`]: Fragment::offset
//! [`total`]: Fragment::total

mod reassembly;

pub use reassembly::{Segments, MAX_REASSEMBLIES};

use vallum_core::wire::{MAX_HANDSHAKE_MESSAGE, PROTOCOL_VERSION};
use vallum_core::HandshakeError;

/// The byte that marks a datagram as a fragment rather than a message.
///
/// It sits where a message's type code sits, but it is **not** a
/// [`MessageType`](vallum_core::wire::MessageType) and must never be assigned as one:
/// `01 07` has to stay unambiguous, or the receiver cannot tell the framings
/// apart. `wire` refuses it on parse, which is what keeps the two apart.
pub const FRAGMENT_CODE: u8 = 0x07;

/// Bytes the envelope adds to every fragment.
pub const FRAGMENT_HEADER_LEN: usize = 10;

/// What an IPv4 outer path spends before the UDP payload: a 20-byte IPv4 header
/// and an 8-byte UDP header.
pub const OUTER_HEADER_LEN_V4: usize = 28;

/// What an IPv6 outer path spends before the UDP payload: a 40-byte IPv6 header
/// and an 8-byte UDP header. This is the worst case and the one
/// [`MAX_OUTER_DATAGRAM`] is built on.
pub const OUTER_HEADER_LEN_V6: usize = 48;

/// The largest UDP payload Vallum will put on the wire.
///
/// `1500 − 40 (IPv6 header) − 8 (UDP) = 1452`. The IPv6 sizes are the worst
/// case, so an IPv4 path has 20 bytes of slack. This is the same budget the
/// inner-MTU policy is built on (`SAFE_MTU_IPV6_OUTER` plus the data overhead is
/// exactly this), so a maximum-size data message and a maximum-size fragment
/// are equally large on the wire, and neither fragments.
pub const MAX_OUTER_DATAGRAM: usize = 1452;

/// The message bytes one fragment carries: [`MAX_OUTER_DATAGRAM`] less the
/// envelope.
pub const MAX_FRAGMENT_DATA: usize = MAX_OUTER_DATAGRAM - FRAGMENT_HEADER_LEN;

/// How long a half-assembled message is held before it is discarded.
///
/// Generous for reordering on a path with a sane RTT, and comfortably shorter
/// than the 5 s handshake retransmission interval, so a lost fragment set is
/// gone before the retransmission that replaces it arrives. An attempt that
/// times out here costs at most one slot in the receiver's table; the
/// retransmission carries a new [`Fragment::message_id`] and starts clean.
pub const REASSEMBLY_TIMEOUT_MS: u64 = 4_000;

/// The envelope of one fragment.
///
/// `total` is the length of the *message* this fragment is part of, and `offset`
/// is where `data` belongs in it. Offsets rather than indices: a sender is free
/// to choose a smaller fragment payload (a narrower path, say), and the receiver
/// does not have to know what that choice was to reassemble the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fragment {
    /// Which message this fragment belongs to.
    ///
    /// Chosen by the sender and reused for every fragment of one message. The
    /// receiver groups by `(source, message_id)`, so the id only has to be
    /// unique among the messages in flight from one address.
    pub message_id: u32,
    /// Where `data` starts in the message.
    pub offset: u16,
    /// The length of the whole message.
    pub total: u16,
}

impl Fragment {
    /// The ten header bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; FRAGMENT_HEADER_LEN] {
        let mut out = [0u8; FRAGMENT_HEADER_LEN];
        out[0] = PROTOCOL_VERSION;
        out[1] = FRAGMENT_CODE;
        out[2..6].copy_from_slice(&self.message_id.to_be_bytes());
        out[6..8].copy_from_slice(&self.offset.to_be_bytes());
        out[8..10].copy_from_slice(&self.total.to_be_bytes());
        out
    }
}

/// Is this datagram a fragment rather than a message?
///
/// Two bytes, so a truncated fragment is still recognised as one and refused by
/// [`parse`] with a fragment-shaped reason instead of being handed to the
/// message parser, which would reject it as an unknown type.
#[must_use]
pub fn is_fragment(datagram: &[u8]) -> bool {
    datagram.len() >= 2 && datagram[0] == PROTOCOL_VERSION && datagram[1] == FRAGMENT_CODE
}

/// Parse one fragment, returning its envelope and the message bytes it carries.
///
/// # Errors
///
/// [`HandshakeError::Wire`] if the datagram is shorter than the envelope, is not
/// a fragment, claims a `total` that is zero or larger than
/// [`MAX_HANDSHAKE_MESSAGE`], carries more data than [`MAX_FRAGMENT_DATA`], or
/// places its data outside `0..total`.
pub fn parse(datagram: &[u8]) -> Result<(Fragment, &[u8]), HandshakeError> {
    let Some(head) = datagram.get(..FRAGMENT_HEADER_LEN) else {
        return Err(HandshakeError::Wire(format!(
            "fragment is {} bytes, shorter than the {FRAGMENT_HEADER_LEN}-byte envelope",
            datagram.len()
        )));
    };
    if head[0] != PROTOCOL_VERSION {
        return Err(HandshakeError::Wire(format!(
            "fragment version {:#04x}, expected {PROTOCOL_VERSION:#04x}",
            head[0]
        )));
    }
    if head[1] != FRAGMENT_CODE {
        return Err(HandshakeError::Wire(format!(
            "datagram type {:#04x} is not a fragment ({FRAGMENT_CODE:#04x})",
            head[1]
        )));
    }

    let message_id = u32::from_be_bytes([head[2], head[3], head[4], head[5]]);
    let offset = u16::from_be_bytes([head[6], head[7]]);
    let total = u16::from_be_bytes([head[8], head[9]]);
    let data = &datagram[FRAGMENT_HEADER_LEN..];

    if total == 0 || usize::from(total) > MAX_HANDSHAKE_MESSAGE {
        return Err(HandshakeError::Wire(format!(
            "fragment claims a {total}-byte message; the cap is {MAX_HANDSHAKE_MESSAGE} \
             and zero is not a message"
        )));
    }
    if data.len() > MAX_FRAGMENT_DATA {
        return Err(HandshakeError::Wire(format!(
            "fragment carries {} bytes of message, more than the {MAX_FRAGMENT_DATA}-byte \
             envelope cap",
            data.len()
        )));
    }
    let end = usize::from(offset) + data.len();
    if end > usize::from(total) {
        return Err(HandshakeError::Wire(format!(
            "fragment covers bytes {}..{end} of a {total}-byte message",
            offset
        )));
    }

    Ok((
        Fragment {
            message_id,
            offset,
            total,
        },
        data,
    ))
}

/// Cut a message into fragment datagrams, each at most [`MAX_OUTER_DATAGRAM`].
///
/// The fixed-budget form; [`split_with_budget`] is what a path narrower than
/// 1500 needs.
///
/// # Errors
///
/// As [`split_with_budget`].
pub fn split(message_id: u32, message: &[u8]) -> Result<Vec<Vec<u8>>, HandshakeError> {
    split_with_budget(message_id, message, MAX_OUTER_DATAGRAM)
}

/// Cut a message into fragment datagrams, each at most `budget` bytes.
///
/// `budget` is the largest UDP payload this path can carry, so it is
/// `path_mtu - 48` (IPv6 header + UDP header). It defaults to
/// [`MAX_OUTER_DATAGRAM`]; a narrower path — PPPoE at 1492, an IPsec tunnel at
/// 1400 — passes a smaller one. The receiver does not need to know: offsets are
/// explicit and the parse cap stays [`MAX_FRAGMENT_DATA`], which a smaller
/// budget is always below.
///
/// # Errors
///
/// [`HandshakeError::Wire`] if `message` is empty or longer than
/// [`MAX_HANDSHAKE_MESSAGE`], or if `budget` is outside
/// `FRAGMENT_HEADER_LEN + 1 ..= MAX_OUTER_DATAGRAM`. A message that already fits
/// makes exactly one fragment; callers that want it unfragmented should not call
/// this at all.
pub fn split_with_budget(
    message_id: u32,
    message: &[u8],
    budget: usize,
) -> Result<Vec<Vec<u8>>, HandshakeError> {
    if !(FRAGMENT_HEADER_LEN + 1..=MAX_OUTER_DATAGRAM).contains(&budget) {
        return Err(HandshakeError::Wire(format!(
            "fragment budget {budget} is outside {}..={MAX_OUTER_DATAGRAM}",
            FRAGMENT_HEADER_LEN + 1
        )));
    }
    let fragment_data = budget - FRAGMENT_HEADER_LEN;
    if message.is_empty() {
        return Err(HandshakeError::Wire(
            "refusing to fragment an empty message".into(),
        ));
    }
    if message.len() > MAX_HANDSHAKE_MESSAGE {
        return Err(HandshakeError::Wire(format!(
            "message of {} bytes exceeds the {MAX_HANDSHAKE_MESSAGE}-byte cap",
            message.len()
        )));
    }
    let Ok(total) = u16::try_from(message.len()) else {
        return Err(HandshakeError::Wire(format!(
            "message of {} bytes does not fit the 16-bit length field",
            message.len()
        )));
    };

    let mut datagrams = Vec::with_capacity(message.len().div_ceil(fragment_data));
    for (index, chunk) in message.chunks(fragment_data).enumerate() {
        // `chunks` yields at most `ceil(total / fragment_data)`, so this is
        // below `total` and inside a `u16` for any message the cap admits.
        let offset = u16::try_from(index * fragment_data).map_err(|_| {
            HandshakeError::Wire(format!("fragment {index} offset does not fit 16 bits"))
        })?;
        let fragment = Fragment {
            message_id,
            offset,
            total,
        };
        let mut datagram = Vec::with_capacity(FRAGMENT_HEADER_LEN + chunk.len());
        datagram.extend_from_slice(&fragment.encode());
        datagram.extend_from_slice(chunk);
        datagrams.push(datagram);
    }
    Ok(datagrams)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use vallum_core::wire::{Message, MessageBuilder, MessageHeader, MessageType};

    fn fragment(message_id: u32, offset: u16, total: u16, data: &[u8]) -> Vec<u8> {
        let mut out = Fragment {
            message_id,
            offset,
            total,
        }
        .encode()
        .to_vec();
        out.extend_from_slice(data);
        out
    }

    #[test]
    fn the_envelope_round_trips() {
        let datagram = fragment(0xDEAD_BEEF, 1442, 4609, b"payload");
        let (head, data) = parse(&datagram).expect("a well-formed fragment");
        assert_eq!(head.message_id, 0xDEAD_BEEF);
        assert_eq!(head.offset, 1442);
        assert_eq!(head.total, 4609);
        assert_eq!(data, b"payload");
        assert!(is_fragment(&datagram));
    }

    #[test]
    fn the_two_framings_cannot_be_confused() {
        // A real handshake message: `01 01` (version, InitHello).
        let message = MessageBuilder::new(MessageHeader {
            version: PROTOCOL_VERSION,
            message_type: MessageType::InitHello,
            suite_id: 0x0003,
            sender_index: 7,
        })
        .finish()
        .expect("an empty handshake message");
        assert!(!is_fragment(&message));

        // And a fragment is refused by the message parser, not misread as one.
        let datagram = fragment(1, 0, 10, &[0u8; 10]);
        assert!(is_fragment(&datagram));
        assert!(Message::parse(&datagram).is_err());

        // The code is reserved: if this ever fails, a message type took 0x07 and
        // `is_fragment` became ambiguous.
        assert!(MessageType::from_code(FRAGMENT_CODE).is_none());
    }

    #[test]
    fn a_truncated_fragment_is_a_fragment_and_is_refused() {
        let short = [PROTOCOL_VERSION, FRAGMENT_CODE, 0, 0];
        assert!(is_fragment(&short), "two bytes are enough to classify");
        let error = parse(&short).expect_err("too short to parse");
        assert!(format!("{error}").contains("shorter than"), "{error}");
    }

    #[test]
    fn parse_refuses_what_a_message_would_carry_differently() {
        // Shorter than the envelope.
        assert!(parse(&[PROTOCOL_VERSION, FRAGMENT_CODE]).is_err());
        // A message type where the fragment code belongs.
        let mut message_shaped = fragment(1, 0, 4, b"abcd");
        message_shaped[1] = 0x01;
        let error = parse(&message_shaped).expect_err("a message is not a fragment");
        assert!(format!("{error}").contains("is not a fragment"), "{error}");
        // A fragment version we do not speak.
        let mut wrong = fragment(1, 0, 4, b"abcd");
        wrong[0] = 0x02;
        let error = parse(&wrong).expect_err("future version");
        assert!(format!("{error}").contains("expected"), "{error}");

        // A zero-length message.
        let error = parse(&fragment(1, 0, 0, b"")).expect_err("total of zero");
        assert!(
            format!("{error}").contains("zero is not a message"),
            "{error}"
        );

        // A message past the cap.
        let error = parse(&fragment(1, 0, u16::MAX, b"x")).expect_err("over the cap");
        assert!(format!("{error}").contains("the cap is"), "{error}");

        // Data past what the envelope allows.
        let error = parse(&fragment(1, 0, 2000, &[0u8; 1452])).expect_err("oversize data");
        assert!(format!("{error}").contains("more than the"), "{error}");

        // Data outside the message it claims to be part of.
        let error = parse(&fragment(1, 100, 100, b"a")).expect_err("offset past total");
        assert!(format!("{error}").contains("covers bytes"), "{error}");
    }

    #[test]
    fn a_handshake_sized_message_splits_into_whole_datagrams() {
        // The size of the tri-hybrid InitHello: the message that motivated this.
        let message: Vec<u8> = (0..4609u32).map(|i| (i % 251) as u8).collect();
        let datagrams = split(0x1234_5678, &message).expect("a legal message");
        assert_eq!(datagrams.len(), 4, "4609 bytes into 1442-byte pieces");
        for datagram in &datagrams {
            assert!(datagram.len() <= MAX_OUTER_DATAGRAM);
        }

        // Reassemble by offset, in reverse, and get the message back exactly.
        let mut out = vec![0u8; message.len()];
        for datagram in datagrams.iter().rev() {
            let (head, data) = parse(datagram).expect("a fragment we just built");
            assert_eq!(usize::from(head.total), message.len());
            out[usize::from(head.offset)..usize::from(head.offset) + data.len()]
                .copy_from_slice(data);
        }
        assert_eq!(out, message);
    }

    #[test]
    fn split_always_refuses_what_parse_would_refuse() {
        assert!(split(1, &[]).is_err());
        assert!(split(1, &vec![0u8; MAX_HANDSHAKE_MESSAGE + 1]).is_err());
        // Exactly at the cap is legal and makes a whole number of fragments.
        let at_cap = vec![7u8; MAX_HANDSHAKE_MESSAGE];
        let datagrams = split(1, &at_cap).expect("exactly the cap");
        assert_eq!(
            datagrams.len(),
            MAX_HANDSHAKE_MESSAGE.div_ceil(MAX_FRAGMENT_DATA)
        );
        for datagram in &datagrams {
            assert!(datagram.len() <= MAX_OUTER_DATAGRAM);
            parse(datagram).expect("every fragment we build parses");
        }
    }

    #[test]
    fn a_smaller_budget_cuts_more_and_reassembles_the_same() {
        let message = vec![0x5Au8; 3_000];
        let narrow = split_with_budget(9, &message, 1_000).expect("a 1000-byte budget");
        let wide = split(9, &message).expect("the default budget");

        assert!(narrow.len() > wide.len(), "a narrower budget must cut more");
        for datagram in &narrow {
            assert!(
                datagram.len() <= 1_000,
                "a fragment exceeded the budget: {}",
                datagram.len()
            );
            parse(datagram).expect("a narrow fragment still parses");
        }

        let mut out = vec![0u8; message.len()];
        for datagram in narrow.iter().rev() {
            let (head, data) = parse(datagram).expect("parse");
            out[usize::from(head.offset)..usize::from(head.offset) + data.len()]
                .copy_from_slice(data);
        }
        assert_eq!(out, message);
    }

    #[test]
    fn a_budget_that_cannot_carry_an_envelope_is_refused() {
        assert!(split_with_budget(1, &[1, 2, 3], FRAGMENT_HEADER_LEN).is_err());
        assert!(split_with_budget(1, &[1, 2, 3], 0).is_err());
        assert!(split_with_budget(1, &[1, 2, 3], MAX_OUTER_DATAGRAM + 1).is_err());
        // The smallest legal budget carries one byte per fragment.
        let datagrams = split_with_budget(1, &[1, 2, 3], FRAGMENT_HEADER_LEN + 1).expect("tiny");
        assert_eq!(datagrams.len(), 3);
    }
}
