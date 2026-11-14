//! Lightweight Wire Obfuscation (LWO v2) for zero-overhead UDP datagram masking.
//!
//! Vallum datagrams and fragments normally begin with a cleartext 8-byte header
//! (`version = 0x01`, `type = 0x01..=0x07`, suite/id/sender fields) followed by
//! high-entropy AEAD ciphertext, KEM payloads, or random tags at the packet tail.
//! LWO masks those leading 8 header bytes using a SplitMix64 keystream derived
//! from the packet's own trailing 8 bytes and length, hiding static protocol
//! signatures from stateless DPI without adding a single byte of wire overhead.

use vallum_core::cookie::{admit_handshake, Admission, COOKIE_SIZE, MAC_SIZE};
use vallum_core::handshake::RESP_TAG_SIZE;
use vallum_core::keys::NONCE_SIZE;
use vallum_core::wire::{
    tag, Message, MessageType, CONFIRMATION_SIZE, INDEX_SIZE, PROTOCOL_VERSION, TIMESTAMP_SIZE,
};
use vallum_crypto::CryptoSuite;

/// Number of leading header bytes masked per packet. Matches `vallum_core::wire::HEADER_LEN`.
pub const HEADER_MASK_LEN: usize = 8;

/// Minimum packet size eligible for LWO masking (`[0..8]` and `[len - 8..len]` are disjoint).
pub const MIN_LWO_LEN: usize = HEADER_MASK_LEN * 2;

/// Minimum random padding appended to handshake/non-full fragment packets
/// (1 masked length byte + 8 random tail bytes).
pub const MIN_HANDSHAKE_PAD: usize = HEADER_MASK_LEN + 1;

/// Maximum random padding appended to handshake/non-full fragment packets.
pub const MAX_HANDSHAKE_PAD: usize = 64;

/// High bit set inside byte 1 (`msg_type`, masked in the 8-byte LWO header)
/// to signal variable handshake/fragment padding at the tail.
const PADDED_FLAG: u8 = 0x80;

fn splitmix_next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Returns whether a plain Vallum wire type code identifies a handshake,
/// cookie, or fragment packet eligible for LWO length jitter.
#[must_use]
pub fn is_handshake_or_fragment(msg_type: u8) -> bool {
    matches!(msg_type, 0x01..=0x03 | 0x06 | 0x07)
}

/// Derives the 8-byte header XOR mask from a packet's trailing 8 bytes and length.
///
/// The first byte of the returned mask is guaranteed non-zero so that any valid
/// Vallum packet starting with [`PROTOCOL_VERSION`] produces a masked first byte
/// strictly different from [`PROTOCOL_VERSION`], enabling unambiguous receiver
/// auto-detection between plain UDP and LWO.
#[must_use]
pub fn derive_mask(tail: &[u8; HEADER_MASK_LEN], packet_len: usize) -> [u8; HEADER_MASK_LEN] {
    let tail_word = u64::from_le_bytes(*tail);
    let len_mix = (packet_len as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let mut state = tail_word ^ len_mix;
    let z = splitmix_next(&mut state);

    let mut mask = z.to_le_bytes();
    if mask[0] == 0 {
        mask[0] = 0x5a;
    }
    mask
}

/// Masks a Vallum packet's 8-byte header in place using its trailing 8 bytes,
/// adding variable tail jitter to handshake and non-full fragment packets
/// within `max_datagram_len`.
///
/// `Data` (`0x04`) packets and full-MTU fragments always incur **0 bytes** of
/// overhead. Returns `true` if masking was applied.
pub fn pad_and_mask_in_place(packet: &mut Vec<u8>, max_datagram_len: usize) -> bool {
    let orig_len = packet.len();
    if orig_len < MIN_LWO_LEN {
        return false;
    }

    if packet[0] == PROTOCOL_VERSION && is_handshake_or_fragment(packet[1]) {
        let slack = max_datagram_len
            .saturating_sub(orig_len)
            .min(MAX_HANDSHAKE_PAD);
        if slack >= MIN_HANDSHAKE_PAD {
            let mut orig_tail = [0u8; HEADER_MASK_LEN];
            orig_tail.copy_from_slice(&packet[orig_len - HEADER_MASK_LEN..]);
            let mut prng = u64::from_le_bytes(orig_tail)
                ^ (orig_len as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);

            let span = slack - MIN_HANDSHAKE_PAD + 1;
            let pad_len = MIN_HANDSHAKE_PAD + ((splitmix_next(&mut prng) as usize) % span);
            let new_len = orig_len + pad_len;

            packet[1] |= PADDED_FLAG;
            packet.resize(new_len, 0);
            for chunk in packet[orig_len..new_len].chunks_mut(8) {
                let bytes = splitmix_next(&mut prng).to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }

            let mut tail = [0u8; HEADER_MASK_LEN];
            tail.copy_from_slice(&packet[new_len - HEADER_MASK_LEN..]);
            let mask = derive_mask(&tail, new_len);
            let pad_len_u8 = u8::try_from(pad_len).unwrap_or(MAX_HANDSHAKE_PAD as u8);
            packet[new_len - HEADER_MASK_LEN - 1] = pad_len_u8 ^ mask[7];
            xor_header(&mut packet[..HEADER_MASK_LEN], &mask);
            return true;
        }
    }

    mask_in_place(packet.as_mut_slice())
}

/// Masks a Vallum packet's 8-byte header in place using its trailing 8 bytes.
///
/// Returns `true` if masking was applied, or `false` if `packet.len() < MIN_LWO_LEN`.
pub fn mask_in_place(packet: &mut [u8]) -> bool {
    let Some(tail_start) = packet.len().checked_sub(HEADER_MASK_LEN) else {
        return false;
    };
    if packet.len() < MIN_LWO_LEN {
        return false;
    }

    let mut tail = [0u8; HEADER_MASK_LEN];
    tail.copy_from_slice(&packet[tail_start..]);
    let mask = derive_mask(&tail, packet.len());
    xor_header(&mut packet[..HEADER_MASK_LEN], &mask);
    true
}

/// Unmasks an LWO-obfuscated packet header in place.
///
/// Returns `false` without mutating `packet` if it is shorter than [`MIN_LWO_LEN`].
pub fn unmask_in_place(packet: &mut [u8]) -> bool {
    mask_in_place(packet)
}

/// Outcome of inspecting an inbound datagram for LWO masking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketEncoding {
    /// Datagram begins with an unmasked [`PROTOCOL_VERSION`] byte.
    Plain,
    /// Datagram was LWO-masked and its header has been unmasked in place.
    LwoUnmasked,
    /// Datagram is neither valid plain Vallum nor a valid LWO-masked packet.
    Unrecognized,
}

/// Detects LWO header masking, unmasks `[0..8]`, and strips any handshake tail
/// padding, returning `Some(logical_len)` or `None` if not an LWO datagram.
pub fn unmask_and_unpad(packet: &mut [u8]) -> Option<usize> {
    let tail_start = packet.len().checked_sub(HEADER_MASK_LEN)?;
    if packet.len() < MIN_LWO_LEN || packet[0] == PROTOCOL_VERSION {
        return None;
    }

    let mut tail = [0u8; HEADER_MASK_LEN];
    tail.copy_from_slice(&packet[tail_start..]);
    let mask = derive_mask(&tail, packet.len());
    if (packet[0] ^ mask[0]) != PROTOCOL_VERSION {
        return None;
    }

    xor_header(&mut packet[..HEADER_MASK_LEN], &mask);
    if (packet[1] & PADDED_FLAG) != 0 {
        let raw_type = packet[1] & !PADDED_FLAG;
        if !is_handshake_or_fragment(raw_type) || packet.len() < MIN_LWO_LEN + MIN_HANDSHAKE_PAD {
            xor_header(&mut packet[..HEADER_MASK_LEN], &mask);
            return None;
        }
        let pad_len = usize::from(packet[packet.len() - HEADER_MASK_LEN - 1] ^ mask[7]);
        if !(MIN_HANDSHAKE_PAD..=MAX_HANDSHAKE_PAD).contains(&pad_len)
            || packet.len() < MIN_LWO_LEN + pad_len
        {
            xor_header(&mut packet[..HEADER_MASK_LEN], &mask);
            return None;
        }
        packet[1] = raw_type;
        Some(packet.len() - pad_len)
    } else if is_valid_vallum_packet(packet) {
        Some(packet.len())
    } else {
        None
    }
}

/// Auto-detects whether an inbound datagram is LWO-masked and unmasks it in place.
///
/// Plain Vallum datagrams always start with [`PROTOCOL_VERSION`] (`0x01`), whereas
/// LWO datagrams never do because `mask[0] != 0`. If unmasking restores
/// [`PROTOCOL_VERSION`] at byte 0, the packet header is unmasked in place and
/// `true` is returned so the transport can reply in LWO format too.
pub fn unmask_if_lwo(packet: &mut [u8]) -> bool {
    unmask_and_unpad(packet).is_some()
}

/// Inspects an inbound datagram, unmasks LWO headers and strips any handshake
/// tail padding, returning `(logical_len, PacketEncoding)`.
/// Validates whether an unmasked, unpadded buffer looks like a Vallum protocol
/// or fragment envelope (version `0x01`, known type `0x01..=0x07`, and header length).
///
/// Used both during LWO/plain classification and as the `HandshakeFilter` gate
/// in `AutoTransport` so non-Vallum traffic cannot lock a carrier or enter the daemon.
pub fn is_valid_vallum_packet(packet: &[u8]) -> bool {
    if packet.len() < HEADER_MASK_LEN || packet[0] != PROTOCOL_VERSION {
        return false;
    }
    match packet[1] {
        0x01..=0x06 => true,
        crate::segment::FRAGMENT_CODE => packet.len() >= crate::segment::FRAGMENT_HEADER_LEN,
        _ => false,
    }
}

/// Extracts the initiator's 32-bit `sender_index` from a plain `InitHello` (`0x01`)
/// or the first segment fragment (`0x07`, `offset == 0`) carrying an `InitHello` header.
#[must_use]
pub fn extract_initiation_sender_index(packet: &[u8]) -> Option<u32> {
    if packet.len() >= HEADER_MASK_LEN
        && packet[0] == PROTOCOL_VERSION
        && packet[1] == MessageType::InitHello.code()
    {
        return Some(u32::from_be_bytes([
            packet[4], packet[5], packet[6], packet[7],
        ]));
    }
    if crate::segment::is_fragment(packet) {
        if let Ok((frag, payload)) = crate::segment::parse(packet) {
            if frag.offset == 0
                && payload.len() >= HEADER_MASK_LEN
                && payload[0] == PROTOCOL_VERSION
                && payload[1] == MessageType::InitHello.code()
            {
                return Some(u32::from_be_bytes([
                    payload[4], payload[5], payload[6], payload[7],
                ]));
            }
        }
    }
    None
}

/// Cryptographically verifies a handshake message's `MAC1` field against
/// `responder_static_pk`.
#[must_use]
pub fn verify_handshake_mac1(
    suite: &dyn CryptoSuite,
    responder_static_pk: &[u8],
    packet: &[u8],
) -> bool {
    let Ok(message) = Message::parse(packet) else {
        return false;
    };
    if message
        .get(tag::MAC1)
        .is_none_or(|tag_bytes| tag_bytes.len() != MAC_SIZE)
    {
        return false;
    }
    matches!(
        admit_handshake(suite, &message, responder_static_pk, &[], false, None),
        Ok(Admission::Accept)
    )
}

/// `HandshakeFilter` gate: validates envelope framing, TLV structure, required
/// cryptographic tag sizes, optional `RECEIVER_INDEX` membership against
/// outstanding initiations, and optional `MAC1` authenticity.
#[must_use]
pub fn is_authentic_handshake_packet(
    packet: &[u8],
    pending_indices: &[u32],
    mac1_key: Option<(&dyn CryptoSuite, &[u8])>,
) -> bool {
    if !is_valid_vallum_packet(packet) {
        return false;
    }

    match packet[1] {
        // InitHello (0x01)
        0x01 => {
            let Ok(msg) = Message::parse(packet) else {
                return false;
            };
            if msg.get(tag::STATIC_CT).is_none_or(<[u8]>::is_empty)
                || msg.get(tag::EPHEMERAL_PK).is_none_or(<[u8]>::is_empty)
                || msg.require_array::<TIMESTAMP_SIZE>(tag::TIMESTAMP).is_err()
                || msg.get(tag::PEER_HINT).is_none_or(<[u8]>::is_empty)
            {
                return false;
            }
            if let Some(m1) = msg.get(tag::MAC1) {
                if m1.len() != MAC_SIZE {
                    return false;
                }
            }
            if let Some(m2) = msg.get(tag::MAC2) {
                if m2.len() != MAC_SIZE {
                    return false;
                }
            }
            if let Some((suite, responder_pk)) = mac1_key {
                return verify_handshake_mac1(suite, responder_pk, packet);
            }
            true
        }
        // RespHello (0x02)
        0x02 => {
            let Ok(msg) = Message::parse(packet) else {
                return false;
            };
            let Ok(rx_bytes) = msg.require_array::<INDEX_SIZE>(tag::RECEIVER_INDEX) else {
                return false;
            };
            let rx = u32::from_be_bytes(rx_bytes);
            if !pending_indices.is_empty() && !pending_indices.contains(&rx) {
                return false;
            }
            msg.get(tag::EPHEMERAL_CT).is_some_and(|v| !v.is_empty())
                && msg.get(tag::STATIC_CT).is_some_and(|v| !v.is_empty())
                && msg
                    .require_array::<CONFIRMATION_SIZE>(tag::CONFIRMATION)
                    .is_ok()
                && msg.require_array::<RESP_TAG_SIZE>(tag::PRE_TAG).is_ok()
        }
        // InitConf (0x03)
        0x03 => {
            let Ok(msg) = Message::parse(packet) else {
                return false;
            };
            msg.require_array::<INDEX_SIZE>(tag::RECEIVER_INDEX).is_ok()
                && msg
                    .require_array::<CONFIRMATION_SIZE>(tag::CONFIRMATION)
                    .is_ok()
        }
        // IdentityDoc (0x05)
        0x05 => Message::parse(packet).is_ok(),
        // CookieReply (0x06)
        0x06 => {
            let Ok(msg) = Message::parse(packet) else {
                return false;
            };
            let Ok(rx_bytes) = msg.require_array::<INDEX_SIZE>(tag::RECEIVER_INDEX) else {
                return false;
            };
            let rx = u32::from_be_bytes(rx_bytes);
            if !pending_indices.is_empty() && !pending_indices.contains(&rx) {
                return false;
            }
            msg.require_array::<NONCE_SIZE>(tag::COOKIE_NONCE).is_ok()
                && msg
                    .get(tag::COOKIE_CT)
                    .is_some_and(|v| v.len() >= COOKIE_SIZE + 16)
        }
        // Data (0x04): envelope already verified; AEAD authenticates payload in Device.
        0x04 => true,
        // Fragment (0x07): validate segment envelope bounds.
        crate::segment::FRAGMENT_CODE => crate::segment::parse(packet).is_ok(),
        _ => false,
    }
}

pub fn classify_and_unpad(packet: &mut [u8]) -> (usize, PacketEncoding) {
    if is_valid_vallum_packet(packet) {
        (packet.len(), PacketEncoding::Plain)
    } else if let Some(logical_len) = unmask_and_unpad(packet) {
        (logical_len, PacketEncoding::LwoUnmasked)
    } else {
        (packet.len(), PacketEncoding::Unrecognized)
    }
}

/// Inspects an inbound datagram, unmasks LWO headers in place if detected,
/// and reports its on-wire encoding so receivers can match peer expectations.
pub fn classify_and_unmask(packet: &mut [u8]) -> PacketEncoding {
    classify_and_unpad(packet).1
}

fn xor_header(header: &mut [u8], mask: &[u8; HEADER_MASK_LEN]) {
    for (byte, mask_byte) in header.iter_mut().zip(mask.iter()) {
        *byte ^= *mask_byte;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_packet(len: usize, seed: u8) -> Vec<u8> {
        let mut pkt = vec![0u8; len];
        pkt[0] = PROTOCOL_VERSION;
        pkt[1] = 0x04;
        pkt[2] = 0x01;
        for (idx, b) in pkt.iter_mut().enumerate().skip(3) {
            *b = seed.wrapping_add((idx as u8).wrapping_mul(37));
        }
        pkt
    }

    #[test]
    fn round_trip_preserves_length_and_bytes() {
        for len in [16usize, 32, 64, 512, 1380] {
            let original = sample_packet(len, len as u8);
            let mut masked = original.clone();
            assert!(mask_in_place(&mut masked));
            assert_eq!(masked.len(), original.len());
            assert_ne!(masked[0], PROTOCOL_VERSION);
            assert_eq!(&masked[HEADER_MASK_LEN..], &original[HEADER_MASK_LEN..]);

            assert!(unmask_in_place(&mut masked));
            assert_eq!(masked, original);
        }
    }

    #[test]
    fn auto_detect_distinguishes_lwo_from_plain() {
        let plain = sample_packet(64, 19);
        let mut plain_copy = plain.clone();
        assert!(!unmask_if_lwo(&mut plain_copy));
        assert_eq!(plain_copy, plain);

        let mut lwo = plain.clone();
        assert!(mask_in_place(&mut lwo));
        assert!(unmask_if_lwo(&mut lwo));
        assert_eq!(lwo, plain);
    }

    #[test]
    fn short_packets_are_left_untouched() {
        let mut short = vec![PROTOCOL_VERSION; MIN_LWO_LEN - 1];
        let snapshot = short.clone();
        assert!(!mask_in_place(&mut short));
        assert!(!unmask_if_lwo(&mut short));
        assert_eq!(short, snapshot);
    }

    #[test]
    fn junk_packets_are_not_misidentified_as_lwo() {
        let mut junk = vec![0xffu8; 40];
        // Tweak tail if needed so mask[0] ^ 0xff happens not to equal PROTOCOL_VERSION.
        let mut tail = [0xffu8; HEADER_MASK_LEN];
        let mask = derive_mask(&tail, junk.len());
        if (junk[0] ^ mask[0]) == PROTOCOL_VERSION {
            junk[0] = 0xfe;
            tail.copy_from_slice(&junk[32..]);
            let _ = tail;
        }
        let snapshot = junk.clone();
        assert!(!unmask_if_lwo(&mut junk));
        assert_eq!(junk, snapshot);
    }

    #[test]
    fn derive_mask_never_has_zero_first_byte() {
        for len in 16usize..256 {
            for seed in 0u8..=255 {
                let tail = [seed; HEADER_MASK_LEN];
                let mask = derive_mask(&tail, len);
                assert_ne!(mask[0], 0);
            }
        }
    }

    #[test]
    fn handshake_and_partial_fragments_pad_and_unpad_cleanly() {
        for msg_type in [0x01u8, 0x02, 0x03, 0x06, 0x07] {
            let mut original = sample_packet(180, msg_type.wrapping_mul(11));
            original[1] = msg_type;
            let mut wire = original.clone();

            assert!(pad_and_mask_in_place(&mut wire, 1452));
            let added = wire.len() - original.len();
            assert!(
                (MIN_HANDSHAKE_PAD..=MAX_HANDSHAKE_PAD).contains(&added),
                "unexpected padding {added} for msg_type {msg_type:#x}"
            );
            assert_ne!(wire[0], PROTOCOL_VERSION);

            let (logical_len, enc) = classify_and_unpad(&mut wire);
            assert_eq!(enc, PacketEncoding::LwoUnmasked);
            assert_eq!(logical_len, original.len());
            assert_eq!(&wire[..logical_len], original.as_slice());
        }
    }

    #[test]
    fn data_and_full_mtu_fragments_incur_zero_padding_overhead() {
        let data = sample_packet(256, 3);
        let mut wire_data = data.clone();
        assert!(pad_and_mask_in_place(&mut wire_data, 1452));
        assert_eq!(wire_data.len(), data.len());
        let (logical_len, enc) = classify_and_unpad(&mut wire_data);
        assert_eq!(enc, PacketEncoding::LwoUnmasked);
        assert_eq!(logical_len, data.len());
        assert_eq!(wire_data, data);

        let mut full_frag = sample_packet(1452, 5);
        full_frag[1] = 0x07;
        let mut wire_frag = full_frag.clone();
        assert!(pad_and_mask_in_place(&mut wire_frag, 1452));
        assert_eq!(wire_frag.len(), 1452);
        let (frag_len, frag_enc) = classify_and_unpad(&mut wire_frag);
        assert_eq!(frag_enc, PacketEncoding::LwoUnmasked);
        assert_eq!(frag_len, full_frag.len());
        assert_eq!(wire_frag, full_frag);
    }

    #[test]
    fn is_valid_vallum_packet_enforces_envelope_version_type_and_length() {
        assert!(!is_valid_vallum_packet(&[]));
        assert!(!is_valid_vallum_packet(&[PROTOCOL_VERSION, 0x04, 0x01]));
        assert!(is_valid_vallum_packet(&[
            PROTOCOL_VERSION,
            0x01,
            0,
            0,
            0,
            0,
            0,
            0
        ]));
        assert!(is_valid_vallum_packet(&[
            PROTOCOL_VERSION,
            0x04,
            0x01,
            0,
            0,
            0,
            0,
            0
        ]));
        // Unknown message type must be rejected even with matching PROTOCOL_VERSION.
        let mut bad_type = vec![PROTOCOL_VERSION, 0x7f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(!is_valid_vallum_packet(&bad_type));
        assert_eq!(
            classify_and_unpad(&mut bad_type),
            (bad_type.len(), PacketEncoding::Unrecognized)
        );
        // Fragment envelope requires full FRAGMENT_HEADER_LEN (10 bytes).
        let short_frag = [PROTOCOL_VERSION, crate::segment::FRAGMENT_CODE, 0, 0, 0, 0, 0, 0, 0];
        assert!(!is_valid_vallum_packet(&short_frag));
        let full_frag = [
            PROTOCOL_VERSION,
            crate::segment::FRAGMENT_CODE,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        assert!(is_valid_vallum_packet(&full_frag));

        // Craft an LWO-sized buffer whose masked byte 0 unmasks to PROTOCOL_VERSION
        // but whose unmasked byte 1 is an unknown type: unmask_and_unpad must reject it.
        let mut bogus_masked = vec![0xaa; MIN_LWO_LEN];
        let tail: [u8; HEADER_MASK_LEN] = bogus_masked[bogus_masked.len() - HEADER_MASK_LEN..]
            .try_into()
            .unwrap();
        let mask = derive_mask(&tail, bogus_masked.len());
        bogus_masked[0] = PROTOCOL_VERSION ^ mask[0];
        bogus_masked[1] = 0x55 ^ mask[1]; // unknown type, PADDED_FLAG clear
        assert_eq!(
            classify_and_unpad(&mut bogus_masked),
            (MIN_LWO_LEN, PacketEncoding::Unrecognized)
        );
    }

    #[test]
    fn authentic_handshake_filter_validates_tlv_tags_receiver_index_and_mac1() {
        use vallum_core::cookie::sign_with_cookies;
        use vallum_core::wire::{MessageBuilder, MessageHeader};
        use vallum_crypto_sdk::SdkSuite;

        let suite = SdkSuite::x25519_sntrup761();
        let responder_pk = b"responder-static-public-key-bytes";

        // 1. Build a TLV-valid InitHello with valid MAC1.
        let mut init_b = MessageBuilder::new(MessageHeader {
            version: PROTOCOL_VERSION,
            message_type: MessageType::InitHello,
            suite_id: suite.suite_id(),
            sender_index: 0x0102_0304,
        });
        init_b.field(tag::STATIC_CT, &[0x11; 32]).unwrap();
        init_b.field(tag::EPHEMERAL_PK, &[0x22; 32]).unwrap();
        init_b
            .field(tag::TIMESTAMP, &[0x33; TIMESTAMP_SIZE])
            .unwrap();
        init_b.field(tag::PEER_HINT, &[0x44; 24]).unwrap();
        sign_with_cookies(&suite, &mut init_b, responder_pk, None).unwrap();
        let init_pkt = init_b.finish().unwrap();

        assert_eq!(extract_initiation_sender_index(&init_pkt), Some(0x0102_0304));
        assert!(verify_handshake_mac1(&suite, responder_pk, &init_pkt));
        assert!(!verify_handshake_mac1(
            &suite,
            b"wrong-responder-static-pk",
            &init_pkt
        ));
        assert!(is_authentic_handshake_packet(
            &init_pkt,
            &[],
            Some((&suite, responder_pk))
        ));
        assert!(!is_authentic_handshake_packet(
            &init_pkt,
            &[],
            Some((&suite, b"wrong-responder-static-pk"))
        ));

        // Corrupt a single byte in MAC1 -> rejected cryptographically.
        let mut bad_mac_init = init_pkt.clone();
        let last = bad_mac_init.len() - 1;
        bad_mac_init[last] ^= 0xff;
        assert!(!verify_handshake_mac1(&suite, responder_pk, &bad_mac_init));

        // 2. Fragment 0 of a segmented InitHello also yields its sender_index.
        let frag0 = crate::segment::Fragment {
            message_id: 77,
            offset: 0,
            total: 4000,
        };
        let mut frag_pkt = frag0.encode().to_vec();
        frag_pkt.extend_from_slice(&init_pkt[..64]);
        assert_eq!(extract_initiation_sender_index(&frag_pkt), Some(0x0102_0304));
        assert!(is_authentic_handshake_packet(&frag_pkt, &[], None));

        // 3. RespHello requires EPHEMERAL_CT, STATIC_CT, RECEIVER_INDEX, CONFIRMATION, PRE_TAG.
        let mut resp_b = MessageBuilder::new(MessageHeader {
            version: PROTOCOL_VERSION,
            message_type: MessageType::RespHello,
            suite_id: suite.suite_id(),
            sender_index: 0x0506_0708,
        });
        resp_b.field(tag::EPHEMERAL_CT, &[0xaa; 32]).unwrap();
        resp_b.field(tag::STATIC_CT, &[0xbb; 32]).unwrap();
        resp_b
            .field(tag::RECEIVER_INDEX, &0x0102_0304u32.to_be_bytes())
            .unwrap();
        resp_b
            .field(tag::CONFIRMATION, &[0xcc; CONFIRMATION_SIZE])
            .unwrap();
        resp_b.field(tag::PRE_TAG, &[0xdd; RESP_TAG_SIZE]).unwrap();
        let resp_pkt = resp_b.finish().unwrap();

        assert!(is_authentic_handshake_packet(
            &resp_pkt,
            &[0x0102_0304],
            None
        ));
        assert!(!is_authentic_handshake_packet(
            &resp_pkt,
            &[0x9999_9999],
            None
        ));

        // Raw non-TLV bytes claiming RespHello (0x02) must fail.
        let mut forged_resp = vec![0xaa; 128];
        forged_resp[0] = PROTOCOL_VERSION;
        forged_resp[1] = 0x02;
        assert!(!is_authentic_handshake_packet(&forged_resp, &[], None));
    }
}
