// SPDX-License-Identifier: Apache-2.0

//! Framing a tunnel packet inside a byte stream.
//!
//! Vallum's packets are datagrams: one `Action::Send` is one message with one
//! length, and the next one begins wherever the last one ended. A stream carrier
//! — the UDP-over-TCP fallback ADR-0026 describes — has no such boundaries, so
//! every packet needs a length prefix or the receiver cannot tell where one ends.
//!
//! This module is that prefix and nothing else. It is deliberately not a carrier:
//! it holds no socket, does no I/O, and knows nothing about connections, because
//! the decision ADR-0026 defers is *whether* to have a stream carrier, and a
//! codec written now is not the same commitment as a carrier added now.
//!
//! # Why two bytes
//!
//! A tunnel packet is bounded by the path MTU, not by 64 KiB: `outer_mtu` is
//! capped well below it, and a stream carrier that accepted a 64 KiB frame would
//! be advertising a bound it cannot enforce. `u16` is therefore both sufficient
//! and a check — a frame claiming more than [`MAX_FRAME`] is refused rather than
//! buffered, so a peer cannot make the reader allocate.

/// The most bytes one frame may carry.
///
/// The tunnel's own largest message is 16 KiB (`MAX_DATA_MESSAGE`), and a data
/// packet carries one message plus its prefix, counter and tag, so 32 KiB has
/// room for anything the protocol can produce and still refuses the rest. The
/// ceiling has to be *below* the prefix's own range or it would be no check at
/// all: a two-byte length can only claim 65 535.
pub const MAX_FRAME: usize = 32 * 1024;

/// The size of the length prefix, in bytes.
pub const FRAME_LEN_SIZE: usize = 2;

/// Why a stream could not be turned back into packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// A length prefix read zero, which no tunnel packet is.
    Empty,
    /// A length prefix claimed more than [`MAX_FRAME`].
    ///
    /// The stream cannot be resynchronised after this: the prefix is the only
    /// thing that says where the next frame begins, so a bogus one ends the
    /// connection rather than skipping bytes.
    TooLong {
        /// What the prefix claimed.
        claimed: usize,
    },
    /// A frame ended before the byte count its prefix promised.
    Truncated {
        /// Bytes the prefix promised.
        expected: usize,
        /// Bytes that arrived before the stream ended.
        got: usize,
    },
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("a zero-length frame is not a tunnel packet"),
            Self::TooLong { claimed } => {
                write!(
                    f,
                    "a frame of {claimed} bytes exceeds the {MAX_FRAME} ceiling"
                )
            }
            Self::Truncated { expected, got } => {
                write!(f, "a frame promised {expected} bytes and ended after {got}")
            }
        }
    }
}

impl std::error::Error for FrameError {}

/// Write one packet as a length-prefixed frame.
///
/// The packet itself is untouched: the tunnel's own header, counters and AEAD are
/// inside it, and a carrier that inspected them would be a second parser with a
/// second opinion.
///
/// # Errors
///
/// If the packet is empty or larger than [`MAX_FRAME`] — both are caller bugs, and
/// a carrier that returned an error would be paying for a length it cannot encode.
#[must_use = "the framed bytes are the packet, and dropping them drops it"]
pub fn frame(packet: &[u8]) -> Result<Vec<u8>, FrameError> {
    if packet.is_empty() {
        return Err(FrameError::Empty);
    }
    if packet.len() > MAX_FRAME {
        return Err(FrameError::TooLong {
            claimed: packet.len(),
        });
    }
    let length = u16::try_from(packet.len()).map_err(|_| FrameError::TooLong {
        claimed: packet.len(),
    })?;
    let mut out = Vec::with_capacity(FRAME_LEN_SIZE + packet.len());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(packet);
    Ok(out)
}

/// Read one frame from the front of `buf`, returning it and the bytes consumed.
///
/// `None` means the buffer does not hold a whole frame yet: the caller reads more
/// and tries again, which is what a stream reader does. The bytes are borrowed
/// from `buf`; nothing is copied.
///
/// # Errors
///
/// If the prefix is zero, or claims more than [`MAX_FRAME`] — see
/// [`FrameError::TooLong`] for why neither can be recovered from.
pub fn unframe(buf: &[u8]) -> Result<Option<(&[u8], usize)>, FrameError> {
    let Some((prefix, rest)) = buf.split_first_chunk::<FRAME_LEN_SIZE>() else {
        return Ok(None);
    };
    let length = usize::from(u16::from_be_bytes(*prefix));
    if length == 0 {
        return Err(FrameError::Empty);
    }
    if length > MAX_FRAME {
        return Err(FrameError::TooLong { claimed: length });
    }
    let Some((packet, _)) = rest.split_at_checked(length) else {
        return Ok(None);
    };
    Ok(Some((packet, FRAME_LEN_SIZE + length)))
}

/// A reader that turns a stream's bytes into frames.
///
/// The buffer grows only as far as [`MAX_FRAME`], because a prefix is refused
/// before the body it promises is buffered.
#[derive(Debug, Default)]
pub struct FrameReader {
    buffer: Vec<u8>,
}

impl FrameReader {
    /// An empty reader.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add bytes read from the stream.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Take the next whole frame, if one has arrived.
    ///
    /// # Errors
    ///
    /// As [`unframe`]: a zero or oversized prefix is fatal to the stream.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, FrameError> {
        let Some((packet, consumed)) = unframe(&self.buffer)? else {
            return Ok(None);
        };
        let packet = packet.to_vec();
        self.buffer.drain(..consumed);
        Ok(Some(packet))
    }

    /// How many bytes are buffered but not yet framed.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.buffer.len()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_packet_survives_framing_unchanged() {
        for length in [1usize, 2, 58, 1_456, MAX_FRAME] {
            let packet: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
            let framed = frame(&packet).expect("frames");
            assert_eq!(framed.len(), FRAME_LEN_SIZE + length);
            let (body, consumed) = unframe(&framed).expect("unframes").expect("complete");
            assert_eq!(body, packet.as_slice(), "{length} bytes");
            assert_eq!(consumed, framed.len());
        }
    }

    #[test]
    fn a_partial_frame_is_not_an_error() {
        let packet = vec![7u8; 100];
        let framed = frame(&packet).expect("frames");

        // One byte of the prefix is not enough to know the length.
        assert_eq!(unframe(&framed[..1]).expect("waiting"), None);
        // Nor is a prefix without its body.
        assert_eq!(unframe(&framed[..2]).expect("waiting"), None);
        assert_eq!(unframe(&framed[..60]).expect("waiting"), None);
    }

    #[test]
    fn a_reader_reassembles_frames_split_across_reads() {
        let first = frame(&[1u8; 40]).expect("frames");
        let second = frame(&[2u8; 300]).expect("frames");
        let mut stream = Vec::new();
        stream.extend_from_slice(&first);
        stream.extend_from_slice(&second);

        let mut reader = FrameReader::new();
        for chunk in stream.chunks(7) {
            reader.push(chunk);
        }
        assert_eq!(
            reader.next_frame().expect("frame").expect("one"),
            vec![1u8; 40]
        );
        assert_eq!(
            reader.next_frame().expect("frame").expect("two"),
            vec![2u8; 300]
        );
        assert_eq!(reader.next_frame().expect("nothing left"), None);
        assert_eq!(reader.pending(), 0);
    }

    #[test]
    fn a_bad_length_prefix_ends_the_stream_instead_of_skipping_bytes() {
        assert_eq!(unframe(&[0, 0]).expect_err("zero"), FrameError::Empty);
        assert_eq!(frame(&[]).expect_err("empty"), FrameError::Empty);

        // A prefix beyond the ceiling is refused before the body is buffered.
        let claimed = u16::MAX;
        let mut reader = FrameReader::new();
        reader.push(&claimed.to_be_bytes());
        assert_eq!(
            reader.next_frame().expect_err("too long"),
            FrameError::TooLong {
                claimed: usize::from(claimed)
            }
        );
        assert_eq!(
            reader.pending(),
            FRAME_LEN_SIZE,
            "nothing was buffered on a refused length"
        );
    }

    #[test]
    fn the_ceiling_refuses_an_oversized_packet_at_both_ends() {
        // Encoding refuses a packet the tunnel cannot produce; decoding refuses
        // the same claim from a peer. One constant, two directions.
        let oversized = vec![0u8; MAX_FRAME + 1];
        assert_eq!(
            frame(&oversized).expect_err("too long"),
            FrameError::TooLong {
                claimed: MAX_FRAME + 1
            }
        );

        let mut reader = FrameReader::new();
        reader.push(&u16::try_from(MAX_FRAME + 1).expect("fits").to_be_bytes());
        assert_eq!(
            reader.next_frame().expect_err("too long"),
            FrameError::TooLong {
                claimed: MAX_FRAME + 1
            }
        );
    }

    #[test]
    fn a_frame_still_waiting_reports_no_error() {
        let framed = frame(&[3u8; 10]).expect("frames");
        let mut reader = FrameReader::new();
        reader.push(&framed[..5]);
        assert_eq!(reader.next_frame().expect("waiting"), None);
        assert_eq!(reader.pending(), 5);
    }
}
