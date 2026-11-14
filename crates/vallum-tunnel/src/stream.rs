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

/// Default HTTP/1.1 Upgrade path for reverse proxies (Caddy / Nginx) forwarding
/// TLS 1.3 `:443` traffic to a local Vallum `TcpTransport` listener.
pub const UPGRADE_PATH: &str = "/_vallum";

/// Maximum bytes buffered while waiting for `\r\n\r\n` on an HTTP Upgrade prelude.
pub const MAX_HTTP_PRELUDE: usize = 4096;

/// Server response completing an HTTP/1.1 `Upgrade: vallum` handshake.
pub const UPGRADE_RESPONSE: &[u8] =
    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: vallum\r\n\r\n";

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
    /// An HTTP/1.1 Upgrade prelude at the start of the stream was malformed or exceeded [`MAX_HTTP_PRELUDE`].
    BadUpgrade,
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
            Self::BadUpgrade => f.write_str("malformed or oversized HTTP/1.1 Upgrade prelude"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Build an HTTP/1.1 `Upgrade: vallum` client request prelude for traversing
/// a reverse proxy such as Caddy or Nginx.
#[must_use]
pub fn upgrade_request(host: &str) -> Vec<u8> {
    let sanitized: String = host
        .chars()
        .filter(|c| !matches!(c, '\r' | '\n'))
        .collect();
    let host_hdr = if sanitized.trim().is_empty() {
        "localhost"
    } else {
        sanitized.trim()
    };
    format!(
        "GET {UPGRADE_PATH} HTTP/1.1\r\nHost: {host_hdr}\r\nConnection: Upgrade\r\nUpgrade: vallum\r\n\r\n"
    )
    .into_bytes()
}

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
/// before the body it promises is buffered. At stream start it also recognizes
/// an optional HTTP/1.1 `Upgrade: vallum` request or `101 Switching Protocols`
/// response prelude for traversing TLS reverse proxies (Caddy / Nginx).
#[derive(Debug)]
pub struct FrameReader {
    buffer: Vec<u8>,
    at_stream_start: bool,
    upgrade_reply_needed: bool,
}

impl Default for FrameReader {
    fn default() -> Self {
        Self {
            buffer: Vec::new(),
            at_stream_start: true,
            upgrade_reply_needed: false,
        }
    }
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

    /// If the reader just consumed an inbound client `GET ... Upgrade` request prelude,
    /// returns the `HTTP/1.1 101 Switching Protocols` response bytes once so the
    /// transport can write them back on the stream.
    pub fn take_upgrade_reply(&mut self) -> Option<&'static [u8]> {
        if self.upgrade_reply_needed {
            self.upgrade_reply_needed = false;
            Some(UPGRADE_RESPONSE)
        } else {
            None
        }
    }

    /// Consume an HTTP/1.1 Upgrade request or `101 Switching Protocols` response at
    /// the start of the stream. Returns `Ok(true)` if more bytes are needed before
    /// deciding/completing the prelude, or `Ok(false)` once ready to read binary frames.
    fn try_consume_http_prelude(&mut self) -> Result<bool, FrameError> {
        const GET_PREFIX: &[u8] = b"GET ";
        const HTTP_PREFIX: &[u8] = b"HTTP/";

        if !self.at_stream_start || self.buffer.is_empty() {
            return Ok(false);
        }

        let is_get = if self.buffer.len() < GET_PREFIX.len() {
            GET_PREFIX.starts_with(&self.buffer)
        } else {
            self.buffer.starts_with(GET_PREFIX)
        };
        let is_http = if self.buffer.len() < HTTP_PREFIX.len() {
            HTTP_PREFIX.starts_with(&self.buffer)
        } else {
            self.buffer.starts_with(HTTP_PREFIX)
        };

        if !is_get && !is_http {
            self.at_stream_start = false;
            return Ok(false);
        }

        let Some(pos) = self.buffer.windows(4).position(|w| w == b"\r\n\r\n") else {
            if self.buffer.len() > MAX_HTTP_PRELUDE {
                return Err(FrameError::BadUpgrade);
            }
            return Ok(true);
        };

        let header_end = pos + 4;
        if header_end > MAX_HTTP_PRELUDE {
            return Err(FrameError::BadUpgrade);
        }

        let head_str =
            core::str::from_utf8(&self.buffer[..pos]).map_err(|_| FrameError::BadUpgrade)?;
        let mut lines = head_str.split("\r\n");
        let first_line = lines.next().ok_or(FrameError::BadUpgrade)?;

        if is_get {
            if !first_line.starts_with("GET /") || !first_line.contains("HTTP/1.") {
                return Err(FrameError::BadUpgrade);
            }
            let has_upgrade = lines.any(|line| {
                let lower = line.to_ascii_lowercase();
                lower.starts_with("upgrade:")
                    && (lower.contains("vallum") || lower.contains("websocket"))
            });
            if !has_upgrade {
                return Err(FrameError::BadUpgrade);
            }
            self.upgrade_reply_needed = true;
        } else if !first_line.starts_with("HTTP/1.1 101")
            && !first_line.starts_with("HTTP/1.0 101")
        {
            return Err(FrameError::BadUpgrade);
        }

        self.buffer.drain(..header_end);
        self.at_stream_start = false;
        Ok(false)
    }

    /// Take the next whole frame, if one has arrived.
    ///
    /// # Errors
    ///
    /// As [`unframe`]: a zero or oversized prefix is fatal to the stream, as is
    /// a malformed or oversized HTTP Upgrade prelude.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, FrameError> {
        if self.try_consume_http_prelude()? {
            return Ok(None);
        }
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

    #[test]
    fn http_upgrade_request_and_response_preludes_unframe_cleanly() {
        let pkt = vec![0x42u8; 96];
        let framed = frame(&pkt).expect("frame");

        // Server side: receives HTTP GET Upgrade request followed immediately by a binary frame
        // delivered in small 7-byte chunks.
        let mut req_stream = upgrade_request("wingman.gold");
        req_stream.extend_from_slice(&framed);

        let mut server_reader = FrameReader::new();
        let mut received = None;
        for chunk in req_stream.chunks(7) {
            server_reader.push(chunk);
            if let Some(frame) = server_reader.next_frame().expect("valid upgrade + frame") {
                received = Some(frame);
                break;
            }
        }
        assert_eq!(received.as_deref(), Some(pkt.as_slice()));
        assert_eq!(server_reader.take_upgrade_reply(), Some(UPGRADE_RESPONSE));
        assert_eq!(server_reader.take_upgrade_reply(), None);

        // Client side: receives 101 Switching Protocols response followed by a frame.
        let mut resp_stream = UPGRADE_RESPONSE.to_vec();
        resp_stream.extend_from_slice(&framed);
        let mut client_reader = FrameReader::new();
        client_reader.push(&resp_stream);
        assert_eq!(
            client_reader
                .next_frame()
                .expect("101 response + frame")
                .as_deref(),
            Some(pkt.as_slice())
        );
        assert_eq!(client_reader.take_upgrade_reply(), None);
    }

    #[test]
    fn malformed_or_oversized_http_prelude_is_refused() {
        let mut bad_upgrade = FrameReader::new();
        bad_upgrade.push(b"GET /_vallum HTTP/1.1\r\nHost: wingman.gold\r\n\r\n");
        assert_eq!(
            bad_upgrade.next_frame().expect_err("missing Upgrade header"),
            FrameError::BadUpgrade
        );

        let mut bad_status = FrameReader::new();
        bad_status.push(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(
            bad_status.next_frame().expect_err("non-101 status rejected"),
            FrameError::BadUpgrade
        );

        let mut oversized = FrameReader::new();
        let mut blob = b"GET /_vallum HTTP/1.1\r\nX-Pad: ".to_vec();
        blob.resize(MAX_HTTP_PRELUDE + 32, b'a');
        oversized.push(&blob);
        assert_eq!(
            oversized.next_frame().expect_err("oversized prelude"),
            FrameError::BadUpgrade
        );
    }
}
