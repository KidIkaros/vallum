// SPDX-License-Identifier: Apache-2.0

//! The frame codec behind the animated bundle QR, shared by every console.
//!
//! A tri-hybrid public line alone is ~4.7 KB of hex and a single QR holds at
//! most ~2.9 KB at version 40-L, so a bundle is split into up to 16 frames:
//!
//! `VALLUM1:<seq>/<total>:<sha256-prefix>:<chunk>`
//!
//! The TUI animates these frames as half-block terminal art; consoles that
//! render the code themselves (the GUI canvas, HTTP clients) take the frame
//! strings from [`encode`] and the module grid from [`grid`]. Same bytes on
//! every surface, so a phone that scans one console's animation reads the
//! other's.

use qrcode::{EcLevel, QrCode};
use vallum_crypto::CryptoSuite;

const HEADER: &str = "VALLUM1";
const MAX_FRAMES: usize = 16;

/// The encoded frames plus the integrity prefix the importer checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frames {
    /// One `VALLUM1:seq/total:hash:chunk` string per frame, in scan order.
    pub frames: Vec<String>,
    /// The first 8 hex chars of SHA-256(`"vallum/bundle/v1"` ‖ data).
    pub hash: String,
}

/// A QR module grid: `modules[y * size + x]` is 1 for a dark module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grid {
    /// Modules per side, without any quiet zone.
    pub size: u32,
    /// Row-major dark/light flags, length `size * size`.
    pub modules: Vec<u8>,
}

/// Encode data as frames, reducing the chunk size until every frame fits.
///
/// The chunk sizes are tried largest-first so small bundles stay few frames;
/// each candidate frame is verified against the encoder before it is kept.
///
/// # Errors
///
/// If even the smallest chunk cannot be encoded, or the frame count exceeds
/// the bound — the caller falls back to the `.vallum-bundle` file.
pub fn encode(data: &str) -> Result<Frames, String> {
    let suite = vallum_crypto_sdk::SdkSuite::tri_hybrid();
    let hash = suite.hash(b"vallum/bundle/v1", data.as_bytes());
    let hash = crate::keys::hex_encode(&hash[..8]);
    for chunk_size in [320usize, 240, 180, 500, 700, 900] {
        let chunks = split_chars(data, chunk_size);
        if chunks.is_empty() || chunks.len() > MAX_FRAMES {
            continue;
        }
        let total = chunks.len();
        let mut frames = Vec::with_capacity(total);
        let mut fits = true;
        for (index, chunk) in chunks.iter().enumerate() {
            let frame = format!("{HEADER}:{}/{total}:{hash}:{chunk}", index + 1);
            if QrCode::with_error_correction_level(frame.as_bytes(), EcLevel::L).is_err() {
                fits = false;
                break;
            }
            frames.push(frame);
        }
        if fits {
            return Ok(Frames { frames, hash });
        }
    }
    Err("the bundle does not fit in a bounded QR frame set; use the .vallum-bundle file".to_owned())
}

/// Render one frame string to its module grid, without any quiet zone — the
/// renderer adds that, the way the TUI's two-module plate does.
///
/// # Errors
///
/// If the frame cannot be encoded.
pub fn grid(frame: &str) -> Result<Grid, String> {
    let code = QrCode::with_error_correction_level(frame.as_bytes(), EcLevel::L)
        .map_err(|error| error.to_string())?;
    let size = code.width() as u32;
    let mut modules = Vec::with_capacity((size * size) as usize);
    for y in 0..size as usize {
        for x in 0..size as usize {
            modules.push(u8::from(code[(x, y)] == qrcode::Color::Dark));
        }
    }
    Ok(Grid { size, modules })
}

fn split_chars(data: &str, size: usize) -> Vec<&str> {
    let mut chunks = Vec::new();
    let mut start = 0;
    while start < data.len() {
        let mut end = (start + size).min(data.len());
        while end > start && !data.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            break;
        }
        chunks.push(&data[start..end]);
        start = end;
    }
    chunks
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    /// Small payload, one frame, and the header the importer parses.
    #[test]
    fn a_short_payload_is_a_single_frame() {
        let frames = encode("hello").expect("encode");
        assert_eq!(frames.frames.len(), 1);
        assert!(frames.frames[0].starts_with("VALLUM1:1/1:"));
        assert!(frames.frames[0].ends_with(":hello"));
        assert_eq!(frames.hash.len(), 16);
    }

    /// Frames reassemble to the payload in scan order, with the hash matching.
    #[test]
    fn frames_reassemble_in_scan_order() {
        let data = "x".repeat(2000);
        let frames = encode(&data).expect("encode");
        assert!(frames.frames.len() > 1);
        assert!(frames.frames.len() <= MAX_FRAMES);
        let mut rebuilt = String::new();
        for (index, frame) in frames.frames.iter().enumerate() {
            let body = frame.strip_prefix("VALLUM1:").expect("header");
            let (seq, rest) = body.split_once('/').expect("seq");
            let (total, rest) = rest.split_once(':').expect("total");
            let (hash, chunk) = rest.split_once(':').expect("hash");
            assert_eq!(seq, (index + 1).to_string());
            assert_eq!(total, frames.frames.len().to_string());
            assert_eq!(hash, frames.hash);
            rebuilt.push_str(chunk);
        }
        assert_eq!(rebuilt, data);
    }

    /// Chunking never splits a UTF-8 character.
    #[test]
    fn chunking_respects_char_boundaries() {
        let data = "é".repeat(500);
        let frames = encode(&data).expect("encode");
        let rebuilt: String = frames
            .frames
            .iter()
            .map(|frame| frame.rsplit(':').next().expect("chunk"))
            .collect();
        assert_eq!(rebuilt, data);
    }

    /// The grid is square, matches the encoder's width, and round-trips the
    /// dark modules the TUI's half-block renderer reads.
    #[test]
    fn the_grid_matches_the_encoder() {
        let frames = encode("VALLUM1:1/1:e8a12c4b:{\"v\":1}").expect("encode");
        let grid = grid(&frames.frames[0]).expect("grid");
        let code = QrCode::with_error_correction_level(frames.frames[0].as_bytes(), EcLevel::L)
            .expect("fits");
        assert_eq!(grid.size as usize, code.width());
        assert_eq!(grid.modules.len(), code.width() * code.width());
        for y in 0..code.width() {
            for x in 0..code.width() {
                assert_eq!(
                    grid.modules[y * code.width() + x],
                    u8::from(code[(x, y)] == qrcode::Color::Dark),
                    "module ({x}, {y})"
                );
            }
        }
    }
}
