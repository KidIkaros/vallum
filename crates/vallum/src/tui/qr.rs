// SPDX-License-Identifier: Apache-2.0

//! Animated multi-frame QR for a bundle.
//!
//! A tri-hybrid config is far beyond one QR (the public line alone is ~4.7 KB
//! of hex), so the bundle is split into frames with an integrity hash.

use std::time::{Duration, Instant};

use qrcode::{EcLevel, QrCode};
use vallum_crypto::CryptoSuite;

const HEADER: &str = "VALLUM1";
const MAX_FRAMES: usize = 16;

#[derive(Debug)]
pub struct QrState {
    pub frames: Vec<String>,
    pub index: usize,
    pub last: Instant,
    pub hash: String,
    pub path: String,
}

impl QrState {
    pub fn next(&mut self) {
        if !self.frames.is_empty() {
            self.index = (self.index + 1) % self.frames.len();
        }
    }

    pub fn previous(&mut self) {
        if !self.frames.is_empty() {
            self.index = (self.index + self.frames.len() - 1) % self.frames.len();
        }
    }

    pub fn tick(&mut self) {
        if self.frames.len() > 1 && self.last.elapsed() >= Duration::from_millis(700) {
            self.next();
            self.last = Instant::now();
        }
    }

    #[must_use]
    pub fn current(&self) -> &str {
        self.frames.get(self.index).map_or("", String::as_str)
    }
}

/// Encode a bundle as frames, reducing the chunk size until every frame fits.
///
/// # Errors
///
/// If even the smallest chunk cannot be encoded or the frame count exceeds the
/// bound.
pub fn encode(data: &str, path: &str) -> Result<QrState, String> {
    let suite = vallum_crypto_sdk::SdkSuite::tri_hybrid();
    let hash = suite.hash(b"vallum/bundle/v1", data.as_bytes());
    let hash = crate::keys::hex_encode(&hash[..8]);
    for chunk_size in [900usize, 700, 500, 300, 180] {
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
            return Ok(QrState {
                frames,
                index: 0,
                last: Instant::now(),
                hash,
                path: path.to_owned(),
            });
        }
    }
    Err("the bundle does not fit in a bounded QR frame set; use the .vallum-bundle file".to_owned())
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

/// Render one frame as terminal lines. Each module is two characters wide.
///
/// # Errors
///
/// If the frame cannot be encoded.
pub fn render(frame: &str) -> Result<Vec<String>, String> {
    let code = QrCode::with_error_correction_level(frame.as_bytes(), EcLevel::L)
        .map_err(|error| error.to_string())?;
    let width = code.width();
    let mut lines = Vec::with_capacity(width);
    for y in 0..width {
        let mut line = String::with_capacity(width * 2);
        for x in 0..width {
            if code[(x, y)] == qrcode::Color::Dark {
                line.push('█');
            } else {
                line.push(' ');
            }
        }
        lines.push(line);
    }
    Ok(lines)
}
