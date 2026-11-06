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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrKind {
    Bundle,
    Invite,
}

#[derive(Debug)]
pub struct QrState {
    pub frames: Vec<String>,
    pub index: usize,
    pub last: Instant,
    pub hash: String,
    pub path: String,
    pub kind: QrKind,
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
            return Ok(QrState {
                frames,
                index: 0,
                last: Instant::now(),
                hash,
                path: path.to_owned(),
                kind: QrKind::Bundle,
            });
        }
    }
    Err("the bundle does not fit in a bounded QR frame set; use the .vallum-bundle file".to_owned())
}

/// Encode a v2 one-time invite command (`vallum join <ticket>`) as a QR modal.
///
/// Unlike a bundle QR, this carries no private key — only the single-use token,
/// the invite id, and the server's expected fingerprint.
pub fn encode_invite(command: &str, path: &str) -> Result<QrState, String> {
    let mut state = encode(command, path)?;
    state.kind = QrKind::Invite;
    Ok(state)
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

/// Render one frame as compact half-block terminal lines with an ISO quiet
/// zone. Two vertical QR modules are packed into each terminal row (`▀`, `▄`,
/// `█`, `' '`) so every module has a ~1:1 square aspect ratio in monospace
/// fonts, and light modules are drawn as foreground blocks so the code sits on
/// a scannable white quiet-zoned plate over dark terminals.
///
/// # Errors
///
/// If the frame cannot be encoded.
pub fn render(frame: &str) -> Result<Vec<String>, String> {
    const QUIET: isize = 2;
    let code = QrCode::with_error_correction_level(frame.as_bytes(), EcLevel::L)
        .map_err(|error| error.to_string())?;
    let size = code.width() as isize;
    let is_dark = |x: isize, y: isize| -> bool {
        x >= 0
            && y >= 0
            && x < size
            && y < size
            && code[(x as usize, y as usize)] == qrcode::Color::Dark
    };
    let span = (size + QUIET * 2) as usize;
    let mut lines = Vec::with_capacity(span.div_ceil(2));
    let mut y = -QUIET;
    while y < size + QUIET {
        let mut line = String::with_capacity(span * 3);
        for x in -QUIET..(size + QUIET) {
            let top_dark = is_dark(x, y);
            let bottom_dark = is_dark(x, y + 1);
            let ch = match (top_dark, bottom_dark) {
                (false, false) => '█',
                (false, true) => '▀',
                (true, false) => '▄',
                (true, true) => ' ',
            };
            line.push(ch);
        }
        lines.push(line);
        y += 2;
    }
    Ok(lines)
}
