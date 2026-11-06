// SPDX-License-Identifier: Apache-2.0

//! "Boundary & Signal" CLI typography and ANSI color tokens.
//!
//! Styling activates only when standard output is a terminal, `NO_COLOR` is not
//! set (`https://no-color.org/`), and `TERM` is not `"dumb"`. Piped output,
//! scripts, and test captures receive plain text with no escape sequences.

use std::io::IsTerminal;

/// Whether ANSI color codes should be emitted on stdout.
#[must_use]
pub fn color_enabled() -> bool {
    std::env::var_os("NO_COLOR").is_none()
        && std::env::var("TERM").as_deref() != Ok("dumb")
        && std::io::stdout().is_terminal()
}

/// Format a status badge (`PASS`, `WARN`, `FAIL`) with semantic color and glyph
/// on an interactive terminal, or plain padded text when piped.
#[must_use]
pub fn status_badge(status: &str) -> String {
    if !color_enabled() {
        return format!("{status:<5}");
    }
    match status {
        "PASS" => "\x1b[1;32m● PASS\x1b[0m".to_owned(),
        "WARN" => "\x1b[1;33m▲ WARN\x1b[0m".to_owned(),
        "FAIL" => "\x1b[1;31m✖ FAIL\x1b[0m".to_owned(),
        other => format!("{other:<5}"),
    }
}

/// Bold cyan brand/signal accent (`◆ Vallum` or highlighted identifiers).
#[must_use]
pub fn accent(text: &str) -> String {
    if color_enabled() {
        format!("\x1b[1;36m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

/// Bold emerald confirmation (`ok`, `ready`, `enrolled`).
#[must_use]
pub fn ok(text: &str) -> String {
    if color_enabled() {
        format!("\x1b[1;32m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

/// Bold amber warning.
#[must_use]
pub fn warn(text: &str) -> String {
    if color_enabled() {
        format!("\x1b[1;33m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

/// Muted secondary metadata or table header rule.
#[must_use]
pub fn muted(text: &str) -> String {
    if color_enabled() {
        format!("\x1b[90m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

/// Bold table header line.
#[must_use]
pub fn table_header(text: &str) -> String {
    if color_enabled() {
        format!("\x1b[1;36m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_tty_badges_are_plain_and_padded() {
        // Under cargo test stdout is a pipe, or NO_COLOR may be set; either way
        // no escape codes may leak into captured output unless on a live TTY.
        if !color_enabled() {
            assert_eq!(status_badge("PASS"), "PASS ");
            assert_eq!(status_badge("WARN"), "WARN ");
            assert_eq!(status_badge("FAIL"), "FAIL ");
            assert_eq!(accent("vallum0"), "vallum0");
        }
    }
}
