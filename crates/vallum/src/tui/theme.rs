// SPDX-License-Identifier: Apache-2.0

//! "Boundary & Signal" TUI design system, color tokens, and typographic helpers.
//!
//! Centralises every color and modifier used across the terminal cockpit so
//! visual hierarchy is consistent and `NO_COLOR` (`https://no-color.org/`)
//! degrades gracefully to bold/dim/reversed monochrome without losing meaning.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

/// Semantic token set for the TUI.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub color: bool,
}

/// Active theme for the current environment.
#[must_use]
pub fn theme() -> Theme {
    Theme::from_env(
        std::env::var_os("NO_COLOR").is_some(),
        std::env::var("TERM").ok().as_deref(),
    )
}

impl Theme {
    #[must_use]
    pub fn from_env(no_color: bool, term: Option<&str>) -> Self {
        let dumb = matches!(term, Some("dumb"));
        Self {
            color: !no_color && !dumb,
        }
    }

    /// Primary signal / brand accent (bold cyan).
    #[must_use]
    pub fn accent(self) -> Style {
        if self.color {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::BOLD)
        }
    }

    /// Non-bold cyan signal (secondary accent, values).
    #[must_use]
    pub fn signal(self) -> Style {
        if self.color {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        }
    }

    /// Primary readable foreground text.
    #[must_use]
    pub fn text(self) -> Style {
        if self.color {
            Style::default().fg(Color::White)
        } else {
            Style::default()
        }
    }

    /// Bold primary foreground text.
    #[must_use]
    pub fn text_bold(self) -> Style {
        self.text().add_modifier(Modifier::BOLD)
    }

    /// Secondary metadata text.
    #[must_use]
    pub fn subtext(self) -> Style {
        if self.color {
            Style::default().fg(Color::Gray)
        } else {
            Style::default()
        }
    }

    /// Muted labels, borders, and hints.
    #[must_use]
    pub fn muted(self) -> Style {
        if self.color {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default().add_modifier(Modifier::DIM)
        }
    }

    /// Healthy / active / inserted state (emerald).
    #[must_use]
    pub fn ok(self) -> Style {
        if self.color {
            Style::default().fg(Color::Green)
        } else {
            Style::default()
        }
    }

    /// Bold healthy state.
    #[must_use]
    pub fn ok_bold(self) -> Style {
        self.ok().add_modifier(Modifier::BOLD)
    }

    /// Warning / aging / rotating state (amber).
    #[must_use]
    pub fn warn(self) -> Style {
        if self.color {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().add_modifier(Modifier::UNDERLINED)
        }
    }

    /// Bold warning state.
    #[must_use]
    pub fn warn_bold(self) -> Style {
        self.warn().add_modifier(Modifier::BOLD)
    }

    /// Error / expired / deleted state (crimson).
    #[must_use]
    pub fn danger(self) -> Style {
        if self.color {
            Style::default().fg(Color::Red)
        } else {
            Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
        }
    }

    /// Bold error state.
    #[must_use]
    pub fn danger_bold(self) -> Style {
        self.danger().add_modifier(Modifier::BOLD)
    }

    /// Outbound TX signal (magenta).
    #[must_use]
    pub fn tx_signal(self) -> Style {
        if self.color {
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::BOLD)
        }
    }

    /// Outbound TX sparkline bars.
    #[must_use]
    pub fn tx_bar(self) -> Style {
        if self.color {
            Style::default().fg(Color::Magenta)
        } else {
            Style::default()
        }
    }

    /// Inverted brand pill (` ◆ VALLUM ` or active tab).
    #[must_use]
    pub fn pill_accent(self) -> Style {
        if self.color {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
        }
    }

    /// Inverted active status badge (` ● ACTIVE `).
    #[must_use]
    pub fn pill_ok(self) -> Style {
        if self.color {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
        }
    }

    /// Inverted warning/transitional status badge (` ◐ STARTING `).
    #[must_use]
    pub fn pill_warn(self) -> Style {
        if self.color {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
        }
    }

    /// Inverted failed status badge (` ✖ FAILED `).
    #[must_use]
    pub fn pill_danger(self) -> Style {
        if self.color {
            Style::default()
                .fg(Color::White)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
        }
    }

    /// Inverted inactive status badge (` ○ INACTIVE `).
    #[must_use]
    pub fn pill_muted(self) -> Style {
        if self.color {
            Style::default()
                .fg(Color::White)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::DIM)
        }
    }

    /// Selected table row highlight.
    #[must_use]
    pub fn row_selected(self) -> Style {
        if self.color {
            Style::default()
                .bg(Color::Rgb(24, 42, 58))
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
        }
    }

    /// Dynamic-width section divider (`── label ──────────────────`).
    #[must_use]
    pub fn section_rule(self, width: u16, label: &str) -> Line<'static> {
        let prefix = format!("── {label} ");
        let tail_len = usize::from(width)
            .saturating_sub(prefix.chars().count() + 2)
            .max(4);
        Line::from(vec![
            Span::styled("── ".to_owned(), self.muted()),
            Span::styled(
                format!("{label} "),
                self.subtext().add_modifier(Modifier::BOLD),
            ),
            Span::styled("─".repeat(tail_len), self.muted()),
        ])
    }
}

/// Condense a multi-kilobyte `vallum1:...` public line into a scannable
/// head…tail capsule so the detail pane never floods with 40 lines of hex.
#[must_use]
pub fn abbreviate_public_line(line: &str, max_chars: usize) -> String {
    let trimmed = line.trim();
    let count = trimmed.chars().count();
    if count <= max_chars || max_chars < 20 {
        return trimmed.to_owned();
    }
    let head_len = (max_chars * 3) / 5;
    let tail_len = max_chars.saturating_sub(head_len + 1);
    let head: String = trimmed.chars().take(head_len).collect();
    let tail: String = trimmed
        .chars()
        .skip(count.saturating_sub(tail_len))
        .collect();
    format!("{head}…{tail} ({count} B)")
}

/// Render a compact proportional RX/TX bar (`━━━──────`) for Tufte data-ink
/// comparison inside the peer detail pane.
#[must_use]
pub fn transfer_share_bar(rx: u64, tx: u64, width: usize) -> (String, String) {
    let total = rx.saturating_add(tx);
    if total == 0 || width == 0 {
        return ("─".repeat(width), String::new());
    }
    let rx_cells = ((rx as u128 * width as u128) / total as u128) as usize;
    let rx_cells = if rx > 0 && rx_cells == 0 {
        1
    } else if tx > 0 && rx_cells >= width {
        width.saturating_sub(1)
    } else {
        rx_cells.min(width)
    };
    let tx_cells = width.saturating_sub(rx_cells);
    ("━".repeat(rx_cells), "━".repeat(tx_cells))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_color_mode_uses_modifiers_instead_of_ansi_colors() {
        let mono = Theme::from_env(true, Some("xterm-256color"));
        assert!(!mono.color);
        assert_eq!(mono.accent().fg, None);
        assert!(mono.pill_accent().add_modifier.contains(Modifier::REVERSED));

        let dumb = Theme::from_env(false, Some("dumb"));
        assert!(!dumb.color);

        let full = Theme::from_env(false, Some("xterm-256color"));
        assert!(full.color);
        assert_eq!(full.accent().fg, Some(Color::Cyan));
    }

    #[test]
    fn abbreviate_public_line_condenses_multi_kilobyte_keys() {
        let short = "vallum1:0003:abcd:-";
        assert_eq!(abbreviate_public_line(short, 40), short);

        let long = format!("vallum1:0003:{}:-", "a1b2".repeat(600));
        let condensed = abbreviate_public_line(&long, 40);
        assert!(condensed.starts_with("vallum1:0003:"));
        assert!(condensed.contains('…'));
        assert!(condensed.ends_with("B)"));
        assert!(condensed.chars().count() < 60);
    }

    #[test]
    fn transfer_share_bar_partitions_width_proportionally() {
        let (rx, tx) = transfer_share_bar(0, 0, 10);
        assert_eq!(rx.chars().count(), 10);
        assert!(tx.is_empty());

        let (rx, tx) = transfer_share_bar(750, 250, 8);
        assert_eq!(rx.chars().count(), 6);
        assert_eq!(tx.chars().count(), 2);
    }
}
