// SPDX-License-Identifier: Apache-2.0

//! A logger small enough to read in one sitting.
//!
//! A tunnel logs at a low rate and to one place, so pulling in a logging
//! framework would buy indirection and a feature matrix and nothing else. What
//! matters is the property P6.3 established: **nothing secret is ever printed**.
//! The device has a redacting [`std::fmt::Debug`] for exactly that reason, and
//! this module is the only other place that turns internal state into text, so it
//! is the other place a key could leak. It does not: it formats what callers hand
//! it, and callers hand it peer ids, epochs, socket addresses, and byte counts.

use std::fmt;

/// How loud to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// A failure.
    Error,
    /// Something surprising that was recovered from.
    Warn,
    /// State changes: a handshake completed, an interface came up.
    Info,
    /// Per-event detail.
    Debug,
}

impl Level {
    /// Parse a configured level. Case-insensitive; `None` if unrecognised.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "error" => Some(Self::Error),
            "warn" | "warning" => Some(Self::Warn),
            "info" => Some(Self::Info),
            "debug" | "trace" => Some(Self::Debug),
            _ => None,
        }
    }

    /// The configured spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }
}

/// A destination and a threshold.
#[derive(Debug, Clone, Copy)]
pub struct Logger {
    level: Level,
}

impl Logger {
    /// A logger that emits `level` and above.
    #[must_use]
    pub fn new(level: Level) -> Self {
        Self { level }
    }

    /// The threshold.
    #[must_use]
    pub fn level(&self) -> Level {
        self.level
    }

    /// Whether a message at `level` would be emitted.
    #[must_use]
    pub fn enabled(&self, level: Level) -> bool {
        level <= self.level
    }

    /// Emit one message, if the level passes.
    pub fn log(&self, level: Level, args: fmt::Arguments<'_>) {
        if !self.enabled(level) {
            return;
        }
        eprintln!("vallum[{}] {args}", level.as_str());
    }
}

/// See [`Logger::log`].
#[macro_export]
macro_rules! log_error {
    ($logger:expr, $($arg:tt)*) => {
        $logger.log($crate::logging::Level::Error, format_args!($($arg)*))
    };
}

/// See [`Logger::log`].
#[macro_export]
macro_rules! log_warn {
    ($logger:expr, $($arg:tt)*) => {
        $logger.log($crate::logging::Level::Warn, format_args!($($arg)*))
    };
}

/// See [`Logger::log`].
#[macro_export]
macro_rules! log_info {
    ($logger:expr, $($arg:tt)*) => {
        $logger.log($crate::logging::Level::Info, format_args!($($arg)*))
    };
}

/// See [`Logger::log`].
#[macro_export]
macro_rules! log_debug {
    ($logger:expr, $($arg:tt)*) => {
        $logger.log($crate::logging::Level::Debug, format_args!($($arg)*))
    };
}
