// SPDX-License-Identifier: Apache-2.0

//! Protocol-level errors.
//!
//! These are Vallum's own errors and never wrap an SDK type: the adapter maps
//! provider failures into [`vallum_crypto`] errors, which are carried here
//! unchanged.

use core::fmt;

use vallum_crypto::{KdfError, KemError, SuiteError};

/// A handshake or wire-framing failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// Malformed or out-of-spec wire data.
    Wire(String),
    /// The message was not the type this step expects.
    WrongMessageType {
        /// The type this step requires.
        expected: &'static str,
        /// The type that arrived.
        got: u8,
    },
    /// The message's suite id is not ours — a downgrade attempt or a mismatch.
    SuiteMismatch {
        /// The suite id this endpoint is using.
        expected: u16,
        /// The suite id carried by the message.
        got: u16,
    },
    /// The message's protocol version is not ours.
    VersionMismatch {
        /// The version this endpoint speaks.
        expected: u8,
        /// The version carried by the message.
        got: u8,
    },
    /// The echoed receiver index did not match our sender index.
    WrongReceiverIndex {
        /// The index we are known by.
        expected: u32,
        /// The index the peer echoed.
        got: u32,
    },
    /// A peer's key-confirmation value did not verify.
    ///
    /// Raised in both directions: [`crate::handshake::initiator_process_resp`]
    /// when the *responder's* confirmation in `RespHello` fails, and
    /// [`crate::handshake::responder_process_conf`] when the *initiator's* in
    /// `InitConf` fails.
    Confirmation,
    /// A hybrid-KEM operation failed.
    Kem(KemError),
    /// A key-derivation operation failed.
    Kdf(KdfError),
    /// A suite operation failed.
    Suite(SuiteError),
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(reason) => write!(f, "HandshakeError: bad wire data: {reason}"),
            Self::WrongMessageType { expected, got } => {
                write!(f, "HandshakeError: expected {expected}, got message type {got:#04x}")
            }
            Self::SuiteMismatch { expected, got } => write!(
                f,
                "HandshakeError: suite mismatch (we use {expected:#06x}, message says {got:#06x})"
            ),
            Self::VersionMismatch { expected, got } => write!(
                f,
                "HandshakeError: version mismatch (we speak {expected}, message says {got})"
            ),
            Self::WrongReceiverIndex { expected, got } => write!(
                f,
                "HandshakeError: receiver index mismatch (ours is {expected}, peer echoed {got})"
            ),
            Self::Confirmation => write!(f, "HandshakeError: key confirmation failed"),
            Self::Kem(e) => write!(f, "HandshakeError: {e}"),
            Self::Kdf(e) => write!(f, "HandshakeError: {e}"),
            Self::Suite(e) => write!(f, "HandshakeError: {e}"),
        }
    }
}

impl std::error::Error for HandshakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Kem(e) => Some(e),
            Self::Kdf(e) => Some(e),
            Self::Suite(e) => Some(e),
            _ => None,
        }
    }
}

impl From<KemError> for HandshakeError {
    fn from(e: KemError) -> Self {
        Self::Kem(e)
    }
}

impl From<KdfError> for HandshakeError {
    fn from(e: KdfError) -> Self {
        Self::Kdf(e)
    }
}

impl From<SuiteError> for HandshakeError {
    fn from(e: SuiteError) -> Self {
        Self::Suite(e)
    }
}
