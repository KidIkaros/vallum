// SPDX-License-Identifier: Apache-2.0

//! Protocol-level errors.
//!
//! These are Vallum's own errors and never wrap an SDK type: the adapter maps
//! provider failures into [`vallum_crypto`] errors, which are carried here
//! unchanged.

use core::fmt;

use vallum_crypto::{AeadError, KdfError, KemError, SigError, SuiteError};

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
    /// The peer is configured with a signing key, but the message carried no
    /// identity signature. Fail closed: absence is never treated as "no identity
    /// wanted", or stripping the field would downgrade the session.
    IdentityMissing,
    /// The message carried an identity signature, but this endpoint has no
    /// signing key configured for the peer, so it cannot be checked. Fail closed
    /// rather than ignore an unverifiable assertion.
    IdentityUnexpected,
    /// A peer's hybrid identity signature did not verify — a forgery, a
    /// substitution, or a message/transcript mismatch.
    IdentityInvalid,
    /// The sealed peer hint did not name the peer the caller resolved it to.
    ///
    /// The hint is *confidential but not authenticated* (anyone who knows the
    /// responder's public key can produce one), so it is never trusted on its
    /// own: the transport resolves it to a configured peer, and this error
    /// means the caller's resolution and the hint disagreed — a spoofed hint, a
    /// stale peer table, or a bug. Fail closed rather than complete a handshake
    /// under a peer the initiator did not name.
    PeerHintMismatch,
    /// An operation needed a signing identity and this endpoint has none.
    NoSigningIdentity,
    /// A hybrid-KEM operation failed.
    Kem(KemError),
    /// A key-derivation operation failed.
    Kdf(KdfError),
    /// A signing operation failed.
    Sign(SigError),
    /// A suite operation failed.
    Suite(SuiteError),
    /// An AEAD operation failed.
    ///
    /// Only the cookie-reply layer uses the AEAD before a session exists: the
    /// reply is sealed under a key derived from the requester's `mac1`. A data
    /// plane failure is [`DataError`], not this.
    Aead(AeadError),
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(reason) => write!(f, "HandshakeError: bad wire data: {reason}"),
            Self::WrongMessageType { expected, got } => {
                write!(
                    f,
                    "HandshakeError: expected {expected}, got message type {got:#04x}"
                )
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
            Self::IdentityMissing => write!(
                f,
                "HandshakeError: the peer is configured with a signing key but sent no identity signature"
            ),
            Self::IdentityUnexpected => write!(
                f,
                "HandshakeError: unexpected identity signature (no signing key configured for this peer)"
            ),
            Self::IdentityInvalid => write!(f, "HandshakeError: identity signature did not verify"),
            Self::PeerHintMismatch => write!(
                f,
                "HandshakeError: the sealed peer hint did not name the resolved peer"
            ),
            Self::NoSigningIdentity => {
                write!(f, "HandshakeError: this endpoint has no signing identity")
            }
            Self::Kem(e) => write!(f, "HandshakeError: {e}"),
            Self::Kdf(e) => write!(f, "HandshakeError: {e}"),
            Self::Sign(e) => write!(f, "HandshakeError: {e}"),
            Self::Suite(e) => write!(f, "HandshakeError: {e}"),
            Self::Aead(e) => write!(f, "HandshakeError: cookie reply did not authenticate: {e}"),
        }
    }
}

impl std::error::Error for HandshakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Kem(e) => Some(e),
            Self::Kdf(e) => Some(e),
            Self::Sign(e) => Some(e),
            Self::Suite(e) => Some(e),
            Self::Aead(e) => Some(e),
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

impl From<SigError> for HandshakeError {
    fn from(e: SigError) -> Self {
        Self::Sign(e)
    }
}

impl From<AeadError> for HandshakeError {
    fn from(e: AeadError) -> Self {
        Self::Aead(e)
    }
}

/// A data-plane failure.
///
/// Deliberately distinct from [`HandshakeError`]: the data plane has failure
/// modes the handshake does not — replay, counter exhaustion, recipient-index
/// demultiplexing — and conflating them would make the caller's retry logic
/// guess wrong. In particular a replay must **not** look like a forgery: the
/// tag verified, the packet is simply one we have already accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataError {
    /// The packet is not a well-formed data message.
    Wire(String),
    /// AEAD authentication failed: the packet was forged, corrupted, or sealed
    /// under a different key, nonce, or associated data.
    Aead(AeadError),
    /// Key derivation for the data plane failed.
    Kdf(KdfError),
    /// The packet's counter was already accepted, or is older than the replay
    /// window. `next` is one past the highest counter accepted so far.
    Replay {
        /// The counter carried by the rejected packet.
        counter: u64,
        /// One past the highest counter accepted so far.
        next: u64,
    },
    /// The counter reached [`crate::data::REJECT_AFTER_MESSAGES`]; the key must
    /// not be used to seal again.
    CounterExhausted {
        /// The counter that was refused.
        counter: u64,
    },
    /// The packet named a different session than this one. Data packets carry
    /// the *recipient's* index in the header, so this is how a receiver demuxes
    /// without trusting the source address.
    WrongIndex {
        /// This session's own index.
        expected: u32,
        /// The index carried by the packet.
        got: u32,
    },
    /// The epoch counter reached `u64::MAX`, so no further epoch can be
    /// installed. Unreachable in practice — it exists so the ratchet cannot
    /// silently wrap back onto a spent epoch.
    EpochExhausted {
        /// The epoch that could not be advanced past.
        epoch: u64,
    },
    /// A padded seal was asked for a target size that cannot hold the payload.
    ///
    /// The sealed plaintext is `u16 BE length ‖ payload ‖ zeros`, so the target
    /// must be at least the payload's length plus the prefix. A shaping machine
    /// that asks for less is a machine bug, not a wire condition, so it fails
    /// rather than silently sending an unpadded packet that breaks the
    /// indistinguishability it was supposed to provide.
    PaddingTooSmall {
        /// The payload's length.
        payload: usize,
        /// The target pre-image length the caller asked for.
        target: usize,
    },
    /// A rekey presented a different crypto suite than the session was
    /// established with.
    ///
    /// A suite is fixed for the life of a session: the epoch axis rides on one
    /// [`CryptoSuite`](vallum_crypto::CryptoSuite)'s key schedule, so changing
    /// suites means a new session, never a new epoch. Silently mixing them would
    /// defeat the point of binding the suite id into every derivation.
    SuiteChanged {
        /// The suite the session was established with.
        expected: u16,
        /// The suite the rekey used.
        got: u16,
    },
}

impl fmt::Display for DataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(reason) => write!(f, "DataError: bad wire data: {reason}"),
            Self::Aead(e) => write!(f, "DataError: authentication failed: {e}"),
            Self::Kdf(e) => write!(f, "DataError: {e}"),
            Self::Replay { counter, next } => write!(
                f,
                "DataError: counter {counter} rejected as replayed or too old (next is {next})"
            ),
            Self::CounterExhausted { counter } => {
                write!(f, "DataError: counter {counter} reached the rekey limit")
            }
            Self::WrongIndex { expected, got } => write!(
                f,
                "DataError: packet names session {got:#010x}, this session is {expected:#010x}"
            ),
            Self::EpochExhausted { epoch } => {
                write!(f, "DataError: epoch {epoch} cannot advance further")
            }
            Self::PaddingTooSmall { payload, target } => write!(
                f,
                "DataError: padded seal target {target} cannot hold a {payload}-byte payload"
            ),
            Self::SuiteChanged { expected, got } => write!(
                f,
                "DataError: rekey changed the crypto suite (session uses {expected:#06x}, rekey uses {got:#06x})"
            ),
        }
    }
}

impl std::error::Error for DataError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Aead(e) => Some(e),
            Self::Kdf(e) => Some(e),
            _ => None,
        }
    }
}

impl From<HandshakeError> for DataError {
    fn from(e: HandshakeError) -> Self {
        Self::Wire(e.to_string())
    }
}

impl From<AeadError> for DataError {
    fn from(e: AeadError) -> Self {
        Self::Aead(e)
    }
}

impl From<KdfError> for DataError {
    fn from(e: KdfError) -> Self {
        Self::Kdf(e)
    }
}
