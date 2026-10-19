// SPDX-License-Identifier: Apache-2.0

//! The data-plane key schedule: expanding a session's root key into directional
//! AEAD keys and nonce prefixes.
//!
//! P1 ends at `KEY`, a single 32-byte secret both ends hold. The data plane
//! needs four things from it — a key and a nonce prefix for each direction —
//! and must be able to do so again for a later epoch (P4's ratchet).
//!
//! ```text
//! epoch_root = KDF(salt = KEY, ikm = frame([transcript, epoch]), info = "vallum/data/root/v1")
//! dir_key    = KDF(salt = epoch_root, ikm = [direction], info = "vallum/data/key/v1",   32)
//! dir_nonce  = KDF(salt = epoch_root, ikm = [direction], info = "vallum/data/nonce/v1", 16)
//! ```
//!
//! # Why this shape
//!
//! - **The transcript and epoch are bound into the key, not into every packet.**
//!   P1's `KEY` already commits to the transcript (through `ROOT`), and the
//!   epoch is folded in here, so a packet sealed in one session can never open
//!   in another even if two sessions were somehow keyed alike. Re-binding the
//!   transcript into each packet's associated data would cost 32 bytes per
//!   packet for no additional security, so the per-packet associated data is
//!   just the header and the counter (see [`crate::data`]). Between them, all
//!   four of `{transcript, epoch, suite, counter}` are bound to every packet.
//!
//! - **Direction is an input, purpose is a label.** Each derivation is a
//!   distinct HKDF invocation, so no two uses share a key even in principle —
//!   not merely "different bytes of one stream". That is the property the P2
//!   gate calls *no key ambiguity*.
//!
//! - **The nonce is `prefix ‖ counter`.** A 24-byte nonce is far wider than the
//!   64-bit counter needs, so the fixed 16-byte prefix is derived per key and
//!   the counter fills the rest. Two different keys therefore cannot collide on
//!   a nonce even at the same counter value, and the counter is never reused
//!   under one key ([`crate::data::REJECT_AFTER_MESSAGES`] is far below 2⁶⁴).

use core::fmt;

use vallum_crypto::{frame, CryptoSuite, KdfError, SharedSecret};

use crate::handshake::SessionKeys;

/// HKDF `info` label for the per-epoch data-plane root.
pub const DATA_ROOT_INFO: &[u8] = b"vallum/data/root/v1";
/// HKDF `info` label for a directional AEAD key.
pub const DATA_KEY_INFO: &[u8] = b"vallum/data/key/v1";
/// HKDF `info` label for a directional nonce prefix.
pub const DATA_NONCE_INFO: &[u8] = b"vallum/data/nonce/v1";

/// AEAD key size, in bytes.
pub const DATA_KEY_SIZE: usize = 32;

/// AEAD nonce size, in bytes.
pub const NONCE_SIZE: usize = 24;

/// Size of the per-key fixed part of the nonce, in bytes.
pub const NONCE_PREFIX_SIZE: usize = 16;

/// Size of the per-packet counter, in bytes.
pub const COUNTER_SIZE: usize = NONCE_SIZE - NONCE_PREFIX_SIZE;

/// Which way round a directional key runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// The initiator's sending key — the responder's receiving key.
    InitiatorToResponder,
    /// The responder's sending key — the initiator's receiving key.
    ResponderToInitiator,
}

impl Direction {
    /// The one-byte label that separates the two directions in the schedule.
    #[must_use]
    fn label(self) -> u8 {
        match self {
            Self::InitiatorToResponder => 0x01,
            Self::ResponderToInitiator => 0x02,
        }
    }
}

/// Which end of the handshake this endpoint is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// We sent `InitHello`.
    Initiator,
    /// We answered it.
    Responder,
}

/// One direction's AEAD key and nonce prefix.
///
/// Opaque and non-`Copy`: it is handed to exactly one
/// [`Sender`](crate::data::Sender) or [`Receiver`](crate::data::Receiver) and
/// zeroized on drop. There is no public accessor, so a caller cannot read a data
/// key back out or build the wrong-direction pair by hand.
#[derive(Clone)]
pub(crate) struct DirectionalKey {
    key: [u8; DATA_KEY_SIZE],
    nonce_prefix: [u8; NONCE_PREFIX_SIZE],
}

impl DirectionalKey {
    /// Derive one direction from an epoch root.
    fn derive<S: CryptoSuite + ?Sized>(
        suite: &S,
        epoch_root: &[u8; 32],
        direction: Direction,
    ) -> Result<Self, KdfError> {
        let label = [direction.label()];
        let mut key = [0u8; DATA_KEY_SIZE];
        suite.kdf(epoch_root, &label, DATA_KEY_INFO, &mut key)?;
        let mut nonce_prefix = [0u8; NONCE_PREFIX_SIZE];
        suite.kdf(epoch_root, &label, DATA_NONCE_INFO, &mut nonce_prefix)?;
        Ok(Self { key, nonce_prefix })
    }

    /// The AEAD key.
    pub(crate) fn key(&self) -> &[u8; DATA_KEY_SIZE] {
        &self.key
    }

    /// The fixed part of the nonce.
    pub(crate) fn nonce_prefix(&self) -> &[u8; NONCE_PREFIX_SIZE] {
        &self.nonce_prefix
    }
}

impl Drop for DirectionalKey {
    fn drop(&mut self) {
        self.key.iter_mut().for_each(|b| *b = 0);
        core::hint::black_box(&mut self.key);
    }
}

impl fmt::Debug for DirectionalKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DirectionalKey(<redacted>)")
    }
}

/// Both directions of one epoch's data-plane keys.
///
/// Produced by [`DataKeys::from_session`] at epoch 0 and by
/// [`DataKeys::derive`] on a rekey. Nothing here is secret-bearing in `Debug`.
#[derive(Debug)]
pub struct DataKeys {
    epoch: u64,
    transcript: [u8; 32],
    init_to_resp: DirectionalKey,
    resp_to_init: DirectionalKey,
}

impl DataKeys {
    /// Derive epoch 0's keys from a completed handshake.
    ///
    /// # Errors
    ///
    /// [`KdfError`] if the suite's KDF fails, or if the suite's AEAD geometry is
    /// not the 32-byte-key / 24-byte-nonce shape this schedule assumes — a
    /// silently truncated key is exactly the failure a boundary is meant to
    /// prevent.
    pub fn from_session<S: CryptoSuite + ?Sized>(
        suite: &S,
        session: &SessionKeys,
    ) -> Result<Self, KdfError> {
        Self::derive(suite, &session.key, &session.transcript, 0)
    }

    /// Derive `epoch`'s keys from an epoch root.
    ///
    /// At epoch 0 the root is the handshake's `KEY`. P4's ratchet passes the
    /// previous epoch's root here to rekey without a new handshake, which is why
    /// this takes the root directly rather than a [`SessionKeys`].
    ///
    /// # Errors
    ///
    /// As [`DataKeys::from_session`].
    pub fn derive<S: CryptoSuite + ?Sized>(
        suite: &S,
        epoch_root: &SharedSecret,
        transcript: &[u8; 32],
        epoch: u64,
    ) -> Result<Self, KdfError> {
        let sizes = suite.sizes();
        if sizes.aead_key != DATA_KEY_SIZE {
            return Err(KdfError::new(format!(
                "suite AEAD key is {} bytes, the data plane needs {DATA_KEY_SIZE}",
                sizes.aead_key
            )));
        }
        if sizes.aead_nonce != NONCE_SIZE {
            return Err(KdfError::new(format!(
                "suite AEAD nonce is {} bytes, the data plane needs {NONCE_SIZE}",
                sizes.aead_nonce
            )));
        }

        let framed = frame(&[transcript, &epoch.to_be_bytes()]);
        let mut root = [0u8; 32];
        suite.kdf(epoch_root.as_bytes(), &framed, DATA_ROOT_INFO, &mut root)?;

        let init_to_resp = DirectionalKey::derive(suite, &root, Direction::InitiatorToResponder)?;
        let resp_to_init = DirectionalKey::derive(suite, &root, Direction::ResponderToInitiator)?;

        let keys = Self {
            epoch,
            transcript: *transcript,
            init_to_resp,
            resp_to_init,
        };
        crate::scrub(&mut root);
        Ok(keys)
    }

    /// The epoch these keys belong to.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The transcript these keys are bound to.
    #[must_use]
    pub fn transcript(&self) -> &[u8; 32] {
        &self.transcript
    }

    /// Split into `(sending, receiving)` for `role`.
    pub(crate) fn split(self, role: Role) -> (DirectionalKey, DirectionalKey) {
        match role {
            // The initiator sends onward with the initiator→responder key.
            Role::Initiator => (self.init_to_resp, self.resp_to_init),
            Role::Responder => (self.resp_to_init, self.init_to_resp),
        }
    }
}

#[cfg(feature = "test-internals")]
/// One direction's `(key, nonce prefix)`, for the external test component.
pub type TestDirection = ([u8; 32], [u8; 16]);

#[cfg(feature = "test-internals")]
impl DataKeys {
    /// The two directions' keys and nonce prefixes, for the external test
    /// component. Test-only; the feature is never enabled by a library build.
    #[must_use]
    pub fn test_directions(&self) -> ([u8; 32], [u8; 32], [u8; 16], [u8; 16]) {
        (
            *self.init_to_resp.key(),
            *self.resp_to_init.key(),
            *self.init_to_resp.nonce_prefix(),
            *self.resp_to_init.nonce_prefix(),
        )
    }

    /// The `(key, nonce prefix)` this role sends with and receives with.
    #[must_use]
    pub fn test_split(&self, role: Role) -> (TestDirection, TestDirection) {
        let (send, recv) = match role {
            Role::Initiator => (&self.init_to_resp, &self.resp_to_init),
            Role::Responder => (&self.resp_to_init, &self.init_to_resp),
        };
        (
            (*send.key(), *send.nonce_prefix()),
            (*recv.key(), *recv.nonce_prefix()),
        )
    }
}
