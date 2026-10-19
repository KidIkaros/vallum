// SPDX-License-Identifier: Apache-2.0

//! The op-A-keyed `RespHello` admission tag (P6.8).
//!
//! One actor: denying a forged `RespHello` the initiator's keygen and two
//! decapsulations. It is an admission token, not the authentication mechanism —
//! the responder confirmation still authenticates.

use vallum_crypto::{frame, CryptoSuite, SharedSecret};

use crate::error::HandshakeError;
use crate::wire::{tag, Message, MessageType};

use super::keyschedule::verify_value;

// ── RespHello admission tag (P6.8) ───────────────────────────────────

/// Length of the `RespHello` admission tag, in bytes.
///
/// The same size as a confirmation value: a MAC over the whole message under a
/// key derived from op A, so only a party that decapsulated op A can produce it.
pub const RESP_TAG_SIZE: usize = 32;

/// Salt for the key that authenticates a `RespHello`.
const RESP_TAG_SALT: &[u8] = b"vallum/resp-tag/seal/v1";
/// Label for the key that authenticates a `RespHello`.
const RESP_TAG_KEY_INFO: &[u8] = b"vallum/resp-tag/key/v1";
/// Label for the tag itself.
const RESP_TAG_INFO: &[u8] = b"vallum/resp-tag/v1";

/// Derive the op-A-keyed key that authenticates a `RespHello` (P6.8).
///
/// Both endpoints can compute it, and both can do so before ops B and C are
/// touched: the initiator from the encapsulation it made, the responder from
/// the decapsulation it did. Only a holder of the responder's static secret can
/// produce it, which is what makes it an admission token for the initiator.
pub(super) fn derive_resp_tag_key(
    suite: &dyn CryptoSuite,
    legs: &[SharedSecret],
) -> Result<[u8; RESP_TAG_SIZE], HandshakeError> {
    let parts: Vec<&[u8]> = legs.iter().map(|leg| &leg.as_bytes()[..]).collect();
    let mut key = [0u8; RESP_TAG_SIZE];
    suite
        .kdf(RESP_TAG_SALT, &frame(&parts), RESP_TAG_KEY_INFO, &mut key)
        .map_err(HandshakeError::Kdf)?;
    Ok(key)
}

/// The `RespHello` admission tag: a MAC over the message under the op-A key.
///
/// `input` is [`crate::wire::Message::resp_tag_input`] — the header plus every
/// field except the tag itself — so the tag binds the optional identity
/// signature too, and mutating any byte of a captured message fails it.
pub fn resp_tag(
    suite: &dyn CryptoSuite,
    key: &[u8; RESP_TAG_SIZE],
    input: &[u8],
) -> Result<[u8; RESP_TAG_SIZE], HandshakeError> {
    let mut tag = [0u8; RESP_TAG_SIZE];
    suite
        .kdf(key, input, RESP_TAG_INFO, &mut tag)
        .map_err(HandshakeError::Kdf)?;
    Ok(tag)
}

/// Verify a `RespHello`'s admission tag with a key retained at send time (P6.8).
///
/// The transport uses this to reject a forged `RespHello` **before** rebuilding
/// the initiator state — a rebuild costs an ephemeral keygen and an op-A
/// encapsulation, which is exactly the work the tag exists to deny an attacker
/// who only observed our `InitHello`. `tag_key` comes from
/// [`InitiatorState::resp_tag_key`].
///
/// A malformed message or a missing tag returns `false`: the caller treats it
/// as a forged message, because nothing downstream would be reached either way.
#[must_use]
pub fn verify_resp_tag(
    suite: &dyn CryptoSuite,
    tag_key: &[u8; RESP_TAG_SIZE],
    resp_hello: &[u8],
) -> bool {
    let Ok(message) = Message::parse(resp_hello) else {
        return false;
    };
    if message.message_type() != MessageType::RespHello {
        return false;
    }
    let Ok(got) = message.require_array::<RESP_TAG_SIZE>(tag::PRE_TAG) else {
        return false;
    };
    let Ok(expected) = resp_tag(suite, tag_key, &message.resp_tag_input()) else {
        return false;
    };
    verify_value(suite, &expected, &got)
}

/// MEX: `KDF(salt = fresh, ikm = static_secret, info = "vallum/mex/v1")`.
///
/// Because HKDF's salt is the HMAC key, the output is unpredictable whenever the
/// static secret is — which is exactly the property that makes the shared secret
/// survive a subverted RNG.
