// SPDX-License-Identifier: Apache-2.0

//! The configured-PSK admission tag on `InitHello`.
//!
//! PQ-WireGuard uses the configured PSK to authenticate the initiation before
//! the responder does ops B and C. Vallum does the same with an explicit tag:
//! it is checked after op A (the only operation needed to resolve the peer) and
//! before any responder encapsulation. `None` means no field and the existing
//! bytes; the tag is an admission check, not a transcript input.

use super::keyschedule::verify_value;
use super::HandshakeError;
use crate::wire::PSK_TAG_SIZE;
use vallum_crypto::{CryptoSuite, SharedSecret};

/// Domain for the admission tag.
const PSK_TAG_INFO: &[u8] = b"vallum/init-psk-tag/v1";

/// Compute the tag over `input` with the configured PSK.
pub(super) fn compute_psk_tag(
    suite: &dyn CryptoSuite,
    psk: &SharedSecret,
    input: &[u8],
) -> Result<[u8; PSK_TAG_SIZE], HandshakeError> {
    let mut tag = [0u8; PSK_TAG_SIZE];
    suite
        .kdf(psk.as_bytes(), input, PSK_TAG_INFO, &mut tag)
        .map_err(HandshakeError::Kdf)?;
    Ok(tag)
}

/// Verify a tag in constant time relative to the derived value.
pub(super) fn verify_psk_tag(
    suite: &dyn CryptoSuite,
    psk: &SharedSecret,
    input: &[u8],
    got: &[u8],
) -> bool {
    let Ok(expected) = compute_psk_tag(suite, psk, input) else {
        return false;
    };
    verify_value(suite, &expected, got)
}
