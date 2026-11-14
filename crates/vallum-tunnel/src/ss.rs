// SPDX-License-Identifier: Apache-2.0

//! Shadowsocks-style AEAD datagram obfuscation (`carrier = "ss"`).
//!
//! Every outbound datagram is wrapped as:
//! `[ 24-byte random nonce ] || [ AEAD_Seal(key, nonce, ad="vallum-ss-v1", pt) ]`
//!
//! On the wire, packets have no plaintext Vallum header, no fixed magic bytes,
//! and uniform-random ciphertext. Inbound datagrams that fail AEAD tag
//! verification are dropped before reaching the tunnel state machine.

use vallum_crypto::{AeadError, CryptoSuite};

/// 24-byte random nonce prepended to every obfuscated datagram.
pub const SS_NONCE_LEN: usize = 24;

/// 32-byte committing AEAD authentication tag appended to the ciphertext.
pub const SS_TAG_LEN: usize = 32;

/// Total per-datagram wire overhead in bytes (`24 + 32 = 56`).
pub const SS_OVERHEAD: usize = SS_NONCE_LEN + SS_TAG_LEN;

const SS_DOMAIN: &[u8] = b"vallum-ss-v1";
const DEFAULT_SS_PSK: &str = "vallum-default-ss-obfs";

/// Derive a 32-byte obfuscation key from an optional operator PSK.
pub fn derive_ss_key<S: CryptoSuite>(suite: &S, psk: Option<&str>) -> [u8; 32] {
    let material = psk
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_SS_PSK);
    suite.hash(SS_DOMAIN, material.as_bytes())
}

/// Seal `plaintext` into an obfuscated datagram `[nonce || ciphertext+tag]`.
///
/// # Errors
///
/// Propagates [`AeadError`] if the underlying suite refuses to seal.
pub fn seal_ss_packet<S: CryptoSuite>(
    suite: &S,
    key: &[u8; 32],
    nonce: &[u8; SS_NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let ct = suite.aead_seal(key, nonce, SS_DOMAIN, plaintext)?;
    let mut out = Vec::with_capacity(SS_NONCE_LEN + ct.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open an obfuscated datagram, returning `None` if truncated or unauthenticated.
pub fn open_ss_packet<S: CryptoSuite>(
    suite: &S,
    key: &[u8; 32],
    datagram: &[u8],
) -> Option<Vec<u8>> {
    if datagram.len() < SS_OVERHEAD {
        return None;
    }
    let (nonce_bytes, ct) = datagram.split_at(SS_NONCE_LEN);
    let nonce: [u8; SS_NONCE_LEN] = nonce_bytes.try_into().ok()?;
    suite.aead_open(key, &nonce, SS_DOMAIN, ct).ok()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use vallum_crypto_sdk::SdkSuite;

    #[test]
    fn seal_and_open_round_trips_and_rejects_tampering() {
        let suite = SdkSuite::tri_hybrid();
        let key = derive_ss_key(&suite, Some("test-psk-123"));
        let nonce = [7u8; SS_NONCE_LEN];
        let payload = b"\x01\x00\x00\x00vallum-handshake-bytes";

        let mut wire = seal_ss_packet(&suite, &key, &nonce, payload).unwrap();
        assert_eq!(wire.len(), payload.len() + SS_OVERHEAD);
        assert_ne!(&wire[SS_NONCE_LEN..], payload);

        let opened = open_ss_packet(&suite, &key, &wire).unwrap();
        assert_eq!(opened, payload);

        // Tampering any byte fails tag verification.
        wire[SS_NONCE_LEN + 2] ^= 0xff;
        assert!(open_ss_packet(&suite, &key, &wire).is_none());

        // Wrong PSK fails tag verification.
        let wrong_key = derive_ss_key(&suite, Some("other-psk"));
        let wire2 = seal_ss_packet(&suite, &key, &nonce, payload).unwrap();
        assert!(open_ss_packet(&suite, &wrong_key, &wire2).is_none());

        // Truncated packet is rejected.
        assert!(open_ss_packet(&suite, &key, &[0u8; SS_OVERHEAD - 1]).is_none());
    }
}
