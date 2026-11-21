// SPDX-License-Identifier: Apache-2.0
//! Sealing a join ticket to a device's hybrid KEM public key (ADR-0049).
//!
//! Device-pull enrolment delivers the ticket desk→device. Verified HTTPS already
//! blocks a network MITM; this seal is defense-in-depth so the ticket never appears
//! in plaintext at the TLS reverse proxy or in desk logs. The desk *mints* the ticket
//! and so knows the plaintext — the seal protects the delivery hop, not the desk.
//!
//! Construction (compose-from-primitives on the `CryptoSuite` trait, no new SDK
//! surface): encapsulate to the device's public-line KEM key, combine the per-leg
//! shared secrets exactly as the handshake combiner does, HKDF with a seal-specific
//! info and the AAD as salt, then the suite's committing AEAD over the ticket with
//! `aad = account_id || device_public_line`. The AAD binds the blob to one account +
//! device, so a captured blob cannot be replayed onto another identity.
//!
//! Randomness and nonce are parameters so the composition is testable with exact
//! vectors; callers pass CSPRNG bytes (`entropy::seed()`), never reused per key.

use vallum_crypto::{CryptoSuite, KemPublicKey, KemSecretKey, SharedSecret};

use crate::keys::{hex_decode, hex_encode};

/// Domain separation from the handshake KDF (`KEM_INFO`) and the enrolment reply.
const SEAL_INFO: &[u8] = b"vallum-desk-ticket-seal-v1";
const NONCE_LEN: usize = 24;

/// A ticket sealed to a device key: the KEM ciphertext, the AEAD nonce, and the
/// committing-AEAD ciphertext (tag appended). Serialized as hex fields for the
/// desk→client JSON relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedTicket {
    pub kem_ct: Vec<u8>,
    pub nonce: [u8; NONCE_LEN],
    pub ct: Vec<u8>,
}

/// Derive the seal AEAD key through the single combiner core (`derive_combined_key`),
/// with the AAD as salt and a seal-specific info — no copied concat/KDF here.
fn seal_key<S: CryptoSuite + ?Sized>(
    suite: &S,
    legs: &[SharedSecret],
    aad: &[u8],
) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    vallum_crypto::derive_combined_key(suite, aad, legs, SEAL_INFO, &mut key)
        .map_err(|error| format!("seal kdf: {error}"))?;
    Ok(key)
}

/// Seal `ticket` to `device_pk`. `aad` should be `account_id || device_public_line`.
/// `randomness` (32 bytes) and `nonce` (24 bytes) must be CSPRNG output, never reused
/// across seals to the same key.
pub fn seal_ticket<S: CryptoSuite + ?Sized>(
    suite: &S,
    ticket: &[u8],
    device_pk: &KemPublicKey,
    aad: &[u8],
    randomness: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
) -> Result<SealedTicket, String> {
    let encapsulation = suite
        .kem_encaps(device_pk, randomness)
        .map_err(|error| format!("seal encaps: {error}"))?;
    let key = seal_key(suite, &encapsulation.shared_secrets, aad)?;
    let ct = suite
        .aead_seal(&key, nonce, aad, ticket)
        .map_err(|error| format!("seal aead: {error}"))?;
    Ok(SealedTicket {
        kem_ct: encapsulation.ciphertext.as_bytes().to_vec(),
        nonce: *nonce,
        ct,
    })
}

/// Open a sealed ticket with the device's KEM secret key and the same `aad`. Fails
/// (never opens) on a wrong key, wrong AAD, or any tampering — the AEAD is committing.
pub fn open_ticket<S: CryptoSuite + ?Sized>(
    suite: &S,
    sealed: &SealedTicket,
    device_sk: &KemSecretKey,
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let legs = suite
        .kem_decaps(device_sk, &sealed.kem_ct)
        .map_err(|error| format!("open decaps: {error}"))?;
    let key = seal_key(suite, &legs, aad)?;
    suite
        .aead_open(&key, &sealed.nonce, aad, &sealed.ct)
        .map_err(|error| format!("open aead: {error}"))
}

impl SealedTicket {
    /// Compact hex-field JSON for the desk→client relay.
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "kem_ct": hex_encode(&self.kem_ct),
            "nonce": hex_encode(&self.nonce),
            "ct": hex_encode(&self.ct),
        })
        .to_string()
    }

    /// Parse the hex-field JSON. Refuses missing fields or a wrong-length nonce.
    pub fn from_json(text: &str) -> Result<Self, String> {
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|error| format!("sealed ticket json: {error}"))?;
        let field = |name: &str| -> Result<Vec<u8>, String> {
            let raw = value
                .get(name)
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| format!("sealed ticket missing `{name}`"))?;
            hex_decode(raw)
        };
        let kem_ct = field("kem_ct")?;
        let nonce_bytes = field("nonce")?;
        let nonce: [u8; NONCE_LEN] = nonce_bytes
            .try_into()
            .map_err(|_| "sealed ticket nonce must be 24 bytes".to_owned())?;
        let ct = field("ct")?;
        Ok(Self { kem_ct, nonce, ct })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vallum_crypto::KemRole;
    use vallum_crypto_sdk::SdkSuite;

    fn suite() -> SdkSuite {
        SdkSuite::tri_hybrid()
    }

    fn device_keypair(seed: &[u8; 32]) -> (KemPublicKey, KemSecretKey) {
        suite().kem_keygen(seed, KemRole::Static).expect("keygen")
    }

    const AAD: &[u8] = b"account-42||vallum1:0003:abcd:-";

    #[test]
    fn a_sealed_ticket_opens_to_the_original() {
        let (pk, sk) = device_keypair(&[7u8; 32]);
        let ticket = b"vallum1-join:host:51820/laptop/id/token/fp";
        let sealed = seal_ticket(&suite(), ticket, &pk, AAD, &[1u8; 32], &[2u8; 24]).expect("seal");
        let opened = open_ticket(&suite(), &sealed, &sk, AAD).expect("open");
        assert_eq!(opened, ticket);
    }

    #[test]
    fn the_wrong_aad_does_not_open() {
        let (pk, sk) = device_keypair(&[7u8; 32]);
        let sealed =
            seal_ticket(&suite(), b"ticket", &pk, AAD, &[1u8; 32], &[2u8; 24]).expect("seal");
        // Replaying the blob onto another account/device must fail.
        assert!(open_ticket(&suite(), &sealed, &sk, b"account-99||other").is_err());
    }

    #[test]
    fn the_wrong_device_key_does_not_open() {
        let (pk, _sk) = device_keypair(&[7u8; 32]);
        let (_pk2, sk2) = device_keypair(&[8u8; 32]);
        let sealed =
            seal_ticket(&suite(), b"ticket", &pk, AAD, &[1u8; 32], &[2u8; 24]).expect("seal");
        assert!(open_ticket(&suite(), &sealed, &sk2, AAD).is_err());
    }

    #[test]
    fn a_tampered_ciphertext_does_not_open() {
        let (pk, sk) = device_keypair(&[7u8; 32]);
        let mut sealed =
            seal_ticket(&suite(), b"ticket", &pk, AAD, &[1u8; 32], &[2u8; 24]).expect("seal");
        let last = sealed.ct.len() - 1;
        sealed.ct[last] ^= 0x01;
        assert!(open_ticket(&suite(), &sealed, &sk, AAD).is_err());
    }

    #[test]
    fn the_same_inputs_seal_deterministically() {
        let (pk, _sk) = device_keypair(&[7u8; 32]);
        let a = seal_ticket(&suite(), b"ticket", &pk, AAD, &[1u8; 32], &[2u8; 24]).expect("seal");
        let b = seal_ticket(&suite(), b"ticket", &pk, AAD, &[1u8; 32], &[2u8; 24]).expect("seal");
        assert_eq!(
            a, b,
            "exact vectors: same (pk, randomness, nonce) → same blob"
        );
    }

    #[test]
    fn json_round_trips() {
        let (pk, sk) = device_keypair(&[7u8; 32]);
        let sealed =
            seal_ticket(&suite(), b"ticket", &pk, AAD, &[1u8; 32], &[2u8; 24]).expect("seal");
        let parsed = SealedTicket::from_json(&sealed.to_json()).expect("parse");
        assert_eq!(parsed, sealed);
        assert_eq!(
            open_ticket(&suite(), &parsed, &sk, AAD).expect("open"),
            b"ticket"
        );
    }

    #[test]
    fn json_refuses_a_wrong_length_nonce() {
        let bad = r#"{"kem_ct":"00","nonce":"00","ct":"00"}"#;
        assert!(SealedTicket::from_json(bad).is_err());
    }
}
