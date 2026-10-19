#![allow(clippy::expect_used, clippy::unwrap_used)]

use vallum_core::identity::*;
use vallum_core::identity::{
    sign_transcript, verify_transcript, IDENTITY_INIT_DOMAIN, IDENTITY_RESP_DOMAIN,
};
use vallum_core::wire::{tag, Message, MessageBuilder};
use vallum_core::HandshakeError;
use vallum_crypto::CryptoSuite;
use vallum_crypto_sdk::SdkSuite;

fn suite() -> SdkSuite {
    SdkSuite::tri_hybrid()
}

/// A wide window around `NOW`, so the tests are not clock-dependent.
const VALIDITY: Validity = Validity {
    not_before: 1_000,
    not_after: 4_000_000_000,
};
const NOW: u64 = 2_000;

#[test]
fn one_seed_yields_independent_kem_and_signing_keys() {
    let suite = suite();
    let seed = [0x11u8; 32];
    let a = StaticIdentity::generate_with_signing(&suite, &seed).unwrap();
    let b = StaticIdentity::generate_with_signing(&suite, &seed).unwrap();

    // Deterministic, and the KEM half is exactly `generate`'s.
    let kem_only = StaticIdentity::generate(&suite, &seed).unwrap();
    assert_eq!(a.public().as_bytes(), kem_only.public().as_bytes());
    assert_eq!(a.public().as_bytes(), b.public().as_bytes());
    assert_eq!(a.signing_public(), b.signing_public());
    assert!(a.signing().is_some() && kem_only.signing().is_none());

    // Different master seeds give different keys on both halves.
    let c = StaticIdentity::generate_with_signing(&suite, &[0x12u8; 32]).unwrap();
    assert_ne!(a.public().as_bytes(), c.public().as_bytes());
    assert_ne!(a.signing_public(), c.signing_public());
}

#[test]
fn identity_signatures_are_bound_to_key_role_and_transcript() {
    let suite = suite();
    let id = StaticIdentity::generate_with_signing(&suite, &[0x21u8; 32]).unwrap();
    let signing = id.signing().unwrap();
    let tr = [0xABu8; 32];

    let sig = sign_transcript(&suite, signing, IDENTITY_RESP_DOMAIN, 3, &tr).unwrap();
    assert!(verify_transcript(
        &suite,
        signing.public(),
        IDENTITY_RESP_DOMAIN,
        3,
        &tr,
        &sig
    ));

    // Wrong role, suite, transcript, and key are all rejected.
    assert!(!verify_transcript(
        &suite,
        signing.public(),
        IDENTITY_INIT_DOMAIN,
        3,
        &tr,
        &sig
    ));
    assert!(!verify_transcript(
        &suite,
        signing.public(),
        IDENTITY_RESP_DOMAIN,
        1,
        &tr,
        &sig
    ));
    assert!(!verify_transcript(
        &suite,
        signing.public(),
        IDENTITY_RESP_DOMAIN,
        3,
        &[0xACu8; 32],
        &sig
    ));

    let other = StaticIdentity::generate_with_signing(&suite, &[0x22u8; 32]).unwrap();
    assert!(!verify_transcript(
        &suite,
        other.signing_public().unwrap(),
        IDENTITY_RESP_DOMAIN,
        3,
        &tr,
        &sig
    ));
}

#[test]
fn identity_document_round_trips_and_verifies() {
    let suite = suite();
    let id = StaticIdentity::generate_with_signing(&suite, &[0x31u8; 32]).unwrap();
    let doc = IdentityDocument::self_sign(&suite, &id, b"alice@example", VALIDITY).unwrap();

    assert_eq!(doc.label(), b"alice@example");
    assert_eq!(doc.kem().as_bytes(), id.public().as_bytes());
    assert_eq!(
        doc.signing().as_bytes(),
        id.signing_public().unwrap().as_bytes()
    );
    assert!(doc.is_self_signed(&suite));

    let bytes = doc.encode(suite.suite_id()).unwrap();
    let decoded = IdentityDocument::decode(&bytes).unwrap();
    assert_eq!(decoded, doc);
    assert!(decoded.is_self_signed(&suite));

    // A peer configured from the document carries both halves.
    let peer = decoded.to_peer(&suite, doc.signing(), NOW).unwrap();
    assert_eq!(peer.kem().as_bytes(), id.public().as_bytes());
    assert_eq!(
        peer.signing().unwrap().as_bytes(),
        id.signing_public().unwrap().as_bytes()
    );
}

#[test]
fn a_tampered_document_is_rejected() {
    let suite = suite();
    let id = StaticIdentity::generate_with_signing(&suite, &[0x41u8; 32]).unwrap();
    let doc = IdentityDocument::self_sign(&suite, &id, b"bob", VALIDITY).unwrap();

    // Swap in a different KEM key: the issuer's signature no longer covers it.
    let other = StaticIdentity::generate_with_signing(&suite, &[0x42u8; 32]).unwrap();
    let forged = IdentityDocument::issue(
        &suite,
        doc.label(),
        other.public().clone(),
        doc.signing().clone(),
        // The attacker does not hold the issuer's secret, so it signs with
        // its own — which is not the document's signing key.
        VALIDITY,
        other.signing().unwrap().secret(),
    )
    .unwrap();
    assert!(!forged.is_self_signed(&suite));
    assert!(matches!(
        forged.to_peer(&suite, doc.signing(), NOW),
        Err(HandshakeError::IdentityInvalid)
    ));

    // A flipped bit anywhere in the encoded document breaks the signature.
    let mut bytes = doc.encode(suite.suite_id()).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let decoded = IdentityDocument::decode(&bytes).unwrap();
    assert!(!decoded.is_self_signed(&suite));

    // An identity without a signing half cannot self-sign.
    let kem_only = StaticIdentity::generate(&suite, &[0x43u8; 32]).unwrap();
    assert!(matches!(
        IdentityDocument::self_sign(&suite, &kem_only, b"x", VALIDITY),
        Err(HandshakeError::NoSigningIdentity)
    ));
}

#[test]
fn a_document_with_a_missing_field_is_a_framing_error() {
    let suite = suite();
    let id = StaticIdentity::generate_with_signing(&suite, &[0x51u8; 32]).unwrap();
    let doc = IdentityDocument::self_sign(&suite, &id, b"carol", VALIDITY).unwrap();
    let bytes = doc.encode(suite.suite_id()).unwrap();

    // Rebuild without the signature field.
    let msg = Message::parse(&bytes).unwrap();
    let mut builder = MessageBuilder::new(msg.header());
    builder
        .field(
            tag::IDENTITY_LABEL,
            msg.require(tag::IDENTITY_LABEL).unwrap(),
        )
        .unwrap();
    builder
        .field(tag::KEM_PUBLIC, msg.require(tag::KEM_PUBLIC).unwrap())
        .unwrap();
    builder
        .field(tag::SIGN_PUBLIC, msg.require(tag::SIGN_PUBLIC).unwrap())
        .unwrap();
    let stripped = builder.finish().unwrap();

    assert!(matches!(
        IdentityDocument::decode(&stripped),
        Err(HandshakeError::Wire(_))
    ));
}
