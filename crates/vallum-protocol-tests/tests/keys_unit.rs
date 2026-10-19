#![allow(clippy::expect_used, clippy::unwrap_used)]

use vallum_core::keys::*;
use vallum_core::SessionKeys;
use vallum_crypto::SharedSecret;
use vallum_crypto_sdk::SdkSuite;

fn session(transcript: [u8; 32], key: [u8; 32]) -> SessionKeys {
    SessionKeys {
        transcript,
        key: SharedSecret::new(key),
        confirm_initiator: SharedSecret::new([1u8; 32]),
        confirm_responder: SharedSecret::new([2u8; 32]),
        own_index: 0x1111_1111,
        peer_index: 0x2222_2222,
    }
}

fn directions(keys: &DataKeys) -> ([u8; 32], [u8; 32], [u8; 16], [u8; 16]) {
    keys.test_directions()
}

#[test]
fn directions_and_purposes_are_all_distinct() {
    let suite = SdkSuite::tri_hybrid();
    let keys = DataKeys::from_session(&suite, &session([7u8; 32], [9u8; 32])).unwrap();
    let (i2r, r2i, n_i2r, n_r2i) = directions(&keys);

    assert_ne!(i2r, r2i, "the two directions must not share a key");
    assert_ne!(n_i2r, n_r2i, "the two directions must not share a nonce");
    // The key and the nonce prefix come from the same root with the same
    // direction label but different `info`, so they must still differ.
    assert_ne!(i2r[..NONCE_PREFIX_SIZE], n_i2r[..], "key leaked into nonce");
}

#[test]
fn role_selects_opposite_halves() {
    let suite = SdkSuite::tri_hybrid();
    let s = session([3u8; 32], [4u8; 32]);

    let init = DataKeys::from_session(&suite, &s)
        .unwrap()
        .test_split(Role::Initiator);
    let resp = DataKeys::from_session(&suite, &s)
        .unwrap()
        .test_split(Role::Responder);

    // The initiator's sending key is the responder's receiving key.
    assert_eq!(init.0, resp.1);
    // And vice versa.
    assert_eq!(init.1 .0, resp.0 .0);
}

#[test]
fn transcript_epoch_and_root_all_change_the_keys() {
    let suite = SdkSuite::tri_hybrid();
    let base = session([5u8; 32], [6u8; 32]);

    let k0 = DataKeys::from_session(&suite, &base).unwrap();

    let mut other_transcript = session([5u8; 32], [6u8; 32]);
    other_transcript.transcript = [0u8; 32];
    let k_t = DataKeys::from_session(&suite, &other_transcript).unwrap();

    let mut other_key = session([5u8; 32], [6u8; 32]);
    other_key.key = SharedSecret::new([0u8; 32]);
    let k_k = DataKeys::from_session(&suite, &other_key).unwrap();

    let k_e = DataKeys::derive(&suite, &base.key, &base.transcript, 1).unwrap();

    let first = directions(&k0).0;
    assert_ne!(first, directions(&k_t).0, "transcript must bind the key");
    assert_ne!(first, directions(&k_k).0, "root key must bind the key");
    assert_ne!(first, directions(&k_e).0, "epoch must bind the key");
    assert_eq!(k0.epoch(), 0);
    assert_eq!(k_e.epoch(), 1);
    assert_eq!(k0.transcript(), &[5u8; 32]);
}

#[test]
fn derivation_is_deterministic() {
    let suite = SdkSuite::tri_hybrid();
    let s = session([8u8; 32], [9u8; 32]);
    let a = DataKeys::from_session(&suite, &s).unwrap();
    let b = DataKeys::from_session(&suite, &s).unwrap();
    assert_eq!(directions(&a), directions(&b));
}
