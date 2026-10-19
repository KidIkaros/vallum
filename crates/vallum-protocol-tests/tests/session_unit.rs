#![allow(clippy::expect_used, clippy::unwrap_used)]

use vallum_core::session::*;
use vallum_core::DataError;
use vallum_core::{Role, SessionKeys};
use vallum_crypto::SharedSecret;

fn keys(tag: u8) -> SessionKeys {
    SessionKeys {
        transcript: [tag; 32],
        key: SharedSecret::new([tag.wrapping_add(0x40); 32]),
        confirm_initiator: SharedSecret::new([1u8; 32]),
        confirm_responder: SharedSecret::new([2u8; 32]),
        own_index: u32::from(tag) + 0x1000,
        peer_index: u32::from(tag) + 0x2000,
    }
}

#[test]
fn epoch_advances_monotonically() {
    let suite = vallum_crypto_sdk::SdkSuite::tri_hybrid();
    let mut session = Session::establish(&suite, &keys(1), Role::Initiator).unwrap();

    assert_eq!(session.epoch(), 0);
    assert_eq!(session.previous_epoch(), None);
    assert_eq!(
        session
            .advance(&suite, &keys(2), Role::Initiator, 0)
            .unwrap(),
        1
    );
    assert_eq!(session.previous_epoch(), Some(0));
    assert_eq!(
        session
            .advance(&suite, &keys(3), Role::Initiator, 10)
            .unwrap(),
        2
    );
    assert_eq!(session.previous_epoch(), Some(1));
}

#[test]
fn a_rapid_rekey_does_not_compound_retention() {
    let suite = vallum_crypto_sdk::SdkSuite::tri_hybrid();
    let mut session = Session::establish(&suite, &keys(1), Role::Initiator).unwrap();
    session
        .advance(&suite, &keys(2), Role::Initiator, 0)
        .unwrap();
    session
        .advance(&suite, &keys(3), Role::Initiator, 1)
        .unwrap();

    // Only the epoch we just left is retained; the one before it is gone.
    assert_eq!(session.previous_epoch(), Some(1));
    assert!(session.retains_previous());
}

#[test]
fn a_different_suite_is_refused() {
    use vallum_crypto::CryptoSuite as _;
    let tri = vallum_crypto_sdk::SdkSuite::tri_hybrid();
    let single = vallum_crypto_sdk::SdkSuite::x25519_sntrup761();
    let mut session = Session::establish(&tri, &keys(1), Role::Initiator).unwrap();

    assert_eq!(
        session.advance(&single, &keys(2), Role::Initiator, 0),
        Err(DataError::SuiteChanged {
            expected: tri.suite_id(),
            got: single.suite_id(),
        })
    );
}

#[test]
fn expire_previous_is_time_bounded() {
    let suite = vallum_crypto_sdk::SdkSuite::tri_hybrid();
    let mut session = Session::establish(&suite, &keys(1), Role::Initiator).unwrap();
    session
        .advance(&suite, &keys(2), Role::Initiator, 1_000)
        .unwrap();

    assert!(!session.expire_previous(1_000));
    assert!(!session.expire_previous(1_000 + RETAIN_PREVIOUS_EPOCH_MS - 1));
    assert!(session.retains_previous());
    assert!(session.expire_previous(1_000 + RETAIN_PREVIOUS_EPOCH_MS));
    assert!(!session.retains_previous());
    assert_eq!(session.previous_epoch(), None);
}

#[test]
fn retire_previous_erases_immediately() {
    let suite = vallum_crypto_sdk::SdkSuite::tri_hybrid();
    let mut session = Session::establish(&suite, &keys(1), Role::Initiator).unwrap();
    session
        .advance(&suite, &keys(2), Role::Initiator, 0)
        .unwrap();

    assert!(session.retire_previous());
    assert!(!session.retire_previous());
    assert!(!session.retains_previous());
}
