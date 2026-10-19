// SPDX-License-Identifier: Apache-2.0

//! Hybrid signing key generation must go through the SDK's bundle cache.
//!
//! Falcon-1024 key generation is the single most expensive operation in the
//! product, and it happens *once per identity* — never per handshake. The
//! adapter gets that by calling `HybridSigningKeyBundle::from_seed_cached`; this
//! test pins it, so a future refactor to the uncached `from_seed` is caught
//! rather than silently costing seconds on every identity load.

#![allow(clippy::expect_used)]

use origin_crypto_sdk::signing::hybrid::bundle_cache_len;
use vallum_crypto::CryptoSuite;
use vallum_crypto_sdk::SdkSuite;

const SEED: [u8; 32] = [0xC7u8; 32];

#[test]
fn sign_keygen_populates_the_bundle_cache() {
    let suite = SdkSuite::tri_hybrid();

    // This is its own test binary, so the process-global cache starts empty.
    assert_eq!(bundle_cache_len(), 0, "cache unexpectedly warm");

    let (pk1, _) = suite.sign_keygen(&SEED).expect("sign_keygen");
    let after_first = bundle_cache_len();
    assert!(
        after_first >= 1,
        "sign_keygen did not populate the bundle cache (0 -> {after_first})"
    );

    // A second derivation from the same seed is a cache hit: same identity, no
    // new entry.
    let (pk2, _) = suite.sign_keygen(&SEED).expect("sign_keygen");
    assert_eq!(pk1.as_bytes(), pk2.as_bytes());
    assert_eq!(bundle_cache_len(), after_first);
}
