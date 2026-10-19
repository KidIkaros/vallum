// SPDX-License-Identifier: Apache-2.0

//! Boundary contract tests for every shipped suite, plus an adapter-swap smoke
//! test.
//!
//! The swap test wraps the SDK adapter in a different `CryptoSuite` type and
//! runs the *same* contract against it. That is the property the P0 gate cares
//! about: the contract depends on the trait alone, so a new provider adapter
//! (including the author's future from-scratch cryptography) is validated
//! without touching protocol code.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use vallum_crypto::{
    AeadError, CryptoSuite, Encapsulation, KdfError, KemError, KemPublicKey, KemRole, KemSecretKey,
    LegKind, SharedSecret, SigError, SignPublicKey, SignSecretKey, WireSizes,
    KEM_ENCAPS_RANDOMNESS,
};
use vallum_crypto_contract::{assert_default_legs, run_contract};
use vallum_crypto_sdk::SdkSuite;

#[test]
fn suite_0x0001_x25519_sntrup761() {
    let suite = SdkSuite::x25519_sntrup761();
    assert_eq!(suite.suite_id(), 0x0001);
    assert_eq!(suite.leg_kinds(), &[LegKind::X25519, LegKind::NtruPrime761]);
    run_contract(&suite);
}

#[test]
fn suite_0x0002_x25519_ml_kem_768() {
    let suite = SdkSuite::from_id(0x0002).expect("suite 0x0002 available");
    assert_eq!(suite.leg_kinds(), &[LegKind::X25519, LegKind::MlKem768]);
    run_contract(&suite);
}

#[test]
fn suite_0x0003_tri_hybrid_is_default() {
    let suite = SdkSuite::from_id(0x0003).expect("suite 0x0003 available");
    assert_default_legs(&suite);
    run_contract(&suite);
}

#[test]
fn unknown_suite_is_rejected() {
    assert!(
        SdkSuite::from_id(0x0100).is_err(),
        "reserved range accepted"
    );
    assert!(SdkSuite::from_id(0xFFFF).is_err(), "bogus suite accepted");
}

/// A second `CryptoSuite` adapter that simply delegates. If the contract only
/// depended on one concrete type, this would not compile.
#[derive(Debug)]
struct SwapSuite<S>(S);

impl<S: CryptoSuite> CryptoSuite for SwapSuite<S> {
    fn suite_id(&self) -> u16 {
        self.0.suite_id()
    }

    fn sizes(&self) -> WireSizes {
        self.0.sizes()
    }

    fn leg_kinds(&self) -> &'static [LegKind] {
        self.0.leg_kinds()
    }

    fn kem_keygen(
        &self,
        seed: &[u8; 32],
        role: KemRole,
    ) -> Result<(KemPublicKey, KemSecretKey), KemError> {
        self.0.kem_keygen(seed, role)
    }

    fn kem_encaps(
        &self,
        pk: &KemPublicKey,
        randomness: &[u8; KEM_ENCAPS_RANDOMNESS],
    ) -> Result<Encapsulation, KemError> {
        self.0.kem_encaps(pk, randomness)
    }

    fn kem_decaps(
        &self,
        sk: &KemSecretKey,
        ciphertext: &[u8],
    ) -> Result<Vec<SharedSecret>, KemError> {
        self.0.kem_decaps(sk, ciphertext)
    }

    fn kdf(&self, salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), KdfError> {
        self.0.kdf(salt, ikm, info, out)
    }

    fn hash(&self, domain: &[u8], data: &[u8]) -> [u8; 32] {
        self.0.hash(domain, data)
    }

    fn aead_seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        ad: &[u8],
        pt: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        self.0.aead_seal(key, nonce, ad, pt)
    }

    fn aead_open(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        ad: &[u8],
        ct: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        self.0.aead_open(key, nonce, ad, ct)
    }

    fn sign_keygen(&self, seed: &[u8; 32]) -> Result<(SignPublicKey, SignSecretKey), SigError> {
        self.0.sign_keygen(seed)
    }

    fn sign(&self, sk: &SignSecretKey, msg: &[u8]) -> Result<Vec<u8>, SigError> {
        self.0.sign(sk, msg)
    }

    fn verify(&self, pk: &SignPublicKey, msg: &[u8], sig: &[u8]) -> bool {
        self.0.verify(pk, msg, sig)
    }
}

#[test]
fn adapter_swap_passes_contract() {
    let suite = SwapSuite(SdkSuite::from_id(0x0003).expect("suite 0x0003 available"));
    run_contract(&suite);
}
