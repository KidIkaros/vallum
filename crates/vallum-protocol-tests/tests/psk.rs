// SPDX-License-Identifier: Apache-2.0

//! A configured per-peer PSK (G1).
//!
//! The PSK is mixed into the key schedule, never sent on the wire. The default
//! `None` path must be byte-identical to every existing vector; a mismatch must
//! fail the responder's confirmation, not produce a usable session.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::atomic::{AtomicUsize, Ordering};
use vallum_core::{
    initiator_hello_with_psk, initiator_process_resp, responder_process_conf,
    responder_process_init_with_psk, HandshakeError, PeerIdentity, SessionKeys, StaticIdentity,
};

use vallum_crypto::{
    AeadError, CryptoSuite, Encapsulation, KdfError, KemError, KemPublicKey, KemRole, KemSecretKey,
    LegKind, SharedSecret, SigError, SignPublicKey, SignSecretKey, WireSizes,
    KEM_ENCAPS_RANDOMNESS,
};
use vallum_crypto_sdk::SdkSuite;

const TIMESTAMP: [u8; 12] = [
    0x40, 0x00, 0x00, 0x00, 0x67, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78,
];

fn psk(byte: u8) -> SharedSecret {
    SharedSecret::new([byte; 32])
}

fn peer(identity: &StaticIdentity) -> PeerIdentity {
    PeerIdentity::from_identity(identity)
}

/// A suite wrapper that counts KEM operations, so a rejection can be shown to
/// happen **before** the responder's expensive ops B/C.
struct CountingSuite {
    inner: SdkSuite,
    encaps: AtomicUsize,
}

impl CountingSuite {
    fn new(inner: SdkSuite) -> Self {
        Self {
            inner,
            encaps: AtomicUsize::new(0),
        }
    }
}

impl CryptoSuite for CountingSuite {
    fn suite_id(&self) -> u16 {
        self.inner.suite_id()
    }

    fn sizes(&self) -> WireSizes {
        self.inner.sizes()
    }

    fn leg_kinds(&self) -> &'static [LegKind] {
        self.inner.leg_kinds()
    }

    fn kem_keygen(
        &self,
        seed: &[u8; 32],
        role: KemRole,
    ) -> Result<(KemPublicKey, KemSecretKey), KemError> {
        self.inner.kem_keygen(seed, role)
    }

    fn kem_encaps(
        &self,
        pk: &KemPublicKey,
        randomness: &[u8; KEM_ENCAPS_RANDOMNESS],
    ) -> Result<Encapsulation, KemError> {
        self.encaps.fetch_add(1, Ordering::Relaxed);
        self.inner.kem_encaps(pk, randomness)
    }

    fn kem_decaps(
        &self,
        sk: &KemSecretKey,
        ciphertext: &[u8],
    ) -> Result<Vec<SharedSecret>, KemError> {
        self.inner.kem_decaps(sk, ciphertext)
    }

    fn kdf(&self, salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), KdfError> {
        self.inner.kdf(salt, ikm, info, out)
    }

    fn hash(&self, domain: &[u8], data: &[u8]) -> [u8; 32] {
        self.inner.hash(domain, data)
    }

    fn aead_seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        ad: &[u8],
        pt: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        self.inner.aead_seal(key, nonce, ad, pt)
    }

    fn aead_open(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        ad: &[u8],
        ct: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        self.inner.aead_open(key, nonce, ad, ct)
    }

    fn sign_keygen(&self, seed: &[u8; 32]) -> Result<(SignPublicKey, SignSecretKey), SigError> {
        self.inner.sign_keygen(seed)
    }

    fn sign(&self, sk: &SignSecretKey, msg: &[u8]) -> Result<Vec<u8>, SigError> {
        self.inner.sign(sk, msg)
    }

    fn verify(&self, pk: &SignPublicKey, msg: &[u8], sig: &[u8]) -> bool {
        self.inner.verify(pk, msg, sig)
    }
}

struct Exchange {
    initiator: SessionKeys,
    responder: SessionKeys,
    init_hello: Vec<u8>,
    resp_hello: Vec<u8>,
}

/// `initiator_psk` is what the initiator configured for the responder;
/// `responder_psk` is what the responder configured for the initiator.
fn run(
    suite: &dyn CryptoSuite,
    initiator_psk: Option<&SharedSecret>,
    responder_psk: Option<&SharedSecret>,
) -> Result<Exchange, HandshakeError> {
    let initiator = StaticIdentity::generate(suite, &[0x11; 32])?;
    let responder = StaticIdentity::generate(suite, &[0x22; 32])?;

    let (init_hello, i_state) = initiator_hello_with_psk(
        suite,
        &initiator,
        &peer(&responder),
        0x0A0B_0C0D,
        TIMESTAMP,
        &[0x33; 32],
        initiator_psk,
        None,
    )?;
    let (resp_hello, r_state) = responder_process_init_with_psk(
        suite,
        &responder,
        &peer(&initiator),
        &init_hello,
        0xE0E1_E2E3,
        &[0x44; 32],
        responder_psk,
    )?;
    let (init_conf, i_keys) = initiator_process_resp(suite, i_state, &initiator, &resp_hello)?;
    let r_keys = responder_process_conf(suite, r_state, &init_conf)?;

    Ok(Exchange {
        initiator: i_keys,
        responder: r_keys,
        init_hello,
        resp_hello,
    })
}

fn shipped_suites() -> Vec<SdkSuite> {
    let mut suites = vec![SdkSuite::x25519_sntrup761()];
    if let Ok(ml) = SdkSuite::from_id(0x0002) {
        suites.push(ml);
    }
    if let Ok(tri) = SdkSuite::from_id(0x0003) {
        suites.push(tri);
    }
    suites
}

#[test]
fn a_matching_psk_produces_the_same_keys() {
    for suite in shipped_suites() {
        let key = psk(0xA5);
        let exchange = run(&suite, Some(&key), Some(&key)).expect("a matching PSK");
        // `own_index`/`peer_index` are mirrored by design; everything else must
        // agree.
        assert_eq!(
            exchange.initiator.transcript, exchange.responder.transcript,
            "suite {suite:?}"
        );
        assert_eq!(
            exchange.initiator.key, exchange.responder.key,
            "suite {suite:?}"
        );
        assert_eq!(
            exchange.initiator.confirm_initiator, exchange.responder.confirm_initiator,
            "suite {suite:?}"
        );
        assert_eq!(
            exchange.initiator.confirm_responder, exchange.responder.confirm_responder,
            "suite {suite:?}"
        );
    }
}

#[test]
fn a_mismatched_psk_fails_the_admission_tag() {
    let suite = SdkSuite::tri_hybrid();
    let result = run(&suite, Some(&psk(0x01)), Some(&psk(0x02)));
    assert!(
        matches!(result, Err(HandshakeError::PskTag)),
        "a different PSK must not produce a session"
    );
}

#[test]
fn a_one_sided_psk_fails_the_admission_tag() {
    let suite = SdkSuite::tri_hybrid();
    assert!(matches!(
        run(&suite, Some(&psk(0x03)), None),
        Err(HandshakeError::PskTag)
    ));
    assert!(matches!(
        run(&suite, None, Some(&psk(0x03))),
        Err(HandshakeError::PskTag)
    ));
}

#[test]
fn the_psk_never_appears_on_the_wire() {
    let suite = SdkSuite::tri_hybrid();
    let key = psk(0xC7);
    let exchange = run(&suite, Some(&key), Some(&key)).expect("a matching PSK");
    for message in [&exchange.init_hello, &exchange.resp_hello] {
        assert!(
            !message.windows(32).any(|window| window == key.as_bytes()),
            "the PSK was found in a handshake message"
        );
    }
}

#[test]
fn a_bad_tag_is_rejected_before_responder_encapsulation() {
    let inner = SdkSuite::tri_hybrid();
    let counting = CountingSuite::new(SdkSuite::tri_hybrid());
    let initiator = StaticIdentity::generate(&inner, &[0x11; 32]).expect("initiator");
    let responder = StaticIdentity::generate(&inner, &[0x22; 32]).expect("responder");

    let (init_hello, _) = initiator_hello_with_psk(
        &inner,
        &initiator,
        &peer(&responder),
        0x0A0B_0C0D,
        TIMESTAMP,
        &[0x33; 32],
        Some(&psk(0x01)),
        None,
    )
    .expect("initiator hello");

    let result = responder_process_init_with_psk(
        &counting,
        &responder,
        &peer(&initiator),
        &init_hello,
        0xE0E1_E2E3,
        &[0x44; 32],
        Some(&psk(0x02)),
    );

    assert!(matches!(result, Err(HandshakeError::PskTag)));
    assert_eq!(
        counting.encaps.load(Ordering::Relaxed),
        0,
        "a rejected InitHello performed a responder encapsulation"
    );
}

#[test]
fn the_psk_adds_an_admission_tag_to_init_hello() {
    // The default path is unchanged (the frozen interop vectors cover it); a
    // configured PSK adds the 32-byte tag and its 4-byte field header.
    let suite = SdkSuite::tri_hybrid();
    let plain = run(&suite, None, None).expect("no PSK");
    let key = psk(0x5A);
    let with_psk = run(&suite, Some(&key), Some(&key)).expect("with PSK");
    assert_eq!(with_psk.init_hello.len(), plain.init_hello.len() + 36);
    assert_ne!(plain.init_hello, with_psk.init_hello);
    assert_ne!(plain.resp_hello, with_psk.resp_hello);
}
