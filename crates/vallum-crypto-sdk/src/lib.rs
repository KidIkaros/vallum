// SPDX-License-Identifier: Apache-2.0

//! # vallum-crypto-sdk
//!
//! The `origin-crypto-sdk` adapter for Vallum's [`CryptoSuite`] boundary.
//!
//! This is the *only* crate in the product that names an SDK type. Everything
//! above the boundary sees [`vallum_crypto`] newtypes and byte slices. Replacing
//! the SDK — including with the author's future from-scratch cryptography —
//! means adding a sibling adapter crate and a suite id; no protocol code moves.
//!
//! ## Suites
//!
//! | id | legs | default? |
//! |----|------|----------|
//! | `0x0001` | X25519 + sntrup761 | no |
//! | `0x0002` | X25519 + ML-KEM-768 | no |
//! | `0x0003` | X25519 + sntrup761 + ML-KEM-768 | **yes** |
//!
//! ## Mapping table (SDK → suite leg)
//!
//! | Leg | SDK API |
//! |-----|---------|
//! | X25519 | `x25519::X25519KeyPair` |
//! | sntrup761 | `pqc::ntru_prime::NtruPrime` |
//! | ML-KEM-768 | `pqc::ml_kem::MlKem768Kem` |
//! | KDF | `kdf::hkdf::hkdf_sha3_256` |
//! | Hash | `sha3_256` |
//! | AEAD | `chacha20_blake3::ChaCha20Blake3` |
//! | Signatures | `signing::hybrid::HybridSigningKeyBundle` + `signing::wire::HybridSig` |

#![forbid(unsafe_code)]

use std::sync::Arc;

use origin_crypto_sdk::chacha20_blake3::ChaCha20Blake3;
use origin_crypto_sdk::drbg::ChaCha20Rng;
use origin_crypto_sdk::kdf::hkdf::hkdf_sha3_256;
use origin_crypto_sdk::pqc::falcon1024::sizes as falcon_sizes;
use origin_crypto_sdk::pqc::ntru_prime::{
    constants as ntru, Ciphertext as NtruCiphertext, NtruPrime, PrivateKey as NtruSecret,
    PublicKey as NtruPublic,
};
use origin_crypto_sdk::sha3_256;
use origin_crypto_sdk::signing::hybrid::HybridSigningKeyBundle;
use origin_crypto_sdk::signing::wire::HybridSig;
use origin_crypto_sdk::x25519::{X25519KeyPair, X25519PublicKey};

use vallum_crypto::{
    AeadError, Ciphertext, CryptoSuite, Encapsulation, KdfError, KemError, KemPublicKey, KemRole,
    KemSecretKey, LegKind, SharedSecret, SigError, SignPublicKey, SignSecretKey, SuiteError,
    WireSizes, KEM_ENCAPS_RANDOMNESS,
};

/// Suite id: `X25519 + sntrup761`.
pub const SUITE_X25519_SNTRUP761: u16 = 0x0001;
/// Suite id: `X25519 + ML-KEM-768`.
pub const SUITE_X25519_MLKEM768: u16 = 0x0002;
/// Suite id: `X25519 + sntrup761 + ML-KEM-768` (default).
pub const SUITE_TRI_HYBRID: u16 = 0x0003;

/// Domain separation for per-leg seed derivation.
const DERIVE_INFO: &[u8] = b"vallum/sdk-suite/v1";
/// Domain separation for per-leg encapsulation-randomness expansion.
const ENCAPS_DERIVE_INFO: &[u8] = b"vallum/sdk-suite/encaps/v1";
/// Domain separation for the hybrid identity key.
const SIGN_DOMAIN: &str = "vallum/identity/v1";

/// An `origin-crypto-sdk`-backed suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SdkSuite {
    id: u16,
}

impl SdkSuite {
    /// The default suite: tri-hybrid `X25519 + sntrup761 + ML-KEM-768`.
    #[cfg(feature = "ml-kem")]
    pub fn tri_hybrid() -> Self {
        Self {
            id: SUITE_TRI_HYBRID,
        }
    }

    /// `X25519 + sntrup761` — the non-NIST-pure fallback.
    pub fn x25519_sntrup761() -> Self {
        Self {
            id: SUITE_X25519_SNTRUP761,
        }
    }

    /// `X25519 + ML-KEM-768`.
    #[cfg(feature = "ml-kem")]
    pub fn x25519_ml_kem_768() -> Self {
        Self {
            id: SUITE_X25519_MLKEM768,
        }
    }

    /// Resolve a suite id from the wire.
    ///
    /// # Errors
    ///
    /// [`SuiteError`] if the id is unknown or requires a disabled feature.
    pub fn from_id(id: u16) -> Result<Self, SuiteError> {
        let known = matches!(
            id,
            SUITE_X25519_SNTRUP761 | SUITE_X25519_MLKEM768 | SUITE_TRI_HYBRID
        );
        #[cfg(not(feature = "ml-kem"))]
        if id == SUITE_X25519_MLKEM768 || id == SUITE_TRI_HYBRID {
            return Err(SuiteError::new(
                "suite requires the `ml-kem` feature, which is not enabled",
            ));
        }
        if known {
            Ok(Self { id })
        } else {
            Err(SuiteError::new(format!("unknown suite id {id:#06x}")))
        }
    }
}

fn leg_kinds_for(id: u16) -> &'static [LegKind] {
    match id {
        SUITE_X25519_SNTRUP761 => &[LegKind::X25519, LegKind::NtruPrime761],
        SUITE_X25519_MLKEM768 => &[LegKind::X25519, LegKind::MlKem768],
        SUITE_TRI_HYBRID => &[LegKind::X25519, LegKind::NtruPrime761, LegKind::MlKem768],
        _ => &[],
    }
}

/// `(public_key, secret_key, ciphertext)` sizes for one leg.
fn leg_sizes(kind: LegKind) -> (usize, usize, usize) {
    match kind {
        LegKind::X25519 => (32, 32, 32),
        LegKind::NtruPrime761 => (ntru::PK_SIZE, ntru::SK_SIZE, ntru::CT_SIZE),
        LegKind::MlKem768 => mlkem_leg_sizes(),
    }
}

fn sizes_for(id: u16) -> WireSizes {
    let mut kem_pk = 0;
    let mut kem_sk = 0;
    let mut kem_ct = 0;
    let legs = leg_kinds_for(id);
    for kind in legs {
        let (pk, sk, ct) = leg_sizes(*kind);
        kem_pk += pk;
        kem_sk += sk;
        kem_ct += ct;
    }
    WireSizes {
        leg_count: legs.len(),
        kem_pk,
        kem_sk,
        kem_ct,
        shared_secret: 32,
        hash: 32,
        aead_key: 32,
        aead_nonce: 24,
        aead_tag: 32,
        sign_pk_max: 32 + falcon_sizes::PUBLIC_KEY,
        // Encoded hybrid signature = u32 falcon-length ‖ falcon ‖ ed25519(64).
        sign_sig_max: 4 + falcon_sizes::SIGNATURE_MAX + 64,
    }
}

// ── helpers ──────────────────────────────────────────────────────────

fn kem_err(e: impl std::fmt::Display) -> KemError {
    KemError::new(e.to_string())
}

fn sig_err(e: impl std::fmt::Display) -> SigError {
    SigError::new(e.to_string())
}

/// Derive sub-key material for `(role, leg)` from the master seed.
fn derive(seed: &[u8; 32], role: KemRole, leg: usize, out: &mut [u8]) -> Result<(), KemError> {
    let role_byte = match role {
        KemRole::Static => 0u8,
        KemRole::Ephemeral => 1u8,
    };
    let mut info = Vec::with_capacity(DERIVE_INFO.len() + 2);
    info.extend_from_slice(DERIVE_INFO);
    info.push(role_byte);
    info.push(u8::try_from(leg).unwrap_or(u8::MAX));
    hkdf_sha3_256(seed, None, &info, out).map_err(kem_err)
}

/// Expand the caller's encapsulation randomness for a given leg.
fn encaps_derive(randomness: &[u8; 32], leg: usize, out: &mut [u8]) -> Result<(), KemError> {
    let mut info = Vec::with_capacity(ENCAPS_DERIVE_INFO.len() + 1);
    info.extend_from_slice(ENCAPS_DERIVE_INFO);
    info.push(u8::try_from(leg).unwrap_or(u8::MAX));
    hkdf_sha3_256(randomness, None, &info, out).map_err(kem_err)
}

/// Take a fixed-size array from `buf` at `off`, advancing `off`.
fn take<const N: usize>(buf: &[u8], off: &mut usize) -> Result<[u8; N], KemError> {
    let end = off
        .checked_add(N)
        .ok_or_else(|| KemError::new("offset overflow"))?;
    let slice = buf
        .get(*off..end)
        .ok_or_else(|| KemError::new(format!("buffer too short: need {N} at {off}")))?;
    let arr: [u8; N] = slice
        .try_into()
        .map_err(|_| KemError::new("bad slice length"))?;
    *off = end;
    Ok(arr)
}

// ── ML-KEM leg (feature-gated) ───────────────────────────────────────

#[cfg(feature = "ml-kem")]
fn mlkem_leg_sizes() -> (usize, usize, usize) {
    use origin_crypto_sdk::pqc::ml_kem::{CT_SIZE, EK_SIZE, SEED_SIZE};
    (EK_SIZE, SEED_SIZE, CT_SIZE)
}

#[cfg(not(feature = "ml-kem"))]
fn mlkem_leg_sizes() -> (usize, usize, usize) {
    (0, 0, 0)
}

#[cfg(feature = "ml-kem")]
fn mlkem_keygen(
    seed: &[u8; 32],
    role: KemRole,
    leg: usize,
    pk: &mut Vec<u8>,
    sk: &mut Vec<u8>,
) -> Result<(), KemError> {
    use origin_crypto_sdk::pqc::ml_kem::{MlKem768Kem, SEED_SIZE};
    let mut sub = [0u8; SEED_SIZE];
    derive(seed, role, leg, &mut sub)?;
    let (dk, ek) = MlKem768Kem::generate_keypair_from_seed(&sub);
    pk.extend_from_slice(&ek.as_bytes());
    sk.extend_from_slice(&dk.to_seed());
    Ok(())
}

#[cfg(not(feature = "ml-kem"))]
fn mlkem_keygen(
    _seed: &[u8; 32],
    _role: KemRole,
    _leg: usize,
    _pk: &mut Vec<u8>,
    _sk: &mut Vec<u8>,
) -> Result<(), KemError> {
    Err(KemError::new("ML-KEM support not compiled in"))
}

#[cfg(feature = "ml-kem")]
fn mlkem_encaps(
    pk: &[u8],
    off: &mut usize,
    randomness: &[u8; 32],
    leg: usize,
    ciphertext: &mut Vec<u8>,
    secrets: &mut Vec<SharedSecret>,
) -> Result<(), KemError> {
    use origin_crypto_sdk::pqc::ml_kem::{EncapsulationKey, MlKem768Kem, EK_SIZE};
    let ek_bytes: [u8; EK_SIZE] = take(pk, off)?;
    let ek = EncapsulationKey::from_bytes(&ek_bytes).map_err(kem_err)?;
    // Deterministic encapsulation so MEX covers this leg and vectors are exact.
    let mut m = [0u8; 32];
    encaps_derive(randomness, leg, &mut m)?;
    let (ct, ss) = MlKem768Kem::encapsulate_deterministic(&ek, &m);
    ciphertext.extend_from_slice(&ct.as_bytes());
    secrets.push(SharedSecret::new(ss));
    Ok(())
}

#[cfg(not(feature = "ml-kem"))]
fn mlkem_encaps(
    _pk: &[u8],
    _off: &mut usize,
    _randomness: &[u8; 32],
    _leg: usize,
    _ciphertext: &mut Vec<u8>,
    _secrets: &mut Vec<SharedSecret>,
) -> Result<(), KemError> {
    Err(KemError::new("ML-KEM support not compiled in"))
}

#[cfg(feature = "ml-kem")]
fn mlkem_decaps(
    ciphertext: &[u8],
    off: &mut usize,
    sk_seed: &[u8; 64],
) -> Result<SharedSecret, KemError> {
    use origin_crypto_sdk::pqc::ml_kem::{
        Ciphertext as MlCiphertext, DecapsulationKey, MlKem768Kem, CT_SIZE,
    };
    let ct_arr: [u8; CT_SIZE] = take(ciphertext, off)?;
    let dk = DecapsulationKey::from_seed(sk_seed);
    let ct = MlCiphertext::from_bytes(&ct_arr).map_err(kem_err)?;
    Ok(SharedSecret::new(MlKem768Kem::decapsulate(&dk, &ct)))
}

#[cfg(not(feature = "ml-kem"))]
fn mlkem_decaps(
    _ciphertext: &[u8],
    _off: &mut usize,
    _sk_seed: &[u8; 64],
) -> Result<SharedSecret, KemError> {
    Err(KemError::new("ML-KEM support not compiled in"))
}

// ── the suite impl ───────────────────────────────────────────────────

impl CryptoSuite for SdkSuite {
    fn suite_id(&self) -> u16 {
        self.id
    }

    fn sizes(&self) -> WireSizes {
        sizes_for(self.id)
    }

    fn leg_kinds(&self) -> &'static [LegKind] {
        leg_kinds_for(self.id)
    }

    fn kem_keygen(
        &self,
        seed: &[u8; 32],
        role: KemRole,
    ) -> Result<(KemPublicKey, KemSecretKey), KemError> {
        let mut pk = Vec::new();
        let mut sk = Vec::new();
        for (i, kind) in self.leg_kinds().iter().enumerate() {
            match kind {
                LegKind::X25519 => {
                    let mut scalar = [0u8; 32];
                    derive(seed, role, i, &mut scalar)?;
                    // Keep the derived scalar as storage; `from_secret_key`
                    // clamps on use, so validation and use agree.
                    let kp = X25519KeyPair::from_secret_key(&scalar).map_err(kem_err)?;
                    pk.extend_from_slice(kp.public_key().as_bytes());
                    sk.extend_from_slice(&scalar);
                }
                LegKind::NtruPrime761 => {
                    let mut sub = [0u8; 32];
                    derive(seed, role, i, &mut sub)?;
                    let (public, secret) = NtruPrime::generate_keypair_from_seed(&sub);
                    pk.extend_from_slice(&public);
                    sk.extend_from_slice(&secret);
                }
                LegKind::MlKem768 => mlkem_keygen(seed, role, i, &mut pk, &mut sk)?,
            }
        }
        Ok((KemPublicKey::new(pk), KemSecretKey::new(sk)))
    }

    fn kem_encaps(
        &self,
        pk: &KemPublicKey,
        randomness: &[u8; KEM_ENCAPS_RANDOMNESS],
    ) -> Result<Encapsulation, KemError> {
        let bytes = pk.as_bytes();
        let mut off = 0usize;
        let mut ciphertext = Vec::new();
        let mut shared_secrets = Vec::new();

        for (i, kind) in self.leg_kinds().iter().enumerate() {
            match kind {
                LegKind::X25519 => {
                    let peer_bytes: [u8; 32] = take(bytes, &mut off)?;
                    let mut scalar = [0u8; 32];
                    encaps_derive(randomness, i, &mut scalar)?;
                    let eph = X25519KeyPair::from_secret_key(&scalar).map_err(kem_err)?;
                    let peer = X25519PublicKey::from_bytes(peer_bytes);
                    let ss = eph.diffie_hellman(&peer).map_err(kem_err)?;
                    ciphertext.extend_from_slice(eph.public_key().as_bytes());
                    shared_secrets.push(SharedSecret::new(*ss.as_bytes()));
                }
                LegKind::NtruPrime761 => {
                    let public: NtruPublic = take(bytes, &mut off)?;
                    let mut sub = [0u8; 32];
                    encaps_derive(randomness, i, &mut sub)?;
                    let mut det_rng = ChaCha20Rng::from_seed(sub);
                    let (ct, ss) = NtruPrime::encapsulate(&public, &mut det_rng);
                    ciphertext.extend_from_slice(&ct);
                    shared_secrets.push(SharedSecret::new(ss));
                }
                LegKind::MlKem768 => mlkem_encaps(
                    bytes,
                    &mut off,
                    randomness,
                    i,
                    &mut ciphertext,
                    &mut shared_secrets,
                )?,
            }
        }
        Ok(Encapsulation {
            ciphertext: Ciphertext::new(ciphertext),
            shared_secrets,
        })
    }

    fn kem_decaps(
        &self,
        sk: &KemSecretKey,
        ciphertext: &[u8],
    ) -> Result<Vec<SharedSecret>, KemError> {
        let kinds = self.leg_kinds();
        let expected = self.sizes().kem_ct;
        if ciphertext.len() != expected {
            return Err(KemError::new(format!(
                "ciphertext is {} bytes, expected {expected}",
                ciphertext.len()
            )));
        }

        let sk_bytes = sk.as_bytes();
        let mut sk_off = 0usize;
        let mut ct_off = 0usize;
        let mut out = Vec::with_capacity(kinds.len());

        for kind in kinds {
            match kind {
                LegKind::X25519 => {
                    let scalar: [u8; 32] = take(sk_bytes, &mut sk_off)?;
                    let peer_bytes: [u8; 32] = take(ciphertext, &mut ct_off)?;
                    let kp = X25519KeyPair::from_secret_key(&scalar).map_err(kem_err)?;
                    let peer = X25519PublicKey::from_bytes(peer_bytes);
                    let ss = kp.diffie_hellman(&peer).map_err(kem_err)?;
                    out.push(SharedSecret::new(*ss.as_bytes()));
                }
                LegKind::NtruPrime761 => {
                    let secret: NtruSecret = take(sk_bytes, &mut sk_off)?;
                    let ct_arr: NtruCiphertext = take(ciphertext, &mut ct_off)?;
                    let ss = NtruPrime::decapsulate(&ct_arr, &secret).map_err(kem_err)?;
                    out.push(SharedSecret::new(ss));
                }
                LegKind::MlKem768 => {
                    let seed: [u8; 64] = take(sk_bytes, &mut sk_off)?;
                    out.push(mlkem_decaps(ciphertext, &mut ct_off, &seed)?);
                }
            }
        }
        Ok(out)
    }

    fn kdf(&self, salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), KdfError> {
        hkdf_sha3_256(ikm, Some(salt), info, out).map_err(|e| KdfError::new(e.to_string()))
    }

    fn hash(&self, domain: &[u8], data: &[u8]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(domain.len() + 1 + data.len());
        buf.extend_from_slice(domain);
        buf.push(0);
        buf.extend_from_slice(data);
        sha3_256(&buf)
    }

    fn aead_seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        ad: &[u8],
        pt: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        ChaCha20Blake3::encrypt(key, nonce, pt, ad).map_err(|e| AeadError::new(e.to_string()))
    }

    fn aead_open(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        ad: &[u8],
        ct: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        ChaCha20Blake3::decrypt(key, nonce, ct, ad).map_err(|e| AeadError::new(e.to_string()))
    }

    fn sign_keygen(&self, seed: &[u8; 32]) -> Result<(SignPublicKey, SignSecretKey), SigError> {
        let bundle =
            HybridSigningKeyBundle::from_seed_cached(seed, SIGN_DOMAIN).map_err(sig_err)?;
        let mut pk = Vec::with_capacity(32 + falcon_sizes::PUBLIC_KEY);
        pk.extend_from_slice(&bundle.ed25519_pk().to_bytes());
        pk.extend_from_slice(bundle.falcon1024_pk().as_bytes());
        Ok((SignPublicKey::new(pk), SignSecretKey::new(bundle)))
    }

    fn sign(&self, sk: &SignSecretKey, msg: &[u8]) -> Result<Vec<u8>, SigError> {
        let bundle = sk
            .downcast_ref::<Arc<HybridSigningKeyBundle>>()
            .ok_or_else(|| SigError::new("signing key is not an SDK bundle"))?;
        let sig = bundle.sign_hybrid(msg);
        let wire = HybridSig::from_sig(&sig);
        let mut out = Vec::new();
        wire.encode(&mut out).map_err(sig_err)?;
        Ok(out)
    }

    fn verify(&self, pk: &SignPublicKey, msg: &[u8], sig: &[u8]) -> bool {
        let bytes = pk.as_bytes();
        let Some((ed, falcon)) = bytes.split_at_checked(32) else {
            return false;
        };
        let Ok(ed_arr) = <[u8; 32]>::try_from(ed) else {
            return false;
        };
        let mut pos = 0usize;
        let Ok(wire) = HybridSig::decode(sig, &mut pos) else {
            return false;
        };
        if pos != sig.len() {
            return false;
        }
        wire.verify(&ed_arr, falcon, msg).is_ok()
    }
}
