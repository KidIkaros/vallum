// SPDX-License-Identifier: Apache-2.0

//! The `CryptoSuite` boundary — Vallum's *entire* cryptographic dependency
//! surface.
//!
//! Everything the protocol needs from *any* crypto implementation is captured
//! here, in terms of byte slices and Vallum-owned newtypes. Nothing in this
//! module names an SDK type. Swapping the implementation behind the boundary
//! (including for the author's future from-scratch cryptography) means writing
//! one new `CryptoSuite` impl plus refreshing one KAT file — the handshake, key
//! schedule, framing, and data plane do not change.
//!
//! # The one rule
//!
//! [`CryptoSuite`] supplies **operations and sizes only**. The *list of legs* in
//! the hybrid combiner is a Vallum constant ([`crate::kem`]); a suite reports
//! the legs it implements via [`CryptoSuite::leg_kinds`], and the protocol
//! verifies that list against what it expects. This is what makes a downgrade
//! (fewer/weaker legs) *detectable* rather than merely absent.

use core::any::Any;
use core::fmt;

use crate::error::{AeadError, KdfError, KemError, SigError};

/// Size of the caller-supplied encapsulation randomness, in bytes.
///
/// Encapsulation takes an explicit 32-byte seed rather than an RNG handle. This
/// makes it **fully deterministic**, so handshake transcripts and session keys
/// are reproducible and byte-exact vectors are possible; and it lets the
/// protocol mix a long-term secret into the randomness (the MEX / dual-PRF
/// hardening from PQ-WireGuard) *before* the KEM runs. The adapter expands the
/// seed into per-leg randomness with its own KDF.
pub const KEM_ENCAPS_RANDOMNESS: usize = 32;

/// The role a KEM key pair plays in the handshake.
///
/// Static and ephemeral keys are derived with different domain separation, so a
/// seed reuse can never produce the same key for both roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemRole {
    /// Long-term key, used for authentication.
    Static,
    /// Per-handshake key, used for forward secrecy.
    Ephemeral,
}

/// Which primitive implements a hybrid-combiner leg.
///
/// Carried so the protocol can assert the leg set it expects. Names refer to
/// *algorithms*, not implementations — the adapter decides who computes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegKind {
    /// X25519 (RFC 7748).
    X25519,
    /// sntrup761 (NTRU Prime).
    NtruPrime761,
    /// ML-KEM-768 (FIPS 203).
    MlKem768,
}

/// Every on-wire length a suite can produce, in bytes.
///
/// The handshake framing is TLV (self-describing), so these are used for
/// *assertions* and buffer sizing, not for parsing. Signature sizes are maxima
/// because the hybrid signature has a variable-length Falcon component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireSizes {
    /// Number of hybrid-combiner legs.
    pub leg_count: usize,
    /// Total public-key size, summed across legs.
    pub kem_pk: usize,
    /// Total secret-key size, summed across legs.
    pub kem_sk: usize,
    /// Total ciphertext size, summed across legs.
    pub kem_ct: usize,
    /// Size of one shared secret (32).
    pub shared_secret: usize,
    /// Size of a hash digest (32).
    pub hash: usize,
    /// AEAD key size (32).
    pub aead_key: usize,
    /// AEAD nonce size (24).
    pub aead_nonce: usize,
    /// AEAD authentication-tag size (32).
    pub aead_tag: usize,
    /// Maximum hybrid public-key size.
    pub sign_pk_max: usize,
    /// Maximum hybrid signature size.
    pub sign_sig_max: usize,
}

// ──────────────────────────────────────────────────────────────────────
// Byte-oriented newtypes
// ──────────────────────────────────────────────────────────────────────

macro_rules! byte_buffer {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, PartialEq, Eq)]
        pub struct $name(Vec<u8>);

        impl $name {
            /// Wrap raw bytes.
            pub fn new(bytes: Vec<u8>) -> Self {
                Self(bytes)
            }

            /// Borrow the bytes.
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            /// Consume the wrapper, returning the bytes.
            pub fn into_bytes(self) -> Vec<u8> {
                self.0
            }

            /// Byte length.
            pub fn len(&self) -> usize {
                self.0.len()
            }

            /// Whether the buffer is empty.
            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({} bytes)", stringify!($name), self.0.len())
            }
        }
    };
}

byte_buffer!(KemPublicKey, "A hybrid KEM public key (all legs concatenated).");
byte_buffer!(Ciphertext, "A hybrid KEM ciphertext (all legs concatenated).");
byte_buffer!(SignPublicKey, "A hybrid signing public key (Ed25519 ‖ Falcon-1024).");

/// A hybrid KEM secret key (all legs concatenated). Zeroized on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct KemSecretKey(Vec<u8>);

impl KemSecretKey {
    /// Wrap raw bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Byte length.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for KemSecretKey {
    fn drop(&mut self) {
        crate::scrub(&mut self.0);
    }
}

impl fmt::Debug for KemSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KemSecretKey(<{} bytes, redacted>)", self.0.len())
    }
}

/// A 32-byte shared secret or key.
#[derive(Clone, PartialEq, Eq)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    /// Wrap a 32-byte secret.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the secret.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consume the wrapper.
    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(|b| *b = 0);
        core::hint::black_box(&mut self.0);
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SharedSecret(<redacted>)")
    }
}

/// An opaque, adapter-owned signing secret key.
///
/// The adapter stores whatever it needs (e.g. a cached key bundle); the protocol
/// only passes it back to [`CryptoSuite::sign`]. No implementation type crosses
/// the boundary.
pub struct SignSecretKey(Box<dyn Any + Send + Sync>);

impl SignSecretKey {
    /// Wrap an adapter-owned value.
    pub fn new<T: Any + Send + Sync>(value: T) -> Self {
        Self(Box::new(value))
    }

    /// Borrow the wrapped value, if it is of type `T`.
    pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
        self.0.downcast_ref::<T>()
    }
}

impl fmt::Debug for SignSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SignSecretKey(<opaque>)")
    }
}

/// The result of encapsulating to every leg of a hybrid public key.
#[derive(Clone, Debug)]
pub struct Encapsulation {
    /// Concatenated ciphertext — one leg after another, in combiner order. This
    /// is the exact wire form.
    pub ciphertext: Ciphertext,
    /// One shared secret per leg, in combiner order.
    pub shared_secrets: Vec<SharedSecret>,
}

impl Encapsulation {
    /// Number of legs.
    pub fn leg_count(&self) -> usize {
        self.shared_secrets.len()
    }
}

// ──────────────────────────────────────────────────────────────────────
// The trait
// ──────────────────────────────────────────────────────────────────────

/// Vallum's entire cryptographic dependency surface.
///
/// Object-safe: a registry may hold `&dyn CryptoSuite` or `Box<dyn CryptoSuite>`.
pub trait CryptoSuite: Send + Sync + 'static {
    /// The suite id written into the handshake header and folded into the
    /// transcript.
    fn suite_id(&self) -> u16;

    /// Every on-wire length this suite can produce.
    fn sizes(&self) -> WireSizes;

    /// The hybrid-combiner legs this suite provides, in order.
    ///
    /// The protocol asserts this against its expected list.
    fn leg_kinds(&self) -> &'static [LegKind];

    // ── KEM ──────────────────────────────────────────────────────────

    /// Derive a hybrid KEM key pair from a 32-byte seed.
    fn kem_keygen(
        &self,
        seed: &[u8; 32],
        role: KemRole,
    ) -> Result<(KemPublicKey, KemSecretKey), KemError>;

    /// Encapsulate to every leg, returning the concatenated ciphertext (wire
    /// form) and the per-leg shared secrets.
    ///
    /// `randomness` must be 32 uniformly random bytes and must never be reused
    /// across encapsulations to the same key. Implementations derive per-leg
    /// randomness from it deterministically, so the same `(pk, randomness)` pair
    /// always yields the same ciphertext and secrets.
    fn kem_encaps(
        &self,
        pk: &KemPublicKey,
        randomness: &[u8; KEM_ENCAPS_RANDOMNESS],
    ) -> Result<Encapsulation, KemError>;

    /// Decapsulate a concatenated ciphertext, returning per-leg shared secrets
    /// in combiner order.
    ///
    /// `ciphertext` must be exactly `sizes().kem_ct` bytes. Implementations must
    /// never fail open: a modified ciphertext yields *different* secrets, never
    /// the original.
    fn kem_decaps(
        &self,
        sk: &KemSecretKey,
        ciphertext: &[u8],
    ) -> Result<Vec<SharedSecret>, KemError>;

    // ── KDF (HKDF-shaped) ────────────────────────────────────────────

    /// HKDF-Shaped derivation: `out = Expand(Extract(salt, ikm), info)`.
    ///
    /// `salt` carries the transcript (or the previous root in a ratchet);
    /// callers bind protocol context into either `salt` or `info`.
    fn kdf(&self, salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), KdfError>;

    // ── Hash ─────────────────────────────────────────────────────────

    /// Domain-separated hash: `H(domain ‖ 0x00 ‖ data)`.
    fn hash(&self, domain: &[u8], data: &[u8]) -> [u8; 32];

    // ── AEAD (must be committing) ────────────────────────────────────

    /// Seal `pt`, returning ciphertext with the tag appended.
    fn aead_seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        ad: &[u8],
        pt: &[u8],
    ) -> Result<Vec<u8>, AeadError>;

    /// Open `ct`, verifying the tag over `ad`.
    fn aead_open(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        ad: &[u8],
        ct: &[u8],
    ) -> Result<Vec<u8>, AeadError>;

    // ── Signatures (hybrid identity) ─────────────────────────────────

    /// Derive a hybrid signing key pair from a 32-byte seed.
    fn sign_keygen(
        &self,
        seed: &[u8; 32],
    ) -> Result<(SignPublicKey, SignSecretKey), SigError>;

    /// Sign `msg`, returning the encoded hybrid signature.
    fn sign(&self, sk: &SignSecretKey, msg: &[u8]) -> Result<Vec<u8>, SigError>;

    /// Verify a hybrid signature. **Both** component signatures must verify.
    fn verify(&self, pk: &SignPublicKey, msg: &[u8], sig: &[u8]) -> bool;
}
