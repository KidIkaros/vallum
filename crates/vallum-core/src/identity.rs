// SPDX-License-Identifier: Apache-2.0

//! Identity: hybrid signature keys, static identities, and identity documents.
//!
//! P1 authenticates a peer by proving it holds a **static KEM secret key**: the
//! responder proves it decapsulated op A, the initiator proves it decapsulated
//! op C. That is enough to *key* a session to a pre-shared public key
//! (WireGuard's cryptokey routing), but it is not by itself a transferable
//! statement of identity — there is nothing a third party can check.
//!
//! P3 adds the missing half: a **hybrid Ed25519 + Falcon-1024 signature over the
//! handshake transcript**, carried in `RespHello` (the responder's) and
//! `InitConf` (the initiator's) as the `IDENTITY_SIG` field. It is taken over
//! `TR` — the transcript that already binds every KEM ciphertext — so the signer
//! commits to the whole session, not to a detached string.
//!
//! ## Both must verify
//!
//! [`CryptoSuite::verify`] must accept a hybrid signature only when **both**
//! component signatures verify. A break of Ed25519 *or* of Falcon-1024 therefore
//! does not yield a forgery. This is the P3 proof obligation; the contract suite
//! (`vallum-crypto-contract`) pins it by tampering with each half independently.
//!
//! ## Fail-closed configuration
//!
//! Whether a peer is expected to sign is *local configuration*
//! ([`PeerIdentity`]), never negotiated:
//!
//! | `PeerIdentity::signing` | `IDENTITY_SIG` present | absent |
//! |---|---|---|
//! | `Some(pk)` | verify; reject on failure | reject ([`HandshakeError::IdentityMissing`]) |
//! | `None` | reject ([`HandshakeError::IdentityUnexpected`]) | accept |
//!
//! There is no wire flag to disagree about, so stripping the signature fails
//! against a peer configured to require one, and an operator who has *not*
//! configured a signing key cannot be silently upgraded into believing one was
//! checked. Asymmetric configuration is a misconfiguration that fails loudly
//! rather than degrading.
//!
//! ## Identity documents
//!
//! [`IdentityDocument`] is the transferable form: a labelled structure binding a
//! KEM public key to a signing public key, signed by an *issuer*. Self-signed it
//! is a key binding; issued by a CA it is a certificate. `decode` → `is_valid` →
//! [`PeerIdentity`] is the whole certificate path, and it needs no new wire
//! machinery — the document reuses the handshake TLV framing.
//!
//! ## One seed, two independent keys
//!
//! [`StaticIdentity::generate_with_signing`] derives the signing seed from the
//! identity master seed through the suite KDF under its own label. The KEM and
//! signing keys are therefore *independent*, and the public halves are bound to
//! each other by the transcript (the signature covers `TR`, which binds the KEM
//! ciphertexts). This is key derivation, not key reuse: unlike Thormarker's
//! construction there is no shared scalar, so no new hardness assumption is
//! inherited. See `docs/proof/hybrid-identity.md` §5.

use vallum_crypto::{
    frame, CryptoSuite, KemPublicKey, KemRole, KemSecretKey, SignPublicKey, SignSecretKey,
};

use crate::error::HandshakeError;
use crate::wire::{tag, Message, MessageBuilder, MessageHeader, MessageType, PROTOCOL_VERSION};

/// Domain label for the responder's identity signature.
pub(crate) const IDENTITY_RESP_DOMAIN: &[u8] = b"vallum/identity/resp/v1";
/// Domain label for the initiator's identity signature.
pub(crate) const IDENTITY_INIT_DOMAIN: &[u8] = b"vallum/identity/init/v1";
/// Domain label for an identity document's signed body.
const IDENTITY_DOC_DOMAIN: &[u8] = b"vallum/identity-doc/v1";
/// Salt and label for deriving a signing seed from an identity master seed.
const SIGN_SEED_SALT: &[u8] = b"vallum/identity/v1";
const SIGN_SEED_INFO: &[u8] = b"vallum/identity/sign-seed/v1";

// ── keys ─────────────────────────────────────────────────────────────

/// A hybrid signing key pair (Ed25519 + Falcon-1024) owned by this endpoint.
///
/// The secret half is kept opaque — it is whatever the adapter stored, and no
/// provider type crosses the boundary. `Debug` reports nothing secret.
#[derive(Debug)]
pub struct SigningIdentity {
    public: SignPublicKey,
    secret: SignSecretKey,
}

impl SigningIdentity {
    /// Derive a hybrid signing key pair from a 32-byte seed.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Sign`] if the suite's key generation fails.
    pub fn generate(suite: &dyn CryptoSuite, seed: &[u8; 32]) -> Result<Self, HandshakeError> {
        let (public, secret) = suite.sign_keygen(seed).map_err(HandshakeError::Sign)?;
        Ok(Self { public, secret })
    }

    /// The public half — what peers and identity documents carry.
    #[must_use]
    pub fn public(&self) -> &SignPublicKey {
        &self.public
    }

    /// The secret half, for [`CryptoSuite::sign`].
    #[must_use]
    pub fn secret(&self) -> &SignSecretKey {
        &self.secret
    }
}

/// A long-term static identity: a hybrid KEM key pair, and optionally a hybrid
/// signing key pair.
///
/// The KEM half is what the handshake keys against (P1). The signing half is a
/// P3 addition and is **optional**: an identity without it produces exactly the
/// P1 wire bytes, which is what keeps the frozen transcripts valid.
#[derive(Debug)]
pub struct StaticIdentity {
    kem_public: KemPublicKey,
    kem_secret: KemSecretKey,
    signing: Option<SigningIdentity>,
}

impl StaticIdentity {
    /// Derive a KEM-only static identity from a 32-byte seed.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Kem`] if the suite's key generation fails.
    pub fn generate(suite: &dyn CryptoSuite, seed: &[u8; 32]) -> Result<Self, HandshakeError> {
        let (kem_public, kem_secret) = suite
            .kem_keygen(seed, KemRole::Static)
            .map_err(HandshakeError::Kem)?;
        Ok(Self {
            kem_public,
            kem_secret,
            signing: None,
        })
    }

    /// Derive a static identity with **both** halves from one master seed.
    ///
    /// The KEM key is [`StaticIdentity::generate`]'s, unchanged (so the wire
    /// bytes are independent of this function existing). The signing seed is a
    /// separately labelled KDF output of the same seed, so the two key pairs are
    /// independent rather than a shared scalar.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Kem`] / [`HandshakeError::Sign`] if key generation
    /// fails, or [`HandshakeError::Kdf`] if seed derivation fails.
    pub fn generate_with_signing(
        suite: &dyn CryptoSuite,
        seed: &[u8; 32],
    ) -> Result<Self, HandshakeError> {
        let mut signing_seed = [0u8; 32];
        suite
            .kdf(SIGN_SEED_SALT, seed, SIGN_SEED_INFO, &mut signing_seed)
            .map_err(HandshakeError::Kdf)?;
        let signing = SigningIdentity::generate(suite, &signing_seed);
        crate::scrub(&mut signing_seed);

        let mut identity = Self::generate(suite, seed)?;
        identity.signing = Some(signing?);
        Ok(identity)
    }

    /// The KEM public half — what peers are configured with.
    #[must_use]
    pub fn public(&self) -> &KemPublicKey {
        &self.kem_public
    }

    /// The KEM secret half.
    #[must_use]
    pub fn secret(&self) -> &KemSecretKey {
        &self.kem_secret
    }

    /// The signing half, if this identity has one.
    #[must_use]
    pub fn signing(&self) -> Option<&SigningIdentity> {
        self.signing.as_ref()
    }

    /// The signing public half, if this identity has one.
    #[must_use]
    pub fn signing_public(&self) -> Option<&SignPublicKey> {
        self.signing.as_ref().map(SigningIdentity::public)
    }

    /// How a *peer* should be configured to talk to this identity.
    ///
    /// Carries the signing public key when there is one, so both ends of a
    /// symmetric configuration require and verify each other's signatures.
    #[must_use]
    pub fn to_peer(&self) -> PeerIdentity {
        PeerIdentity {
            kem: self.kem_public.clone(),
            signing: self.signing.as_ref().map(|s| s.public.clone()),
        }
    }
}

/// The *expected* identity of a peer, from local configuration.
///
/// `kem` is always required (it is what the handshake encapsulates to). `signing`
/// is required when third-party-verifiable identity is wanted, and drives the
/// fail-closed rules in the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    kem: KemPublicKey,
    signing: Option<SignPublicKey>,
}

impl PeerIdentity {
    /// A peer known only by its KEM key (P1 behaviour; no signature expected).
    #[must_use]
    pub fn kem_only(kem: KemPublicKey) -> Self {
        Self { kem, signing: None }
    }

    /// A peer known by its KEM key *and* a signing key it must prove.
    #[must_use]
    pub fn with_signing(kem: KemPublicKey, signing: SignPublicKey) -> Self {
        Self {
            kem,
            signing: Some(signing),
        }
    }

    /// Configure a peer from a local identity — the symmetric case in tests and
    /// the common two-sided deployment.
    #[must_use]
    pub fn from_identity(identity: &StaticIdentity) -> Self {
        identity.to_peer()
    }

    /// The peer's KEM public key.
    #[must_use]
    pub fn kem(&self) -> &KemPublicKey {
        &self.kem
    }

    /// The peer's signing public key, if a signature is required.
    #[must_use]
    pub fn signing(&self) -> Option<&SignPublicKey> {
        self.signing.as_ref()
    }
}

// ── signatures over the transcript ───────────────────────────────────

/// The exact bytes an identity signature covers:
/// `frame([domain, suite_id, identity_key, transcript])`.
///
/// `identity_key` is included so the signature cannot be lifted onto a different
/// public key (the analogue of TLS's `CertificateVerify` binding), and `domain`
/// separates the initiator's and responder's statements so neither can be
/// replayed as the other.
pub(crate) fn identity_signature_input(
    domain: &[u8],
    suite_id: u16,
    identity_key: &[u8],
    transcript: &[u8],
) -> Vec<u8> {
    frame(&[domain, &suite_id.to_be_bytes(), identity_key, transcript])
}

/// Sign a handshake transcript under `domain`.
///
/// # Errors
///
/// [`HandshakeError::Sign`] if the signing operation fails.
pub(crate) fn sign_transcript(
    suite: &dyn CryptoSuite,
    signing: &SigningIdentity,
    domain: &[u8],
    suite_id: u16,
    transcript: &[u8],
) -> Result<Vec<u8>, HandshakeError> {
    let input = identity_signature_input(domain, suite_id, signing.public().as_bytes(), transcript);
    suite
        .sign(signing.secret(), &input)
        .map_err(HandshakeError::Sign)
}

/// Verify a peer's identity signature over `transcript`.
#[must_use]
pub(crate) fn verify_transcript(
    suite: &dyn CryptoSuite,
    expected: &SignPublicKey,
    domain: &[u8],
    suite_id: u16,
    transcript: &[u8],
    signature: &[u8],
) -> bool {
    let input = identity_signature_input(domain, suite_id, expected.as_bytes(), transcript);
    suite.verify(expected, &input, signature)
}

// ── identity documents ───────────────────────────────────────────────

/// A labelled binding of a KEM public key to a signing public key, signed by an
/// issuer.
///
/// The signature is over `frame([domain, suite_id, label, kem_pk, sign_pk])`.
/// Self-signed, the document is the subject's own key binding; signed by a CA
/// (an issuer other than `signing`), it is a certificate. The structure is
/// identical either way — which is the point: the certificate path is a policy
/// on the issuer key, not a second format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityDocument {
    label: Vec<u8>,
    kem: KemPublicKey,
    signing: SignPublicKey,
    /// The window this document asserts, in unix seconds.
    validity: Validity,
    signature: Vec<u8>,
}

/// The validity window of an identity document, in unix seconds.
///
/// `not_before` is inclusive and `not_after` exclusive, the same shape TLS
/// certificates use. The core is clock-free: the caller supplies `now`, exactly
/// as the handshake takes a caller-supplied `Tai64n`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    /// The first second at which the document is valid.
    pub not_before: u64,
    /// The first second at which it is **no longer** valid.
    pub not_after: u64,
}

impl Validity {
    /// A window. An empty window (`not_before >= not_after`) is legal to build
    /// and never valid — issuing one is a caller bug the verifier refuses.
    #[must_use]
    pub fn new(not_before: u64, not_after: u64) -> Self {
        Self {
            not_before,
            not_after,
        }
    }

    /// Whether `now` falls inside the window.
    #[must_use]
    pub fn contains(&self, now: u64) -> bool {
        self.not_before <= now && now < self.not_after
    }
}

impl IdentityDocument {
    /// Issue a document over `(label, kem, signing)` and sign it with `issuer`.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Sign`] if the issuing signature fails.
    pub fn issue(
        suite: &dyn CryptoSuite,
        label: &[u8],
        kem: KemPublicKey,
        signing: SignPublicKey,
        validity: Validity,
        issuer: &SignSecretKey,
    ) -> Result<Self, HandshakeError> {
        let mut doc = Self {
            label: label.to_vec(),
            kem,
            signing,
            validity,
            signature: Vec::new(),
        };
        let input = doc.signature_input(suite.suite_id());
        doc.signature = suite.sign(issuer, &input).map_err(HandshakeError::Sign)?;
        Ok(doc)
    }

    /// Self-sign a document for `identity`.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::NoSigningIdentity`] if the identity has no signing half,
    /// or [`HandshakeError::Sign`] if signing fails.
    pub fn self_sign(
        suite: &dyn CryptoSuite,
        identity: &StaticIdentity,
        label: &[u8],
        validity: Validity,
    ) -> Result<Self, HandshakeError> {
        let signing = identity
            .signing()
            .ok_or(HandshakeError::NoSigningIdentity)?;
        Self::issue(
            suite,
            label,
            identity.public().clone(),
            signing.public().clone(),
            validity,
            signing.secret(),
        )
    }

    fn signature_input(&self, suite_id: u16) -> Vec<u8> {
        frame(&[
            IDENTITY_DOC_DOMAIN,
            &suite_id.to_be_bytes(),
            &self.label,
            &self.validity.not_before.to_be_bytes(),
            &self.validity.not_after.to_be_bytes(),
            self.kem.as_bytes(),
            self.signing.as_bytes(),
        ])
    }

    /// Whether `issuer` signed this document's body.
    #[must_use]
    pub fn is_valid(&self, suite: &dyn CryptoSuite, issuer: &SignPublicKey) -> bool {
        suite.verify(
            issuer,
            &self.signature_input(suite.suite_id()),
            &self.signature,
        )
    }

    /// Whether this document is self-signed (its own signing key issued it).
    ///
    /// Structural only: it says nothing about the validity window.
    #[must_use]
    pub fn is_self_signed(&self, suite: &dyn CryptoSuite) -> bool {
        self.is_valid(suite, &self.signing)
    }

    /// Whether `issuer` signed this document **and** `now_unix` is inside its
    /// window.
    ///
    /// Acceptance must use this, not [`Self::is_valid`]: the latter is the
    /// structural check, and a valid signature over an expired window is still
    /// an expired document.
    #[must_use]
    pub fn is_valid_at(
        &self,
        suite: &dyn CryptoSuite,
        issuer: &SignPublicKey,
        now_unix: u64,
    ) -> bool {
        self.is_valid(suite, issuer) && self.validity.contains(now_unix)
    }

    /// The window this document asserts.
    #[must_use]
    pub fn validity(&self) -> Validity {
        self.validity
    }

    /// The document label — the identity text it asserts.
    #[must_use]
    pub fn label(&self) -> &[u8] {
        &self.label
    }

    /// The bound KEM public key.
    #[must_use]
    pub fn kem(&self) -> &KemPublicKey {
        &self.kem
    }

    /// The bound signing public key.
    #[must_use]
    pub fn signing(&self) -> &SignPublicKey {
        &self.signing
    }

    /// The issuer's signature bytes.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Encode for storage or transmission, using the handshake TLV framing.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Wire`] if a field or the assembled document exceeds the
    /// framing limits.
    pub fn encode(&self, suite_id: u16) -> Result<Vec<u8>, HandshakeError> {
        let header = MessageHeader {
            version: PROTOCOL_VERSION,
            message_type: MessageType::IdentityDoc,
            suite_id,
            sender_index: 0,
        };
        let mut builder = MessageBuilder::new(header);
        builder.field(tag::IDENTITY_LABEL, &self.label)?;
        builder.field(tag::NOT_BEFORE, &self.validity.not_before.to_be_bytes())?;
        builder.field(tag::NOT_AFTER, &self.validity.not_after.to_be_bytes())?;
        builder.field(tag::KEM_PUBLIC, self.kem.as_bytes())?;
        builder.field(tag::SIGN_PUBLIC, self.signing.as_bytes())?;
        builder.field(tag::IDENTITY_SIG, &self.signature)?;
        builder.finish()
    }

    /// Decode a document. The signature is *not* checked here — call
    /// [`Self::is_valid`] with the expected issuer.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Wire`] if the framing is malformed or a field is absent
    /// or the message is not an identity document.
    pub fn decode(bytes: &[u8]) -> Result<Self, HandshakeError> {
        let message = Message::parse(bytes)?;
        message.expect_type(MessageType::IdentityDoc)?;
        Ok(Self {
            label: message.require(tag::IDENTITY_LABEL)?.to_vec(),
            // Both are required: a document without a window is refused rather
            // than read as "valid forever". There are no deployed documents, so
            // the fail-closed choice costs nothing and removes the weakest
            // possible default.
            validity: Validity::new(
                u64::from_be_bytes(message.require_array::<8>(tag::NOT_BEFORE)?),
                u64::from_be_bytes(message.require_array::<8>(tag::NOT_AFTER)?),
            ),
            kem: KemPublicKey::new(message.require(tag::KEM_PUBLIC)?.to_vec()),
            signing: SignPublicKey::new(message.require(tag::SIGN_PUBLIC)?.to_vec()),
            signature: message.require(tag::IDENTITY_SIG)?.to_vec(),
        })
    }

    /// Validate against `issuer`, check the window, and turn the document into a
    /// configurable peer.
    ///
    /// This is the certificate path in one call: the peer is trusted only if the
    /// issuer signed *this* binding of KEM key and signing key, **and** `now_unix`
    /// is inside the window. The clock is the caller's; the core has none.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::IdentityInvalid`] if the issuer's signature does not
    /// verify, [`HandshakeError::IdentityNotYetValid`] if `now_unix` is before
    /// the window, or [`HandshakeError::IdentityExpired`] if it is at or past the
    /// end.
    pub fn to_peer(
        &self,
        suite: &dyn CryptoSuite,
        issuer: &SignPublicKey,
        now_unix: u64,
    ) -> Result<PeerIdentity, HandshakeError> {
        if !self.is_valid(suite, issuer) {
            return Err(HandshakeError::IdentityInvalid);
        }
        if now_unix < self.validity.not_before {
            return Err(HandshakeError::IdentityNotYetValid);
        }
        if now_unix >= self.validity.not_after {
            return Err(HandshakeError::IdentityExpired);
        }
        Ok(PeerIdentity::with_signing(
            self.kem.clone(),
            self.signing.clone(),
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
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
}
