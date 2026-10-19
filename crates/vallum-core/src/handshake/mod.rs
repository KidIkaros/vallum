// SPDX-License-Identifier: Apache-2.0

//! Vallum's three-message hybrid-KEM authenticated key exchange (KEM-AKE).
//!
//! ```text
//! Initiator                                              Responder
//! ─────────                                              ─────────
//! InitHello    ── STATIC_CT (A), EPHEMERAL_PK, TIMESTAMP,
//!                  PEER_HINT ──────────────────────────────▶   [static key]
//!              ◀── EPHEMERAL_CT (B), STATIC_CT (C),
//!                  CONFIRMATION (conf_r), IDENTITY_SIG ────    RespHello
//! InitConf     ── CONFIRMATION (conf_i), IDENTITY_SIG ───▶      [verify]
//! ```
//!
//! ## Peer identification (P6)
//!
//! A responder has to decide *which configured peer* an `InitHello` came from
//! before it can build `RespHello`, because op C is encapsulated to the
//! initiator's **static** key. WireGuard gets that for free: its init message
//! carries the initiator's static key encrypted to the responder's static key,
//! so the responder decrypts it and looks the peer up. Vallum's op A is a hybrid
//! KEM encapsulation to that same key, and a KEM yields a shared secret, not an
//! identity — so nothing in `STATIC_CT` names the initiator.
//!
//! P6 therefore adds one field. `PEER_HINT` is
//! `AEAD(KDF(salt = "vallum/peer-hint/seal/v1", ikm = ss_A), H("vallum/peer-hint/v1", …))`
//! — a short fingerprint of the initiator's static **public** KEM key, sealed
//! under a key derived from op A. Op A is encapsulated to the *responder's*
//! static key, so both ends can compute that key before the peer is known: the
//! initiator from the encapsulation it just made, the responder from the
//! decapsulation it just did. That is the whole trick, and it is what
//! [`responder_identify`] exposes as a separate phase.
//!
//! Read the trust model carefully, because it is asymmetric:
//!
//! * **Confidential.** A passive observer holds neither op A's shared secret nor
//!   the responder's static key, so it learns nothing about which peer is
//!   connecting — the same property WireGuard's encrypted static key has.
//! * **Not authenticated.** Anyone who knows the responder's *public* key can
//!   encapsulate op A and derive the seal key, so anyone can produce a hint
//!   naming any peer. It is therefore resolved by the transport and then
//!   *checked* by [`responder_accept`]: the hint must name the peer the caller
//!   resolved. A forged hint can only create a handshake that fails at
//!   `InitConf`, never a session under the wrong peer.
//!
//! The hint is also deliberately short (8 bytes). It is an index, not an
//! identity: op C and the confirmations are what authenticate, and a hint
//! collision costs one wasted attempt.
//!
//! ## Identity (P3)
//!
//! The confirmation values authenticate *key possession*: they prove a peer
//! holds the static KEM secret its public key names. They do not prove a
//! *name*. P3 adds an optional **hybrid Ed25519 + Falcon-1024 signature over
//! `TR`** — the responder's in `RespHello`, the initiator's in `InitConf` — so a
//! third party holding the peer's signing key can check who it was talking to.
//! Because the signature is over `TR`, it commits the signer to every KEM
//! ciphertext in the session. The signature keys, the fail-closed rules, and the
//! identity-document (certificate) form live in [`crate::identity`].
//!
//! ## Explicit confirmation, both directions
//!
//! WireGuard uses the initiator's *first data packet* as implicit confirmation,
//! which is exactly what made it unprovable in eCK-PFS-PSK. PQ-WireGuard adds an
//! explicit confirmation message; it also puts an explicit confirmation in
//! `RespHello` (its `zero` field), so that **both** parties authenticate each
//! other *before* accepting the session key. Vallum does the same, and it is not
//! optional: without `conf_r` the initiator would accept a key on the strength of
//! an unauthenticated `RespHello`.
//!
//! * `conf_r` (responder → initiator, inside `RespHello`) is derived from `KEY`,
//!   and `KEY` requires decapsulating op A — so verifying it proves the peer holds
//!   `σ_r`. That authenticates the **responder** to the initiator.
//! * `conf_i` (initiator → responder, in `InitConf`) requires ops B *and* C, i.e.
//!   the initiator's ephemeral and static secrets. That authenticates the
//!   **initiator** to the responder.
//!
//! ## Staged transcript
//!
//! The confirmation values must be verifiable at the point their message
//! arrives, so the transcript is built in stages that mirror PQ-WireGuard's
//! running hash chain rather than as one hash of the final byte sequence:
//!
//! ```text
//! TR1  = H("vallum/tr/init", suite_id ‖ sid_i ‖ epk_i ‖ ct_A ‖ timestamp)
//! TR   = H("vallum/tr/resp", suite_id ‖ TR1 ‖ sid_r ‖ ct_B ‖ ct_C)
//! ROOT = KDF(salt = TR,  ikm = ss_A ‖ ss_B ‖ ss_C, info = "vallum/kem/v1")
//! PSK  = H("vallum/psk/v1", frame([spk_i, spk_r]))          // UKS mitigation
//! KEY  = KDF(salt = ROOT, ikm = PSK, info = "vallum/psk-mix/v1")
//! conf_r = KDF(salt = KEY, ikm = TR,             info = "vallum/confirm/resp/v1")
//! TR2    = H("vallum/tr/conf", suite_id ‖ TR ‖ conf_r)
//! conf_i = KDF(salt = KEY, ikm = TR2,            info = "vallum/confirm/init/v1")
//! ```
//!
//! `TR` binds everything before the responder's confirmation and is therefore the
//! key-schedule transcript; `TR2` binds `conf_r` and is what `conf_i` commits to.
//! Every concatenation is length-framed, so it is unambiguous. `KEY` is the
//! handshake root the data plane will expand (P4); P1 freezes it together with
//! both confirmation values.
//!
//! Note that the transcript is built from **parsed field values** rather than the
//! raw received bytes. That is deliberate: it removes any need to canonicalise
//! TLV ordering, and (unlike `H(InitHello ‖ RespHello)`) it lets the responder
//! hash `RespHello` before its confirmation exists.
//!
//! ## The three KEM operations
//!
//! | op | direction | peer key | purpose |
//! |----|-----------|----------|---------|
//! | A | initiator → responder | responder **static** | responder authentication |
//! | B | responder → initiator | initiator **ephemeral** | forward secrecy |
//! | C | responder → initiator | initiator **static** | initiator authentication |
//!
//! One round trip plus an explicit confirmation.
//!
//! ## MEX (dual-PRF hardening)
//!
//! The two **static** encapsulations (A and C) do not use raw randomness. Their
//! encapsulation seed is `KDF(salt = fresh, ikm = sender_static_secret, info = …)`
//! — the sender's own long-term secret is mixed into the KEM randomness. This is
//! PQ-WireGuard's MEX fix: a subverted RNG cannot fix the shared secret, because
//! the adversary would also need the static secret. Op B is ephemeral and uses
//! plain fresh randomness.
//!
//! ## Randomness
//!
//! This module takes no RNG. Every handshake is a pure function of the caller's
//! `handshake_seed` (32 bytes of fresh randomness) and the peer's static key, so
//! a full transcript is byte-exact and reproducible — which is what makes the
//! frozen vectors in `tests/interop.rs` possible. The runtime layer is
//! responsible for sourcing `handshake_seed`, `sender_index`, and the timestamp.

use vallum_crypto::{
    CryptoSuite, KemPublicKey, KemRole, KemSecretKey, SharedSecret, SignPublicKey,
};

use crate::error::HandshakeError;
use crate::identity::{
    sign_transcript, PeerIdentity, StaticIdentity, IDENTITY_INIT_DOMAIN, IDENTITY_RESP_DOMAIN,
};
use crate::wire::{
    tag, Message, MessageBuilder, MessageHeader, MessageType, CONFIRMATION_SIZE, PROTOCOL_VERSION,
    TIMESTAMP_SIZE,
};

mod admission;
mod hint;
mod keyschedule;

pub use admission::{resp_tag, verify_resp_tag, RESP_TAG_SIZE};
pub use hint::{peer_hint, PEER_HINT_SIZE};

use admission::derive_resp_tag_key;
use hint::hint_crypt;
use keyschedule::{
    check_identity_signature, confirm_initiator, derive_seed, mex_randomness, schedule,
    transcript_conf, transcript_init, transcript_resp, verify_confirmation, verify_value,
    A_FRESH_INFO, B_FRESH_INFO, C_FRESH_INFO, EPH_SEED_INFO,
};

// ── identity ─────────────────────────────────────────────────────────

// [`StaticIdentity`] and [`PeerIdentity`] live in [`crate::identity`] together
// with the hybrid signature and identity-document machinery. The handshake uses
// them as-is: a peer's KEM key is what the encapsulations target, and a peer's
// optional signing key decides whether an identity signature is required.

// ── session keys ─────────────────────────────────────────────────────

/// The result of a completed handshake.
///
/// `Debug` cannot leak: every secret field is [`SharedSecret`], which redacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeys {
    /// The handshake transcript hash — public, but bound into every key.
    pub transcript: [u8; 32],
    /// The handshake root key. The data plane expands this (P4).
    pub key: SharedSecret,
    /// The value the initiator sends in `InitConf` to confirm the key.
    pub confirm_initiator: SharedSecret,
    /// The value the responder sends in `RespHello` to confirm the key.
    ///
    /// This gives the initiator explicit assurance that the responder derived
    /// `key` — i.e. holds `σ_r` — *before* the initiator accepts the session.
    /// PQ-WireGuard's `zero` field plays the same role.
    pub confirm_responder: SharedSecret,
    /// The 32-bit session index this endpoint announced in its own handshake
    /// messages.
    ///
    /// Data packets carry the *recipient's* index (WireGuard's `receiver`
    /// field), so a receiver demuxes on this value and a sender stamps the
    /// peer's. See [`crate::data::Sender`].
    pub own_index: u32,
    /// The 32-bit index the peer announced.
    pub peer_index: u32,
}

// ── state ────────────────────────────────────────────────────────────

/// Initiator state carried between `InitHello` and `RespHello`.
#[derive(Debug)]
pub struct InitiatorState {
    suite_id: u16,
    sender_index: u32,
    ephemeral_public: KemPublicKey,
    ephemeral_secret: KemSecretKey,
    /// Op A's ciphertext, as sent. Bound into transcript stage 1.
    static_ct: Vec<u8>,
    /// The timestamp we sent. Bound into transcript stage 1.
    timestamp: [u8; TIMESTAMP_SIZE],
    static_public: Vec<u8>,
    peer_public: Vec<u8>,
    /// The peer's signing public key, if this endpoint requires a signature
    /// (fail-closed: presence here means `RespHello` must carry one).
    peer_signing: Option<SignPublicKey>,
    init_hello: Vec<u8>,
    /// Per-leg secrets from op A (initiator → responder static).
    static_legs: Vec<SharedSecret>,
    /// The configured PSK this handshake was started with, if any (G1).
    psk: Option<SharedSecret>,
}

impl InitiatorState {
    /// The suite id this handshake is bound to.
    #[must_use]
    pub fn suite_id(&self) -> u16 {
        self.suite_id
    }

    /// The session index we chose and sent in `InitHello`.
    #[must_use]
    pub fn sender_index(&self) -> u32 {
        self.sender_index
    }

    /// Our ephemeral public key (the one the responder encapsulates op B to).
    #[must_use]
    pub fn ephemeral_public(&self) -> &KemPublicKey {
        &self.ephemeral_public
    }

    /// The exact `InitHello` bytes we sent — useful for a transport layer that
    /// must retransmit, and for tests. The key schedule does *not* hash these
    /// bytes; it hashes the parsed fields (see the module docs).
    #[must_use]
    pub fn init_hello(&self) -> &[u8] {
        &self.init_hello
    }

    /// The op-A-keyed key a `RespHello` must carry a tag under (P6.8).
    ///
    /// A transport that wants to reject a forged `RespHello` **before**
    /// rebuilding the handshake state stores this at send time; it is the only
    /// secret [`resp_tag`] needs. It is as sensitive as the state it is
    /// derived from.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Kdf`] if the suite's KDF fails.
    pub fn resp_tag_key(
        &self,
        suite: &dyn CryptoSuite,
    ) -> Result<[u8; RESP_TAG_SIZE], HandshakeError> {
        derive_resp_tag_key(suite, &self.static_legs)
    }
}

/// Responder state carried between `RespHello` and `InitConf`.
#[derive(Debug)]
pub struct ResponderState {
    suite_id: u16,
    sender_index: u32,
    peer_index: u32,
    resp_hello: Vec<u8>,
    timestamp: [u8; TIMESTAMP_SIZE],
    /// The initiator's signing public key, if this endpoint requires one.
    peer_signing: Option<SignPublicKey>,
    keys: SessionKeys,
}

impl ResponderState {
    /// The suite id this handshake is bound to.
    #[must_use]
    pub fn suite_id(&self) -> u16 {
        self.suite_id
    }

    /// The session index we chose and sent in `RespHello`.
    #[must_use]
    pub fn sender_index(&self) -> u32 {
        self.sender_index
    }

    /// The initiator's session index, echoed from `InitHello`.
    #[must_use]
    pub fn peer_index(&self) -> u32 {
        self.peer_index
    }

    /// The exact `RespHello` bytes we sent.
    #[must_use]
    pub fn resp_hello(&self) -> &[u8] {
        &self.resp_hello
    }

    /// The initiator's timestamp, still unvalidated (`InitHello` carries it for
    /// the anti-replay check P2 adds).
    #[must_use]
    pub fn timestamp(&self) -> &[u8; TIMESTAMP_SIZE] {
        &self.timestamp
    }

    /// Keys derived for this handshake, usable once `InitConf` verifies.
    #[must_use]
    pub fn session_keys(&self) -> &SessionKeys {
        &self.keys
    }
}

// ── handshake steps ──────────────────────────────────────────────────

/// Step 1 (initiator): build `InitHello` and retain the state to finish.
///
/// `peer` is the responder's identity, known from the peer configuration
/// (WireGuard-style cryptokey routing). Its KEM key is what op A encapsulates to;
/// its optional signing key is what the responder's `IDENTITY_SIG` will be
/// checked against.
///
/// # Errors
///
/// [`HandshakeError::Kem`] / [`HandshakeError::Kdf`] if a crypto operation
/// fails, or [`HandshakeError::Wire`] if the message cannot be framed.
pub fn initiator_hello(
    suite: &dyn CryptoSuite,
    identity: &StaticIdentity,
    peer: &PeerIdentity,
    sender_index: u32,
    timestamp: [u8; TIMESTAMP_SIZE],
    handshake_seed: &[u8; 32],
) -> Result<(Vec<u8>, InitiatorState), HandshakeError> {
    let suite_id = suite.suite_id();
    let peer_public = peer.kem();

    let eph_seed = derive_seed(suite, handshake_seed, EPH_SEED_INFO)?;
    let a_fresh = derive_seed(suite, handshake_seed, A_FRESH_INFO)?;

    // The initiator's ephemeral key pair: B is encapsulated to this, and its
    // secret is destroyed at the end of the handshake — that is the forward
    // secrecy for op B.
    let (ephemeral_public, ephemeral_secret) = suite
        .kem_keygen(&eph_seed, KemRole::Ephemeral)
        .map_err(HandshakeError::Kem)?;

    // Op A: initiator → responder static, MEX-bound to our own static secret.
    let randomness = mex_randomness(suite, identity.secret(), &a_fresh)?;
    let encapsulation = suite
        .kem_encaps(peer_public, &randomness)
        .map_err(HandshakeError::Kem)?;

    let header = MessageHeader {
        version: PROTOCOL_VERSION,
        message_type: MessageType::InitHello,
        suite_id,
        sender_index,
    };
    // P6: the sealed peer hint. It is derived from op A's shared secret, which
    // only a holder of the *responder's* static secret can reproduce — so a
    // passive observer cannot read which peer is calling, while the responder
    // can, and can therefore resolve the peer before it builds op C.
    let (hint_key, hint_nonce) = hint_crypt(suite, &encapsulation.shared_secrets)?;
    let sealed_hint = suite.aead_seal(
        &hint_key,
        &hint_nonce,
        &header.encode(),
        &peer_hint(suite, identity.public()),
    )?;

    let mut builder = MessageBuilder::new(header);
    builder.field(tag::STATIC_CT, encapsulation.ciphertext.as_bytes())?;
    builder.field(tag::EPHEMERAL_PK, ephemeral_public.as_bytes())?;
    builder.field(tag::TIMESTAMP, &timestamp)?;
    builder.field(tag::PEER_HINT, &sealed_hint)?;
    let init_hello = builder.finish()?;

    let state = InitiatorState {
        suite_id,
        sender_index,
        ephemeral_public,
        ephemeral_secret,
        static_ct: encapsulation.ciphertext.as_bytes().to_vec(),
        timestamp,
        static_public: identity.public().as_bytes().to_vec(),
        peer_public: peer_public.as_bytes().to_vec(),
        peer_signing: peer.signing().cloned(),
        init_hello: init_hello.clone(),
        static_legs: encapsulation.shared_secrets,
        psk: peer.preshared_key().cloned(),
    };
    Ok((init_hello, state))
}

/// What an `InitHello` reveals **before its sender is authenticated** (P6).
///
/// Decapsulating op A needs only the responder's *own* static secret, so it can
/// be done on a message from an unknown address — and that is what makes the
/// sealed peer hint readable. Everything here is still unauthenticated: the
/// sender is not identified until [`responder_accept`] completes and
/// `InitConf` verifies.
///
/// `Debug` cannot leak: the secrets are [`SharedSecret`], which redacts.
#[derive(Debug)]
pub struct InitHelloInfo {
    suite_id: u16,
    sender_index: u32,
    timestamp: [u8; TIMESTAMP_SIZE],
    ephemeral_public: KemPublicKey,
    static_ct: Vec<u8>,
    peer_hint: [u8; PEER_HINT_SIZE],
    /// Op A's per-leg secrets, recovered by decapsulation.
    static_legs: Vec<SharedSecret>,
}

impl InitHelloInfo {
    /// The suite id this message is bound to.
    #[must_use]
    pub fn suite_id(&self) -> u16 {
        self.suite_id
    }

    /// The initiator's session index, which `RespHello` must echo.
    #[must_use]
    pub fn sender_index(&self) -> u32 {
        self.sender_index
    }

    /// The initiator's timestamp, still unvalidated (P2 checks it at `InitConf`).
    #[must_use]
    pub fn timestamp(&self) -> &[u8; TIMESTAMP_SIZE] {
        &self.timestamp
    }

    /// The peer this message *claims* to come from.
    ///
    /// Confidential but **not** authenticated: resolve it against your peer
    /// table, then let [`responder_accept`] check that the two agree. A forged
    /// hint can only name a peer the initiator does not hold the key for, which
    /// fails at `InitConf` — it can never complete a session under the wrong
    /// peer.
    #[must_use]
    pub fn peer_hint(&self) -> &[u8; PEER_HINT_SIZE] {
        &self.peer_hint
    }
}

/// Step 2a (responder): read an `InitHello` far enough to choose a peer.
///
/// This is the phase that has to come first for any responder with more than one
/// configured peer, and the reason the `PEER_HINT` field exists at all. WireGuard
/// gets peer identification for free because its init message carries the
/// initiator's static key *encrypted to the responder's static key*; Vallum's op A
/// is a KEM encapsulation to that same key and yields a shared secret rather than
/// an identity, so the identity travels beside it — sealed under that shared
/// secret, which both ends can compute before the peer is known.
///
/// The admission gate (`mac1`/`mac2`) should run **before** this: it is cheap,
/// whereas this decapsulates op A.
///
/// # Errors
///
/// [`HandshakeError::WrongMessageType`] / [`HandshakeError::SuiteMismatch`] on a
/// message that is not an `InitHello` for this suite, [`HandshakeError::Wire`]
/// on a missing or mis-sized field (including a missing hint — stripping it is
/// not a way to skip the check), [`HandshakeError::Kem`] if op A fails, or
/// [`HandshakeError::Aead`] if the hint does not unseal.
pub fn responder_identify(
    suite: &dyn CryptoSuite,
    identity: &StaticIdentity,
    init_hello: &[u8],
) -> Result<InitHelloInfo, HandshakeError> {
    let suite_id = suite.suite_id();
    let message = Message::parse(init_hello)?;
    message.expect_type(MessageType::InitHello)?;
    message.expect_suite(suite_id)?;

    let static_ct = message.require(tag::STATIC_CT)?;
    let ephemeral_pk = message.require(tag::EPHEMERAL_PK)?;
    let timestamp = message.require_array::<TIMESTAMP_SIZE>(tag::TIMESTAMP)?;
    let sealed_hint = message.require(tag::PEER_HINT)?;

    let expected_len = PEER_HINT_SIZE + suite.sizes().aead_tag;
    if sealed_hint.len() != expected_len {
        return Err(HandshakeError::Wire(format!(
            "peer hint is {} bytes, expected {expected_len}",
            sealed_hint.len()
        )));
    }

    // Op A: recover our share by decapsulating the initiator's static ciphertext.
    // Our own static secret is all this needs, which is exactly why the hint can
    // be read on a message from an unidentified sender.
    let static_legs = suite
        .kem_decaps(identity.secret(), static_ct)
        .map_err(HandshakeError::Kem)?;

    let (hint_key, hint_nonce) = hint_crypt(suite, &static_legs)?;
    let header = MessageHeader {
        version: PROTOCOL_VERSION,
        message_type: MessageType::InitHello,
        suite_id,
        sender_index: message.sender_index(),
    };
    let plain = suite.aead_open(&hint_key, &hint_nonce, &header.encode(), sealed_hint)?;
    let peer_hint = <[u8; PEER_HINT_SIZE]>::try_from(plain.as_slice()).map_err(|_| {
        HandshakeError::Wire(format!("unsealed peer hint is {} bytes", plain.len()))
    })?;

    Ok(InitHelloInfo {
        suite_id,
        sender_index: message.sender_index(),
        timestamp,
        ephemeral_public: KemPublicKey::new(ephemeral_pk.to_vec()),
        static_ct: static_ct.to_vec(),
        peer_hint,
        static_legs,
    })
}

/// Step 2b (responder): build `RespHello` for a **resolved** peer, retain state.
///
/// `RespHello` carries the responder's **confirmation value** (`conf_r`), which
/// proves to the initiator that this responder holds `σ_r`. It is derived from
/// the Op A decapsulation already done in [`responder_identify`].
///
/// `peer` is the initiator's identity *as resolved by the caller*. The hint in
/// `info` is checked against it, so a caller whose lookup and whose hint
/// disagree is told ([`HandshakeError::PeerHintMismatch`]) rather than
/// completing a session under a peer the initiator did not name.
///
/// # Errors
///
/// [`HandshakeError::PeerHintMismatch`] if `info` names another peer,
/// [`HandshakeError::Kem`] / [`HandshakeError::Kdf`] / [`HandshakeError::Sign`]
/// if a crypto operation fails, or [`HandshakeError::Wire`] if `RespHello`
/// cannot be framed.
pub fn responder_accept(
    suite: &dyn CryptoSuite,
    identity: &StaticIdentity,
    peer: &PeerIdentity,
    info: &InitHelloInfo,
    sender_index: u32,
    handshake_seed: &[u8; 32],
) -> Result<(Vec<u8>, ResponderState), HandshakeError> {
    let suite_id = suite.suite_id();
    let peer_public = peer.kem();

    // The hint is confidential, not authenticated, so it is *checked* rather
    // than trusted: it must name the peer the caller resolved.
    if info.peer_hint != peer_hint(suite, peer_public) {
        return Err(HandshakeError::PeerHintMismatch);
    }

    // Op B: responder → initiator ephemeral, plain fresh randomness (the
    // ephemeral key is itself fresh, so MEX has nothing to add).
    let b_fresh = derive_seed(suite, handshake_seed, B_FRESH_INFO)?;
    let b = suite
        .kem_encaps(&info.ephemeral_public, &b_fresh)
        .map_err(HandshakeError::Kem)?;

    // Op C: responder → initiator static, MEX-bound to our own static secret.
    let c_fresh = derive_seed(suite, handshake_seed, C_FRESH_INFO)?;
    let c_randomness = mex_randomness(suite, identity.secret(), &c_fresh)?;
    let c = suite
        .kem_encaps(peer_public, &c_randomness)
        .map_err(HandshakeError::Kem)?;

    let header = MessageHeader {
        version: PROTOCOL_VERSION,
        message_type: MessageType::RespHello,
        suite_id,
        sender_index,
    };

    let mut legs = info.static_legs.clone();
    legs.extend_from_slice(&b.shared_secrets);
    legs.extend_from_slice(&c.shared_secrets);

    // Transcript stages 1 and 2. Stage 2 covers exactly the fields above (the
    // RespHello core), because the responder's own confirmation is derived from
    // it and so cannot yet be part of it.
    let transcript_init = transcript_init(
        suite,
        suite_id,
        info.sender_index,
        info.ephemeral_public.as_bytes(),
        &info.static_ct,
        &info.timestamp,
    );
    let transcript_resp = transcript_resp(
        suite,
        suite_id,
        &transcript_init,
        sender_index,
        b.ciphertext.as_bytes(),
        c.ciphertext.as_bytes(),
    );

    // Op order in the combiner is A ‖ B ‖ C on both sides.
    let (key, confirm_responder) = schedule(
        suite,
        &transcript_resp,
        &legs,
        peer_public.as_bytes(),
        identity.public().as_bytes(),
        peer.preshared_key(),
    )?;

    // The confirmation goes in RespHello itself, so the initiator authenticates
    // us before it accepts the session (PQ-WireGuard's `zero`).
    let mut builder = MessageBuilder::new(header);
    builder.field(tag::EPHEMERAL_CT, b.ciphertext.as_bytes())?;
    builder.field(tag::STATIC_CT, c.ciphertext.as_bytes())?;
    builder.field(tag::RECEIVER_INDEX, &info.sender_index.to_be_bytes())?;
    builder.field(tag::CONFIRMATION, confirm_responder.as_bytes())?;
    // P3: our hybrid identity signature over TR. Present exactly when we hold a
    // signing identity — a peer that requires one rejects its absence.
    if let Some(signing) = identity.signing() {
        let signature = sign_transcript(
            suite,
            signing,
            IDENTITY_RESP_DOMAIN,
            suite_id,
            &transcript_resp,
        )?;
        builder.field(tag::IDENTITY_SIG, &signature)?;
    }
    // P6.8: the op-A-keyed admission tag, emitted last so it covers every other
    // field — including the optional signature. The initiator checks it before
    // decapsulating ops B and C, so a forged `RespHello` costs one KDF.
    let tag_key = derive_resp_tag_key(suite, &info.static_legs)?;
    let pre_tag = resp_tag(suite, &tag_key, &builder.resp_tag_input())?;
    builder.field(tag::PRE_TAG, &pre_tag)?;
    let resp_hello = builder.finish()?;

    // Stage 3 and the initiator's confirmation, which commits to conf_r.
    let transcript_conf = transcript_conf(
        suite,
        suite_id,
        &transcript_resp,
        confirm_responder.as_bytes(),
    );
    let confirm_initiator = confirm_initiator(suite, &key, &transcript_conf)?;

    let keys = SessionKeys {
        transcript: transcript_resp,
        key,
        confirm_initiator,
        confirm_responder,
        own_index: sender_index,
        peer_index: info.sender_index,
    };

    let state = ResponderState {
        suite_id,
        sender_index,
        peer_index: info.sender_index,
        resp_hello: resp_hello.clone(),
        timestamp: info.timestamp,
        peer_signing: peer.signing().cloned(),
        keys,
    };
    Ok((resp_hello, state))
}

/// Step 2, single-peer: [`responder_identify`], then [`responder_accept`].
///
/// For a responder that already knows who it is talking to — a two-party
/// deployment, or a transport that has resolved the source address and only
/// needs the hint to be *consistent* with it. A responder with several peers
/// should call the two phases itself and resolve [`InitHelloInfo::peer_hint`]
/// against its peer table, which needs no extra machinery: this function is
/// exactly those two steps.
///
/// # Errors
///
/// As [`responder_identify`] and [`responder_accept`].
pub fn responder_process_init(
    suite: &dyn CryptoSuite,
    identity: &StaticIdentity,
    peer: &PeerIdentity,
    init_hello: &[u8],
    sender_index: u32,
    handshake_seed: &[u8; 32],
) -> Result<(Vec<u8>, ResponderState), HandshakeError> {
    let info = responder_identify(suite, identity, init_hello)?;
    responder_accept(suite, identity, peer, &info, sender_index, handshake_seed)
}

/// Step 3 (initiator): consume `RespHello`, verify the responder, derive keys,
/// build `InitConf`.
///
/// Returns [`HandshakeError::Confirmation`] if the responder's confirmation
/// value in `RespHello` does not verify — i.e. the peer does not hold `σ_r`.
/// Nothing is accepted before that check passes.
///
/// # Errors
///
/// [`HandshakeError::Wire`] on a malformed or unexpected message,
/// [`HandshakeError::Confirmation`] if the responder did not prove the key, or
/// [`HandshakeError::Kem`] / [`HandshakeError::Kdf`] if a crypto operation
/// fails.
pub fn initiator_process_resp(
    suite: &dyn CryptoSuite,
    state: InitiatorState,
    identity: &StaticIdentity,
    resp_hello: &[u8],
) -> Result<(Vec<u8>, SessionKeys), HandshakeError> {
    let message = Message::parse(resp_hello)?;
    message.expect_type(MessageType::RespHello)?;
    message.expect_suite(state.suite_id)?;
    message.expect_receiver_index(state.sender_index)?;

    let ephemeral_ct = message.require(tag::EPHEMERAL_CT)?;
    let static_ct = message.require(tag::STATIC_CT)?;
    let peer_confirmation = message.require_array::<CONFIRMATION_SIZE>(tag::CONFIRMATION)?;

    // P6.8: the admission tag, checked *before* any decapsulation. Deriving op
    // A's key required the responder to decapsulate our `InitHello`, so only a
    // holder of σ_r can produce this tag. An attacker who observed our
    // `InitHello` knows our index and can forge a `RespHello`, but that forgery
    // now costs one KDF instead of two hybrid decapsulations. The tag is an
    // admission token only: `conf_r` below is still what authenticates the
    // session.
    let tag_key = state.resp_tag_key(suite)?;
    let expected_tag = resp_tag(suite, &tag_key, &message.resp_tag_input())?;
    let got_tag = message.require_array::<RESP_TAG_SIZE>(tag::PRE_TAG)?;
    if !verify_value(suite, &expected_tag, &got_tag) {
        return Err(HandshakeError::RespTag);
    }

    // Op B: only our ephemeral secret recovers this — the forward-secret leg.
    let b_legs = suite
        .kem_decaps(&state.ephemeral_secret, ephemeral_ct)
        .map_err(HandshakeError::Kem)?;

    // Op C: only our static secret recovers this — the leg that authenticates us.
    let c_legs = suite
        .kem_decaps(identity.secret(), static_ct)
        .map_err(HandshakeError::Kem)?;

    let mut legs = state.static_legs;
    legs.extend_from_slice(&b_legs);
    legs.extend_from_slice(&c_legs);

    let transcript_init = transcript_init(
        suite,
        state.suite_id,
        state.sender_index,
        state.ephemeral_public.as_bytes(),
        &state.static_ct,
        &state.timestamp,
    );
    let transcript_resp = transcript_resp(
        suite,
        state.suite_id,
        &transcript_init,
        message.sender_index(),
        ephemeral_ct,
        static_ct,
    );

    let (key, confirm_responder) = schedule(
        suite,
        &transcript_resp,
        &legs,
        &state.static_public,
        &state.peer_public,
        state.psk.as_ref(),
    )?;

    // Authenticate the responder *before* accepting the session key: only a party
    // holding σ_r can have decapsulated op A and so derived `key`. Without this
    // check the initiator would accept a key from an unauthenticated RespHello —
    // exactly the gap that made WireGuard unprovable in eCK-PFS-PSK.
    if !verify_confirmation(suite, &confirm_responder, &peer_confirmation) {
        return Err(HandshakeError::Confirmation);
    }

    // P3: the responder's identity signature over TR. Fail closed on absence
    // (when configured) and on an unexpected signature; see
    // [`check_identity_signature`].
    check_identity_signature(
        suite,
        state.suite_id,
        IDENTITY_RESP_DOMAIN,
        &transcript_resp,
        state.peer_signing.as_ref(),
        message.get(tag::IDENTITY_SIG),
    )?;

    let transcript_conf = transcript_conf(
        suite,
        state.suite_id,
        &transcript_resp,
        confirm_responder.as_bytes(),
    );
    let confirm_initiator = confirm_initiator(suite, &key, &transcript_conf)?;

    let keys = SessionKeys {
        transcript: transcript_resp,
        key,
        confirm_initiator,
        confirm_responder,
        own_index: state.sender_index,
        peer_index: message.sender_index(),
    };

    let header = MessageHeader {
        version: PROTOCOL_VERSION,
        message_type: MessageType::InitConf,
        suite_id: state.suite_id,
        sender_index: state.sender_index,
    };
    let mut builder = MessageBuilder::new(header);
    builder.field(tag::CONFIRMATION, keys.confirm_initiator.as_bytes())?;
    builder.field(tag::RECEIVER_INDEX, &message.sender_index().to_be_bytes())?;
    // P3: our hybrid identity signature over the same TR the responder signed,
    // under the initiator's domain label. The responder requires it when it has
    // an initiator signing key configured.
    if let Some(signing) = identity.signing() {
        let signature = sign_transcript(
            suite,
            signing,
            IDENTITY_INIT_DOMAIN,
            state.suite_id,
            &transcript_resp,
        )?;
        builder.field(tag::IDENTITY_SIG, &signature)?;
    }
    let init_conf = builder.finish()?;

    Ok((init_conf, keys))
}

/// Step 4 (responder): verify `InitConf` and release the session keys.
///
/// # Errors
///
/// [`HandshakeError::Confirmation`] if the initiator did not prove the key, or
/// [`HandshakeError::Wire`] on a malformed or unexpected message.
pub fn responder_process_conf(
    suite: &dyn CryptoSuite,
    state: ResponderState,
    init_conf: &[u8],
) -> Result<SessionKeys, HandshakeError> {
    let message = Message::parse(init_conf)?;
    message.expect_type(MessageType::InitConf)?;
    message.expect_suite(state.suite_id)?;
    message.expect_receiver_index(state.sender_index)?;

    let confirmation = message.require_array::<CONFIRMATION_SIZE>(tag::CONFIRMATION)?;

    if !verify_confirmation(suite, &state.keys.confirm_initiator, &confirmation) {
        return Err(HandshakeError::Confirmation);
    }

    // P3: the initiator's identity signature over TR (the same value the
    // responder signed). Only reached once the initiator has proven the key.
    check_identity_signature(
        suite,
        state.suite_id,
        IDENTITY_INIT_DOMAIN,
        &state.keys.transcript,
        state.peer_signing.as_ref(),
        message.get(tag::IDENTITY_SIG),
    )?;

    Ok(state.keys)
}
