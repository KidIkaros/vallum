// SPDX-License-Identifier: Apache-2.0

//! # vallum-core
//!
//! Vallum's handshake core: self-describing TLV framing ([`wire`]) and the
//! three-message hybrid-KEM authenticated key exchange ([`handshake`]).
//!
//! This crate depends on [`vallum_crypto`] **only** — no provider, no SDK, no
//! RNG crate. Randomness enters as caller-supplied seeds, which is what makes
//! the handshake byte-exact and what keeps the crypto boundary narrow enough to
//! survive having the implementation swapped underneath it.
//!
//! ## Handshake at a glance
//!
//! ```text
//! Initiator                                              Responder
//! ─────────                                              ─────────
//! InitHello    ── STATIC_CT (A), EPHEMERAL_PK, TIMESTAMP ──▶   [static key]
//!              ◀── EPHEMERAL_CT (B), STATIC_CT (C),
//!                  CONFIRMATION (conf_r), IDENTITY_SIG ────    RespHello
//! InitConf     ── CONFIRMATION (conf_i), IDENTITY_SIG ───▶      [verify]
//! ```
//!
//! | op | direction | peer key | purpose |
//! |----|-----------|----------|---------|
//! | A | init → resp | responder **static** | responder authentication |
//! | B | resp → init | initiator **ephemeral** | forward secrecy |
//! | C | resp → init | initiator **static** | initiator authentication |
//!
//! Both static encapsulations (A and C) are **MEX-bound**: their randomness is
//! derived from fresh handshake entropy *and* the sender's static secret, so a
//! subverted RNG cannot fix the resulting key (PQ-WireGuard's dual-PRF fix).
//!
//! Confirmation is **mutual and explicit**: the responder proves key possession
//! in `RespHello`, the initiator in `InitConf`. Neither party accepts a key
//! before authenticating the other. See `docs/proof/eck-pfs-psk.md`.
//!
//! ## Key schedule
//!
//! ```text
//! TR1  = H("vallum/tr/init", suite_id ‖ sid_i ‖ epk_i ‖ ct_A ‖ timestamp)
//! TR   = H("vallum/tr/resp", suite_id ‖ TR1 ‖ sid_r ‖ ct_B ‖ ct_C)
//! ROOT = KDF(salt = TR,  ikm = ss_A ‖ ss_B ‖ ss_C, info = "vallum/kem/v1")
//! PSK  = H("vallum/psk/v1", frame([spk_i, spk_r]))          // UKS mitigation
//! KEY  = KDF(salt = ROOT, ikm = PSK, info = "vallum/psk-mix/v1")
//! conf_r = KDF(salt = KEY, ikm = TR,   info = "vallum/confirm/resp/v1")
//! TR2    = H("vallum/tr/conf", suite_id ‖ TR ‖ conf_r)
//! conf_i = KDF(salt = KEY, ikm = TR2,  info = "vallum/confirm/init/v1")
//! ```
//!
//! The transcript is staged because `conf_r` is inside `RespHello`: the responder
//! must hash `RespHello`'s core fields *before* its own confirmation exists, and
//! the initiator's confirmation commits to the transcript that includes `conf_r`.
//! This mirrors PQ-WireGuard's running hash chain (`H10 = H(H9 ‖ zero)`).
//!
//! `KEY` is the handshake root the data plane expands; P1 freezes it.
//! Every concatenation is length-framed, so it is unambiguous.
//!
//! ## Identity (P3)
//!
//! [`identity`] adds the transferable half of authentication: a hybrid
//! Ed25519 + Falcon-1024 signature over `TR`, carried in `RespHello` and
//! `InitConf`, plus an issuer-signed identity document that binds a KEM key to a
//! signing key. See `docs/proof/hybrid-identity.md`.
//!
//! ## Data plane (P2)
//!
//! [`keys`] expands `KEY` into a directional AEAD key and nonce prefix per
//! epoch; [`data`] seals and opens transport packets with the header and counter
//! as associated data; [`replay`] drops duplicates from an authenticated sliding
//! window; [`cookie`] supplies the `mac1`/`mac2` anti-flood layer; [`timestamp`]
//! guards against a replayed handshake; [`timer`] bounds a key's lifetime.
//! See `docs/proof/committing-aead-multikey.md`.

#![forbid(unsafe_code)]

pub mod cookie;
pub mod data;
pub mod error;
pub mod handshake;
pub mod identity;
pub mod keys;
pub mod replay;
pub mod timer;
pub mod timestamp;
pub mod wire;

pub use data::{
    establish, establish_epoch, Receiver, Sender, REJECT_AFTER_MESSAGES, REKEY_AFTER_MESSAGES,
};
pub use error::{DataError, HandshakeError};
pub use handshake::{
    initiator_hello, initiator_process_resp, responder_process_conf, responder_process_init,
    InitiatorState, ResponderState, SessionKeys,
};
pub use identity::{IdentityDocument, PeerIdentity, SigningIdentity, StaticIdentity};
pub use keys::{DataKeys, Role, COUNTER_SIZE, DATA_KEY_SIZE, NONCE_PREFIX_SIZE, NONCE_SIZE};
pub use replay::{ReplayFilter, REPLAY_WINDOW};
pub use timer::{TimerAction, Timers};
pub use timestamp::{Tai64n, Tai64nGuard, TimestampError};
pub use wire::{
    Message, MessageBuilder, MessageHeader, MessageType, MAX_DATA_MESSAGE, MAX_HANDSHAKE_MESSAGE,
    PROTOCOL_VERSION,
};

/// Best-effort memory scrub the optimizer is unlikely to elide.
///
/// The same construction as `vallum-crypto`'s internal helper, kept local
/// because that one is crate-private.
pub(crate) fn scrub(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        *byte = 0;
    }
    core::hint::black_box(buf);
}
