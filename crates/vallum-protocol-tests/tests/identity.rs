// SPDX-License-Identifier: Apache-2.0

//! P3 gate tests: hybrid identity signatures over the handshake transcript.
//!
//! The gate is "both must verify" plus the identity-document round-trip. The
//! primitive-level half of "both must verify" is pinned by the byte sweep in
//! `vallum-crypto-contract`; the tests here pin the *protocol* half:
//!
//! 1. **Positive** — signed peers complete, the signature is over `TR`, and the
//!    two roles' signatures are distinct and correctly domain-separated.
//! 2. **Signature field shape** — the added bytes are exactly one TLV field per
//!    message, so the unsigned path is byte-identical to P1.
//! 3. **Fail-closed negatives** — absence when required, presence when
//!    unexpected, a forged signature, a wrong-role signature, and a replayed
//!    signature from another session are each rejected.
//! 4. **Identity documents** — a CA-issued document configures a peer, and a
//!    document from the wrong issuer does not.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use vallum_core::wire::{tag, Message, MessageBuilder};
use vallum_core::{
    initiator_hello, initiator_process_resp, resp_tag, responder_process_conf,
    responder_process_init, HandshakeError, IdentityDocument, PeerIdentity, SessionKeys,
    StaticIdentity, Validity, RESP_TAG_SIZE,
};
use vallum_crypto::CryptoSuite;
use vallum_crypto_sdk::SdkSuite;

const TS: [u8; 12] = [
    0x40, 0x00, 0x00, 0x00, 0x67, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78,
];
const I_IDX: u32 = 0x1111_1111;
const R_IDX: u32 = 0x2222_2222;

/// The frozen domain labels the protocol signs under. Spelling them out here
/// (rather than importing them) is deliberate: if a future edit moves the
/// binding, this test fails rather than silently following.
const RESP_DOMAIN: &[u8] = b"vallum/identity/resp/v1";
const INIT_DOMAIN: &[u8] = b"vallum/identity/init/v1";

/// A wide window around `NOW`, so these tests are not clock-dependent.
const VALIDITY: Validity = Validity {
    not_before: 1_000,
    not_after: 4_000_000_000,
};
const NOW: u64 = 2_000;

/// A KEM + hybrid-signature identity.
fn identity(suite: &SdkSuite, seed: &[u8; 32]) -> StaticIdentity {
    StaticIdentity::generate_with_signing(suite, seed).expect("identity")
}

/// A KEM-only identity (P1 semantics: no signature).
fn kem_identity(suite: &SdkSuite, seed: &[u8; 32]) -> StaticIdentity {
    StaticIdentity::generate(suite, seed).expect("identity")
}

/// The exact bytes a signature covers, reconstructed from the public constants.
fn signature_input(domain: &[u8], suite_id: u16, pk: &[u8], transcript: &[u8]) -> Vec<u8> {
    vallum_crypto::frame(&[domain, &suite_id.to_be_bytes(), pk, transcript])
}

fn field(bytes: &[u8], tag: u16) -> Option<Vec<u8>> {
    Message::parse(bytes)
        .expect("parse")
        .get(tag)
        .map(<[u8]>::to_vec)
}

/// Rebuild a message without one field, preserving the header and the rest.
fn without_field(bytes: &[u8], drop: u16) -> Vec<u8> {
    let message = Message::parse(bytes).expect("parse");
    let mut builder = MessageBuilder::new(message.header());
    for t in message.tags() {
        if t == drop {
            continue;
        }
        builder
            .field(t, message.get(t).expect("field"))
            .expect("field");
    }
    builder.finish().expect("finish")
}

/// Rebuild a message with one field replaced (or appended, if absent).
fn with_field(bytes: &[u8], tag: u16, value: &[u8]) -> Vec<u8> {
    let message = Message::parse(bytes).expect("parse");
    let mut builder = MessageBuilder::new(message.header());
    let mut replaced = false;
    for t in message.tags() {
        if t == tag {
            builder.field(t, value).expect("field");
            replaced = true;
        } else {
            builder
                .field(t, message.get(t).expect("field"))
                .expect("field");
        }
    }
    if !replaced {
        builder.field(tag, value).expect("field");
    }
    builder.finish().expect("finish")
}

/// Flip one bit in a message field, in place.
fn flip_field_bit(bytes: &[u8], tag: u16, index: usize) -> Vec<u8> {
    let mut value = field(bytes, tag).expect("field present");
    value[index] ^= 1;
    with_field(bytes, tag, &value)
}

/// Re-seal a mutated `RespHello`'s op-A admission tag (P6.8).
///
/// These tests mutate the message to exercise the *identity* layer, which runs
/// after the tag. Without re-sealing, the mutation would be rejected by the tag
/// first and the identity rule would go untested — a correct rejection, but the
/// wrong one for what the test claims.
fn retag(suite: &SdkSuite, key: &[u8; RESP_TAG_SIZE], bytes: &[u8]) -> Vec<u8> {
    let message = Message::parse(bytes).expect("parse");
    let tag_value = resp_tag(suite, key, &message.resp_tag_input()).expect("tag");
    let mut builder = MessageBuilder::new(message.header());
    for t in message.tags() {
        if t != tag::PRE_TAG {
            builder
                .field(t, message.get(t).expect("field"))
                .expect("field");
        }
    }
    builder.field(tag::PRE_TAG, &tag_value).expect("field");
    builder.finish().expect("finish")
}

/// A complete four-step exchange, returning every message and both key sets.
struct Run {
    init_hello: Vec<u8>,
    resp_hello: Vec<u8>,
    init_conf: Vec<u8>,
    init_keys: SessionKeys,
    resp_keys: SessionKeys,
}

/// Assert that two endpoints derived the same session.
///
/// The indices are the one thing that must *not* match — each end's own index is
/// the other's peer index — so they are compared mirrored rather than equal.
fn keys_agree(a: &SessionKeys, b: &SessionKeys) {
    assert_eq!(a.transcript, b.transcript, "transcript");
    assert_eq!(a.key.as_bytes(), b.key.as_bytes(), "key");
    assert_eq!(
        a.confirm_initiator.as_bytes(),
        b.confirm_initiator.as_bytes(),
        "conf_i"
    );
    assert_eq!(
        a.confirm_responder.as_bytes(),
        b.confirm_responder.as_bytes(),
        "conf_r"
    );
    assert_eq!(a.own_index, b.peer_index, "index mirror");
    assert_eq!(a.peer_index, b.own_index, "index mirror");
}

fn full(
    suite: &SdkSuite,
    initiator: &StaticIdentity,
    responder: &StaticIdentity,
    init_seed: [u8; 32],
    resp_seed: [u8; 32],
) -> Run {
    let peer_r = PeerIdentity::from_identity(responder);
    let peer_i = PeerIdentity::from_identity(initiator);

    let (init_hello, i_state) =
        initiator_hello(suite, initiator, &peer_r, I_IDX, TS, &init_seed).expect("InitHello");
    let (resp_hello, r_state) =
        responder_process_init(suite, responder, &peer_i, &init_hello, R_IDX, &resp_seed)
            .expect("RespHello");
    let (init_conf, init_keys) =
        initiator_process_resp(suite, i_state, initiator, &resp_hello).expect("InitConf");
    let resp_keys = responder_process_conf(suite, r_state, &init_conf).expect("verify InitConf");

    Run {
        init_hello,
        resp_hello,
        init_conf,
        init_keys,
        resp_keys,
    }
}

// ── positive ─────────────────────────────────────────────────────────

#[test]
fn signed_peers_complete_and_the_signatures_cover_the_transcript() {
    let suite = SdkSuite::tri_hybrid();
    let initiator = identity(&suite, &[0x11u8; 32]);
    let responder = identity(&suite, &[0x22u8; 32]);
    let run = full(&suite, &initiator, &responder, [0xA1u8; 32], [0xB1u8; 32]);

    keys_agree(&run.init_keys, &run.resp_keys);
    let tr = run.init_keys.transcript;
    let r_pk = responder.signing_public().unwrap();
    let i_pk = initiator.signing_public().unwrap();
    let r_sig = field(&run.resp_hello, tag::IDENTITY_SIG).expect("responder signature");
    let i_sig = field(&run.init_conf, tag::IDENTITY_SIG).expect("initiator signature");

    // Each signature verifies against the *peer's* key over the agreed TR, with
    // the role's own domain label.
    assert!(suite.verify(
        r_pk,
        &signature_input(RESP_DOMAIN, suite.suite_id(), r_pk.as_bytes(), &tr),
        &r_sig
    ));
    assert!(suite.verify(
        i_pk,
        &signature_input(INIT_DOMAIN, suite.suite_id(), i_pk.as_bytes(), &tr),
        &i_sig
    ));

    // The two are distinct — role domain separation, not a shared statement.
    assert_ne!(r_sig, i_sig);

    // And each is bound to *this* transcript: the same bytes do not verify over
    // a different one, nor under the other role's domain.
    let mut other_tr = tr;
    other_tr[0] ^= 1;
    assert!(!suite.verify(
        r_pk,
        &signature_input(RESP_DOMAIN, suite.suite_id(), r_pk.as_bytes(), &other_tr),
        &r_sig
    ));
    assert!(!suite.verify(
        r_pk,
        &signature_input(INIT_DOMAIN, suite.suite_id(), r_pk.as_bytes(), &tr),
        &r_sig
    ));
    assert!(!suite.verify(
        r_pk,
        &signature_input(RESP_DOMAIN, suite.suite_id(), i_pk.as_bytes(), &tr),
        &r_sig
    ));
}

#[test]
fn unsigned_peers_still_complete_with_no_signature_fields() {
    let suite = SdkSuite::tri_hybrid();
    let initiator = kem_identity(&suite, &[0x31u8; 32]);
    let responder = kem_identity(&suite, &[0x32u8; 32]);
    let run = full(&suite, &initiator, &responder, [0xC1u8; 32], [0xD1u8; 32]);

    keys_agree(&run.init_keys, &run.resp_keys);
    assert!(field(&run.resp_hello, tag::IDENTITY_SIG).is_none());
    assert!(field(&run.init_conf, tag::IDENTITY_SIG).is_none());
}

// ── the cost of the signature field ──────────────────────────────────

#[test]
fn a_signature_adds_exactly_one_field_per_message() {
    let suite = SdkSuite::tri_hybrid();

    let plain_i = kem_identity(&suite, &[0x41u8; 32]);
    let plain_r = kem_identity(&suite, &[0x42u8; 32]);
    let plain = full(&suite, &plain_i, &plain_r, [0xE1u8; 32], [0xF1u8; 32]);

    let signed_i = identity(&suite, &[0x11u8; 32]);
    let signed_r = identity(&suite, &[0x22u8; 32]);
    let signed = full(&suite, &signed_i, &signed_r, [0xE1u8; 32], [0xF1u8; 32]);

    let r_sig = field(&signed.resp_hello, tag::IDENTITY_SIG).unwrap();
    let i_sig = field(&signed.init_conf, tag::IDENTITY_SIG).unwrap();

    // InitHello is untouched: the initiator's signature rides in InitConf.
    assert_eq!(signed.init_hello.len(), plain.init_hello.len());
    // Each of RespHello and InitConf grows by exactly `tag u16 | len u16 | sig`.
    assert_eq!(
        signed.resp_hello.len(),
        plain.resp_hello.len() + 4 + r_sig.len()
    );
    assert_eq!(
        signed.init_conf.len(),
        plain.init_conf.len() + 4 + i_sig.len()
    );

    println!(
        "P3 wire cost (tri-hybrid): InitHello {}  RespHello {} -> {} (+{})  InitConf {} -> {} (+{})",
        plain.init_hello.len(),
        plain.resp_hello.len(),
        signed.resp_hello.len(),
        4 + r_sig.len(),
        plain.init_conf.len(),
        signed.init_conf.len(),
        4 + i_sig.len(),
    );
}

// ── fail-closed negatives ────────────────────────────────────────────

#[test]
fn a_stripped_responder_signature_is_rejected() {
    let suite = SdkSuite::tri_hybrid();
    let initiator = identity(&suite, &[0x11u8; 32]);
    let responder = identity(&suite, &[0x22u8; 32]);

    let (init_hello, i_state) = initiator_hello(
        &suite,
        &initiator,
        &PeerIdentity::from_identity(&responder),
        I_IDX,
        TS,
        &[0xA1u8; 32],
    )
    .unwrap();
    let (resp_hello, _) = responder_process_init(
        &suite,
        &responder,
        &PeerIdentity::from_identity(&initiator),
        &init_hello,
        R_IDX,
        &[0xB1u8; 32],
    )
    .unwrap();

    // Re-seal the admission tag: the mutation targets the identity rule, which
    // runs after the tag, and the tag itself must not be the thing that rejects.
    let key = i_state.resp_tag_key(&suite).unwrap();
    let stripped = retag(&suite, &key, &without_field(&resp_hello, tag::IDENTITY_SIG));
    assert!(matches!(
        initiator_process_resp(&suite, i_state, &initiator, &stripped),
        Err(HandshakeError::IdentityMissing)
    ));
}

#[test]
fn a_stripped_initiator_signature_is_rejected() {
    let suite = SdkSuite::tri_hybrid();
    let initiator = identity(&suite, &[0x11u8; 32]);
    let responder = identity(&suite, &[0x22u8; 32]);

    let (init_hello, i_state) = initiator_hello(
        &suite,
        &initiator,
        &PeerIdentity::from_identity(&responder),
        I_IDX,
        TS,
        &[0xA1u8; 32],
    )
    .unwrap();
    let (resp_hello, r_state) = responder_process_init(
        &suite,
        &responder,
        &PeerIdentity::from_identity(&initiator),
        &init_hello,
        R_IDX,
        &[0xB1u8; 32],
    )
    .unwrap();
    let (init_conf, _) = initiator_process_resp(&suite, i_state, &initiator, &resp_hello).unwrap();

    let stripped = without_field(&init_conf, tag::IDENTITY_SIG);
    assert!(matches!(
        responder_process_conf(&suite, r_state, &stripped),
        Err(HandshakeError::IdentityMissing)
    ));
}

#[test]
fn a_forged_responder_signature_is_rejected() {
    let suite = SdkSuite::tri_hybrid();
    let initiator = identity(&suite, &[0x11u8; 32]);
    let responder = identity(&suite, &[0x22u8; 32]);

    let (init_hello, i_state) = initiator_hello(
        &suite,
        &initiator,
        &PeerIdentity::from_identity(&responder),
        I_IDX,
        TS,
        &[0xA1u8; 32],
    )
    .unwrap();
    let (resp_hello, _) = responder_process_init(
        &suite,
        &responder,
        &PeerIdentity::from_identity(&initiator),
        &init_hello,
        R_IDX,
        &[0xB1u8; 32],
    )
    .unwrap();

    // Flip the last byte — inside the Falcon half of the encoded signature —
    // then re-seal the admission tag so the identity rule is what rejects.
    let key = i_state.resp_tag_key(&suite).unwrap();
    let forged = retag(
        &suite,
        &key,
        &flip_field_bit(&resp_hello, tag::IDENTITY_SIG, {
            field(&resp_hello, tag::IDENTITY_SIG).unwrap().len() - 1
        }),
    );
    assert!(matches!(
        initiator_process_resp(&suite, i_state, &initiator, &forged),
        Err(HandshakeError::IdentityInvalid)
    ));
}

/// The P6.8 admission tag covers the signature field too: mutating a captured
/// `RespHello`'s signature without re-sealing fails at the tag, so a signed
/// session cannot be made to spend two decapsulations on a mutated message.
#[test]
fn a_mutated_signature_fails_the_admission_tag() {
    let suite = SdkSuite::tri_hybrid();
    let initiator = identity(&suite, &[0x11u8; 32]);
    let responder = identity(&suite, &[0x22u8; 32]);

    let (init_hello, i_state) = initiator_hello(
        &suite,
        &initiator,
        &PeerIdentity::from_identity(&responder),
        I_IDX,
        TS,
        &[0xA1u8; 32],
    )
    .unwrap();
    let (resp_hello, _) = responder_process_init(
        &suite,
        &responder,
        &PeerIdentity::from_identity(&initiator),
        &init_hello,
        R_IDX,
        &[0xB1u8; 32],
    )
    .unwrap();

    let forged = flip_field_bit(&resp_hello, tag::IDENTITY_SIG, {
        field(&resp_hello, tag::IDENTITY_SIG).unwrap().len() - 1
    });
    assert!(matches!(
        initiator_process_resp(&suite, i_state, &initiator, &forged),
        Err(HandshakeError::RespTag)
    ));
}

#[test]
fn an_unexpected_signature_is_rejected_in_both_directions() {
    let suite = SdkSuite::tri_hybrid();
    let initiator = identity(&suite, &[0x11u8; 32]);
    let responder = identity(&suite, &[0x22u8; 32]);

    // The initiator is configured with only the responder's KEM key, so the
    // responder's signature is unexpected and the run fails closed.
    let (init_hello, i_state) = initiator_hello(
        &suite,
        &initiator,
        &PeerIdentity::kem_only(responder.public().clone()),
        I_IDX,
        TS,
        &[0xA1u8; 32],
    )
    .unwrap();
    let (resp_hello, _r_state) = responder_process_init(
        &suite,
        &responder,
        &PeerIdentity::from_identity(&initiator),
        &init_hello,
        R_IDX,
        &[0xB1u8; 32],
    )
    .unwrap();
    assert!(matches!(
        initiator_process_resp(&suite, i_state, &initiator, &resp_hello),
        Err(HandshakeError::IdentityUnexpected)
    ));

    // Symmetric: the responder knows only the initiator's KEM key, but the
    // initiator signs in InitConf.
    let (init_hello, i_state) = initiator_hello(
        &suite,
        &initiator,
        &PeerIdentity::from_identity(&responder),
        I_IDX,
        TS,
        &[0xA1u8; 32],
    )
    .unwrap();
    let (resp_hello, r_state) = responder_process_init(
        &suite,
        &responder,
        &PeerIdentity::kem_only(initiator.public().clone()),
        &init_hello,
        R_IDX,
        &[0xB1u8; 32],
    )
    .unwrap();
    let (init_conf, _) = initiator_process_resp(&suite, i_state, &initiator, &resp_hello).unwrap();
    assert!(matches!(
        responder_process_conf(&suite, r_state, &init_conf),
        Err(HandshakeError::IdentityUnexpected)
    ));
}

#[test]
fn a_signature_is_bound_to_its_role() {
    let suite = SdkSuite::tri_hybrid();
    let initiator = identity(&suite, &[0x11u8; 32]);
    let responder = identity(&suite, &[0x22u8; 32]);

    let (init_hello, i_state) = initiator_hello(
        &suite,
        &initiator,
        &PeerIdentity::from_identity(&responder),
        I_IDX,
        TS,
        &[0xA1u8; 32],
    )
    .unwrap();
    let (resp_hello, r_state) = responder_process_init(
        &suite,
        &responder,
        &PeerIdentity::from_identity(&initiator),
        &init_hello,
        R_IDX,
        &[0xB1u8; 32],
    )
    .unwrap();
    let (init_conf, _) = initiator_process_resp(&suite, i_state, &initiator, &resp_hello).unwrap();

    // Splice the responder's (valid, but wrong-role) signature into InitConf.
    let responder_sig = field(&resp_hello, tag::IDENTITY_SIG).unwrap();
    let spliced = with_field(&init_conf, tag::IDENTITY_SIG, &responder_sig);
    assert!(matches!(
        responder_process_conf(&suite, r_state, &spliced),
        Err(HandshakeError::IdentityInvalid)
    ));
}

#[test]
fn a_signature_does_not_replay_across_sessions() {
    let suite = SdkSuite::tri_hybrid();
    let initiator = identity(&suite, &[0x11u8; 32]);
    let responder = identity(&suite, &[0x22u8; 32]);

    // Session 1 — a complete handshake, from which we keep the responder's
    // signature.
    let (init_hello, i_state) = initiator_hello(
        &suite,
        &initiator,
        &PeerIdentity::from_identity(&responder),
        I_IDX,
        TS,
        &[0xA1u8; 32],
    )
    .unwrap();
    let (resp_hello_1, _) = responder_process_init(
        &suite,
        &responder,
        &PeerIdentity::from_identity(&initiator),
        &init_hello,
        R_IDX,
        &[0xB1u8; 32],
    )
    .unwrap();
    let _ = initiator_process_resp(&suite, i_state, &initiator, &resp_hello_1).unwrap();
    let stale_sig = field(&resp_hello_1, tag::IDENTITY_SIG).unwrap();

    // Session 2 — same identities, different ephemeral entropy. The responder's
    // own signature is valid; the *stale* one is not, because TR differs.
    let (init_hello, i_state) = initiator_hello(
        &suite,
        &initiator,
        &PeerIdentity::from_identity(&responder),
        I_IDX,
        TS,
        &[0xA2u8; 32],
    )
    .unwrap();
    let (resp_hello_2, _) = responder_process_init(
        &suite,
        &responder,
        &PeerIdentity::from_identity(&initiator),
        &init_hello,
        R_IDX,
        &[0xB2u8; 32],
    )
    .unwrap();

    // Sanity: the fresh signature is valid over the fresh transcript.
    assert_eq!(
        field(&resp_hello_2, tag::IDENTITY_SIG).unwrap().len(),
        stale_sig.len()
    );

    // Re-seal the admission tag: the splice is the identity-layer forgery under
    // test, not a tag failure.
    let key = i_state.resp_tag_key(&suite).unwrap();
    let replayed = retag(
        &suite,
        &key,
        &with_field(&resp_hello_2, tag::IDENTITY_SIG, &stale_sig),
    );
    assert!(matches!(
        initiator_process_resp(&suite, i_state, &initiator, &replayed),
        Err(HandshakeError::IdentityInvalid)
    ));
}

// ── identity documents (the certificate path) ────────────────────────

#[test]
fn a_document_is_only_valid_inside_its_window() {
    let suite = SdkSuite::tri_hybrid();
    let ca = identity(&suite, &[0x81u8; 32]);
    let subject = identity(&suite, &[0x82u8; 32]);
    let ca_pk = ca.signing_public().unwrap();
    let validity = Validity::new(1_000, 2_000);

    let doc = IdentityDocument::issue(
        &suite,
        b"subject@example",
        subject.public().clone(),
        subject.signing_public().unwrap().clone(),
        validity,
        ca.signing().unwrap().secret(),
    )
    .unwrap();

    // Inclusive start, exclusive end.
    assert!(!doc.is_valid_at(&suite, ca_pk, 999));
    assert!(doc.is_valid_at(&suite, ca_pk, 1_000));
    assert!(doc.is_valid_at(&suite, ca_pk, 1_999));
    assert!(!doc.is_valid_at(&suite, ca_pk, 2_000));

    // `to_peer` says *why* rather than collapsing both ends into one error.
    assert!(matches!(
        doc.to_peer(&suite, ca_pk, 999),
        Err(HandshakeError::IdentityNotYetValid)
    ));
    assert!(matches!(
        doc.to_peer(&suite, ca_pk, 2_000),
        Err(HandshakeError::IdentityExpired)
    ));
    assert!(doc.to_peer(&suite, ca_pk, 1_500).is_ok());
}

#[test]
fn a_document_without_a_window_is_refused() {
    let suite = SdkSuite::tri_hybrid();
    let id = identity(&suite, &[0x83u8; 32]);
    let doc = IdentityDocument::self_sign(&suite, &id, b"nowindow", VALIDITY).unwrap();
    let bytes = doc.encode(suite.suite_id()).unwrap();

    for field in [tag::NOT_BEFORE, tag::NOT_AFTER] {
        let stripped = without_field(&bytes, field);
        assert!(
            matches!(
                IdentityDocument::decode(&stripped),
                Err(HandshakeError::Wire(_))
            ),
            "a document without {field:#06x} decoded"
        );
    }
}

#[test]
fn a_tampered_window_breaks_the_signature() {
    let suite = SdkSuite::tri_hybrid();
    let id = identity(&suite, &[0x84u8; 32]);
    let doc = IdentityDocument::self_sign(&suite, &id, b"window", VALIDITY).unwrap();
    let bytes = doc.encode(suite.suite_id()).unwrap();

    // Extend the window in the encoded body; the signature covers both fields.
    let mut extended = VALIDITY.not_after.to_be_bytes();
    extended[7] = extended[7].wrapping_add(1);
    let tampered = with_field(&bytes, tag::NOT_AFTER, &extended);
    let decoded = IdentityDocument::decode(&tampered).expect("still well formed");
    assert!(!decoded.is_valid(&suite, doc.signing()));
}

#[test]
fn an_identity_document_configures_a_peer_end_to_end() {
    let suite = SdkSuite::tri_hybrid();
    let ca = identity(&suite, &[0x71u8; 32]);
    let initiator = identity(&suite, &[0x72u8; 32]);
    let responder = identity(&suite, &[0x73u8; 32]);
    let ca_pk = ca.signing_public().unwrap();

    // A CA issues a document binding each subject's KEM key to its signing key.
    let init_doc = IdentityDocument::issue(
        &suite,
        b"initiator@example",
        initiator.public().clone(),
        initiator.signing_public().unwrap().clone(),
        VALIDITY,
        ca.signing().unwrap().secret(),
    )
    .unwrap();
    let resp_doc = IdentityDocument::issue(
        &suite,
        b"responder@example",
        responder.public().clone(),
        responder.signing_public().unwrap().clone(),
        VALIDITY,
        ca.signing().unwrap().secret(),
    )
    .unwrap();

    // Round-trip through the wire and validate against the CA. This is the
    // whole certificate path: decode, check the issuer, configure the peer.
    let init_doc = IdentityDocument::decode(&init_doc.encode(suite.suite_id()).unwrap()).unwrap();
    let resp_doc = IdentityDocument::decode(&resp_doc.encode(suite.suite_id()).unwrap()).unwrap();
    let peer_i = init_doc.to_peer(&suite, ca_pk, NOW).unwrap();
    let peer_r = resp_doc.to_peer(&suite, ca_pk, NOW).unwrap();

    // The document's KEM key is the one the handshake must encapsulate to.
    let (init_hello, i_state) =
        initiator_hello(&suite, &initiator, &peer_r, I_IDX, TS, &[0xA1u8; 32]).unwrap();
    let (resp_hello, r_state) = responder_process_init(
        &suite,
        &responder,
        &peer_i,
        &init_hello,
        R_IDX,
        &[0xB1u8; 32],
    )
    .unwrap();
    let (init_conf, ikeys) =
        initiator_process_resp(&suite, i_state, &initiator, &resp_hello).unwrap();
    let rkeys = responder_process_conf(&suite, r_state, &init_conf).unwrap();
    keys_agree(&ikeys, &rkeys);

    // A document a different issuer signed is not a credential for this CA.
    let rogue = identity(&suite, &[0x74u8; 32]);
    let forged = IdentityDocument::issue(
        &suite,
        b"responder@example",
        responder.public().clone(),
        responder.signing_public().unwrap().clone(),
        VALIDITY,
        rogue.signing().unwrap().secret(),
    )
    .unwrap();
    assert!(matches!(
        forged.to_peer(&suite, ca_pk, NOW),
        Err(HandshakeError::IdentityInvalid)
    ));
}
