// SPDX-License-Identifier: Apache-2.0

//! WireGuard-style `mac1` / `mac2` cookies: the anti-flood layer.
//!
//! Decapsulating a handshake is expensive — sntrup761 decapsulation and an
//! ML-KEM decapsulation dominate everything else in the protocol. An attacker
//! who can send packets from a spoofed source can therefore make a responder do
//! that work for free. Two keyed MACs on the front of every handshake fix it:
//!
//! | field | keyed by | proves | cost |
//! |-------|----------|--------|------|
//! | `mac1` | `H("vallum/mac1/key/v1" ‖ responder static pk)` | the sender knows the responder's **public** key | one hash + one KDF |
//! | `mac2` | a cookie the responder issued **for the sender's address** | the sender can receive at that address | one hash + one KDF |
//!
//! `mac2` is the one that costs an attacker something: to obtain a cookie the
//! sender must be able to *receive* a reply, so a spoofed source address cannot
//! produce one. A responder under load answers only `mac2`-bearing handshakes,
//! and the work per spoofed packet drops to one KDF.
//!
//! # What `mac1` is not
//!
//! `mac1` is keyed by a *public* value, so **anyone who knows the responder's
//! public key can compute it**. It is a cheap junk filter and a way to name the
//! peer before any KEM work — as in WireGuard, it is not authentication and must
//! never be treated as such. The plan's P2 gate is explicit about this.
//!
//! # What the cookie reply hides
//!
//! The reply is sealed under a key derived from the requester's `mac1`
//! ([`seal_cookie_reply`]). That stops an attacker who did not see the request
//! from reading the cookie — and only that. An attacker who saw the request
//! (and so its `mac1`) can decrypt the reply too, which is why a cookie is
//! never treated as a secret key, only as an address probe.
//!
//! # Wire form
//!
//! [`build_cookie_reply`] frames a sealed cookie as a `CookieReply`
//! ([`MessageType::CookieReply`]): the request's `sender_index` echoed in
//! `RECEIVER_INDEX`, a fresh `COOKIE_NONCE`, and the sealed cookie in
//! `COOKIE_CT`. It carries **no** `mac1` — a MAC would prove nothing (the reader
//! must already possess the request's `mac1` to unseal it) — and it is 96 bytes
//! against a multi-kilobyte `InitHello`, so it is not a reflection amplifier.
//! [`read_cookie_reply`] is the requester's mirror: it checks the type and
//! suite, unseals with the `mac1` it sent, and returns the echoed index so the
//! retry can be routed to the right handshake.
//!
//! *When* to answer with a cookie is the transport's decision (the
//! [`CookieSecret`] rotation schedule and the `under_load` signal); this module
//! supplies the mechanism, not the policy.

use core::fmt;

use vallum_crypto::{AeadError, CryptoSuite, KdfError};

use crate::error::HandshakeError;
use crate::keys::NONCE_SIZE;
use crate::wire::{
    tag, Message, MessageBuilder, MessageHeader, MessageType, INDEX_SIZE, PROTOCOL_VERSION,
};

/// Size of a `mac1` or `mac2`, in bytes.
pub const MAC_SIZE: usize = 16;

/// Size of a cookie, in bytes.
pub const COOKIE_SIZE: usize = 16;

/// How long a cookie secret should be kept before rotating, in seconds.
///
/// WireGuard's value. Not enforced here — `vallum-core` has no clock; the daemon
/// owns the rotation schedule. Rotating keeps the set of live cookies bounded,
/// so an attacker who has collected cookies must keep collecting them.
pub const COOKIE_ROTATION_SECONDS: u64 = 120;

/// Hash domain for the `mac1` key.
const MAC1_KEY_INFO: &[u8] = b"vallum/mac1/key/v1";
/// HKDF `info` label for a `mac1`.
const MAC1_INFO: &[u8] = b"vallum/mac1/v1";
/// HKDF `info` label for a `mac2`.
const MAC2_INFO: &[u8] = b"vallum/mac2/v1";
/// HKDF `info` label for a cookie.
const COOKIE_INFO: &[u8] = b"vallum/cookie/v1";
/// Hash domain for the cookie-reply AEAD key.
const REPLY_KEY_INFO: &[u8] = b"vallum/cookie-reply/key/v1";
/// Hash domain used to compare a `mac2` without leaking where it differs.
const MAC_CMP_DOMAIN: &[u8] = b"vallum/mac-cmp/v1";

/// Compute the `mac1` for `input`.
///
/// `input` is the handshake message with the cookie fields removed — see
/// [`Message::mac1_input`](crate::wire::Message::mac1_input) — which is what
/// makes the MAC cover the framing as well as the fields.
///
/// # Errors
///
/// [`KdfError`] if the suite's KDF fails.
pub fn mac1<S: CryptoSuite + ?Sized>(
    suite: &S,
    responder_static_pk: &[u8],
    input: &[u8],
) -> Result<[u8; MAC_SIZE], KdfError> {
    let key = suite.hash(MAC1_KEY_INFO, responder_static_pk);
    let mut out = [0u8; MAC_SIZE];
    suite.kdf(&key, input, MAC1_INFO, &mut out)?;
    Ok(out)
}

/// Compute the `mac2` for `input` under a cookie.
///
/// `input` here includes the `mac1` field, so `mac2` commits to it — an attacker
/// cannot strip the `mac1` and keep a valid `mac2`.
///
/// # Errors
///
/// [`KdfError`] if the suite's KDF fails.
pub fn mac2<S: CryptoSuite + ?Sized>(
    suite: &S,
    cookie: &[u8; COOKIE_SIZE],
    input: &[u8],
) -> Result<[u8; MAC_SIZE], KdfError> {
    let mut out = [0u8; MAC_SIZE];
    suite.kdf(cookie, input, MAC2_INFO, &mut out)?;
    Ok(out)
}

/// Compare a received MAC against one we computed.
///
/// Hashing both sides first, as the handshake's confirmation check does, gives a
/// fixed-size comparison over a value the protocol already binds; a timing
/// signal on it reveals nothing about the MAC.
fn mac_equal<S: CryptoSuite + ?Sized>(suite: &S, expected: &[u8; MAC_SIZE], got: &[u8]) -> bool {
    suite.hash(MAC_CMP_DOMAIN, got) == suite.hash(MAC_CMP_DOMAIN, expected)
}

/// The responder's rotating cookie secret.
///
/// Holds the current secret and the previous one, so rotating does not
/// invalidate cookies already handed out (an initiator's reply may still be in
/// flight).
#[derive(Clone)]
pub struct CookieSecret {
    current: [u8; 32],
    previous: [u8; 32],
    have_previous: bool,
}

impl CookieSecret {
    /// Seed a fresh secret. `seed` must be uniformly random and must never be
    /// reused for a different responder address.
    #[must_use]
    pub fn new(seed: &[u8; 32]) -> Self {
        Self {
            current: *seed,
            previous: *seed,
            have_previous: false,
        }
    }

    /// Install a new secret, keeping the old one valid.
    ///
    /// `seed` must be uniformly random. Call this on the schedule in
    /// [`COOKIE_ROTATION_SECONDS`].
    pub fn rotate(&mut self, seed: &[u8; 32]) {
        self.previous = self.current;
        self.current = *seed;
        self.have_previous = true;
    }

    /// Derive the cookie for `client` under the current secret.
    ///
    /// `client` is opaque to this module — the transport encodes whatever
    /// identifies the sender (WireGuard uses the source address bytes). Two
    /// different senders must never share an encoding, or they share cookies.
    ///
    /// # Errors
    ///
    /// [`KdfError`] if the suite's KDF fails.
    pub fn cookie<S: CryptoSuite + ?Sized>(
        &self,
        suite: &S,
        client: &[u8],
    ) -> Result<[u8; COOKIE_SIZE], KdfError> {
        self.cookie_under(suite, &self.current, client)
    }

    /// Whether `mac2` is valid for `client` over `input`.
    ///
    /// Accepts the previous secret as well as the current one. A wrong-length
    /// `mac2` is simply invalid, not an error.
    ///
    /// # Errors
    ///
    /// [`KdfError`] if the suite's KDF fails.
    pub fn verify_mac2<S: CryptoSuite + ?Sized>(
        &self,
        suite: &S,
        client: &[u8],
        input: &[u8],
        received: &[u8],
    ) -> Result<bool, KdfError> {
        if received.len() != MAC_SIZE {
            return Ok(false);
        }

        let current = self.cookie_under(suite, &self.current, client)?;
        if mac_equal(suite, &mac2(suite, &current, input)?, received) {
            return Ok(true);
        }

        if self.have_previous {
            let previous = self.cookie_under(suite, &self.previous, client)?;
            if mac_equal(suite, &mac2(suite, &previous, input)?, received) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn cookie_under<S: CryptoSuite + ?Sized>(
        &self,
        suite: &S,
        secret: &[u8; 32],
        client: &[u8],
    ) -> Result<[u8; COOKIE_SIZE], KdfError> {
        let mut out = [0u8; COOKIE_SIZE];
        suite.kdf(secret, client, COOKIE_INFO, &mut out)?;
        Ok(out)
    }
}

impl Drop for CookieSecret {
    fn drop(&mut self) {
        self.current.iter_mut().for_each(|b| *b = 0);
        self.previous.iter_mut().for_each(|b| *b = 0);
        core::hint::black_box(&mut self.current);
        core::hint::black_box(&mut self.previous);
    }
}

impl fmt::Debug for CookieSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CookieSecret(<redacted>, previous: {})",
            self.have_previous
        )
    }
}

/// Seal a cookie for the requester that sent `mac1`.
///
/// The reply is readable only by someone who saw the request (and so knows
/// `mac1`). It is **not** readable by an off-path attacker. See the module docs
/// for why that is the whole of the guarantee.
///
/// # Errors
///
/// [`AeadError`] if the suite's seal fails.
pub fn seal_cookie_reply<S: CryptoSuite + ?Sized>(
    suite: &S,
    mac1: &[u8; MAC_SIZE],
    nonce: &[u8; NONCE_SIZE],
    cookie: &[u8; COOKIE_SIZE],
) -> Result<Vec<u8>, AeadError> {
    let key = reply_key(suite, mac1);
    suite.aead_seal(&key, nonce, mac1, cookie)
}

/// Open a cookie reply sealed for the request whose `mac1` we sent.
///
/// # Errors
///
/// [`AeadError`] if the tag does not verify or the plaintext is not a cookie.
pub fn open_cookie_reply<S: CryptoSuite + ?Sized>(
    suite: &S,
    mac1: &[u8; MAC_SIZE],
    nonce: &[u8; NONCE_SIZE],
    sealed: &[u8],
) -> Result<[u8; COOKIE_SIZE], AeadError> {
    let key = reply_key(suite, mac1);
    let plaintext = suite.aead_open(&key, nonce, mac1, sealed)?;
    <[u8; COOKIE_SIZE]>::try_from(plaintext.as_slice()).map_err(|_| {
        AeadError::new(format!(
            "cookie reply is {} bytes, expected {COOKIE_SIZE}",
            plaintext.len()
        ))
    })
}

/// The cookie-reply AEAD key: a hash of the `mac1` that keyed the request.
fn reply_key<S: CryptoSuite + ?Sized>(suite: &S, mac1: &[u8; MAC_SIZE]) -> [u8; 32] {
    suite.hash(REPLY_KEY_INFO, mac1)
}

/// The responder's decision on an arriving handshake, taken **before** any KEM
/// work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Do the KEM work.
    Accept,
    /// The message carried no `mac1` field.
    NoMac1,
    /// The `mac1` did not match our static public key.
    BadMac1,
    /// The `mac2` did not match the source address.
    BadMac2,
    /// We are under load and the message carried no `mac2`. Reply with a cookie
    /// and drop it.
    NeedCookie,
}

/// Decide whether to spend KEM time on an arriving handshake.
///
/// Everything here is a keyed MAC: two hashes and up to three KDFs. That is the
/// whole point — the expensive decapsulations run only for admitted messages, so
/// a flood of junk costs the responder almost nothing.
///
/// `client` identifies the sender for cookie purposes ([`CookieSecret::cookie`]);
/// `under_load` is the caller's load signal. When `under_load` is set and
/// `cookies` is `None` this fails **closed** (`NeedCookie`): refusing to admit is
/// always the safe direction.
///
/// # Errors
///
/// [`KdfError`] if the suite's KDF fails.
pub fn admit_handshake<S: CryptoSuite + ?Sized>(
    suite: &S,
    message: &Message<'_>,
    responder_static_pk: &[u8],
    client: &[u8],
    under_load: bool,
    cookies: Option<&CookieSecret>,
) -> Result<Admission, KdfError> {
    let Some(received_mac1) = message.get(tag::MAC1) else {
        return Ok(Admission::NoMac1);
    };
    let expected_mac1 = mac1(suite, responder_static_pk, &message.mac1_input())?;
    if !mac_equal(suite, &expected_mac1, received_mac1) {
        return Ok(Admission::BadMac1);
    }

    if !under_load {
        return Ok(Admission::Accept);
    }

    let Some(cookies) = cookies else {
        return Ok(Admission::NeedCookie);
    };
    let Some(received_mac2) = message.get(tag::MAC2) else {
        return Ok(Admission::NeedCookie);
    };
    if cookies.verify_mac2(suite, client, &message.mac2_input(), received_mac2)? {
        Ok(Admission::Accept)
    } else {
        Ok(Admission::BadMac2)
    }
}

/// Attach the cookie fields to a handshake under construction.
///
/// Adds `mac1` always, and `mac2` when `cookie` is known. Every other field must
/// already be in the builder — the builder enforces the ordering, so a
/// mis-ordered message is an error rather than one whose MAC the responder would
/// compute differently.
///
/// # Errors
///
/// [`HandshakeError::Kdf`] if the suite's KDF fails, or
/// [`HandshakeError::Wire`] if the builder rejects the field.
pub fn sign_with_cookies<S: CryptoSuite + ?Sized>(
    suite: &S,
    builder: &mut crate::wire::MessageBuilder,
    responder_static_pk: &[u8],
    cookie: Option<&[u8; COOKIE_SIZE]>,
) -> Result<(), HandshakeError> {
    let tag_value = mac1(suite, responder_static_pk, &builder.mac1_input())?;
    builder.field(tag::MAC1, &tag_value)?;
    if let Some(cookie) = cookie {
        let tag_value = mac2(suite, cookie, &builder.mac2_input())?;
        builder.field(tag::MAC2, &tag_value)?;
    }
    Ok(())
}

/// Build the responder's answer to a handshake that carried no valid `mac2`.
///
/// `request_index` is the `sender_index` from the offending `InitHello`, echoed
/// back so the initiator can route the cookie to the right outstanding
/// handshake. `request_mac1` is that message's `mac1`, which keys the reply: only
/// someone who sent the request — and so saw its `mac1` — can read the cookie
/// back. `nonce` must be fresh; the caller supplies it, as everywhere else in
/// this crate.
///
/// The reply carries no `mac1` of its own. It is useless to anyone who did not
/// see the request, and a requester already knows the responder's public key, so
/// there is nothing for a MAC to prove. It is also far smaller than the request
/// it answers (96 bytes against a multi-kilobyte `InitHello`), so it cannot be
/// turned into a reflection amplifier.
///
/// # Errors
///
/// [`HandshakeError::Aead`] if the seal fails, or [`HandshakeError::Wire`] if a
/// field is rejected.
pub fn build_cookie_reply<S: CryptoSuite + ?Sized>(
    suite: &S,
    request_index: u32,
    request_mac1: &[u8; MAC_SIZE],
    nonce: &[u8; NONCE_SIZE],
    cookie: &[u8; COOKIE_SIZE],
) -> Result<Vec<u8>, HandshakeError> {
    let sealed = seal_cookie_reply(suite, request_mac1, nonce, cookie)?;

    let header = MessageHeader {
        version: PROTOCOL_VERSION,
        message_type: MessageType::CookieReply,
        suite_id: suite.suite_id(),
        // A cookie reply belongs to no session: it exists so a session can
        // *start*. The requester is named by `RECEIVER_INDEX`, not by us.
        sender_index: 0,
    };
    let mut builder = MessageBuilder::new(header);
    builder.field(tag::RECEIVER_INDEX, &request_index.to_be_bytes())?;
    builder.field(tag::COOKIE_NONCE, nonce)?;
    builder.field(tag::COOKIE_CT, &sealed)?;
    builder.finish()
}

/// Read a cookie reply that answers our own request.
///
/// `our_mac1` is the `mac1` we put on the `InitHello` this reply answers. Using
/// it to unseal the cookie is also what binds the reply to that request: a
/// cookie issued for someone else's handshake, or replayed under a different
/// request, fails to authenticate. The caller must therefore keep the `mac1` of
/// an outstanding handshake.
///
/// Returns `(request_index, cookie)`: the `sender_index` we put on the request,
/// echoed back, so the caller can attach the cookie to the retry it is about to
/// send.
///
/// # Errors
///
/// [`HandshakeError::WrongMessageType`] if it is not a cookie reply,
/// [`HandshakeError::SuiteMismatch`] if it names another suite,
/// [`HandshakeError::Wire`] if a field is missing or the wrong size, or
/// [`HandshakeError::Aead`] if it does not authenticate under `our_mac1`.
pub fn read_cookie_reply<S: CryptoSuite + ?Sized>(
    suite: &S,
    message: &Message<'_>,
    our_mac1: &[u8; MAC_SIZE],
) -> Result<(u32, [u8; COOKIE_SIZE]), HandshakeError> {
    message.expect_type(MessageType::CookieReply)?;
    // The reply key is a hash under *our* suite, so a mismatched suite could
    // never open it anyway; checking first just names the failure.
    message.expect_suite(suite.suite_id())?;

    let index = u32::from_be_bytes(message.require_array::<INDEX_SIZE>(tag::RECEIVER_INDEX)?);
    let nonce = message.require_array::<NONCE_SIZE>(tag::COOKIE_NONCE)?;
    let sealed = message.require(tag::COOKIE_CT)?;
    let cookie = open_cookie_reply(suite, our_mac1, &nonce, sealed)?;
    Ok((index, cookie))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use vallum_crypto_sdk::SdkSuite;

    const PK: &[u8] = b"a responder static public key";
    const MSG: &[u8] = b"an InitHello with the cookie fields removed";

    fn suite() -> SdkSuite {
        SdkSuite::tri_hybrid()
    }

    #[test]
    fn mac1_is_a_function_of_the_public_key_and_the_message() {
        let s = suite();
        let a = mac1(&s, PK, MSG).unwrap();
        assert_eq!(a, mac1(&s, PK, MSG).unwrap(), "deterministic");
        assert_ne!(a, mac1(&s, b"another key", MSG).unwrap());
        assert_ne!(a, mac1(&s, PK, b"another message").unwrap());
    }

    #[test]
    fn mac1_needs_no_secret_but_mac2_does() {
        // `mac1` is computable from public data alone — that is its purpose, and
        // why it must never be mistaken for authentication. `mac2` is the layer
        // that actually costs an attacker: without the secret it cannot be
        // produced.
        let s = suite();
        let secret = CookieSecret::new(&[1u8; 32]);
        let attacker_secret = CookieSecret::new(&[2u8; 32]);

        let honest = mac2(&s, &secret.cookie(&s, b"addr").unwrap(), MSG).unwrap();
        let forged = mac2(&s, &attacker_secret.cookie(&s, b"addr").unwrap(), MSG).unwrap();
        assert_ne!(honest, forged);
        assert!(!secret.verify_mac2(&s, b"addr", MSG, &forged).unwrap());
        assert!(secret.verify_mac2(&s, b"addr", MSG, &honest).unwrap());
    }

    #[test]
    fn a_cookie_validates_only_for_its_own_address() {
        let s = suite();
        let secret = CookieSecret::new(&[3u8; 32]);
        let cookie = secret.cookie(&s, b"10.0.0.1:51820").unwrap();
        let m = mac2(&s, &cookie, MSG).unwrap();

        assert!(secret.verify_mac2(&s, b"10.0.0.1:51820", MSG, &m).unwrap());
        assert!(!secret.verify_mac2(&s, b"10.0.0.2:51820", MSG, &m).unwrap());
        assert!(!secret
            .verify_mac2(&s, b"10.0.0.1:51820", b"other message", &m)
            .unwrap());
        assert!(
            !secret
                .verify_mac2(&s, b"10.0.0.1:51820", MSG, &[0u8; 16])
                .unwrap(),
            "an all-zero mac2 is not valid"
        );
        assert!(
            !secret
                .verify_mac2(&s, b"10.0.0.1:51820", MSG, &[0u8; 17])
                .unwrap(),
            "the wrong length is invalid, not an error"
        );
    }

    #[test]
    fn rotation_keeps_the_previous_cookie_valid_but_not_older_ones() {
        let s = suite();
        let mut secret = CookieSecret::new(&[1u8; 32]);
        let old = mac2(&s, &secret.cookie(&s, b"addr").unwrap(), MSG).unwrap();

        secret.rotate(&[2u8; 32]);
        let new = mac2(&s, &secret.cookie(&s, b"addr").unwrap(), MSG).unwrap();
        assert_ne!(old, new, "the cookie changed");

        assert!(
            secret.verify_mac2(&s, b"addr", MSG, &old).unwrap(),
            "a reply already in flight still validates"
        );
        assert!(secret.verify_mac2(&s, b"addr", MSG, &new).unwrap());

        secret.rotate(&[3u8; 32]);
        assert!(
            !secret.verify_mac2(&s, b"addr", MSG, &old).unwrap(),
            "two rotations back is gone"
        );
        assert!(secret.verify_mac2(&s, b"addr", MSG, &new).unwrap());
    }

    #[test]
    fn a_cookie_reply_round_trips_and_is_bound_to_the_request() {
        let s = suite();
        let request_mac1 = mac1(&s, PK, MSG).unwrap();
        let nonce = [7u8; NONCE_SIZE];
        let cookie = [9u8; COOKIE_SIZE];

        let sealed = seal_cookie_reply(&s, &request_mac1, &nonce, &cookie).unwrap();
        assert_eq!(
            open_cookie_reply(&s, &request_mac1, &nonce, &sealed).unwrap(),
            cookie
        );

        // A reply for another request's mac1 does not open.
        let other_mac1 = mac1(&s, b"another key", MSG).unwrap();
        assert!(open_cookie_reply(&s, &other_mac1, &nonce, &sealed).is_err());
        // Nor does it open under another nonce.
        let other_nonce = [8u8; NONCE_SIZE];
        assert!(open_cookie_reply(&s, &request_mac1, &other_nonce, &sealed).is_err());
        // Nor does a truncated reply.
        assert!(open_cookie_reply(&s, &request_mac1, &nonce, &sealed[..sealed.len() - 1]).is_err());
    }

    #[test]
    fn a_cookie_reply_round_trips_through_the_wire() {
        let s = suite();
        let request_mac1 = mac1(&s, PK, MSG).unwrap();
        let nonce = [7u8; NONCE_SIZE];
        let cookie = [9u8; COOKIE_SIZE];
        let request_index = 0xDEAD_BEEF;

        let bytes = build_cookie_reply(&s, request_index, &request_mac1, &nonce, &cookie).unwrap();

        // The wire form is small and fixed: a requester must not be able to make
        // the responder emit more than it received (no reflection amplifier).
        assert!(bytes.len() < 128, "a cookie reply is {} bytes", bytes.len());

        let msg = Message::parse(&bytes).unwrap();
        assert_eq!(msg.message_type(), MessageType::CookieReply);
        assert_eq!(
            msg.sender_index(),
            0,
            "a cookie reply belongs to no session"
        );

        let (index, got) = read_cookie_reply(&s, &msg, &request_mac1).unwrap();
        assert_eq!(index, request_index, "the request index is echoed");
        assert_eq!(got, cookie);
    }

    #[test]
    fn a_cookie_reply_is_unreadable_without_our_own_request() {
        let s = suite();
        let ours = mac1(&s, PK, MSG).unwrap();
        let theirs = mac1(&s, b"another key", MSG).unwrap();
        let nonce = [7u8; NONCE_SIZE];

        let bytes = build_cookie_reply(&s, 1, &theirs, &nonce, &[9u8; COOKIE_SIZE]).unwrap();
        let msg = Message::parse(&bytes).unwrap();

        // A reply issued for someone else's request does not open under ours:
        // the cookie is bound to the request that asked for it.
        assert!(matches!(
            read_cookie_reply(&s, &msg, &ours),
            Err(HandshakeError::Aead(_))
        ));
        assert!(read_cookie_reply(&s, &msg, &theirs).is_ok());
    }

    #[test]
    fn a_cookie_reply_asserts_its_type_and_suite() {
        let s = suite();
        let mac = mac1(&s, PK, MSG).unwrap();
        let bytes =
            build_cookie_reply(&s, 1, &mac, &[7u8; NONCE_SIZE], &[9u8; COOKIE_SIZE]).unwrap();
        let msg = Message::parse(&bytes).unwrap();
        assert!(msg.expect_type(MessageType::CookieReply).is_ok());
        assert!(msg.expect_suite(s.suite_id()).is_ok());

        // A reply whose suite id was rewritten is refused before any AEAD work.
        let mut forged = bytes.clone();
        forged[2..4].copy_from_slice(&0x0099u16.to_be_bytes());
        let forged = Message::parse(&forged).unwrap();
        assert!(matches!(
            read_cookie_reply(&s, &forged, &mac),
            Err(HandshakeError::SuiteMismatch { .. })
        ));

        // And a data message is not a cookie reply.
        let mut b = MessageBuilder::new(MessageHeader {
            version: PROTOCOL_VERSION,
            message_type: MessageType::Data,
            suite_id: s.suite_id(),
            sender_index: 0,
        });
        b.field(tag::COUNTER, &1u64.to_be_bytes()).unwrap();
        b.field(tag::DATA_CT, b"ct").unwrap();
        let data_bytes = b.finish().unwrap();
        let data = Message::parse(&data_bytes).unwrap();
        assert!(matches!(
            read_cookie_reply(&s, &data, &mac),
            Err(HandshakeError::WrongMessageType { .. })
        ));
    }

    #[test]
    fn a_truncated_cookie_reply_is_a_framing_error_not_a_panic() {
        let s = suite();
        let mac = mac1(&s, PK, MSG).unwrap();
        let bytes =
            build_cookie_reply(&s, 1, &mac, &[7u8; NONCE_SIZE], &[9u8; COOKIE_SIZE]).unwrap();
        let msg = Message::parse(&bytes).unwrap();

        // Drop each field in turn and confirm the reader reports a missing field
        // rather than unwrapping one.
        for missing in [tag::RECEIVER_INDEX, tag::COOKIE_NONCE, tag::COOKIE_CT] {
            let mut rebuilt = MessageBuilder::new(MessageHeader {
                version: PROTOCOL_VERSION,
                message_type: MessageType::CookieReply,
                suite_id: s.suite_id(),
                sender_index: 0,
            });
            for t in [tag::RECEIVER_INDEX, tag::COOKIE_NONCE, tag::COOKIE_CT] {
                if t != missing {
                    rebuilt.field(t, msg.require(t).unwrap()).unwrap();
                }
            }
            let short_bytes = rebuilt.finish().unwrap();
            let short = Message::parse(&short_bytes).unwrap();
            assert!(
                matches!(
                    read_cookie_reply(&s, &short, &mac),
                    Err(HandshakeError::Wire(_))
                ),
                "missing field {missing:#06x} should be a framing error"
            );
        }
    }
}
