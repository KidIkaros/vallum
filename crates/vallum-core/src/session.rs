// SPDX-License-Identifier: Apache-2.0

//! The epoch axis: one peer session, keyed by a sequence of handshakes.
//!
//! P1 produces a session — `KEY`, a transcript, an index pair. P2 seals packets
//! under `epoch_root = KDF(salt = KEY, ikm = frame([transcript, epoch]))`. That
//! `epoch` is the ratchet axis, and until P4 nothing ever moved it: every
//! implementation called [`establish_epoch`] with `0`.
//!
//! P4 moves it by **re-running the handshake**. Each epoch is keyed by a fresh
//! tri-hybrid encapsulation — a new `KEY` and a new transcript — and the epoch
//! counter is the only thing carried across. There is no symmetric chain.
//!
//! # Why there is no symmetric chain
//!
//! A ratchet of the form `root ← KDF(root)` is a non-additive synchronous stream
//! cipher, and Babbage–Golić time/memory tradeoff attacks apply to it: the
//! *effective* security is bounded by the ratchet state, not by the key size, and
//! only bounding the number of steps keeps that bound above the design target.
//! See `docs/proof/ratchet-pcs.md`. Vallum takes the paper's other recommendation
//! instead — keep fresh ephemeral key exchange as the mechanism — so the epoch's
//! key comes from the handshake, not from the previous epoch's key.
//!
//! The consequences are worth stating plainly, because they are stronger than a
//! chain would be:
//!
//! * **Post-compromise security is by construction, not by argument.** The new
//!   epoch's root is not a function of the old epoch's root. An attacker who
//!   holds every byte of epoch *n* — root, directional keys, counters — holds
//!   nothing that helps with epoch *n+1*, which is keyed by a fresh
//!   X25519 + sntrup761 + ML-KEM-768 exchange. With a symmetric chain, the same
//!   attacker would simply ratchet forward.
//! * **Time/memory tradeoffs have no target.** There is no chain to invert.
//!
//! # What the session does own
//!
//! Three things, and the third is the one that needs care:
//!
//! 1. **A monotonic epoch counter.** `epoch` is folded into every key
//!    ([`crate::DataKeys::derive`]), so it must never repeat, and the session
//!    refuses to wrap ([`DataError::EpochExhausted`]).
//! 2. **A fixed suite.** The epoch axis rides on one [`CryptoSuite`]'s schedule;
//!    a rekey that presents a different suite is rejected
//!    ([`DataError::SuiteChanged`]) rather than quietly mixed in.
//! 3. **Exactly one superseded epoch, receive-only and bounded in time.** A rekey
//!    is not instantaneous at the peer, so packets sealed under the old epoch may
//!    still be in flight. The old *sending* key is dropped the moment the new
//!    epoch lands; the old *receiving* key is kept only so those stragglers open,
//!    and only until [`RETAIN_PREVIOUS_EPOCH_MS`] has passed since the advance.
//!    Then it is erased.
//!
//! Point 3 is where "erasure-based PCS" meets reality: erasing the old epoch's
//! keys immediately would turn a benign rekey into a packet-loss event, so the
//! erasure is *bounded* rather than immediate, and the bound is the same
//! [`REJECT_AFTER_TIME_MS`] the timers use to expire a superseded session.
//!
//! # Demultiplexing without an epoch on the wire
//!
//! The epoch is **not** carried in data packets. A receiver demultiplexes on the
//! recipient index the packet already names — which is checked before any
//! cryptography — and offers the packet to the retained epoch only when the index
//! says it belongs elsewhere. A packet for neither epoch costs two integer
//! comparisons and no AEAD work. Putting an epoch counter on the wire would
//! instead hand an attacker an oracle for which epoch a guess landed in, for no
//! benefit.
//!
//! ```text
//! handshake ──▶ KEY, TR ──▶ Session::advance(now_ms) ──▶ epoch n+1
//!                                │
//!                                └─ supersedes epoch n: receive-only until
//!                                   now_ms + RETAIN_PREVIOUS_EPOCH_MS, then erased
//! ```

use vallum_crypto::CryptoSuite;

use crate::data::{establish_epoch, Receiver, Sender};
use crate::error::DataError;
use crate::handshake::SessionKeys;
use crate::keys::Role;
use crate::timer::REJECT_AFTER_TIME_MS;

/// How long a superseded epoch is retained, receive-only, for in-flight packets.
///
/// A rekey is not atomic at the peer: it may still be sending under the old
/// epoch while the new handshake completes. This is the same bound the timers
/// use to expire a superseded session, so a packet that is still in flight when
/// the epoch is erased would have been rejected as too old anyway.
pub const RETAIN_PREVIOUS_EPOCH_MS: u64 = REJECT_AFTER_TIME_MS;

/// One epoch's live state: the key we send under and the key we receive under.
#[derive(Debug)]
struct Epoch {
    sender: Sender,
    receiver: Receiver,
}

/// A superseded epoch, kept receive-only until it ages out.
#[derive(Debug)]
struct Retained {
    receiver: Receiver,
    /// The caller-supplied millisecond clock reading at the advance.
    since_ms: u64,
}

/// One end of a peer relationship across rekeys.
///
/// The session is the thing [`crate::timer::Timers`] decides to rekey and
/// [`crate::data`] seals and opens through. It owns the epoch counter that
/// [`establish_epoch`] documents as the caller's obligation.
///
/// `Debug` cannot leak: every key field is behind [`Sender`]/[`Receiver`], whose
/// `DirectionalKey`s redact.
#[derive(Debug)]
pub struct Session {
    suite_id: u16,
    epoch: u64,
    current: Epoch,
    previous: Option<Retained>,
}

impl Session {
    /// Install epoch 0 from a completed handshake.
    ///
    /// # Errors
    ///
    /// [`DataError::Kdf`] if the suite's key schedule fails or its AEAD geometry
    /// is not the shape the data plane assumes.
    pub fn establish<S: CryptoSuite + ?Sized>(
        suite: &S,
        keys: &SessionKeys,
        role: Role,
    ) -> Result<Self, DataError> {
        let suite_id = suite.suite_id();
        let (sender, receiver) = establish_epoch(
            suite,
            &keys.key,
            &keys.transcript,
            0,
            role,
            keys.own_index,
            keys.peer_index,
        )?;

        Ok(Self {
            suite_id,
            epoch: 0,
            current: Epoch { sender, receiver },
            previous: None,
        })
    }

    /// Install the next epoch from a **fresh** handshake's result.
    ///
    /// `keys` must come from a new handshake, not from the previous epoch: that
    /// independence is the ratchet's entire security argument (module docs). The
    /// new handshake's indices replace the old ones — they are per-session, and
    /// data packets carry the recipient's index, so the retained receiver keeps
    /// its own old index and is unaffected.
    ///
    /// `now_ms` is a caller-supplied monotonic clock reading; it stamps the
    /// superseded epoch so [`Self::expire_previous`] can bound its retention.
    ///
    /// Any previously retained epoch is **dropped first** — the session never
    /// holds more than one superseded epoch, so the retention window cannot
    /// compound across rapid rekeys.
    ///
    /// # Errors
    ///
    /// - [`DataError::SuiteChanged`] if `suite` is not the session's suite.
    /// - [`DataError::EpochExhausted`] at `u64::MAX`.
    /// - [`DataError::Kdf`] as [`Self::establish`].
    pub fn advance<S: CryptoSuite + ?Sized>(
        &mut self,
        suite: &S,
        keys: &SessionKeys,
        role: Role,
        now_ms: u64,
    ) -> Result<u64, DataError> {
        let suite_id = suite.suite_id();
        if suite_id != self.suite_id {
            return Err(DataError::SuiteChanged {
                expected: self.suite_id,
                got: suite_id,
            });
        }

        let epoch = self
            .epoch
            .checked_add(1)
            .ok_or(DataError::EpochExhausted { epoch: self.epoch })?;

        let (sender, receiver) = establish_epoch(
            suite,
            &keys.key,
            &keys.transcript,
            epoch,
            role,
            keys.own_index,
            keys.peer_index,
        )?;

        // Replacing `current` drops the superseded *sender* immediately: we send
        // under the new epoch from this instant. Only the *receiver* is carried
        // over, and only so packets already in flight still open.
        let superseded = core::mem::replace(&mut self.current, Epoch { sender, receiver });
        self.previous = Some(Retained {
            receiver: superseded.receiver,
            since_ms: now_ms,
        });
        self.epoch = epoch;

        Ok(epoch)
    }

    /// The epoch currently in use.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The superseded epoch still retained for stragglers, if any.
    #[must_use]
    pub fn previous_epoch(&self) -> Option<u64> {
        self.previous.as_ref().map(|r| r.receiver.epoch())
    }

    /// The suite this session is bound to.
    #[must_use]
    pub fn suite_id(&self) -> u16 {
        self.suite_id
    }

    /// Our own session index, as announced in the most recent handshake.
    #[must_use]
    pub fn own_index(&self) -> u32 {
        self.current.receiver.own_index()
    }

    /// The peer's session index, as announced in the most recent handshake.
    #[must_use]
    pub fn peer_index(&self) -> u32 {
        self.current.sender.peer_index()
    }

    /// The outgoing half of the current epoch, for counters and rekey decisions.
    #[must_use]
    pub fn sender(&self) -> &Sender {
        &self.current.sender
    }

    /// Whether the caller should begin a fresh handshake at its next
    /// opportunity.
    #[must_use]
    pub fn needs_rekey(&self) -> bool {
        self.current.sender.needs_rekey()
    }

    /// Whether a superseded epoch is still being retained.
    #[must_use]
    pub fn retains_previous(&self) -> bool {
        self.previous.is_some()
    }

    /// Seal one layer-3 packet under the current epoch.
    ///
    /// # Errors
    ///
    /// As [`Sender::seal`].
    pub fn seal<S: CryptoSuite + ?Sized>(
        &mut self,
        suite: &S,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, DataError> {
        self.current.sender.seal(suite, plaintext)
    }

    /// Seal one layer-3 packet under the current epoch, at a chosen size.
    ///
    /// The transport's shaping hook: a machine that wants a packet in a fixed
    /// size class asks for the sealed plaintext to be exactly `target` bytes, and
    /// the padding is inside the AEAD. `target` is a *pre-image* length, so the
    /// packet that lands on the wire is larger by the header, the framing and the
    /// tag — the size class an observer sees is `target` plus a per-suite
    /// constant, which is why the caller clamps it to what
    /// [`crate::wire::MAX_DATA_MESSAGE`] can carry.
    ///
    /// # Errors
    ///
    /// As [`Sender::seal_padded`].
    pub fn seal_padded<S: CryptoSuite + ?Sized>(
        &mut self,
        suite: &S,
        plaintext: &[u8],
        target: usize,
    ) -> Result<Vec<u8>, DataError> {
        self.current.sender.seal_padded(suite, plaintext, target)
    }

    /// Open one inbound packet, from either the current or the retained epoch.
    ///
    /// The epoch is decided by the **index** the packet names, not by trying
    /// cryptography on both: if the current epoch's error is not
    /// [`DataError::WrongIndex`], the packet was addressed to it and its error is
    /// final. Only a packet addressed elsewhere is offered to the retained epoch,
    /// and the retained epoch's verdict then replaces the default — so a replayed
    /// straggler reports as [`DataError::Replay`], not as a stray index mismatch.
    ///
    /// # Errors
    ///
    /// As [`Receiver::open`], for whichever epoch the packet named.
    pub fn open<S: CryptoSuite + ?Sized>(
        &mut self,
        suite: &S,
        packet: &[u8],
    ) -> Result<Vec<u8>, DataError> {
        let error = match self.current.receiver.open(suite, packet) {
            Ok(plaintext) => return Ok(plaintext),
            Err(e) => e,
        };

        // Only an index mismatch means the packet was not addressed to the
        // current epoch; anything else is a verdict on this packet.
        if !matches!(error, DataError::WrongIndex { .. }) {
            return Err(error);
        }

        if let Some(previous) = self.previous.as_mut() {
            match previous.receiver.open(suite, packet) {
                Ok(plaintext) => return Ok(plaintext),
                // The packet named the retained epoch: its verdict, not the
                // current epoch's index mismatch, is the one to report.
                Err(e) if !matches!(e, DataError::WrongIndex { .. }) => return Err(e),
                Err(_) => {}
            }
        }

        Err(error)
    }

    /// Erase the superseded epoch once [`RETAIN_PREVIOUS_EPOCH_MS`] has passed
    /// since the advance.
    ///
    /// Returns `true` if this call erased it. Safe to call at any time; it is a
    /// no-op before the window closes and once it has been erased.
    pub fn expire_previous(&mut self, now_ms: u64) -> bool {
        let due = self
            .previous
            .as_ref()
            .is_some_and(|r| now_ms.saturating_sub(r.since_ms) >= RETAIN_PREVIOUS_EPOCH_MS);
        if due {
            self.previous = None;
        }
        due
    }

    /// Erase the superseded epoch immediately, ignoring the retention window.
    ///
    /// This is the teardown path (session close, handshake failure) and the
    /// erasure primitive the PCS argument rests on; the timed path is
    /// [`Self::expire_previous`]. Returns `true` if something was erased.
    pub fn retire_previous(&mut self) -> bool {
        self.previous.take().is_some()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use vallum_crypto::SharedSecret;

    fn keys(tag: u8) -> SessionKeys {
        SessionKeys {
            transcript: [tag; 32],
            key: SharedSecret::new([tag.wrapping_add(0x40); 32]),
            confirm_initiator: SharedSecret::new([1u8; 32]),
            confirm_responder: SharedSecret::new([2u8; 32]),
            own_index: u32::from(tag) + 0x1000,
            peer_index: u32::from(tag) + 0x2000,
        }
    }

    #[test]
    fn epoch_advances_monotonically() {
        let suite = vallum_crypto_sdk::SdkSuite::tri_hybrid();
        let mut session = Session::establish(&suite, &keys(1), Role::Initiator).unwrap();

        assert_eq!(session.epoch(), 0);
        assert_eq!(session.previous_epoch(), None);
        assert_eq!(
            session
                .advance(&suite, &keys(2), Role::Initiator, 0)
                .unwrap(),
            1
        );
        assert_eq!(session.previous_epoch(), Some(0));
        assert_eq!(
            session
                .advance(&suite, &keys(3), Role::Initiator, 10)
                .unwrap(),
            2
        );
        assert_eq!(session.previous_epoch(), Some(1));
    }

    #[test]
    fn a_rapid_rekey_does_not_compound_retention() {
        let suite = vallum_crypto_sdk::SdkSuite::tri_hybrid();
        let mut session = Session::establish(&suite, &keys(1), Role::Initiator).unwrap();
        session
            .advance(&suite, &keys(2), Role::Initiator, 0)
            .unwrap();
        session
            .advance(&suite, &keys(3), Role::Initiator, 1)
            .unwrap();

        // Only the epoch we just left is retained; the one before it is gone.
        assert_eq!(session.previous_epoch(), Some(1));
        assert!(session.retains_previous());
    }

    #[test]
    fn a_different_suite_is_refused() {
        use vallum_crypto::CryptoSuite as _;
        let tri = vallum_crypto_sdk::SdkSuite::tri_hybrid();
        let single = vallum_crypto_sdk::SdkSuite::x25519_sntrup761();
        let mut session = Session::establish(&tri, &keys(1), Role::Initiator).unwrap();

        assert_eq!(
            session.advance(&single, &keys(2), Role::Initiator, 0),
            Err(DataError::SuiteChanged {
                expected: tri.suite_id(),
                got: single.suite_id(),
            })
        );
    }

    #[test]
    fn expire_previous_is_time_bounded() {
        let suite = vallum_crypto_sdk::SdkSuite::tri_hybrid();
        let mut session = Session::establish(&suite, &keys(1), Role::Initiator).unwrap();
        session
            .advance(&suite, &keys(2), Role::Initiator, 1_000)
            .unwrap();

        assert!(!session.expire_previous(1_000));
        assert!(!session.expire_previous(1_000 + RETAIN_PREVIOUS_EPOCH_MS - 1));
        assert!(session.retains_previous());
        assert!(session.expire_previous(1_000 + RETAIN_PREVIOUS_EPOCH_MS));
        assert!(!session.retains_previous());
        assert_eq!(session.previous_epoch(), None);
    }

    #[test]
    fn retire_previous_erases_immediately() {
        let suite = vallum_crypto_sdk::SdkSuite::tri_hybrid();
        let mut session = Session::establish(&suite, &keys(1), Role::Initiator).unwrap();
        session
            .advance(&suite, &keys(2), Role::Initiator, 0)
            .unwrap();

        assert!(session.retire_previous());
        assert!(!session.retire_previous());
        assert!(!session.retains_previous());
    }
}
