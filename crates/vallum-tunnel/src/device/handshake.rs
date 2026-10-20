// SPDX-License-Identifier: Apache-2.0

//! The handshake driver: start, retransmit, accept, confirm, install.

use super::state::{Handshake, Initiating, PendingConf, Responding};
use super::*;

/// Re-frame a message produced by the handshake with `mac1`, and `mac2` if a
/// cookie is available.
///
/// `vallum-core`'s handshake functions deliberately emit no MAC fields — a MAC is
/// a transport concern, and a handshake that baked one in could not be replayed
/// under a cookie. Adding them means re-framing: parse, copy the fields in order,
/// sign. The field order is preserved exactly, which matters because `mac1` is
/// computed over the fields *before* it.
fn attach_cookies(
    suite: &dyn CryptoSuite,
    message: &[u8],
    responder_public: &[u8],
    cookie: Option<&[u8; COOKIE_SIZE]>,
) -> Result<Vec<u8>, vallum_core::HandshakeError> {
    let parsed = Message::parse(message)?;
    let mut builder = MessageBuilder::new(parsed.header());
    for tag in parsed.tags() {
        if let Some(value) = parsed.get(tag) {
            builder.field(tag, value)?;
        }
    }
    sign_with_cookies(suite, &mut builder, responder_public, cookie)?;
    builder.finish()
}

impl Device {
    pub(super) fn on_init_hello(
        &mut self,
        clock: Clock,
        source: SocketAddr,
        message: &Message<'_>,
        bytes: &[u8],
        rng: &mut dyn Randomness,
        out: &mut Vec<Action>,
    ) {
        let suite = Arc::clone(&self.suite);
        let now = clock.monotonic_ms;
        let client = client_bytes(source);

        // (1) The admission gate. Two MACs and no KEM work, before anything
        //     expensive touches an unauthenticated datagram.
        let admission = match admit_handshake(
            &*suite,
            message,
            self.identity.public().as_bytes(),
            &client,
            self.under_load,
            Some(&self.cookie_secret),
        ) {
            Ok(admission) => admission,
            Err(_) => return,
        };
        match admission {
            Admission::Accept => {}
            Admission::NeedCookie => {
                self.send_cookie_reply(&*suite, message, source, &client, rng, out);
                return;
            }
            // No `mac1`, a wrong `mac1`, or a wrong `mac2`: drop in silence. The
            // responder has not been told anything it should believe yet.
            Admission::NoMac1 | Admission::BadMac1 | Admission::BadMac2 => return,
        }

        // (2) Decapsulate op A and read the confidential, unauthenticated hint.
        let Ok(info) = responder_identify(&*suite, &self.identity, bytes) else {
            return;
        };
        let Some((index, which)) = self.peer_with_hint(info.peer_hint()) else {
            return;
        };
        if let Some(reason) = self.validity_refusal(index, which, clock.wall.unix_seconds()) {
            out.push(Action::Refused {
                peer: PeerId::from_index(index),
                reason,
            });
            return;
        }

        // (3) A *different* peer's configured endpoint must not disagree with the
        //     hint: that is either a misconfiguration the operator needs to see,
        //     or a spoof aimed at the wrong peer. Either way, refuse.
        if let Some(owner) = self.peer_owning_endpoint(source) {
            if owner != PeerId::from_index(index) {
                return;
            }
        }

        // (4) The timestamp, read-only. Committing here would let one forged
        //     `InitHello` lock the real peer out forever, because the guard would
        //     then reject the peer's own, genuine retransmission.
        let stamp = Tai64n::from_bytes(*info.timestamp());
        if self.peers[index].timestamp_guard.check(stamp).is_err() {
            return;
        }

        // (5) A repeated initiation is answered from the cache. The initiator
        //     retransmits the *same* `InitHello` — same index, same bytes — so the
        //     answer it already has is still the right answer. Reusing it matters
        //     for more than cost: if the two ends retransmit on the same tick, a
        //     fresh answer would move us to a new index while the initiator's
        //     confirmation still named the old one, and the handshake would stall
        //     until both sides gave up. A cached reply also does no decapsulation,
        //     and cannot amplify: it is smaller than the message that asks for it.
        if let Handshake::Responding(resp) = &self.peers[index].handshake {
            if resp.state.peer_index() == info.sender_index() {
                let resp_hello = resp.state.resp_hello().to_vec();
                out.push(Action::Send {
                    destination: source,
                    bytes: resp_hello,
                });
                return;
            }
        }

        // (6) Simultaneous initiation: exactly one side may answer, and the
        //     smaller public key keeps its own attempt.
        if matches!(self.peers[index].handshake, Handshake::Initiating(_)) {
            if self.identity.public().as_bytes()
                < self.peers[index].config.identity().kem().as_bytes()
            {
                return;
            }
            self.peers[index].handshake = Handshake::Idle;
            self.remap(index);
        }

        // (7) Answer. Allocating the index *before* `responder_accept` reserves it
        //     against reuse while the handshake is outstanding.
        let own_index = self.alloc_index();
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        let accepted = responder_accept_with_psk(
            &*suite,
            &self.identity,
            self.peers[index].identity_at(which),
            &info,
            own_index,
            &seed,
            self.peers[index].config.preshared_key(),
        );
        let Ok((resp_hello, state)) = accepted else {
            return;
        };

        self.peers[index].handshake = Handshake::Responding(Box::new(Responding { state, source }));
        // A new initiation is a new transcript: begin a fresh attempt run, so a
        // responder that once gave up on an older one is not dead to this caller.
        self.peers[index].timers.begin_handshake(now);
        self.remap(index);
        // The reply goes to where the `InitHello` came from — the only address we
        // have — but the peer's endpoint is not committed until `InitConf`.
        out.push(Action::Send {
            destination: source,
            bytes: resp_hello,
        });
    }

    /// Answer an `InitHello` that carried no `mac2` while under load.
    pub(super) fn send_cookie_reply(
        &mut self,
        suite: &dyn CryptoSuite,
        message: &Message<'_>,
        source: SocketAddr,
        client: &[u8],
        rng: &mut dyn Randomness,
        out: &mut Vec<Action>,
    ) {
        let Some(mac1) = message
            .get(tag::MAC1)
            .and_then(|value| <[u8; MAC_SIZE]>::try_from(value).ok())
        else {
            return;
        };
        let Ok(cookie) = self.cookie_secret.cookie(suite, client) else {
            return;
        };
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill(&mut nonce);
        let Ok(reply) = build_cookie_reply(suite, message.sender_index(), &mac1, &nonce, &cookie)
        else {
            return;
        };
        out.push(Action::Send {
            destination: source,
            bytes: reply,
        });
    }

    pub(super) fn on_cookie_reply(&mut self, message: &Message<'_>, out: &mut Vec<Action>) {
        let suite = Arc::clone(&self.suite);

        // The index is in the clear so the right outstanding handshake can be
        // found; the cookie itself only opens under that handshake's `mac1`.
        let Ok(index) = message.require_array::<INDEX_SIZE>(tag::RECEIVER_INDEX) else {
            return;
        };
        let index = u32::from_be_bytes(index);

        let Some(peer_id) = self.index.get(&index).copied() else {
            return;
        };
        let peer_index = peer_id.index();
        let Handshake::Initiating(init) = &self.peers[peer_index].handshake else {
            return;
        };
        let mac1 = init.mac1;
        let Ok((request_index, cookie)) = read_cookie_reply(&*suite, message, &mac1) else {
            return;
        };
        if request_index != index {
            return;
        }

        if let Handshake::Initiating(init) = &mut self.peers[peer_index].handshake {
            init.cookie = Some(cookie);
        }
        // Retry immediately with `mac2`: the cookie was issued precisely because
        // the first attempt could not be admitted. The target stays the address we
        // dialled, never the reply's source — a cookie reply carries no
        // authenticated address, so believing it would be a redirection
        // primitive.
        self.resend_init_hello(peer_index, out);
    }

    pub(super) fn on_resp_hello(
        &mut self,
        clock: Clock,
        source: SocketAddr,
        bytes: &[u8],
        out: &mut Vec<Action>,
    ) {
        let suite = Arc::clone(&self.suite);
        let now = clock.monotonic_ms;

        let Ok(receiver) = Message::parse(bytes)
            .and_then(|message| message.require_array::<INDEX_SIZE>(tag::RECEIVER_INDEX))
        else {
            return;
        };
        let receiver = u32::from_be_bytes(receiver);
        let Some(peer_id) = self.index.get(&receiver).copied() else {
            return;
        };
        let index = peer_id.index();
        if !matches!(self.peers[index].handshake, Handshake::Initiating(_)) {
            return;
        }

        // Rebuild the state from the stored inputs and consume it. On failure the
        // inputs go back, so a forged `RespHello` costs a bounded amount of work
        // instead of ending the handshake.
        let handshake = core::mem::replace(&mut self.peers[index].handshake, Handshake::Idle);
        let Handshake::Initiating(init) = handshake else {
            return;
        };

        // P6.8: the op-A-keyed admission tag, checked **before** the rebuild. An
        // attacker who observed our `InitHello` knows the index and can forge a
        // `RespHello`; without this check the forgery buys an ephemeral keygen
        // and an op-A encapsulation. With it, the forgery costs one KDF and the
        // handshake is untouched.
        if !verify_resp_tag(&*suite, &init.resp_tag_key, bytes) {
            self.peers[index].rejected += 1;
            self.peers[index].handshake = Handshake::Initiating(init);
            return;
        }

        let rebuilt = initiator_hello_with_psk(
            &*suite,
            &self.identity,
            self.peers[index].config.identity(),
            init.sender_index,
            *init.timestamp.as_bytes(),
            &init.seed,
            self.peers[index].config.preshared_key(),
        );
        let Ok((_, state)) = rebuilt else {
            self.peers[index].handshake = Handshake::Initiating(init);
            return;
        };

        match initiator_process_resp(&*suite, state, &self.identity, bytes) {
            Ok((init_conf, keys)) => {
                // The responder has proven the key, so the address it answered
                // from is now trustworthy for this peer — unless the peer is
                // pinned, in which case an answer from anywhere else is the
                // roaming-mischief case and is refused.
                if !self.endpoint_allowed(index, source) {
                    self.peers[index].rejected += 1;
                    self.peers[index].handshake = Handshake::Initiating(init);
                    out.push(Action::Refused {
                        peer: PeerId::from_index(index),
                        reason: Refusal::EndpointPinned,
                    });
                    return;
                }
                self.peers[index].endpoint = Some(source);
                self.install_session(index, &keys, Role::Initiator, clock, out);
                out.push(Action::Send {
                    destination: source,
                    bytes: init_conf.clone(),
                });
                self.peers[index].pending_conf = Some(PendingConf {
                    bytes: init_conf,
                    first_ms: now,
                    last_ms: now,
                });
            }
            Err(_) => {
                self.peers[index].rejected += 1;
                self.peers[index].handshake = Handshake::Initiating(init);
            }
        }
    }

    pub(super) fn on_init_conf(
        &mut self,
        clock: Clock,
        source: SocketAddr,
        bytes: &[u8],
        out: &mut Vec<Action>,
    ) {
        let suite = Arc::clone(&self.suite);

        let Ok(receiver) = Message::parse(bytes)
            .and_then(|message| message.require_array::<INDEX_SIZE>(tag::RECEIVER_INDEX))
        else {
            return;
        };
        let receiver = u32::from_be_bytes(receiver);
        let Some(peer_id) = self.index.get(&receiver).copied() else {
            return;
        };
        let index = peer_id.index();

        let handshake = core::mem::replace(&mut self.peers[index].handshake, Handshake::Idle);
        let Handshake::Responding(resp) = handshake else {
            // A duplicate: the initiator retransmitted an `InitConf` we already
            // processed. Nothing to do, and nothing to complain about.
            return;
        };

        let timestamp = Tai64n::from_bytes(*resp.state.timestamp());
        match responder_process_conf(&*suite, resp.state, bytes) {
            Ok(keys) => {
                if !self.endpoint_allowed(index, source) {
                    // A pinned peer whose confirmation came from somewhere else:
                    // refuse it rather than silently keeping the old address, so
                    // a redirected handshake does not look successful.
                    self.peers[index].rejected += 1;
                    self.remap(index);
                    out.push(Action::Refused {
                        peer: PeerId::from_index(index),
                        reason: Refusal::EndpointPinned,
                    });
                    return;
                }
                // The initiator has now proven the key, so its timestamp may be
                // committed and its address believed.
                self.peers[index].timestamp_guard.commit(timestamp);
                self.peers[index].endpoint = Some(source);
                self.install_session(index, &keys, Role::Responder, clock, out);
            }
            Err(_) => {
                // Consumed and rejected. The initiator's own retransmission, or its
                // `InitConf` resend, will drive a fresh attempt.
                self.peers[index].rejected += 1;
                self.remap(index);
            }
        }
    }

    /// Resend the initiator's `InitConf` until an authenticated packet arrives.
    pub(super) fn retransmit_conf(&mut self, index: usize, now: u64, out: &mut Vec<Action>) {
        let Some(conf) = &mut self.peers[index].pending_conf else {
            return;
        };
        // Stop after the same window the handshake retransmissions use: a
        // responder that has not answered by then is not going to, and the rekey
        // path will pick it up.
        if now.saturating_sub(conf.first_ms) >= REKEY_ATTEMPT_TIME_MS {
            self.peers[index].pending_conf = None;
            return;
        }
        if now.saturating_sub(conf.last_ms) < REKEY_TIMEOUT_MS {
            return;
        }
        conf.last_ms = now;

        let (Some(endpoint), Some(conf)) = (
            self.peers[index].endpoint,
            self.peers[index].pending_conf.as_ref(),
        ) else {
            return;
        };
        out.push(Action::Send {
            destination: endpoint,
            bytes: conf.bytes.clone(),
        });
    }

    // ── handshake driving ────────────────────────────────────────────

    /// Begin a handshake with `peer`, if one is not already in flight.
    pub(super) fn start_handshake(
        &mut self,
        index: usize,
        clock: Clock,
        rng: &mut dyn Randomness,
        out: &mut Vec<Action>,
    ) {
        if !matches!(self.peers[index].handshake, Handshake::Idle) {
            return;
        }
        if let Some(reason) = self.validity_refusal(index, 0, clock.wall.unix_seconds()) {
            out.push(Action::Refused {
                peer: PeerId::from_index(index),
                reason,
            });
            return;
        }
        // No address to dial: the peer must call us. Common for a roaming peer
        // whose endpoint has not been learned yet.
        let Some(endpoint) = self.peers[index].endpoint else {
            return;
        };
        let suite = Arc::clone(&self.suite);

        let sender_index = self.alloc_index();
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        let timestamp = clock.wall;

        let built = initiator_hello_with_psk(
            &*suite,
            &self.identity,
            self.peers[index].config.identity(),
            sender_index,
            *timestamp.as_bytes(),
            &seed,
            self.peers[index].config.preshared_key(),
        );
        let Ok((init_hello, state)) = built else {
            return;
        };
        // The op-A-keyed admission key. The state itself is discarded — the
        // handshake rebuilds it deterministically from the stored inputs — but
        // this one derived secret is retained so a forged `RespHello` can be
        // rejected before that rebuild (P6.8).
        let Ok(resp_tag_key) = state.resp_tag_key(&*suite) else {
            return;
        };

        // `mac1` is keyed by the *responder's* public key and proves only that we
        // know it. That is its purpose: it costs an attacker nothing to compute,
        // and it lets the responder filter junk before spending a cookie.
        let peer_public = self.peers[index]
            .config
            .identity()
            .kem()
            .as_bytes()
            .to_vec();
        let Ok(mac1) = compute_mac1(&*suite, &peer_public, &init_hello) else {
            return;
        };
        let Ok(framed) = attach_cookies(&*suite, &init_hello, &peer_public, None) else {
            return;
        };

        self.peers[index].handshake = Handshake::Initiating(Box::new(Initiating {
            sender_index,
            seed,
            timestamp,
            mac1,
            cookie: None,
            init_hello,
            resp_tag_key,
        }));
        self.peers[index].timers.begin_handshake(clock.monotonic_ms);
        self.remap(index);

        out.push(Action::Send {
            destination: endpoint,
            bytes: framed,
        });
    }

    pub(super) fn retransmit_handshake(
        &mut self,
        index: usize,
        clock: Clock,
        out: &mut Vec<Action>,
    ) {
        let now = clock.monotonic_ms;
        match &self.peers[index].handshake {
            Handshake::Initiating(_) => {
                self.resend_init_hello(index, out);
                self.peers[index].timers.on_handshake_sent(now);
            }
            Handshake::Responding(resp) => {
                let (source, resp_hello) = (resp.source, resp.state.resp_hello().to_vec());
                out.push(Action::Send {
                    destination: source,
                    bytes: resp_hello,
                });
                self.peers[index].timers.on_handshake_sent(now);
            }
            Handshake::Idle => {}
        }
    }

    /// Resend the stored `InitHello` for a peer.
    ///
    /// The address is the peer's committed endpoint, never an inbound datagram's
    /// source: a retransmission must not be redirectable by an attacker.
    pub(super) fn resend_init_hello(&mut self, index: usize, out: &mut Vec<Action>) {
        let suite = Arc::clone(&self.suite);
        let Some(endpoint) = self.peers[index].endpoint else {
            return;
        };
        let peer_public = self.peers[index]
            .config
            .identity()
            .kem()
            .as_bytes()
            .to_vec();
        let Handshake::Initiating(init) = &self.peers[index].handshake else {
            return;
        };
        let Ok(framed) = attach_cookies(
            &*suite,
            &init.init_hello,
            &peer_public,
            init.cookie.as_ref(),
        ) else {
            return;
        };
        out.push(Action::Send {
            destination: endpoint,
            bytes: framed,
        });
    }

    /// Clear an in-flight handshake without touching an established session.
    pub(super) fn abandon_handshake(&mut self, index: usize) {
        if !matches!(self.peers[index].handshake, Handshake::Idle) {
            self.peers[index].handshake = Handshake::Idle;
            self.remap(index);
        }
    }

    /// Drop a session whose key the timers have rejected.
    ///
    /// The timers must be told, or `Expire` outranks every other action forever:
    /// the session is already gone, but `poll` still reports expiry, which stops
    /// the rekey retransmitting and `start_handshake` from ever being reached
    /// again. A handshake already in flight is left alone — it keeps its own
    /// retransmission and give-up schedule.
    pub(super) fn tear_down(&mut self, index: usize, now: u64) {
        self.peers[index].session = None;
        self.peers[index].previous_own_index = None;
        self.peers[index].pending_conf = None;
        self.peers[index].timers.on_torn_down(now);
        self.remap(index);
    }

    /// Install a completed handshake as the peer's live session.
    ///
    /// A first handshake establishes epoch `0`; every later one advances to the
    /// next epoch and retains the previous receiver for stragglers. The role is
    /// whichever end we were in *this* handshake, which is why a rekey may be
    /// initiated by either side.
    pub(super) fn install_session(
        &mut self,
        index: usize,
        keys: &SessionKeys,
        role: Role,
        clock: Clock,
        out: &mut Vec<Action>,
    ) {
        let suite = Arc::clone(&self.suite);
        let peer_id = PeerId::from_index(index);
        let previous = self.peers[index].session.as_ref().map(Session::own_index);

        let epoch = match self.peers[index].session.as_mut() {
            Some(session) => match session.advance(&*suite, keys, role, clock.monotonic_ms) {
                Ok(epoch) => epoch,
                Err(_) => return,
            },
            None => match Session::establish(&*suite, keys, role) {
                Ok(session) => {
                    self.peers[index].session = Some(session);
                    0
                }
                Err(_) => return,
            },
        };

        self.peers[index].handshake = Handshake::Idle;
        self.peers[index].previous_own_index = previous;
        self.peers[index].last_handshake = Some(clock.wall);
        self.peers[index].timers.on_established(clock.monotonic_ms);
        self.remap(index);

        out.push(Action::Established {
            peer: peer_id,
            epoch,
            role,
        });
    }

    // ── data plane ───────────────────────────────────────────────────
}

/// A stable byte encoding of a socket address, used as the cookie's client key.
///
/// The encoding is the responder's alone — an initiator merely echoes the cookie
/// it is given — so any injective encoding works. Address and port are both
/// included, so a cookie is bound to the full endpoint and a NAT rebinding
/// correctly invalidates it.
pub(super) fn client_bytes(address: SocketAddr) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(18);
    match address {
        SocketAddr::V4(v4) => {
            bytes.push(4);
            bytes.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            bytes.push(6);
            bytes.extend_from_slice(&v6.ip().octets());
        }
    }
    bytes.extend_from_slice(&address.port().to_be_bytes());
    bytes
}
