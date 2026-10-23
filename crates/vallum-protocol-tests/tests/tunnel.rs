// SPDX-License-Identifier: Apache-2.0

//! The P6.3 gate: the whole transport, driven end to end over the real suite.
//!
//! Everything below runs **two devices in one process** and moves datagrams by
//! function call. No socket is opened, no packet leaves the machine, and no test
//! sleeps — which is the point of the sans-IO design. If this file is green, the
//! handshake driver, the cookie gate, cryptokey routing, the replay filter and the
//! shaping hook all agree with each other; if it is red, nothing about the product
//! matters yet.
//!
//! The suite is the real tri-hybrid, so the wire bytes are the ones the frozen
//! vectors cover. The `Randomness` is *deterministic* — it is a test double, not a
//! cryptographic generator, and it exists so a failure can be reproduced.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use vallum_core::identity::StaticIdentity;
use vallum_core::shaping::Machine;
use vallum_core::wire::{tag, HEADER_LEN, MAX_HANDSHAKE_MESSAGE};
use vallum_core::{
    Message, MessageBuilder, MessageHeader, MessageType, Role, Tai64n, PROTOCOL_VERSION,
};
use vallum_crypto::{
    AeadError, CryptoSuite, Encapsulation, KdfError, KemError, KemPublicKey, KemRole, KemSecretKey,
    LegKind, SharedSecret, SigError, SignPublicKey, SignSecretKey, WireSizes,
    KEM_ENCAPS_RANDOMNESS,
};
use vallum_crypto_sdk::SdkSuite;
use vallum_tunnel::{Action, Clock, Device, Event, PeerConfig, PeerId, Prefix, Randomness};

// ── test doubles ─────────────────────────────────────────────────────

/// A deterministic, **non-cryptographic** byte source.
///
/// A counter mixed into every byte. It must not be used by anything that is
/// trusted; it is here so a failing interop run can be replayed exactly.
struct TestRng(u64);

impl Randomness for TestRng {
    fn fill(&mut self, out: &mut [u8]) {
        for byte in out.iter_mut() {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *byte = (self.0 >> 33) as u8;
        }
    }
}

/// A delegating suite that counts KEM operations (P6.8).
///
/// The gate asserts that a forged `RespHello` reaches *no* KEM work, which the
/// outcome alone cannot show.
struct CountingSuite {
    inner: SdkSuite,
    keygen: AtomicUsize,
    encaps: AtomicUsize,
    decaps: AtomicUsize,
}

impl CountingSuite {
    fn new(inner: SdkSuite) -> Self {
        Self {
            inner,
            keygen: AtomicUsize::new(0),
            encaps: AtomicUsize::new(0),
            decaps: AtomicUsize::new(0),
        }
    }

    fn kem_ops(&self) -> usize {
        self.keygen.load(Ordering::Relaxed)
            + self.encaps.load(Ordering::Relaxed)
            + self.decaps.load(Ordering::Relaxed)
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
        self.keygen.fetch_add(1, Ordering::Relaxed);
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
        self.decaps.fetch_add(1, Ordering::Relaxed);
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

/// One side of the simulated link.
struct Host {
    device: Device,
    endpoint: SocketAddr,
    rng: TestRng,
    inbox: VecDeque<(SocketAddr, Vec<u8>)>,
    /// Plaintext the device asked to be delivered locally.
    delivered: Vec<Vec<u8>>,
    /// Sessions that came up, in order.
    established: Vec<(PeerId, u64, Role)>,
    /// Every datagram handed to the caller to send, in order.
    sent: Vec<Vec<u8>>,
}

impl Host {
    fn new(device: Device, endpoint: SocketAddr, seed: u64) -> Self {
        Self {
            device,
            endpoint,
            rng: TestRng(seed),
            inbox: VecDeque::new(),
            delivered: Vec::new(),
            established: Vec::new(),
            sent: Vec::new(),
        }
    }

    fn established_once(&self) -> bool {
        !self.established.is_empty()
    }

    /// The handle of this host's only peer.
    fn peer_id(&self) -> PeerId {
        self.device.peers().next().expect("one peer").0
    }

    fn stats(&self) -> vallum_tunnel::PeerStats {
        self.device.stats(self.peer_id()).expect("a peer")
    }
}

/// A two-party link with no underlying network.
struct Net {
    clock_ms: u64,
    wall_s: u64,
    hosts: Vec<Host>,
    /// The next datagrams of these message types, in order, are swallowed
    /// instead of delivered. How a lost message is simulated.
    drop_types: Vec<MessageType>,
}

impl Net {
    fn clock(&self) -> Clock {
        Clock::new(self.clock_ms, Tai64n::from_unix(self.wall_s, 0))
    }

    /// Move time forward on both clocks, the wall clock strictly.
    fn advance(&mut self, ms: u64) {
        self.clock_ms += ms;
        // A rekey must carry a strictly newer `Tai64n` and the guard orders by
        // it, so the wall clock may never stand still across an advance.
        self.wall_s += 1 + ms / 1000;
    }

    /// Record a host's actions, returning the datagrams it wants sent.
    fn record(&mut self, host: usize, actions: Vec<Action>) -> Vec<(usize, SocketAddr, Vec<u8>)> {
        let mut sends = Vec::new();
        for action in actions {
            match action {
                Action::Send { destination, bytes } => sends.push((host, destination, bytes)),
                Action::Deliver { packet } => self.hosts[host].delivered.push(packet),
                Action::Established { peer, epoch, role } => {
                    self.hosts[host].established.push((peer, epoch, role));
                }
                Action::Refused { .. } => {}
            }
        }
        sends
    }

    /// Put datagrams on the link, honouring the drop list.
    fn route_sends(&mut self, sends: Vec<(usize, SocketAddr, Vec<u8>)>) {
        for (from, destination, bytes) in sends {
            let source = self.hosts[from].endpoint;
            self.hosts[from].sent.push(bytes.clone());
            let Some(to) = self
                .hosts
                .iter()
                .position(|host| host.endpoint == destination)
            else {
                continue;
            };
            if let Ok(message) = Message::parse(&bytes) {
                if let Some(position) = self
                    .drop_types
                    .iter()
                    .position(|kind| *kind == message.message_type())
                {
                    self.drop_types.remove(position);
                    continue;
                }
            }
            self.hosts[to].inbox.push_back((source, bytes));
        }
    }

    /// Hand one outbound packet to a host's interface.
    fn outbound(&mut self, host: usize, packet: Vec<u8>) {
        let clock = self.clock();
        let entry = &mut self.hosts[host];
        let actions = entry
            .device
            .handle(clock, Event::OutboundIp { packet }, &mut entry.rng);
        let sends = self.record(host, actions);
        self.route_sends(sends);
    }

    /// Deliver everything in flight, up to `rounds` times over, ticking each time.
    fn pump(&mut self, rounds: usize) {
        for _ in 0..rounds {
            let clock = self.clock();
            let mut sends = Vec::new();
            for index in 0..self.hosts.len() {
                let host = &mut self.hosts[index];
                let mut events = Vec::new();
                while let Some((source, bytes)) = host.inbox.pop_front() {
                    events.push(Event::Datagram { source, bytes });
                }
                events.push(Event::Tick);
                for event in events {
                    let actions = host.device.handle(clock, event, &mut host.rng);
                    for action in actions {
                        match action {
                            Action::Send { destination, bytes } => {
                                sends.push((index, destination, bytes))
                            }
                            Action::Deliver { packet } => host.delivered.push(packet),
                            Action::Established { peer, epoch, role } => {
                                host.established.push((peer, epoch, role));
                            }
                            Action::Refused { .. } => {}
                        }
                    }
                }
            }
            if sends.is_empty() {
                return;
            }
            self.route_sends(sends);
        }
    }

    /// Run until the link is quiet and no host has anything held.
    fn settle(&mut self) {
        for _ in 0..64 {
            let before: usize = self.hosts.iter().map(|host| host.inbox.len()).sum();
            let held: usize = self.hosts.iter().map(|host| host.stats().queued).sum();
            self.pump(1);
            let after: usize = self.hosts.iter().map(|host| host.inbox.len()).sum();
            let held_after: usize = self.hosts.iter().map(|host| host.stats().queued).sum();
            if before == 0 && after == 0 && held == 0 && held_after == 0 {
                return;
            }
        }
        panic!("the link never went quiet");
    }

    /// Advance the clock in steps and pump each time, so a machine that blocks
    /// and releases on a timer is given the chance to drain.
    fn settle_over(&mut self, step_ms: u64, steps: usize) {
        for _ in 0..steps {
            self.advance(step_ms);
            self.pump(4);
        }
    }
}

// ── fixtures ─────────────────────────────────────────────────────────

/// A prefix, from its text form.
fn net(prefix: &str) -> Prefix {
    Prefix::from_str(prefix).expect("a valid prefix")
}

/// An endpoint, from its text form.
fn endpoint(text: &str) -> SocketAddr {
    SocketAddr::from_str(text).expect("a valid endpoint")
}

/// A minimal, well-formed IPv4/UDP packet.
///
/// Only the fields the tunnel reads are meaningful: the version nibble, the two
/// addresses, and a payload to compare byte for byte.
fn ipv4(source: [u8; 4], destination: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 20 + payload.len()];
    packet[0] = 0x45; // version 4, header length 5 words
    packet[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    packet[8] = 64; // ttl
    packet[9] = 17; // udp
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet[20..].copy_from_slice(payload);
    packet
}

const A_IP: [u8; 4] = [10, 0, 0, 1];
const B_IP: [u8; 4] = [10, 0, 0, 2];
const A_EP: &str = "10.0.0.1:51820";
const B_EP: &str = "10.0.0.2:51820";

/// The seeds A and B always generate from, so a failure replays exactly.
const A_SEED: [u8; 32] = [0xA1; 32];
const B_SEED: [u8; 32] = [0xB2; 32];

fn suite() -> Arc<dyn CryptoSuite> {
    Arc::new(SdkSuite::tri_hybrid())
}

/// How a fixture's two peers are configured.
#[derive(Debug, Clone, Copy, Default)]
struct Shape {
    /// A has an address to dial.
    a_dials: bool,
    /// B has an address to dial. Both together is the simultaneous-open case.
    b_dials: bool,
}

impl Shape {
    /// The ordinary case: A dials B, B learns A's address by roaming.
    const ROAMING: Self = Self {
        a_dials: true,
        b_dials: false,
    };
    /// Both ends can dial.
    const BOTH_DIAL: Self = Self {
        a_dials: true,
        b_dials: true,
    };
}

/// The standard two-host fixture, with optional shaping machines for A.
fn net_with(a_shaping: Vec<Machine>, shape: Shape) -> Net {
    net_full(a_shaping, shape, None, None)
}

/// As [`net_with`], and each end may additionally be told to keep its path warm.
fn net_full(
    a_shaping: Vec<Machine>,
    shape: Shape,
    a_keepalive: Option<Duration>,
    b_keepalive: Option<Duration>,
) -> Net {
    net_full_suite(suite(), a_shaping, shape, a_keepalive, b_keepalive)
}

/// As [`net_full`], with a caller-supplied suite — how the P6.8 gate counts KEM
/// operations without changing what the tunnel does.
fn net_full_suite(
    suite: Arc<dyn CryptoSuite>,
    a_shaping: Vec<Machine>,
    shape: Shape,
    a_keepalive: Option<Duration>,
    b_keepalive: Option<Duration>,
) -> Net {
    let a_identity = StaticIdentity::generate(&*suite, &A_SEED).expect("a key");
    let b_identity = StaticIdentity::generate(&*suite, &B_SEED).expect("a key");

    let mut a_peer =
        PeerConfig::new("b", b_identity.to_peer()).with_allowed_ips([net("10.0.0.2/32")]);
    if shape.a_dials {
        a_peer = a_peer.with_endpoint(endpoint(B_EP));
    }
    if let Some(interval) = a_keepalive {
        a_peer = a_peer.with_persistent_keepalive(interval);
    }
    if !a_shaping.is_empty() {
        a_peer = a_peer.with_shaping(a_shaping);
    }

    let mut b_peer =
        PeerConfig::new("a", a_identity.to_peer()).with_allowed_ips([net("10.0.0.1/32")]);
    if shape.b_dials {
        b_peer = b_peer.with_endpoint(endpoint(A_EP));
    }
    if let Some(interval) = b_keepalive {
        b_peer = b_peer.with_persistent_keepalive(interval);
    }

    let a = Device::new(
        suite.clone(),
        a_identity,
        vec![a_peer],
        &mut TestRng(0x1111),
        0,
    )
    .expect("A's configuration is consistent");
    let b = Device::new(suite, b_identity, vec![b_peer], &mut TestRng(0x2222), 0)
        .expect("B's configuration is consistent");

    Net {
        clock_ms: 0,
        wall_s: 1_700_000_000,
        hosts: vec![
            Host::new(a, endpoint(A_EP), 0xAAAA),
            Host::new(b, endpoint(B_EP), 0xBBBB),
        ],
        drop_types: Vec::new(),
    }
}

fn two_hosts() -> Net {
    net_with(Vec::new(), Shape::ROAMING)
}

// ── the gate ─────────────────────────────────────────────────────────

#[test]
fn two_hosts_establish_and_carry_traffic_both_ways() {
    let mut net = two_hosts();

    // A has a packet for B and no session yet: it must hold the packet and start
    // a handshake rather than discard the packet.
    let ping = ipv4(A_IP, B_IP, b"ping");
    net.outbound(0, ping.clone());
    net.settle();

    assert!(net.hosts[0].established_once(), "A never established");
    assert!(net.hosts[1].established_once(), "B never established");
    assert_eq!(
        net.hosts[0].established,
        vec![(net.hosts[0].peer_id(), 0, Role::Initiator)]
    );
    assert_eq!(
        net.hosts[1].established,
        vec![(net.hosts[1].peer_id(), 0, Role::Responder)]
    );

    // The packet that started it all arrives, byte for byte.
    assert_eq!(net.hosts[1].delivered, vec![ping]);

    // B was never told A's address: it learned it from the handshake, and only
    // committed it once A proved the key.
    let a_peer = net.hosts[1].peer_id();
    assert_eq!(net.hosts[1].device.endpoint(a_peer), Some(endpoint(A_EP)));

    // ...and traffic flows the other way too.
    let pong = ipv4(B_IP, A_IP, b"pong");
    net.outbound(1, pong.clone());
    net.settle();
    assert_eq!(net.hosts[0].delivered, vec![pong]);

    let stats = net.hosts[1].stats();
    assert_eq!(stats.delivered, 1);
    assert_eq!(stats.rejected, 0);
    assert_eq!(stats.queued, 0);
}

#[test]
fn a_second_packet_rides_the_established_session_with_no_handshake() {
    let mut net = two_hosts();
    net.outbound(0, ipv4(A_IP, B_IP, b"one"));
    net.settle();

    let datagrams = net.hosts[0].sent.len();
    net.advance(100);
    net.outbound(0, ipv4(A_IP, B_IP, b"two"));
    net.settle();

    // Exactly one more datagram went out, and it was the data packet.
    assert_eq!(net.hosts[0].sent.len(), datagrams + 1);
    assert_eq!(
        net.hosts[1].delivered,
        vec![ipv4(A_IP, B_IP, b"one"), ipv4(A_IP, B_IP, b"two")]
    );
}

// ── the anti-spoofing rule ───────────────────────────────────────────

#[test]
fn a_packet_claiming_an_address_the_peer_does_not_own_is_rejected() {
    let mut net = two_hosts();
    net.outbound(0, ipv4(A_IP, B_IP, b"hello"));
    net.settle();
    assert_eq!(net.hosts[1].delivered.len(), 1);

    // A's interface emits a packet whose source is *not* in the range B granted
    // it. A does not police its own sources — the receiving end does, because
    // that is the only place a peer cannot lie its way past.
    net.outbound(0, ipv4([10, 9, 9, 9], B_IP, b"spoofed"));
    net.settle();

    assert_eq!(
        net.hosts[1].delivered.len(),
        1,
        "a spoofed source address was delivered"
    );
    assert_eq!(net.hosts[1].stats().rejected, 1);
}

#[test]
fn a_destination_no_peer_claims_is_dropped_locally() {
    let mut net = two_hosts();
    net.outbound(0, ipv4(A_IP, [192, 168, 1, 1], b"nowhere"));
    net.settle();
    assert!(
        net.hosts[0].sent.is_empty(),
        "a packet with no route went out"
    );
    assert!(net.hosts[1].delivered.is_empty());
}

// ── replay ───────────────────────────────────────────────────────────

#[test]
fn a_replayed_data_packet_is_not_delivered_twice() {
    let mut net = two_hosts();
    net.outbound(0, ipv4(A_IP, B_IP, b"first"));
    net.settle();

    let datagram = net.hosts[0].sent.last().expect("a data packet").clone();
    let source = net.hosts[0].endpoint;

    // The exact bytes B already opened, a second time. The sliding window has
    // accepted the counter, so this is a replay and must be refused — after the
    // tag is verified, so the refusal is not itself an oracle.
    net.hosts[1].inbox.push_back((source, datagram));
    net.pump(2);
    assert_eq!(
        net.hosts[1].delivered.len(),
        1,
        "a replayed packet was delivered"
    );
    assert_eq!(net.hosts[1].stats().rejected, 1);
}

// ── hostile input ────────────────────────────────────────────────────

#[test]
fn junk_datagrams_are_dropped_without_effect() {
    let mut net = two_hosts();
    net.outbound(0, ipv4(A_IP, B_IP, b"hello"));
    net.settle();

    let source = endpoint("203.0.113.9:1");
    let mut cases: Vec<Vec<u8>> = vec![
        // Empty, truncated, absurdly long.
        Vec::new(),
        vec![0x01],
        vec![0x01; 4],
        vec![0xFF; MAX_HANDSHAKE_MESSAGE + 64],
        // A plausible header with nothing behind it.
        vec![0x01, 0x04, 0x00, 0x03, 0xDE, 0xAD, 0xBE, 0xEF],
        // A data packet naming an index nothing owns.
        vec![0x01, 0x04, 0x00, 0x03, 0xFF, 0xFF, 0xFF, 0xFF],
        // A well-formed `Data` with a bogus counter and ciphertext.
        vec![
            0x01, 0x04, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, // Data, index 1
            0x00, 0x06, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, // counter 0
            0x00, 0x40, 0x00, 0x14, // DATA_CT, 20 bytes
            0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45,
            0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
        ],
    ];
    // A plausible header for every message type, with no fields behind it.
    for kind in 0x01..=0x06u8 {
        cases.push(vec![0x01, kind, 0x00, 0x03, 0xDE, 0xAD, 0xBE, 0xEF]);
    }

    for bytes in cases {
        net.hosts[1].inbox.push_back((source, bytes));
        net.pump(2);
    }

    // Nothing was delivered, the session survived, and the link still works.
    assert_eq!(net.hosts[1].delivered.len(), 1);
    assert_eq!(net.hosts[1].established.len(), 1);
    net.outbound(0, ipv4(A_IP, B_IP, b"still-here"));
    net.settle();
    assert_eq!(net.hosts[1].delivered.len(), 2);
}

#[test]
fn a_wrong_suite_id_is_ignored() {
    let mut net = two_hosts();
    // Suite 0x0100 is reserved for a future, non-NIST suite. A peer speaking it is
    // not one of ours, and must not be answered or acted on.
    let datagram = vec![
        0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, // InitHello, suite 0x0100
        0x00, 0x01, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF,
    ];
    net.hosts[1]
        .inbox
        .push_back((endpoint("203.0.113.9:1"), datagram));
    net.pump(2);
    assert!(net.hosts[1].sent.is_empty());
    assert!(net.hosts[1].established.is_empty());
}

// ── the cookie gate under load ───────────────────────────────────────

#[test]
fn an_under_load_responder_makes_the_initiator_prove_its_address() {
    let mut net = two_hosts();
    net.hosts[1].device.set_under_load(true);

    net.outbound(0, ipv4(A_IP, B_IP, b"knock"));

    // The first thing A sends is an `InitHello`; B, under load, answers it with a
    // cookie rather than doing the KEM work.
    assert_eq!(net.hosts[0].sent.len(), 1);
    assert_eq!(
        Message::parse(&net.hosts[0].sent[0])
            .expect("a message")
            .message_type(),
        MessageType::InitHello
    );

    net.settle();

    assert!(
        net.hosts[1].established_once(),
        "the cookie retry never completed"
    );
    assert_eq!(net.hosts[1].delivered, vec![ipv4(A_IP, B_IP, b"knock")]);

    // A retried exactly once, and the retry carried a `mac2`.
    let inits: Vec<&Vec<u8>> = net.hosts[0]
        .sent
        .iter()
        .filter(|bytes| {
            Message::parse(bytes).is_ok_and(|m| m.message_type() == MessageType::InitHello)
        })
        .collect();
    assert_eq!(inits.len(), 2, "A did not retry the handshake exactly once");
    assert!(
        inits[1].len() > inits[0].len(),
        "the retry did not carry a mac2"
    );
}

// ── simultaneity ─────────────────────────────────────────────────────

#[test]
fn simultaneous_initiation_converges_on_one_session() {
    let mut net = net_with(Vec::new(), Shape::BOTH_DIAL);

    // Both sides have an address to dial and both want to send. This is the
    // ordinary case on a real link, and the case that deadlocks if both ends
    // insist on being the initiator.
    net.outbound(0, ipv4(A_IP, B_IP, b"from-a"));
    net.outbound(1, ipv4(B_IP, A_IP, b"from-b"));
    net.settle();

    assert!(net.hosts[0].established_once(), "A never converged");
    assert!(net.hosts[1].established_once(), "B never converged");
    // Exactly one session each: a second `Established` would mean the tie was
    // broken twice, in opposite directions.
    assert_eq!(net.hosts[0].established.len(), 1);
    assert_eq!(net.hosts[1].established.len(), 1);
    assert_eq!(net.hosts[0].established[0].1, 0);
    assert_eq!(net.hosts[1].established[0].1, 0);
    // The two ends agree on who initiated.
    assert_ne!(net.hosts[0].established[0].2, net.hosts[1].established[0].2);

    assert_eq!(net.hosts[1].delivered, vec![ipv4(A_IP, B_IP, b"from-a")]);
    assert_eq!(net.hosts[0].delivered, vec![ipv4(B_IP, A_IP, b"from-b")]);
}

// ── a lost message ───────────────────────────────────────────────────

#[test]
fn a_lost_init_conf_is_retransmitted_until_the_responder_answers() {
    let mut net = two_hosts();
    // Swallow exactly the `InitConf` that A sends.
    net.drop_types.push(MessageType::InitConf);

    net.outbound(0, ipv4(A_IP, B_IP, b"payload"));

    // A's `InitHello` reaches B, B answers, A completes as initiator and sends an
    // `InitConf` that is dropped. B is left waiting for it.
    net.pump(8);

    assert!(net.hosts[0].established_once(), "the initiator side failed");
    assert!(
        !net.hosts[1].established_once(),
        "the responder completed without the confirmation"
    );
    assert!(
        net.hosts[1].delivered.is_empty(),
        "traffic flowed before the handshake completed"
    );

    // The retransmission timer is `REKEY_TIMEOUT_MS`; past it, A repeats.
    net.advance(6_000);
    net.settle();

    assert!(
        net.hosts[1].established_once(),
        "the responder never recovered a lost confirmation"
    );

    // The packet A was holding went out as soon as A believed the handshake was
    // done — which was before B had keys — so it was lost. That is the honest
    // cost of a lost third message, and it is recovered by the *next* packet
    // rather than by buffering one for a peer with no session.
    assert!(
        net.hosts[1].delivered.is_empty(),
        "a packet arrived before the responder had keys"
    );
    net.outbound(0, ipv4(A_IP, B_IP, b"after"));
    net.settle();
    assert_eq!(net.hosts[1].delivered, vec![ipv4(A_IP, B_IP, b"after")]);
}

#[test]
fn a_lost_resp_hello_is_recovered_by_the_initiator() {
    let mut net = two_hosts();
    net.drop_types.push(MessageType::RespHello);
    net.outbound(0, ipv4(A_IP, B_IP, b"payload"));

    net.pump(8);
    assert!(!net.hosts[0].established_once());
    // The handshake is retried, not abandoned: a forged or lost reply must not
    // end the attempt.
    assert!(net.hosts[0]
        .device
        .handshake_in_flight(net.hosts[0].peer_id()));

    // Both ends retransmit now, on the same tick. The responder must reuse the
    // answer it already had rather than allocate a new index: if it did not, the
    // initiator's confirmation would name an index the responder had discarded and
    // the handshake would stall until both sides gave up.
    net.advance(6_000);
    net.settle();

    assert_eq!(
        net.hosts[0].established.len(),
        1,
        "A established more than once"
    );
    assert_eq!(
        net.hosts[1].established.len(),
        1,
        "B established more than once"
    );
    assert_eq!(net.hosts[1].delivered, vec![ipv4(A_IP, B_IP, b"payload")]);
    assert_eq!(
        net.hosts[0].device.endpoint(net.hosts[0].peer_id()),
        Some(endpoint(B_EP))
    );
}

#[test]
fn a_repeated_initiation_is_answered_from_the_cache() {
    // The confirmation is lost, so the responder stays in `Responding` and the
    // initiator retransmits its `InitHello` — byte for byte, same index.
    let mut net = two_hosts();
    net.drop_types.push(MessageType::InitConf);
    net.outbound(0, ipv4(A_IP, B_IP, b"x"));
    net.pump(8);
    assert!(!net.hosts[1].established_once());
    assert_eq!(net.hosts[1].sent.len(), 1, "B answered once");

    let answer = net.hosts[1].sent[0].clone();
    let initiation = net.hosts[0].sent[0].clone();
    let source = net.hosts[0].endpoint;

    // The same initiation again, with no clock movement.
    net.hosts[1].inbox.push_back((source, initiation));
    net.pump(2);

    assert_eq!(
        net.hosts[1].sent.len(),
        2,
        "the repeated initiation was not answered exactly once"
    );
    assert_eq!(
        net.hosts[1].sent[1], answer,
        "the retransmitted initiation was given a fresh answer, not the cached one"
    );
    // The responder is still where it was, holding the same index.
    assert!(!net.hosts[1].established_once());
}

#[test]
fn a_lost_init_hello_is_recovered_by_the_initiator() {
    let mut net = two_hosts();
    net.drop_types.push(MessageType::InitHello);
    net.outbound(0, ipv4(A_IP, B_IP, b"payload"));

    net.pump(8);
    assert!(net.hosts[1].established.is_empty());

    net.advance(6_000);
    net.settle();
    assert!(net.hosts[0].established_once());
    assert!(net.hosts[1].established_once());
    assert_eq!(net.hosts[1].delivered, vec![ipv4(A_IP, B_IP, b"payload")]);
}

// ── the handshake is a real handshake ────────────────────────────────

#[test]
fn a_peer_configured_with_the_wrong_key_cannot_establish() {
    let suite = suite();
    let a_identity = StaticIdentity::generate(&*suite, &A_SEED).expect("a key");
    let a_public = a_identity.to_peer();
    // A holds the *wrong* public key for B: B's real private key is not the one A
    // is configured for, so A's `mac1` cannot verify and no confirmation can
    // match. B's own private key is a third, unrelated one.
    let stranger = StaticIdentity::generate(&*suite, &[0xC3; 32]).expect("a key");

    let a = Device::new(
        suite.clone(),
        a_identity,
        vec![PeerConfig::new("b", stranger.to_peer())
            .with_allowed_ips([net("10.0.0.2/32")])
            .with_endpoint(endpoint(B_EP))],
        &mut TestRng(0x1111),
        0,
    )
    .expect("A's configuration is consistent");
    let unrelated = StaticIdentity::generate(&*suite, &[0xD4; 32]).expect("a key");
    let b = Device::new(
        suite,
        unrelated,
        vec![PeerConfig::new("a", a_public).with_allowed_ips([net("10.0.0.1/32")])],
        &mut TestRng(0x2222),
        0,
    )
    .expect("B's configuration is consistent");

    let mut net = Net {
        clock_ms: 0,
        wall_s: 1_700_000_000,
        hosts: vec![
            Host::new(a, endpoint(A_EP), 0xAAAA),
            Host::new(b, endpoint(B_EP), 0xBBBB),
        ],
        drop_types: Vec::new(),
    };

    net.outbound(0, ipv4(A_IP, B_IP, b"should-not-arrive"));
    // Well past every retry and give-up window.
    net.settle_over(10_000, 30);

    assert!(
        !net.hosts[0].established_once(),
        "a wrong key still produced a session"
    );
    assert!(!net.hosts[1].established_once());
    assert!(net.hosts[1].delivered.is_empty());
}

// ── shaping ──────────────────────────────────────────────────────────

#[test]
fn a_pad_machine_fixes_the_sealed_size_of_every_data_packet() {
    let mut net = net_with(vec![Machine::pad_to_size(512)], Shape::ROAMING);
    let tag = suite().sizes().aead_tag;

    net.outbound(0, ipv4(A_IP, B_IP, b"tiny"));
    net.settle();

    let data = net.hosts[0]
        .sent
        .iter()
        .rev()
        .find(|bytes| Message::parse(bytes).is_ok_and(|m| m.message_type() == MessageType::Data))
        .expect("a data packet");
    // header + COUNTER field (framing + value) + DATA_CT framing + target + tag.
    let expected = HEADER_LEN + 4 + 8 + 4 + 512 + tag;
    assert_eq!(
        data.len(),
        expected,
        "the pad target did not reach the wire"
    );

    // The peer strips the padding and delivers the packet unchanged.
    net.outbound(0, ipv4(A_IP, B_IP, b"second"));
    net.settle();
    assert_eq!(
        net.hosts[1].delivered,
        vec![ipv4(A_IP, B_IP, b"tiny"), ipv4(A_IP, B_IP, b"second")]
    );
}

#[test]
fn a_min_interval_machine_holds_and_then_releases_traffic() {
    let mut net = net_with(vec![Machine::min_interval(50)], Shape::ROAMING);

    // Establish first: this send arms the interval.
    net.outbound(0, ipv4(A_IP, B_IP, b"first"));
    net.settle();
    assert_eq!(net.hosts[1].delivered.len(), 1);

    // Two more packets in the same instant. The machine has just sent, so it is
    // holding: both are queued, not sent.
    net.outbound(0, ipv4(A_IP, B_IP, b"second"));
    net.outbound(0, ipv4(A_IP, B_IP, b"third"));
    net.pump(4);
    assert_eq!(net.hosts[1].delivered.len(), 1, "the interval held nothing");
    assert_eq!(
        net.hosts[0].stats().queued,
        2,
        "the held packets are unaccounted for"
    );

    // Past each interval, one packet drains and the machine re-arms.
    net.settle_over(60, 4);
    assert_eq!(
        net.hosts[1].delivered,
        vec![
            ipv4(A_IP, B_IP, b"first"),
            ipv4(A_IP, B_IP, b"second"),
            ipv4(A_IP, B_IP, b"third"),
        ]
    );
    assert_eq!(net.hosts[0].stats().queued, 0);
}

// ── keepalive policy ─────────────────────────────────────────────────

/// A configured interval is a *cadence*: due at the interval, twice the
/// interval, and nowhere in between.
#[test]
fn a_persistent_keepalive_is_sent_once_per_interval() {
    let mut net = net_full(
        Vec::new(),
        Shape::ROAMING,
        None,
        Some(Duration::from_millis(1_000)),
    );

    // Establish, then let the link go quiet: B has nothing of its own to send.
    net.outbound(0, ipv4(A_IP, B_IP, b"hello"));
    net.settle();
    assert!(net.hosts[1].established_once());
    let before = net.hosts[1].sent.len();

    // Short of the interval, nothing.
    net.advance(999);
    net.pump(1);
    assert_eq!(net.hosts[1].sent.len(), before, "not due yet");

    // On the interval, exactly one empty packet.
    net.advance(1);
    net.pump(1);
    assert_eq!(net.hosts[1].sent.len(), before + 1, "one keepalive");

    // The next deadline is the next interval, not the next tick.
    net.advance(999);
    net.pump(1);
    assert_eq!(net.hosts[1].sent.len(), before + 1, "still not due");
    net.advance(1);
    net.pump(1);
    assert_eq!(net.hosts[1].sent.len(), before + 2, "and another");
}

/// With no session, a keepalive is a *dial*: the peer a NAT forgot is the peer
/// that never spoke, so the interval has to make it speak.
#[test]
fn a_persistent_keepalive_peer_with_no_session_dials_itself() {
    // Both ends *can* dial; only B is told to. Nothing is ever sent by hand.
    let mut net = net_full(
        Vec::new(),
        Shape::BOTH_DIAL,
        None,
        Some(Duration::from_millis(1_000)),
    );

    net.advance(999);
    net.pump(4);
    assert!(
        !net.hosts[1].established_once(),
        "no dial before the interval"
    );

    net.advance(1);
    net.pump(4);
    net.settle();
    assert_eq!(
        net.hosts[1].established.first().map(|(_, _, role)| *role),
        Some(Role::Initiator),
        "B reached A with nothing to send"
    );
    assert_eq!(
        net.hosts[0].established.first().map(|(_, _, role)| *role),
        Some(Role::Responder)
    );
}

/// With no interval configured a tunnel is silent when idle: the field is
/// opt-in, and a peer that never asked for a keepalive must not acquire one.
#[test]
fn an_idle_tunnel_without_an_interval_says_nothing() {
    let mut net = two_hosts();
    net.outbound(0, ipv4(A_IP, B_IP, b"hello"));
    net.settle();
    assert!(net.hosts[1].established_once());

    let before: usize = net.hosts.iter().map(|host| host.sent.len()).sum();
    // Four silent seconds: below the 5 s handshake-retransmit floor and far
    // below the reactive keepalive's 10 s, so any packet here would be a
    // persistent keepalive that should not exist.
    net.settle_over(1_000, 4);
    let after: usize = net.hosts.iter().map(|host| host.sent.len()).sum();
    assert_eq!(after, before, "an idle tunnel with no interval is silent");
}

/// The reactive keepalive is untouched by the policy one: a peer that spoke and
/// heard nothing is still poked after ten silent seconds.
#[test]
fn the_reactive_keepalive_still_fires_without_an_interval() {
    let mut net = two_hosts();
    net.outbound(0, ipv4(A_IP, B_IP, b"hello"));
    net.settle();
    // B answers, which is how the initiator learns the handshake is finished.
    net.outbound(1, ipv4(B_IP, A_IP, b"pong"));
    net.settle();

    // A speaks once more and hears nothing, so its idle clock starts.
    net.advance(1_000);
    net.outbound(0, ipv4(A_IP, B_IP, b"poke"));
    net.settle();
    let before = net.hosts[0].sent.len();

    // Ten silent seconds, then exactly one empty packet from A.
    net.settle_over(1_000, 12);
    assert_eq!(
        net.hosts[0].sent.len(),
        before + 1,
        "one reactive keepalive in twelve silent seconds"
    );
}

/// A keepalive is not a broadcast: a peer with no address to dial waits to be
/// called, exactly as an outbound packet would have to.
#[test]
fn a_keepalive_peer_with_no_endpoint_waits_to_be_called() {
    // B has an interval but no endpoint; A is the end that dials.
    let mut net = net_full(
        Vec::new(),
        Shape::ROAMING,
        None,
        Some(Duration::from_millis(1_000)),
    );

    net.advance(5_000);
    net.pump(4);
    for host in &net.hosts {
        assert!(
            host.sent.is_empty(),
            "nothing to send, and nobody to send it to"
        );
    }

    // Once A calls, B's interval has a path to keep warm.
    net.outbound(0, ipv4(A_IP, B_IP, b"hello"));
    net.settle();
    assert!(net.hosts[1].established_once());
}

/// At a 5 s cadence and a send at t = 5 s, the persistent deadline and the
/// reactive one coincide at t = 15 s. They are both an empty packet, so the tick
/// must emit one, not two.
#[test]
fn a_persistent_keepalive_suppresses_the_reactive_one_when_they_coincide() {
    let mut net = net_full(
        Vec::new(),
        Shape::ROAMING,
        Some(Duration::from_millis(5_000)),
        None,
    );

    net.outbound(0, ipv4(A_IP, B_IP, b"hello"));
    net.settle();
    // B answers, clearing the initiator's retransmit state so the only timer
    // left is the one under test.
    net.outbound(1, ipv4(B_IP, A_IP, b"pong"));
    net.settle();

    // A sends once at t = 5 s: the reactive deadline is now t = 15 s, which is
    // also the third persistent deadline.
    net.advance(5_000);
    net.outbound(0, ipv4(A_IP, B_IP, b"poke"));
    net.settle();
    let before = net.hosts[0].sent.len();

    // t = 10 s: the persistent keepalive alone.
    net.advance(5_000);
    net.pump(1);
    assert_eq!(net.hosts[0].sent.len(), before + 1, "the 10 s cadence");

    // t = 15 s: both rules are due; exactly one packet goes out.
    net.advance(5_000);
    net.pump(1);
    assert_eq!(
        net.hosts[0].sent.len(),
        before + 2,
        "one packet where the two rules meet"
    );
}

// ── the queue is bounded ─────────────────────────────────────────────

#[test]
fn a_full_queue_drops_rather_than_grows() {
    let mut net = two_hosts();
    // Hold the queue open by never giving B an address to answer... instead, keep
    // A from establishing by dropping every `InitHello`, so A queues while it
    // retries.
    net.drop_types.clear();
    let packet = ipv4(A_IP, B_IP, b"x");
    for _ in 0..(vallum_tunnel::MAX_QUEUED_PACKETS + 32) {
        net.outbound(0, packet.clone());
    }
    let stats = net.hosts[0].stats();
    assert!(
        stats.queued <= vallum_tunnel::MAX_QUEUED_PACKETS,
        "the queue grew past its bound"
    );
    assert!(stats.dropped > 0, "nothing was dropped at the bound");
}

// ── configuration is validated as a whole ────────────────────────────

#[test]
fn overlapping_allowed_ips_are_refused() {
    let suite = suite();
    let a_identity = StaticIdentity::generate(&*suite, &A_SEED).expect("a key");
    let b_identity = StaticIdentity::generate(&*suite, &B_SEED).expect("a key");
    let c_identity = StaticIdentity::generate(&*suite, &[0xD4; 32]).expect("a key");

    let result = Device::new(
        suite,
        a_identity,
        vec![
            PeerConfig::new("b", b_identity.to_peer()).with_allowed_ips([net("10.0.0.0/24")]),
            PeerConfig::new("c", c_identity.to_peer()).with_allowed_ips([net("10.0.0.128/25")]),
        ],
        &mut TestRng(1),
        0,
    );

    match result {
        Err(vallum_tunnel::ConfigError::OverlappingAllowedIps {
            first,
            second,
            network,
        }) => {
            assert_eq!(first, "b");
            assert_eq!(second, "c");
            assert_eq!(network, net("10.0.0.128/25"));
        }
        other => panic!("expected an overlap refusal, got {other:?}"),
    }
}

#[test]
fn a_duplicate_peer_identity_is_refused() {
    let suite = suite();
    let a_identity = StaticIdentity::generate(&*suite, &A_SEED).expect("a key");
    let b_identity = StaticIdentity::generate(&*suite, &B_SEED).expect("a key");

    let result = Device::new(
        suite,
        a_identity,
        vec![
            PeerConfig::new("b", b_identity.to_peer()).with_allowed_ips([net("10.0.0.2/32")]),
            PeerConfig::new("b-again", b_identity.to_peer()).with_allowed_ips([net("10.0.0.3/32")]),
        ],
        &mut TestRng(1),
        0,
    );

    assert!(matches!(
        result,
        Err(vallum_tunnel::ConfigError::DuplicatePeer { .. })
    ));
}

#[test]
fn a_duplicate_peer_with_a_different_psk_is_still_a_duplicate() {
    let suite = suite();
    let a_identity = StaticIdentity::generate(&*suite, &A_SEED).expect("a key");
    let b_identity = StaticIdentity::generate(&*suite, &B_SEED).expect("a key");

    let result = Device::new(
        suite,
        a_identity,
        vec![
            PeerConfig::new("b", b_identity.to_peer())
                .with_allowed_ips([net("10.0.0.2/32")])
                .with_preshared_key(SharedSecret::new([0x11; 32])),
            PeerConfig::new("b-again", b_identity.to_peer())
                .with_allowed_ips([net("10.0.0.3/32")])
                .with_preshared_key(SharedSecret::new([0x22; 32])),
        ],
        &mut TestRng(1),
        0,
    );

    assert!(
        matches!(
            result,
            Err(vallum_tunnel::ConfigError::DuplicatePeer { .. })
        ),
        "the same KEM key is the same peer, whatever PSK it is configured with"
    );
}

#[test]
fn a_v4_and_a_v6_peer_do_not_conflict() {
    let suite = suite();
    let a_identity = StaticIdentity::generate(&*suite, &A_SEED).expect("a key");
    let b_identity = StaticIdentity::generate(&*suite, &B_SEED).expect("a key");
    let c_identity = StaticIdentity::generate(&*suite, &[0xD4; 32]).expect("a key");

    let device = Device::new(
        suite,
        a_identity,
        vec![
            PeerConfig::new("b", b_identity.to_peer()).with_allowed_ips([net("10.0.0.0/8")]),
            PeerConfig::new("c", c_identity.to_peer()).with_allowed_ips([net("2001:db8::/32")]),
        ],
        &mut TestRng(1),
        0,
    )
    .expect("v4 and v6 never conflict");

    assert_eq!(device.peer_count(), 2);
}

// ── routing ──────────────────────────────────────────────────────────

#[test]
fn routing_picks_the_peer_that_claims_the_destination() {
    let suite = suite();
    let a_identity = StaticIdentity::generate(&*suite, &A_SEED).expect("a key");
    let b_identity = StaticIdentity::generate(&*suite, &B_SEED).expect("a key");
    let c_identity = StaticIdentity::generate(&*suite, &[0xD4; 32]).expect("a key");

    let mut device = Device::new(
        suite,
        a_identity,
        vec![
            PeerConfig::new("b", b_identity.to_peer()).with_allowed_ips([net("10.0.0.2/32")]),
            PeerConfig::new("c", c_identity.to_peer()).with_allowed_ips([net("10.0.0.3/32")]),
        ],
        &mut TestRng(1),
        0,
    )
    .expect("consistent");

    // Neither peer has an address, so nothing can go out — but the routing
    // decision is observable through the queues.
    let _ = device.handle(
        Clock::new(0, Tai64n::from_unix(1, 0)),
        Event::OutboundIp {
            packet: ipv4(A_IP, [10, 0, 0, 3], b"to-c"),
        },
        &mut TestRng(9),
    );

    let ids: Vec<PeerId> = device.peers().map(|(id, _)| id).collect();
    assert_eq!(
        device.stats(ids[1]).expect("a peer").queued,
        1,
        "the packet was not routed to the peer claiming the address"
    );
    assert_eq!(device.stats(ids[0]).expect("a peer").queued, 0);
}

// ── the payload length prefix is always present ──────────────────────

#[test]
fn an_empty_payload_is_a_keepalive_and_delivers_nothing() {
    let mut net = two_hosts();
    net.outbound(0, ipv4(A_IP, B_IP, b"hello"));
    net.settle();
    let delivered = net.hosts[1].delivered.len();

    // A keepalive is a data packet with an empty payload; the peer discards it on
    // open, so it must not surface as a zero-length "packet". `KEEPALIVE_TIMEOUT`
    // is 10 s, so 11 s of quiet is enough to provoke one.
    net.settle_over(11_000, 1);
    assert_eq!(net.hosts[1].delivered.len(), delivered);

    // ...and the session is still usable afterwards.
    net.outbound(0, ipv4(A_IP, B_IP, b"after"));
    net.settle();
    assert_eq!(net.hosts[1].delivered.len(), delivered + 1);
}

// ── the index space ──────────────────────────────────────────────────

#[test]
fn a_data_packet_naming_the_reserved_index_matches_no_peer() {
    // Zero is reserved for cookie replies, which belong to no session. A data
    // packet naming it must not match any peer even before a handshake.
    let mut net = two_hosts();
    let mut datagram = vec![0x01, 0x04, 0x00, 0x03];
    datagram.extend_from_slice(&0u32.to_be_bytes());
    datagram.extend_from_slice(&[0x00, 0x06, 0x00, 0x08]);
    datagram.extend_from_slice(&0u64.to_be_bytes());
    datagram.extend_from_slice(&[0x00, 0x40, 0x00, 0x00]);
    net.hosts[1]
        .inbox
        .push_back((endpoint("203.0.113.9:1"), datagram));
    net.pump(2);
    assert!(net.hosts[1].delivered.is_empty());
    assert!(net.hosts[1].established.is_empty());
}

// ── the RespHello admission tag (P6.8) ───────────────────────────────

#[test]
fn a_forged_resp_hello_costs_no_kem_work() {
    // An attacker who observed A's `InitHello` knows A's index. It can therefore
    // address a `RespHello` to A's outstanding handshake — the cheap message.
    // Without the op-A-keyed tag, A would rebuild its state (ephemeral keygen +
    // an op-A encapsulation) and decapsulate twice before noticing. With it, the
    // forgery costs a parse and a KDF, and the handshake survives.
    let counting = Arc::new(CountingSuite::new(SdkSuite::tri_hybrid()));
    let mut net = net_full_suite(counting.clone(), Vec::new(), Shape::ROAMING, None, None);

    // A has a packet for B, so it starts a handshake. The `InitHello` is kept
    // here and never delivered: we forge the answer instead.
    net.outbound(0, ipv4(A_IP, B_IP, b"ping"));
    let init = net.hosts[0]
        .sent
        .iter()
        .find(|bytes| {
            Message::parse(bytes).is_ok_and(|m| m.message_type() == MessageType::InitHello)
        })
        .expect("A's InitHello")
        .clone();
    let index = Message::parse(&init).expect("parse").sender_index();
    let peer = net.hosts[0].peer_id();
    assert!(net.hosts[0].device.handshake_in_flight(peer));

    let header = MessageHeader {
        version: PROTOCOL_VERSION,
        message_type: MessageType::RespHello,
        suite_id: counting.suite_id(),
        sender_index: 0x0B0B_0B0B,
    };
    let mut builder = MessageBuilder::new(header);
    builder
        .field(tag::EPHEMERAL_CT, &vec![0u8; counting.sizes().kem_ct])
        .unwrap();
    builder
        .field(tag::STATIC_CT, &vec![0u8; counting.sizes().kem_ct])
        .unwrap();
    builder
        .field(tag::RECEIVER_INDEX, &index.to_be_bytes())
        .unwrap();
    builder.field(tag::CONFIRMATION, &[0u8; 32]).unwrap();
    builder.field(tag::PRE_TAG, &[0u8; 32]).unwrap();
    let forged = builder.finish().unwrap();

    let before = counting.kem_ops();
    let clock = net.clock();
    let host = &mut net.hosts[0];
    let actions = host.device.handle(
        clock,
        Event::Datagram {
            source: endpoint(B_EP),
            bytes: forged,
        },
        &mut host.rng,
    );

    assert_eq!(
        counting.kem_ops(),
        before,
        "a forged RespHello performed KEM work"
    );
    assert!(
        !actions
            .iter()
            .any(|action| matches!(action, Action::Established { .. })),
        "a forged RespHello established a session"
    );
    assert_eq!(net.hosts[0].stats().rejected, 1);
    assert!(
        net.hosts[0].device.handshake_in_flight(peer),
        "the forged answer consumed the handshake"
    );
}

// ── the timestamp is committed only once the key is proven ───────────

#[test]
fn a_forged_init_hello_cannot_lock_a_peer_out() {
    // A genuine handshake, then a forged `InitHello` claiming a far-future
    // timestamp. If the timestamp were committed on arrival, the responder would
    // then refuse A's own, genuine retransmissions forever.
    let mut net = two_hosts();
    net.outbound(0, ipv4(A_IP, B_IP, b"hello"));
    net.settle();
    assert!(net.hosts[1].established_once());

    // Forge by replaying a *real* `InitHello` from A's transcript: the reply is
    // dropped (B has no matching in-flight handshake for that index), and the
    // guard must not have been advanced by it.
    let init = net.hosts[0]
        .sent
        .iter()
        .find(|bytes| {
            Message::parse(bytes).is_ok_and(|m| m.message_type() == MessageType::InitHello)
        })
        .expect("A's InitHello")
        .clone();
    let source = net.hosts[0].endpoint;
    net.hosts[1].inbox.push_back((source, init));
    net.pump(4);
    // Whatever B chose to do with the duplicate, the session is intact.
    assert_eq!(net.hosts[1].established.len(), 1);
    net.outbound(0, ipv4(A_IP, B_IP, b"still-works"));
    net.settle();
    assert_eq!(net.hosts[1].delivered.len(), 2);
}

/// A rekey that fails until the device gives up must not kill the peer for good.
/// A fresh trigger — here an outbound packet — has to start a fresh run, with a
/// fresh retransmission budget.
#[test]
fn a_peer_that_gave_up_recovers_when_the_path_comes_back() {
    let mut net = two_hosts();
    net.outbound(0, ipv4(A_IP, B_IP, b"hello"));
    net.settle();
    assert!(net.hosts[1].established_once());

    // Black-hole the path for 220 s. A's rekey starts at 120 s, fails, and gives
    // up at 210 s; both keys expire at 180 s. Nothing is delivered throughout.
    for _ in 0..220 {
        net.advance(1_000);
        net.pump(1);
        for host in &mut net.hosts {
            host.inbox.clear();
        }
    }

    // The path is back. One packet must be enough to rebuild the tunnel.
    let before = net.hosts[1].established.len();
    net.outbound(0, ipv4(A_IP, B_IP, b"after"));
    for _ in 0..50 {
        net.pump(1);
    }
    assert_eq!(
        net.hosts[1].established.len(),
        before + 1,
        "a peer that gave up never came back"
    );
    assert_eq!(
        net.hosts[1].delivered.last(),
        Some(&ipv4(A_IP, B_IP, b"after")),
        "the packet that restarted the handshake was not delivered"
    );
}

// ── the server-restart case ──────────────────────────────────────────

/// A server that restarts loses its session but keeps its identity.
///
/// The client still holds its own session, so the next handshake completes on
/// both sides — but the epoch is a **local** counter, folded into the
/// data-plane KDF (`vallum-core/src/keys.rs`: `frame([transcript, epoch])`). A
/// server that re-establishes at epoch 0 while the client advances to epoch 1
/// derives a *different* data-plane root, so the two ends cannot open each
/// other's packets even though the handshake succeeded.
///
/// This is the shape of ADR-0019's measured symptom: the client re-establishes
/// successfully every 120 s and traffic still does not return.
///
/// The fix (epoch negotiation on the wire, ADR-0019) is in, so this runs in
/// the gate: it fails again if a change reintroduces the divergence.
#[test]
fn a_server_that_restarts_and_loses_its_session_still_carries_traffic() {
    let suite = suite();
    let a_identity = StaticIdentity::generate(&*suite, &A_SEED).expect("a key");
    let b_identity = StaticIdentity::generate(&*suite, &B_SEED).expect("b key");

    let a_peer = PeerConfig::new("b", b_identity.to_peer())
        .with_allowed_ips([net("10.0.0.2/32")])
        .with_endpoint(endpoint(B_EP));
    let b_peer = PeerConfig::new("a", a_identity.to_peer()).with_allowed_ips([net("10.0.0.1/32")]);

    let a_peer_identity = a_identity.to_peer();
    let a = Device::new(
        suite.clone(),
        a_identity,
        vec![a_peer],
        &mut TestRng(0x1111),
        0,
    )
    .expect("A's configuration is consistent");
    let b = Device::new(
        suite.clone(),
        b_identity,
        vec![b_peer],
        &mut TestRng(0x2222),
        0,
    )
    .expect("B's configuration is consistent");

    let mut link = Net {
        clock_ms: 0,
        wall_s: 1_700_000_000,
        hosts: vec![
            Host::new(a, endpoint(A_EP), 0xAAAA),
            Host::new(b, endpoint(B_EP), 0xBBBB),
        ],
        drop_types: Vec::new(),
    };

    // First handshake: both ends establish at epoch 0 and traffic flows.
    link.outbound(0, ipv4(A_IP, B_IP, b"before"));
    link.settle();
    assert_eq!(link.hosts[1].delivered, vec![ipv4(A_IP, B_IP, b"before")]);

    // The server restarts: it keeps its identity and its peer configuration,
    // and loses its session — exactly what a daemon restart does.
    let restarted_b_identity =
        StaticIdentity::generate(&*suite, &B_SEED).expect("the restarted server's key");
    let restarted_b = Device::new(
        suite,
        restarted_b_identity,
        vec![PeerConfig::new("a", a_peer_identity).with_allowed_ips([net("10.0.0.1/32")])],
        &mut TestRng(0x2222),
        0,
    )
    .expect("the restarted server's configuration is consistent");
    link.hosts[1].device = restarted_b;
    link.hosts[1].established.clear();
    link.hosts[1].delivered.clear();

    // The client rekeys on its own 120 s timer. Both ends must end up with a
    // session, and traffic must flow.
    link.advance(130_000);
    link.pump(8);

    let epoch_a = link.hosts[0].device.epoch(link.hosts[0].peer_id());
    let epoch_b = link.hosts[1].device.epoch(link.hosts[1].peer_id());
    assert!(
        epoch_a.is_some() && epoch_b.is_some(),
        "the tunnel did not re-establish: A={epoch_a:?} B={epoch_b:?}"
    );
    eprintln!("PROBE epoch_a={epoch_a:?} epoch_b={epoch_b:?}");

    link.outbound(0, ipv4(A_IP, B_IP, b"after"));
    link.settle();
    assert_eq!(
        link.hosts[1].delivered,
        vec![ipv4(A_IP, B_IP, b"after")],
        "the tunnel re-established but carries no traffic"
    );
}

/// The restart the other way round: the **client** restarts while the server
/// keeps its live session.
///
/// The restarted client has no session and claims epoch `0`; the server's
/// counter is already past it. The agreement rule ADR-0019 fixed exists for
/// exactly this case: the responder agrees an epoch at least as high as its
/// own next, so the two ends meet at `1` rather than deriving at `0` and `1` —
/// the same divergence the server-restart test pins, mirrored.
#[test]
fn a_client_that_restarts_reconnects_while_the_server_keeps_its_session() {
    let suite = suite();
    let a_identity = StaticIdentity::generate(&*suite, &A_SEED).expect("a key");
    let b_identity = StaticIdentity::generate(&*suite, &B_SEED).expect("b key");

    let a_peer = PeerConfig::new("b", b_identity.to_peer())
        .with_allowed_ips([net("10.0.0.2/32")])
        .with_endpoint(endpoint(B_EP));
    let b_peer = PeerConfig::new("a", a_identity.to_peer()).with_allowed_ips([net("10.0.0.1/32")]);

    let b_peer_identity = b_identity.to_peer();
    let a = Device::new(
        suite.clone(),
        a_identity,
        vec![a_peer],
        &mut TestRng(0x1111),
        0,
    )
    .expect("A's configuration is consistent");
    let b = Device::new(
        suite.clone(),
        b_identity,
        vec![b_peer],
        &mut TestRng(0x2222),
        0,
    )
    .expect("B's configuration is consistent");

    let mut link = Net {
        clock_ms: 0,
        wall_s: 1_700_000_000,
        hosts: vec![
            Host::new(a, endpoint(A_EP), 0xAAAA),
            Host::new(b, endpoint(B_EP), 0xBBBB),
        ],
        drop_types: Vec::new(),
    };

    // First handshake: both ends establish at epoch 0 and traffic flows.
    link.outbound(0, ipv4(A_IP, B_IP, b"before"));
    link.settle();
    assert_eq!(link.hosts[1].delivered, vec![ipv4(A_IP, B_IP, b"before")]);

    // The client restarts: fresh identity cache, no session, counter at zero.
    // The server keeps everything. The wall clock moves first, so the restarted
    // client's `InitHello` timestamp is fresh under the server's anti-replay
    // guard — in a real restart, wall time moved too.
    link.advance(2_000);
    link.pump(4);

    let restarted_a_identity =
        StaticIdentity::generate(&*suite, &A_SEED).expect("the restarted client's key");
    let restarted_a = Device::new(
        suite,
        restarted_a_identity,
        vec![PeerConfig::new("b", b_peer_identity)
            .with_allowed_ips([net("10.0.0.2/32")])
            .with_endpoint(endpoint(B_EP))],
        &mut TestRng(0x1111),
        0,
    )
    .expect("the restarted client's configuration is consistent");
    link.hosts[0].device = restarted_a;
    link.hosts[0].established.clear();

    // The first packet the restarted client sends drives a fresh handshake.
    // Both ends must agree on the epoch and traffic must flow.
    link.outbound(0, ipv4(A_IP, B_IP, b"after"));
    link.settle();

    let epoch_a = link.hosts[0].device.epoch(link.hosts[0].peer_id());
    let epoch_b = link.hosts[1].device.epoch(link.hosts[1].peer_id());
    assert_eq!(
        epoch_a, epoch_b,
        "the ends did not agree on an epoch after the client restarted"
    );
    assert!(
        epoch_a.is_some(),
        "the tunnel did not re-establish: A={epoch_a:?} B={epoch_b:?}"
    );

    link.outbound(0, ipv4(A_IP, B_IP, b"second"));
    link.settle();
    assert_eq!(
        link.hosts[1].delivered,
        vec![
            ipv4(A_IP, B_IP, b"before"),
            ipv4(A_IP, B_IP, b"after"),
            ipv4(A_IP, B_IP, b"second"),
        ],
        "the tunnel re-established but carries no traffic"
    );
}
