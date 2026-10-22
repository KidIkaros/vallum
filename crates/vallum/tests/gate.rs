// SPDX-License-Identifier: Apache-2.0

//! P6.4's gate: two *daemons*, not two devices.
//!
//! P6.3 proved the transport with a harness that fed it events by hand. This file
//! proves the layer above: the same two hosts, but each one configured from a TOML
//! file, keyed from a key file on disk, reading and writing through an interface
//! trait, driven by a real thread loop over a real (in-process) network.
//!
//! Everything the loop would get from the kernel is substituted once, at the one
//! seam each thing has:
//!
//! | the real thing | here |
//! | --- | --- |
//! | `/dev/net/tun` | [`vallum::tun::mock`] — a pair of channels |
//! | `UdpSocket` | [`MemoryNetwork`] — mailboxes keyed by `SocketAddr` |
//! | `Instant` / `SystemTime` | [`MockClock`] — set by hand, never advances |
//!
//! What is *not* substituted is any of the logic: the config parser, the key
//! encoder, the peer table, the handshake, the timers, the routing checks. A test
//! here fails if any of them breaks.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use vallum::clock::{MockClock, TimeSource};
use vallum::config::{Config, ResolveConfig, Resolved};
use vallum::entropy::OsRng;
use vallum::keys;
use vallum::logging::{Level, Logger};
use vallum::net::{DatagramSocket, MemoryNetwork, MemorySocket};
use vallum::run::{self, LoopStats, Shutdown};
use vallum::tun;
use vallum::Error;
use vallum_core::identity::PeerIdentity;
use vallum_crypto::{CryptoSuite, KemPublicKey};
use vallum_crypto_sdk::SdkSuite;
use vallum_tunnel::Device;

// ── fixtures ─────────────────────────────────────────────────────────

const SUITE: u16 = 0x0003;
const A_IP: &str = "10.7.0.1";
const B_IP: &str = "10.7.0.2";
const A_EP: &str = "203.0.113.9:51820";
const B_EP: &str = "198.51.100.4:51820";
const A_SEED: [u8; 32] = [0xA1; 32];
const B_SEED: [u8; 32] = [0xB2; 32];

/// A fixed wall clock reading, so a handshake timestamp is reproducible.
const WALL_SECS: u64 = 1_700_000_000;

/// A short bound for "this must not arrive".
const QUIET: Duration = Duration::from_millis(400);

/// A long bound for "this must arrive": generous, because a loaded test host is
/// slow and a false failure here would be a bad test.
const PATIENT: Duration = Duration::from_secs(10);

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

/// A directory that cleans up after itself.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "vallum-gate-{tag}-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Only the fields the device reads: the version nibble, the two addresses, and
/// a payload to compare byte for byte.
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

fn a_packet(from: &str, to: &str, payload: &[u8]) -> Vec<u8> {
    ipv4(octets(from), octets(to), payload)
}

fn octets(dotted: &str) -> [u8; 4] {
    let mut out = [0u8; 4];
    for (slot, part) in out.iter_mut().zip(dotted.split('.')) {
        *slot = part.parse().expect("dotted quad");
    }
    out
}

fn suite() -> SdkSuite {
    SdkSuite::tri_hybrid()
}

fn socket_address(text: &str) -> SocketAddr {
    text.parse().expect("socket address")
}

// ── the key-and-config path, exactly as the CLI walks it ─────────────

/// A host's key file, written to disk, and the public line a peer must carry.
struct Prepared {
    name: String,
    secret: keys::SecretFile,
    public: String,
}

/// Write a key file the way `vallum keygen` does, then read the public line back
/// the way `vallum pubkey` does.
fn prepare(dir: &Path, name: &str, seed: [u8; 32]) -> Prepared {
    let secret = keys::new_secret(SUITE, false, seed);
    let key_path = dir.join(format!("{name}.key"));
    keys::save_secret(&key_path, &secret).expect("write key file");

    let reloaded = keys::load_secret(&key_path).expect("read key file back");
    assert_eq!(
        reloaded.seed, secret.seed,
        "the key file did not round trip"
    );

    let identity = keys::identity(&suite(), &reloaded).expect("expand the key");
    Prepared {
        name: name.to_owned(),
        public: keys::encode_public(SUITE, &identity.to_peer()),
        secret,
    }
}

fn config_text(
    name: &str,
    key_path: &Path,
    address: &str,
    listen: SocketAddr,
    level: Level,
    peers: &str,
) -> String {
    format!(
        "[interface]\n\
         name = \"{name}\"\n\
         private_key = \"{}\"\n\
         address = \"{address}\"\n\
         listen = \"{listen}\"\n\
         \n\
         [log]\n\
         level = \"{}\"\n\
         \n\
         {peers}",
        key_path.display(),
        level.as_str(),
    )
}

/// Write a config file and run it through the real parser and validator.
fn resolve_text(dir: &Path, name: &str, text: &str) -> Result<Resolved, Error> {
    let path = dir.join(format!("{name}.toml"));
    fs::write(&path, text).expect("write config");
    Config::load(&path)?.resolve(&path, &suite())
}

/// A peer table entry, as an operator would write it.
fn peer_entry(name: &str, public: &str, endpoint: Option<SocketAddr>, allowed: &[&str]) -> String {
    let allowed = allowed
        .iter()
        .map(|net| format!("\"{net}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let endpoint = endpoint.map_or_else(String::new, |ep| format!("endpoint = \"{ep}\"\n"));
    format!(
        "[[peer]]\n\
         name = \"{name}\"\n\
         public_key = \"{public}\"\n\
         {endpoint}\
         allowed_ips = [{allowed}]\n"
    )
}

// ── a running daemon ─────────────────────────────────────────────────

/// One daemon, running in a thread, with the two ends a test needs.
struct Host {
    name: String,
    interface: tun::mock::MockInterface,
    shutdown: Shutdown,
    join: Option<JoinHandle<Result<LoopStats, Error>>>,
}

impl Host {
    /// Hand a packet to the kernel side, as if the host had sent it.
    fn send(&self, packet: Vec<u8>) {
        self.interface
            .inject(packet)
            .expect("inject into the interface");
    }

    /// The next packet the daemon delivered, or `None` within `within`.
    fn receive(&self, within: Duration) -> Option<Vec<u8>> {
        self.interface.next_delivered_within(within)
    }

    /// Stop the loop and collect what it did.
    fn stop(&mut self) -> LoopStats {
        self.shutdown.trigger();
        let join = self.join.take().expect("host stopped once");
        join.join()
            .expect("the loop thread panicked")
            .unwrap_or_else(|e| panic!("host `{}` failed: {e}", self.name))
    }
}

/// Build the device, the interface, the socket and the clock, then run the loop.
fn launch(
    dir: &Path,
    net: &MemoryNetwork,
    prepared: &Prepared,
    address: &str,
    listen: SocketAddr,
    peers: &str,
    level: Level,
) -> Host {
    let key_path = dir.join(format!("{}.key", prepared.name));
    let text = config_text(&prepared.name, &key_path, address, listen, level, peers);
    launch_from_text(dir, net, prepared, text, listen)
}

/// As [`launch`], from a config the test wrote itself.
fn launch_from_text(
    dir: &Path,
    net: &MemoryNetwork,
    prepared: &Prepared,
    text: String,
    listen: SocketAddr,
) -> Host {
    let resolved = resolve_text(dir, &prepared.name, &text).expect("the config must resolve");
    for warning in &resolved.warnings {
        eprintln!("config warning: {warning}");
    }
    let level = resolved.level;

    let clock = Arc::new(MockClock::new());
    clock.set(0, WALL_SECS, 0);

    let device = Device::new(
        Arc::new(suite()),
        resolved.identity,
        resolved.peers,
        &mut OsRng::new(),
        clock.monotonic_ms(),
    )
    .expect("the peer table must be accepted");

    let name = prepared.name.clone();
    let (parts, interface) = tun::mock::pair(&name, 1280);
    let socket: Arc<dyn DatagramSocket> = Arc::new(net.bind(listen).expect("bind the socket"));
    let shared = Arc::new(vallum::net::SharedSocket::new(socket));
    let shutdown = Shutdown::new();

    let policy = run::Loop {
        tick_ms: 10,
        ..run::Loop::default()
    };
    let control = resolved
        .control
        .clone()
        .map(|path| vallum::control::ControlServer {
            path: path.clone(),
            context: vallum::control::ControlContext {
                interface: name.clone(),
                addresses: resolved.addresses.clone(),
                private_key: resolved.seed.clone(),
                private_key_path: dir.join(format!("{name}.key")),
                control_path: Some(path),
                listen,
                fwmark: resolved.fwmark,
                socket: Arc::clone(&shared),
                suite: Arc::new(suite()),
                stats: Arc::new(vallum::run::SharedStats::default()),
            },
        });

    let thread_clock = Arc::clone(&clock);
    let thread_shutdown = shutdown.clone();
    let thread_name = name.clone();
    let join = thread::Builder::new()
        .name(format!("vallum-{name}"))
        .spawn(move || {
            let mut rng = OsRng::new();
            run::run(
                device,
                run::Attached {
                    parts,
                    socket: shared,
                    clock: thread_clock as Arc<dyn TimeSource>,
                    budget: resolved.outer_budget,
                    control,
                },
                &mut rng,
                Logger::new(level),
                policy,
                thread_shutdown,
            )
        })
        .expect("spawn the loop thread");

    // The device moved into the thread; the test only needs the interface, the
    // flag, and the join handle.
    let _ = thread_name;
    assert_eq!(interface.name(), name);
    Host {
        name,
        interface,
        shutdown,
        join: Some(join),
    }
}

/// Two hosts, the A→B direction ready to dial and B left to roam.
fn two_hosts(tag: &str) -> (TempDir, MemoryNetwork, Host, Host) {
    let dir = TempDir::new(tag);
    let net = MemoryNetwork::new();

    let a = prepare(dir.path(), "a", A_SEED);
    let b = prepare(dir.path(), "b", B_SEED);

    // A dials B; B is told nothing about A and must learn its address from the
    // handshake. That asymmetry is what exercises roaming in every test here.
    let peers_a = peer_entry("b", &b.public, Some(socket_address(B_EP)), &["10.7.0.2/32"]);
    let peers_b = peer_entry("a", &a.public, None, &["10.7.0.1/32"]);

    let host_a = launch(
        dir.path(),
        &net,
        &a,
        &format!("{A_IP}/24"),
        socket_address(A_EP),
        &peers_a,
        Level::Warn,
    );
    let host_b = launch(
        dir.path(),
        &net,
        &b,
        &format!("{B_IP}/24"),
        socket_address(B_EP),
        &peers_b,
        Level::Warn,
    );
    (dir, net, host_a, host_b)
}

// ── the gate ─────────────────────────────────────────────────────────

#[test]
fn two_daemons_establish_and_carry_traffic_both_ways() {
    let (_dir, _net, mut a, mut b) = two_hosts("carry");

    // A has a packet for B and no session. The loop holds it, starts a handshake,
    // and the packet goes out the moment the handshake completes — across three
    // real threads and a real socket boundary.
    let request = a_packet(A_IP, B_IP, b"request");
    a.send(request.clone());
    let delivered = b.receive(PATIENT).expect("B never received the request");
    assert_eq!(delivered, request);

    // ...and the other way, over the session A started.
    let reply = a_packet(B_IP, A_IP, b"reply");
    b.send(reply.clone());
    let delivered = a.receive(PATIENT).expect("A never received the reply");
    assert_eq!(delivered, reply);

    // The loop saw the handshake complete, which is the action stream reaching
    // the operator, not just the transport.
    let stats = a.stop();
    assert!(
        stats.established >= 1,
        "A's loop reported no handshake: {stats:?}"
    );
    assert!(
        stats.datagrams_sent >= 3,
        "A sent only {}",
        stats.datagrams_sent
    );
    assert_eq!(stats.packets_delivered, 1, "A delivered {stats:?}");
    // The `InitHello` (4 609 B) and the `RespHello` (4 378 B) do not fit a
    // datagram, so a tunnel that came up at all came up through the segmentation
    // envelope. Both sides had to reassemble one, which is the loop's socket-side
    // wiring in both directions — the property this test exists to pin, since a
    // device fed whole messages would never notice the difference.
    assert!(
        stats.reassembled >= 1,
        "A assembled no message, so nothing was segmented: {stats:?}"
    );
    let stats_b = b.stop();
    assert!(
        stats_b.reassembled >= 1,
        "B assembled no message, so A sent no fragments: {stats_b:?}"
    );
}

#[test]
fn a_narrow_outer_mtu_carries_the_handshake_and_segments_data() {
    // The same two daemons on a path the config says is 1000 bytes: the
    // configured budget is 952 (the IPv6 worst case), a v4 destination gets 972
    // back, the derived inner MTU is 894, and a 900-byte payload (978 bytes on
    // the wire) therefore still crosses as two fragments. This is the wiring from `interface.outer_mtu`
    // through `Resolved` into the segmenter, which no unit test covers end to
    // end.
    let dir = TempDir::new("narrow");
    let net = MemoryNetwork::new();
    let a = prepare(dir.path(), "a", A_SEED);
    let b = prepare(dir.path(), "b", B_SEED);
    let peers_a = peer_entry("b", &b.public, Some(socket_address(B_EP)), &["10.7.0.2/32"]);
    let peers_b = peer_entry("a", &a.public, None, &["10.7.0.1/32"]);

    let narrow = |text: String| text.replace("[interface]", "[interface]\nouter_mtu = 1000");
    let key_a = dir.path().join("a.key");
    let key_b = dir.path().join("b.key");
    let text_a = narrow(config_text(
        "a",
        &key_a,
        &format!("{A_IP}/24"),
        socket_address(A_EP),
        Level::Warn,
        &peers_a,
    ));
    let text_b = narrow(config_text(
        "b",
        &key_b,
        &format!("{B_IP}/24"),
        socket_address(B_EP),
        Level::Warn,
        &peers_b,
    ));

    let mut host_a = launch_from_text(dir.path(), &net, &a, text_a, socket_address(A_EP));
    let mut host_b = launch_from_text(dir.path(), &net, &b, text_b, socket_address(B_EP));

    let packet = a_packet(A_IP, B_IP, &[0x42u8; 900]);
    host_a.send(packet.clone());
    assert_eq!(
        host_b
            .receive(PATIENT)
            .expect("the narrow path carried nothing"),
        packet
    );

    let stats = host_a.stop();
    assert!(stats.established >= 1, "no handshake: {stats:?}");
    assert!(
        stats.reassembled >= 1,
        "the handshake was not segmented: {stats:?}"
    );
    host_b.stop();
}

#[test]
fn a_packet_claiming_a_disallowed_source_is_dropped() {
    let (_dir, _net, mut a, mut b) = two_hosts("spoof");

    // Prove the tunnel is up first, so a later silence means "rejected" and not
    // "never worked".
    let honest = a_packet(A_IP, B_IP, b"honest");
    a.send(honest.clone());
    assert_eq!(b.receive(PATIENT).expect("tunnel never came up"), honest);

    // B now claims a source it was never granted. B's own routing only looks at
    // the *destination*, so it seals and sends this happily; the drop has to
    // happen at A, on the inbound source check. If it does not, a peer can speak
    // for any address on the tunnel.
    b.send(a_packet("10.9.9.9", A_IP, b"spoofed"));

    assert!(
        a.receive(QUIET).is_none(),
        "A delivered a packet whose source address B was not allowed to use"
    );

    // And the tunnel is still usable, so the rejection was not a crash.
    let after = a_packet(A_IP, B_IP, b"after");
    a.send(after.clone());
    assert_eq!(
        b.receive(PATIENT).expect("tunnel died after a spoof"),
        after
    );

    let _ = a.stop();
    let _ = b.stop();
}

#[test]
fn junk_datagrams_do_not_disturb_the_tunnel() {
    let (_dir, net, mut a, mut b) = two_hosts("junk");

    let first = a_packet(A_IP, B_IP, b"first");
    a.send(first.clone());
    assert_eq!(b.receive(PATIENT).expect("tunnel never came up"), first);

    // An unrelated host on the network hammers A. None of this is a valid
    // message: a truncated header, the wrong version, a suite A does not speak,
    // and a byte pattern that is not TLV at all.
    let attacker: MemorySocket = net
        .bind(socket_address("192.0.2.77:40000"))
        .expect("bind attacker");
    for junk in [
        &b"\x01\x01\xff\xff\x00\x00\x00\x00"[..], // right shape, wrong suite
        &[0xff; 1400][..],                        // not a message
        &b"get me in"[..],                        // nothing like one
        &[],                                      // an empty datagram
    ] {
        let _ = attacker.send_to(junk, socket_address(A_EP));
    }

    // A is still there and still speaking. Note this asserts *exactly* the second
    // packet: if any junk had been believed, something else would arrive first.
    let second = a_packet(A_IP, B_IP, b"second");
    a.send(second.clone());
    assert_eq!(
        b.receive(PATIENT).expect("junk cost the tunnel a packet"),
        second,
        "junk produced traffic on the tunnel"
    );

    let _ = a.stop();
    let _ = b.stop();
}

// ── the config surface ───────────────────────────────────────────────

#[test]
fn a_key_file_is_owner_only_and_expands_to_the_same_key_twice() {
    let dir = TempDir::new("keyfile");
    let prepared = prepare(dir.path(), "a", A_SEED);

    // Same seed, same public key: nothing derived is stored, so a reload cannot
    // disagree with a regeneration.
    let again = prepare(dir.path(), "a2", A_SEED);
    assert_eq!(prepared.public, again.public);

    // Two different seeds are two different keys, which is the whole point.
    let other = prepare(dir.path(), "a3", B_SEED);
    assert_ne!(prepared.public, other.public);

    // The line is tagged, names the suite, and has no signing key.
    assert!(prepared.public.starts_with("vallum1:0003:"));
    assert!(prepared.public.ends_with(":-"));

    // Mode 0600 at creation: a private key readable by anyone else is a private
    // key that is not private.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(dir.path().join("a.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "key file mode is {:04o}", mode & 0o777);
        assert!(keys::permission_warning(&dir.path().join("a.key")).is_none());
    }

    // A second `keygen` at the same path must refuse rather than clobber a key.
    let key_path = dir.path().join("a.key");
    let error = keys::save_secret(&key_path, &prepared.secret).unwrap_err();
    assert!(
        matches!(error, Error::IoPath { .. }),
        "expected a refusal, got {error:?}"
    );
    assert_eq!(
        keys::load_secret(&key_path).unwrap().seed,
        prepared.secret.seed,
        "the refused write damaged the key"
    );
}

#[test]
fn a_mistyped_field_is_a_config_error_not_a_silent_default() {
    let dir = TempDir::new("typo");
    let _a = prepare(dir.path(), "a", A_SEED);
    let b = prepare(dir.path(), "b", B_SEED);
    let key_path = dir.path().join("a.key");

    // `allowed_ip` for `allowed_ips`: without `deny_unknown_fields` this would
    // parse, and the peer would silently have no addresses at all.
    let text = config_text(
        "a",
        &key_path,
        "10.7.0.1/24",
        socket_address(A_EP),
        Level::Info,
        &format!(
            "[[peer]]\nname = \"b\"\npublic_key = \"{}\"\nallowed_ip = [\"10.7.0.2/32\"]\n",
            b.public
        ),
    );
    let error = resolve_text(dir.path(), "a", &text).unwrap_err();
    assert!(
        matches!(error, Error::Toml { .. }),
        "a typo was accepted: {error:?}"
    );

    // The same file with `allowed_ips` resolves, so the test above is about the
    // typo and not about the file being broken.
    let good = config_text(
        "a2",
        &key_path,
        "10.7.0.1/24",
        socket_address(A_EP),
        Level::Info,
        &peer_entry("b", &b.public, None, &["10.7.0.2/32"]),
    );
    // The key file is named `a.key`; the config name only affects the log line.
    let resolved = resolve_text(dir.path(), "a", &good).expect("the corrected file must resolve");
    assert_eq!(resolved.peers.len(), 1);
    assert!(resolved.warnings.is_empty(), "{:?}", resolved.warnings);
}

#[test]
fn a_persistent_keepalive_is_optional_and_zero_is_not_off() {
    let dir = TempDir::new("keepalive");
    let _a = prepare(dir.path(), "a", A_SEED);
    let b = prepare(dir.path(), "b", B_SEED);
    let key_path = dir.path().join("a.key");

    let resolve = |name: &str, extra: &str| {
        let text = config_text(
            name,
            &key_path,
            "10.7.0.1/24",
            socket_address(A_EP),
            Level::Info,
            &format!(
                "[[peer]]\nname = \"b\"\npublic_key = \"{}\"\n\
                 allowed_ips = [\"10.7.0.2/32\"]\n{extra}",
                b.public
            ),
        );
        resolve_text(dir.path(), name, &text)
    };

    // The field is optional: omitted means off, so nothing sends on its own.
    let off = resolve("off", "").expect("an omitted field is valid");
    assert_eq!(off.peers[0].persistent_keepalive(), None);

    // A whole number of seconds is the configuration.
    let on = resolve("on", "persistent_keepalive = 25\n").expect("25 s is valid");
    assert_eq!(
        on.peers[0].persistent_keepalive(),
        Some(Duration::from_secs(25))
    );

    // Zero is refused, not quietly read as off: a field the operator wrote and
    // the daemon ignores is how a security setting goes missing.
    let error = resolve("zero", "persistent_keepalive = 0\n").unwrap_err();
    assert!(matches!(error, Error::Invalid { .. }), "{error:?}");
    assert!(
        error.to_string().contains("persistent_keepalive"),
        "{error}"
    );
}

#[test]
fn a_relative_key_path_is_resolved_against_the_config_not_the_cwd() {
    let dir = TempDir::new("relkey");

    // Key in a subdirectory, config one level up naming it relatively. If the
    // path were resolved against the working directory this would fail whenever
    // `vallum run` was started from anywhere but `dir`.
    let key_dir = dir.path().join("keys");
    fs::create_dir_all(&key_dir).expect("create key dir");
    let secret = keys::new_secret(SUITE, false, A_SEED);
    keys::save_secret(&key_dir.join("a.key"), &secret).expect("write key");

    let config_path = dir.path().join("vallum.toml");
    fs::write(
        &config_path,
        format!(
            "[interface]\nprivate_key = \"keys/a.key\"\naddress = \"10.7.0.1/24\"\n\
             listen = \"{A_EP}\"\n",
        ),
    )
    .expect("write config");

    let config = Config::load(&config_path).expect("parse");
    assert_eq!(config.suite_id(&config_path).expect("suite"), SUITE);
    let resolved = config
        .resolve(&config_path, &suite())
        .expect("a relative key path must resolve next to the config");
    assert_eq!(
        resolved
            .addresses
            .first()
            .map(ToString::to_string)
            .as_deref(),
        Some("10.7.0.1/24")
    );

    // And an absolute path is still used as written.
    assert_eq!(
        vallum::config::resolve_key_path(&config_path, Path::new("/etc/vallum/x.key")),
        PathBuf::from("/etc/vallum/x.key")
    );
}

#[test]
fn a_peer_for_another_suite_is_refused() {
    let dir = TempDir::new("suite");
    let a = prepare(dir.path(), "a", A_SEED);
    let key_path = dir.path().join("a.key");

    // A syntactically perfect line for suite 0x0001, pasted into a 0x0003
    // daemon. The keys are not interchangeable, so this must fail at startup
    // rather than at the first handshake.
    let foreign = keys::encode_public(0x0001, &a_synthetic_peer());
    let text = config_text(
        "a",
        &key_path,
        "10.7.0.1/24",
        socket_address(A_EP),
        Level::Info,
        &peer_entry("b", &foreign, None, &["10.7.0.2/32"]),
    );
    let error = resolve_text(dir.path(), "a", &text).unwrap_err();
    match error {
        Error::Invalid { what, .. } => {
            assert!(what.contains("0x0001"), "unhelpful message: {what}");
            assert!(what.contains("peer[0]"), "unhelpful message: {what}");
        }
        other => panic!("expected a config error, got {other:?}"),
    }
    let _ = a;
}

#[test]
fn a_peer_outside_the_interface_prefix_is_warned_about() {
    let dir = TempDir::new("prefix");
    prepare(dir.path(), "a", A_SEED);
    let key_path = dir.path().join("a.key");

    // A /32 interface address covers no peer, so the kernel installs no route and
    // the packet would never reach the tunnel. Loud, not fatal.
    let text = config_text(
        "a",
        &key_path,
        "10.7.0.9/32",
        socket_address(A_EP),
        Level::Info,
        &peer_entry(
            "b",
            &keys::encode_public(SUITE, &a_synthetic_peer()),
            None,
            &["10.7.0.2/32"],
        ),
    );
    let resolved = resolve_text(dir.path(), "a", &text).expect("a warning is not an error");
    assert_eq!(resolved.warnings.len(), 1, "{:?}", resolved.warnings);
    assert!(
        resolved.warnings[0].contains("10.7.0.2/32"),
        "the warning does not name the address: {}",
        resolved.warnings[0]
    );
    assert!(
        resolved.warnings[0].contains("ip route add"),
        "the warning does not say what to run: {}",
        resolved.warnings[0]
    );

    // And a prefix that does cover the peer says nothing.
    let quiet = config_text(
        "a2",
        &key_path,
        "10.7.0.0/24",
        socket_address(A_EP),
        Level::Info,
        &peer_entry(
            "b",
            &keys::encode_public(SUITE, &a_synthetic_peer()),
            None,
            &["10.7.0.2/32"],
        ),
    );
    let resolved = resolve_text(dir.path(), "a", &quiet).expect("resolve");
    assert!(resolved.warnings.is_empty(), "{:?}", resolved.warnings);
}

#[test]
fn two_peers_claiming_the_same_address_are_refused() {
    let dir = TempDir::new("overlap");
    prepare(dir.path(), "a", A_SEED);
    let key_path = dir.path().join("a.key");

    // Two peers, two different keys, the same address. Routing would then depend
    // on config order, so the transport refuses it — and this test is here to
    // prove the daemon does not paper over that refusal.
    let first = keys::encode_public(SUITE, &a_synthetic_peer());
    let second = keys::encode_public(
        SUITE,
        &PeerIdentity::kem_only(KemPublicKey::new(vec![0x5c; 2374])),
    );
    let text = config_text(
        "a",
        &key_path,
        "10.7.0.0/24",
        socket_address(A_EP),
        Level::Info,
        &format!(
            "{}{}",
            peer_entry("b", &first, None, &["10.7.0.2/32"]),
            peer_entry("c", &second, None, &["10.7.0.2/32"]),
        ),
    );
    let resolved = resolve_text(dir.path(), "a", &text).expect("the config itself parses");

    let outcome = Device::new(
        Arc::new(suite()),
        resolved.identity,
        resolved.peers,
        &mut OsRng::new(),
        0,
    );
    match outcome {
        Err(vallum_tunnel::ConfigError::OverlappingAllowedIps { .. }) => {}
        other => panic!("expected the peer table to refuse, got {other:?}"),
    }
}

/// A peer identity of the right shape for the tri-hybrid suite. The daemon never
/// dereferences the bytes during config validation, so a synthetic key is enough
/// to exercise the *policy* checks without running a key generation.
fn a_synthetic_peer() -> PeerIdentity {
    PeerIdentity::kem_only(KemPublicKey::new(vec![0x4d; 2374]))
}

#[test]
fn the_suite_is_taken_from_the_key_not_from_a_flag() {
    let dir = TempDir::new("suitefromkey");
    let key_path = dir.path().join("a.key");

    // A key file written for 0x0001, then used by a daemon whose suite came from
    // that same file: it resolves, because there is nothing to disagree with.
    let secret = keys::new_secret(0x0001, false, A_SEED);
    keys::save_secret(&key_path, &secret).expect("write key file");
    let identity = keys::identity(&SdkSuite::x25519_sntrup761(), &secret).expect("expand");
    let public = keys::encode_public(0x0001, &identity.to_peer());

    let text = config_text(
        "a",
        &key_path,
        "10.7.0.1/24",
        socket_address(A_EP),
        Level::Info,
        &peer_entry("b", &public, None, &["10.7.0.2/32"]),
    );
    let path = dir.path().join("a.toml");
    fs::write(&path, &text).expect("write config");
    let config = Config::load(&path).expect("parse");

    // Resolving against the *wrong* suite must fail, naming both ids.
    match config.resolve(&path, &suite()) {
        Err(Error::Key { why, .. }) => {
            assert!(why.contains("0x0001"), "unhelpful message: {why}");
            assert!(why.contains("0x0003"), "unhelpful message: {why}");
        }
        other => panic!("expected the mismatch to be caught, got {other:?}"),
    }

    // Resolving against the key's own suite succeeds.
    let resolved = config
        .resolve(&path, &SdkSuite::x25519_sntrup761())
        .expect("the key and the suite agree");
    assert_eq!(resolved.peers.len(), 1);
    let _ = CryptoSuite::suite_id(&suite());
}

/// G2: when the control socket file is deleted underneath a running daemon, the
/// loop notices on its tick, re-binds the socket at the configured path, and
/// answers subsequent control requests without requiring a daemon restart.
#[test]
fn a_removed_control_socket_is_rebound_by_the_daemon() {
    let dir = TempDir::new("ctlrebind");
    let net = MemoryNetwork::new();
    let prepared = prepare(dir.path(), "a", A_SEED);
    let key_path = dir.path().join(format!("{}.key", prepared.name));
    let ctl_path = dir.path().join("a.sock");

    let text = format!(
        "[interface]\n\
         name = \"{}\"\n\
         private_key = \"{}\"\n\
         address = \"10.7.0.1/24\"\n\
         listen = \"{}\"\n\
         control = \"{}\"\n\
         \n\
         [log]\n\
         level = \"info\"\n",
        prepared.name,
        key_path.display(),
        socket_address(A_EP),
        ctl_path.display(),
    );

    let mut host = launch_from_text(dir.path(), &net, &prepared, text, socket_address(A_EP));

    // The control socket must exist and respond.
    let start_deadline = Instant::now() + Duration::from_secs(2);
    while !ctl_path.exists() && Instant::now() < start_deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(ctl_path.exists(), "control socket was created at launch");
    let reply = vallum::control::request(&ctl_path, "get=1\n").expect("initial control request");
    assert!(reply.contains("errno=0"), "expected errno=0, got {reply:?}");

    // Delete the control socket underneath the running daemon.
    fs::remove_file(&ctl_path).expect("delete socket");
    assert!(!ctl_path.exists(), "socket file was removed");

    // The daemon ticks at 10 ms (in gate tests) and checks if the socket was removed;
    // within 500 ms it must notice and recreate the socket file.
    let deadline = Instant::now() + Duration::from_millis(500);
    while !ctl_path.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        ctl_path.exists(),
        "daemon failed to re-bind the deleted control socket"
    );

    // The recreated socket must answer requests.
    let reply = vallum::control::request(&ctl_path, "get=1\n").expect("re-bound control request");
    assert!(
        reply.contains("errno=0"),
        "expected errno=0 on rebound socket, got {reply:?}"
    );

    let _ = host.stop();
}
