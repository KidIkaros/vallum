// SPDX-License-Identifier: Apache-2.0

//! The loop: three sources of events, one device, and the actions it asks for.
//!
//! ```text
//!   TUN reader ─┐
//!   UDP reader ─┼─▶ mpsc ─▶ Segments ─▶ Device ─▶ Action ─┬─▶ Segments ─▶ socket.send_to
//!   100 ms tick ┘          reassemble  handle/poll        └─▶ tun.write_packet
//! ```
//!
//! The [`Segments`] envelope wraps the socket on both directions, so the device
//! works in whole messages and no message depends on IP fragmentation: a
//! tri-hybrid `InitHello` is 4 609 bytes, and a NAT cannot translate the IP
//! fragments that would carry it. See `vallum_tunnel::segment`.
//!
//! Only the main thread touches the [`Device`]. The two reader threads do one
//! thing: block on their device and hand the bytes over. That is the whole reason
//! the transport is sans-IO — the concurrency here is three channels and no shared
//! mutable state, and the interesting logic is already tested without any of it.
//!
//! # The tick
//!
//! Nothing in the loop needs a fast timer. Rekey deadlines are seconds, keepalives
//! are tens of seconds, and data packets are event-driven, so a tick exists only
//! to *notice* a deadline and the default is a relaxed 100 ms. It is also the
//! loop's shutdown latency, which is why it is not larger.
//!
//! # Under load
//!
//! The reader threads count what they have queued. Past
//! [`Loop::under_load_depth`] the loop tells the device it is under load, which is
//! the signal P2's admission rules use to demand a cookie before doing KEM work.
//! The count is advisory and can be wrong for one tick; it exists to make the
//! device's own fail-closed behaviour engage, not to be a measurement.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use vallum_tunnel::{Action, Clock, Device, Event, Randomness, Segments};

use crate::clock::TimeSource;
use crate::control::{self, ControlServer};
use crate::error::Error;
use crate::logging::Logger;
use crate::net::SharedSocket;
use crate::tun::InterfaceParts;
use crate::{log_debug, log_info, log_warn};

/// How often the loop wakes with nothing to do.
pub const DEFAULT_TICK_MS: u64 = 100;

/// How often the reader's peer-exemption set is rebuilt. A deadline rather than
/// an idle tick, because under load there is no idle tick.
const ENDPOINT_REFRESH_MS: u64 = 100;

/// Queued events past which the device is told it is under load.
pub const DEFAULT_UNDER_LOAD_DEPTH: usize = 64;

/// How many destinations have their path MTU read from the routing table.
///
/// One `connect` plus `getsockopt` per destination, once each, so the cost is
/// bounded by this rather than by how many addresses the send path can be
/// talked into using. Well above any realistic peer count.
pub const PROBED_PATH_LIMIT: usize = 64;

/// The largest datagram a UDP read will accept.
///
/// One byte past [`vallum_core::wire::MAX_HANDSHAKE_MESSAGE`], not 65 535. No
/// valid message is longer than the cap, so a datagram that *could* be valid
/// always fits and is never truncated; a datagram one byte over the cap survives
/// truncation as exactly `MAX + 1` bytes, which the parser refuses. Reading only
/// this much bounds what one unauthenticated packet can make the daemon allocate
/// to 16 KiB, instead of 64.
pub const UDP_BUFFER: usize = vallum_core::wire::MAX_HANDSHAKE_MESSAGE + 1;

/// How many events may wait between the reader threads and the loop.
///
/// The channel used to be unbounded, so a sender that outran the loop — a flood
/// of junk datagrams, each copied into the queue — could grow it until the
/// process ran out of memory. It is bounded now, and the readers block when it
/// is full. Blocking is the right backpressure: the kernel's socket buffer then
/// fills and the kernel drops, which is the same decision the network would make
/// one hop earlier, and no packet is reordered or silently discarded by us.
///
/// 256 is four times the under-load depth, so the device is told "under load"
/// and starts issuing cookies well before senders are blocked.
pub const QUEUE_CAPACITY: usize = 256;

/// Timing and policy knobs for the loop.
#[derive(Debug, Clone, Copy)]
pub struct Loop {
    /// The idle tick, in milliseconds.
    pub tick_ms: u64,
    /// See [`DEFAULT_UNDER_LOAD_DEPTH`].
    pub under_load_depth: usize,
}

impl Default for Loop {
    fn default() -> Self {
        Self {
            tick_ms: DEFAULT_TICK_MS,
            under_load_depth: DEFAULT_UNDER_LOAD_DEPTH,
        }
    }
}

/// A flag the loop checks, and anyone else can raise.
///
/// A tunnel is stopped from the outside — a signal handler, another thread, a
/// test — and the loop must be able to notice without owning a signal handler.
#[derive(Debug, Clone, Default)]
pub struct Shutdown {
    flag: Arc<AtomicBool>,
}

impl Shutdown {
    /// A flag that is not raised.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Ask the loop to stop. It stops after the current event.
    pub fn trigger(&self) {
        self.flag.store(true, Ordering::Relaxed);
    }

    /// The flag itself, for something outside this crate to raise.
    ///
    /// A signal handler is the reason this exists: `signal-hook` wants an
    /// `Arc<AtomicBool>` to set, and the daemon owns the handlers while the loop
    /// owns the flag. Handing out the `Arc` keeps the handler out of this crate.
    #[must_use]
    pub fn atomic(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.flag)
    }

    /// Whether the loop has been asked to stop.
    #[must_use]
    pub fn is_triggered(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }
}

/// [`LoopStats`] live, behind atomics.
///
/// The control socket answers `get` on the loop thread, but a scrape must not
/// wait for the loop to finish to read counters — and `metrics`/`uapi` render
/// them while the daemon is still running. Each field is a `Relaxed` counter
/// written once per loop iteration; readers get a slightly stale but always
/// consistent-with-itself value.
#[derive(Debug, Default)]
pub struct SharedStats {
    datagrams_sent: AtomicU64,
    datagrams_failed: AtomicU64,
    packets_delivered: AtomicU64,
    packets_failed: AtomicU64,
    established: AtomicU64,
    refusals: AtomicU64,
    reassembled: AtomicU64,
    fragments_dropped: AtomicU64,
    dropped_malformed: AtomicU64,
    dropped_unknown_index: AtomicU64,
    fragments_rate_limited: AtomicU64,
    control_rebind_failures: AtomicU64,
}

impl SharedStats {
    /// Publish a snapshot of the loop's counters.
    pub fn publish(&self, stats: &LoopStats) {
        self.datagrams_sent
            .store(stats.datagrams_sent, Ordering::Relaxed);
        self.datagrams_failed
            .store(stats.datagrams_failed, Ordering::Relaxed);
        self.packets_delivered
            .store(stats.packets_delivered, Ordering::Relaxed);
        self.packets_failed
            .store(stats.packets_failed, Ordering::Relaxed);
        self.established.store(stats.established, Ordering::Relaxed);
        self.refusals.store(stats.refusals, Ordering::Relaxed);
        self.reassembled.store(stats.reassembled, Ordering::Relaxed);
        self.fragments_dropped
            .store(stats.fragments_dropped, Ordering::Relaxed);
        self.dropped_malformed
            .store(stats.dropped_malformed, Ordering::Relaxed);
        self.dropped_unknown_index
            .store(stats.dropped_unknown_index, Ordering::Relaxed);
        self.fragments_rate_limited
            .store(stats.fragments_rate_limited, Ordering::Relaxed);
        self.control_rebind_failures
            .store(stats.control_rebind_failures, Ordering::Relaxed);
    }

    /// Read every counter as one [`LoopStats`].
    #[must_use]
    pub fn snapshot(&self) -> LoopStats {
        LoopStats {
            datagrams_sent: self.datagrams_sent.load(Ordering::Relaxed),
            datagrams_failed: self.datagrams_failed.load(Ordering::Relaxed),
            packets_delivered: self.packets_delivered.load(Ordering::Relaxed),
            packets_failed: self.packets_failed.load(Ordering::Relaxed),
            established: self.established.load(Ordering::Relaxed),
            refusals: self.refusals.load(Ordering::Relaxed),
            reassembled: self.reassembled.load(Ordering::Relaxed),
            fragments_dropped: self.fragments_dropped.load(Ordering::Relaxed),
            dropped_malformed: self.dropped_malformed.load(Ordering::Relaxed),
            dropped_unknown_index: self.dropped_unknown_index.load(Ordering::Relaxed),
            fragments_rate_limited: self.fragments_rate_limited.load(Ordering::Relaxed),
            control_rebind_failures: self.control_rebind_failures.load(Ordering::Relaxed),
        }
    }
}

/// What the loop did, for the caller to log or a test to assert on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoopStats {
    /// Datagrams handed to the socket.
    pub datagrams_sent: u64,
    /// Datagrams that could not be sent.
    pub datagrams_failed: u64,
    /// Packets written to the interface.
    pub packets_delivered: u64,
    /// Packets that could not be written.
    pub packets_failed: u64,
    /// Handshakes that completed.
    pub established: u64,
    /// Handshakes refused for a policy reason (expired identity, pinned endpoint).
    pub refusals: u64,
    /// Messages delivered out of reassembled fragments.
    pub reassembled: u64,
    /// Fragments refused, and half-assembled messages abandoned.
    pub fragments_dropped: u64,
    /// Datagrams dropped because they did not parse as a transport message.
    pub dropped_malformed: u64,
    /// Datagrams dropped because the sender index matched no session.
    pub dropped_unknown_index: u64,
    /// Datagrams refused by the per-source admission bucket before reassembly:
    /// sources that are not a configured peer, over their allowance (ADR-0030).
    pub fragments_rate_limited: u64,
    /// Times the control socket could not be re-bound because the runtime
    /// directory became unreachable — the daemon can see that something is
    /// wrong and cannot fix it, so this counter is how a scraper finds out.
    pub control_rebind_failures: u64,
}

/// Whether the control socket is there, gone, or cannot be inspected.
///
/// The third case is the one that matters and the one `Path::exists()` cannot
/// express: it collapses every error — including "permission denied" — into
/// `false`. A daemon that has dropped to `interface.user` and then lost access
/// to `/run/vallum` (a group reset by `systemd-tmpfiles`, a mode change, a
/// mount) therefore reads its own live socket as deleted and retries a bind it
/// can never win.
#[derive(Debug)]
enum SocketState {
    Present,
    Gone,
    Unreachable(io::Error),
}

fn socket_state(path: &Path) -> SocketState {
    match std::fs::symlink_metadata(path) {
        Ok(_) => SocketState::Present,
        Err(error) if error.kind() == io::ErrorKind::NotFound => SocketState::Gone,
        Err(error) => SocketState::Unreachable(error),
    }
}

/// Whether a repeating condition should be logged now.
///
/// `None` means it has not been explained yet, so it must be. After that the
/// answer is a deadline, not a heuristic: at most one explanation per interval.
/// The counters carry the volume that the log no longer carries — that is the
/// trade, and it is only safe because every repeating condition worth reading
/// has a counter beside it.
///
/// Called with an explicit `now` so the deadline is testable without sleeping.
fn rebind_should_warn(last: Option<Instant>, now: Instant, interval: Duration) -> bool {
    match last {
        None => true,
        // `duration_since` panics on a `now` before `last`, which a mock clock in
        // a test can produce; `saturating_duration_since` answers zero instead.
        Some(last) => now.saturating_duration_since(last) >= interval,
    }
}

/// Everything the loop needs from the operating system.
///
/// Grouped rather than passed one by one: they are the three substitutions a test
/// makes — a mock interface, an in-process network, a clock it controls — and a
/// caller that swaps the platform should do it in one place.
pub struct Attached {
    /// The interface, in two halves.
    pub parts: InterfaceParts,
    /// The datagram socket, swappable at runtime.
    pub socket: Arc<SharedSocket>,
    /// The two clocks.
    pub clock: Arc<dyn TimeSource>,
    /// The largest UDP payload the outer path can carry (`outer_mtu - 48`).
    pub budget: usize,
    /// The control socket, if configured.
    pub control: Option<ControlServer>,
    /// The addresses this interface owns. A packet leaving it may only carry
    /// one of these unless [`Self::forward`] is set: anything else is refused
    /// by the peer's `allowed_ips` check, so sending it converts a local
    /// mistake into silent far-side loss.
    pub addresses: Vec<vallum_tunnel::Prefix>,
    /// Whether this node is a gateway: a packet whose source is not an
    /// address here may still be relayed, because the far side's
    /// `allowed_ips` check is where a source claim is judged. See ADR-0020.
    pub forward: bool,
}

impl std::fmt::Debug for Attached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attached")
            .field("parts", &self.parts)
            .finish_non_exhaustive()
    }
}

/// One thing waiting for the device.
#[derive(Debug)]
pub(crate) enum Input {
    Ip(Vec<u8>),
    Datagram(SocketAddr, Vec<u8>),
    /// A control request, answered on the loop thread. `privileged` is the
    /// accept loop's SO_PEERCRED verdict — false for a `vallum`-group console,
    /// whose `get` is rendered with secrets redacted (ADR-0048).
    Control {
        request: crate::uapi::Request,
        privileged: bool,
        reply: mpsc::Sender<String>,
    },
}

/// Run the tunnel until the shutdown flag is raised.
///
/// Blocks the calling thread; returns when the flag is set, or when both reader
/// halves have gone away.
///
/// # Errors
///
/// Is this peer sending into a path that has stopped answering?
///
/// One-way silence, not "the peer is offline": a peer that is simply quiet
/// sends nothing, so `sent_age_ms` grows with `received_age_ms` and this stays
/// false. The failure this names is the one where the kernel keeps accepting
/// datagrams (so `datagrams_failed` stays 0) and nothing comes back.
fn path_stalled(received_age_ms: u64, sent_age_ms: u64, keepalive_ms: u64) -> bool {
    // Two keepalives, so one lost datagram is not a stall; a minute when the
    // peer has no persistent keepalive to calibrate against.
    let limit_ms = if keepalive_ms > 0 {
        keepalive_ms.saturating_mul(2)
    } else {
        60_000
    };
    // Both ages against the same limit: a peer with a 300 s keepalive is legal,
    // and a hardcoded 120 s made the stall undetectable for it (review).
    received_age_ms > limit_ms && sent_age_ms <= limit_ms
}

/// If a reader thread cannot be spawned. A socket or interface that fails while
/// running is logged and counted, not fatal: a tunnel does not exit because one
/// datagram did not go.
#[must_use = "the run loop returns only when the tunnel has stopped"]
/// Whether a packet's inner source may leave this interface.
///
/// Two claims, one rule (ADR-0020). Owned, always: a source inside
/// `addresses` is this host speaking, and it is right to decline anything
/// else locally when the host is not a gateway — that turns the peer's
/// silent `allowed_ips` refusal (no counter, no ICMP, no log) into a cause
/// named here, which is what made the physical-address leak from a socket
/// bound before the tunnel came up diagnosable.
///
/// Not owned, and `[interface] forward` is on: the node is a gateway, and a
/// packet whose destination routes to a peer but whose source belongs to
/// nobody here is a relayed flow — the honest case is a conntrack reply that
/// came back after this host forwarded its neighbour's packet. Far-side
/// policy still governs: the receiving peer's `allowed_ips` decides whether
/// to accept the source, so relaying does not let a host claim another's
/// address, it just refuses claims where they are real instead of where a
/// relay merely looks like one.
fn outbound_allows(
    source: Option<std::net::IpAddr>,
    addresses: &[vallum_tunnel::Prefix],
    forwards: bool,
) -> bool {
    source.is_some_and(|ip| {
        addresses.iter().any(|prefix| prefix.contains(&ip)) || (forwards && !is_link_local(&ip))
    })
}

/// Whether `ip` sits inside a link-local block (v4 `169.254.0.0/16`, v6
/// `fe80::/10`).
///
/// A link-local source means nothing across a link boundary, whoever's
/// interface it claims to come from, so it is refused even by a gateway.
#[must_use]
fn is_link_local(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_link_local(),
        std::net::IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            first & 0xffc0 == 0xfe80
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod outbound_source_tests {
    use super::{is_link_local, outbound_allows};
    use std::net::IpAddr;
    use std::str::FromStr;
    use vallum_tunnel::Prefix;

    fn addrs() -> Vec<Prefix> {
        vec![
            Prefix::from_str("10.7.0.2/32").expect("valid prefix literal"),
            Prefix::from_str("fd00:7::2/128").expect("valid prefix literal"),
        ]
    }

    fn ip(text: &str) -> Option<IpAddr> {
        text.parse::<IpAddr>().ok()
    }

    #[test]
    fn the_tunnel_address_is_ours() {
        assert!(outbound_allows(ip("10.7.0.2"), &addrs(), false));
        assert!(outbound_allows(ip("fd00:7::2"), &addrs(), false));
    }

    #[test]
    fn a_physical_address_is_not_ours() {
        // The address observed leaking on the live deployment: a socket bound
        // before the tunnel came up keeps using the physical interface's
        // global IPv6, and the peer rejects every packet it sends.
        assert!(!outbound_allows(
            ip("2600:4041:542b:7800:6781:d74:5e93:4f62"),
            &addrs(),
            false,
        ));
    }

    #[test]
    fn a_link_local_source_is_not_ours() {
        // Also observed rejected on the live deployment. A link-local address
        // has no meaning beyond its own link, so it can never be a valid
        // payload for a tunnel that crosses one.
        assert!(!outbound_allows(
            ip("fe80::6d93:636d:98a0:a51a"),
            &addrs(),
            false
        ));
    }

    #[test]
    fn an_unparseable_packet_is_not_ours() {
        assert!(!outbound_allows(None, &addrs(), false));
    }

    #[test]
    fn a_gateway_relays_a_foreign_source() {
        // The conntrack reply that made the first verify-remote run fail: a
        // server that forwarded a neighbour's packet to the internet received
        // the reply back with src 1.1.1.1 and refused it locally, so every
        // forwarded flow died while ping still worked.
        assert!(outbound_allows(ip("1.1.1.1"), &addrs(), true));
    }

    #[test]
    fn a_gateway_still_refuses_link_local_and_unparseable() {
        assert!(!outbound_allows(
            ip("fe80::6d93:636d:98a0:a51a"),
            &addrs(),
            true
        ));
        assert!(!outbound_allows(None, &addrs(), true));
    }

    #[test]
    fn the_v4_link_local_block_is_recognised() {
        assert!(is_link_local(
            &"169.254.19.53".parse::<IpAddr>().expect("ip")
        ));
        assert!(is_link_local(&"fe80::1".parse::<IpAddr>().expect("ip")));
        assert!(!is_link_local(&"1.1.1.1".parse::<IpAddr>().expect("ip")));
        assert!(!is_link_local(&"fec0::1".parse::<IpAddr>().expect("ip")));
    }
}

/// Per-source admission for datagrams from sources that are not a peer.
///
/// A captured fragment replayed at line rate costs the responder ~26 µs of its
/// only loop thread per packet, and nothing about it can be authenticated before
/// reassembly — an initiation is itself fragmented (ADR-0030). The bucket gives
/// a stranger an allowance and refuses the rest, counted, so a flood reads as a
/// symptom instead of silence.
///
/// Two generations rather than one map: when the current generation is full the
/// previous one is dropped and the current becomes previous. That is an O(1)
/// approximation of least-recently-seen eviction, which matters because the case
/// it defends against is the one where every packet carries a new source.
struct Admission {
    current: HashMap<std::net::IpAddr, Bucket>,
    previous: HashMap<std::net::IpAddr, Bucket>,
    burst: f64,
    rate: f64,
}

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    last_ms: u64,
}

/// One full initiation is ~20 fragments; a peer's first contact must fit.
const ADMISSION_BURST: f64 = 64.0;
/// Per source, per second, once the burst is spent.
const ADMISSION_PER_SECOND: f64 = 50.0;
/// Distinct sources tracked per generation.
const ADMISSION_SOURCES: usize = 4096;
/// A configured peer's allowance. Not unlimited: the exemption is keyed on the
/// peer's `SocketAddr`, and on a client that address is the server's public
/// host:port from its own config — an off-path attacker who spoofs it would
/// otherwise skip admission entirely (review, 2026-11-11). A peer's rekey herd
/// is ~20-64 fragments per handshake at a few handshakes per second, so this is
/// two orders of magnitude of headroom that still bounds a spoofer.
/// Sized so the tunnel is never the thing being limited: 20,000 datagrams/s is
/// ~280 Mbit/s at a 1400-byte MTU, and the bucket is per source address, so on a
/// server each client has its own. A spoofer of one peer endpoint is bounded to
/// 20,000 pps instead of unbounded — a bound, not a solution; doing admission
/// after the first authenticated packet is the real answer and needs its own ADR.
const PEER_BURST: f64 = 4_096.0;
const PEER_PER_SECOND: f64 = 20_000.0;

impl Admission {
    fn new() -> Self {
        Self::with(ADMISSION_BURST, ADMISSION_PER_SECOND)
    }

    /// A bucket with its own size, for a class of source that is not a
    /// stranger but must still be bounded.
    fn with(burst: f64, rate: f64) -> Self {
        Self {
            current: HashMap::new(),
            previous: HashMap::new(),
            burst,
            rate,
        }
    }

    /// Whether a datagram from `source` may be parsed now.
    fn allow(&mut self, source: std::net::IpAddr, now_ms: u64) -> bool {
        if let Some(bucket) = self.current.get_mut(&source) {
            return bucket.take(now_ms, self.burst, self.rate);
        }
        // Seen in the previous generation: keep its allowance rather than
        // granting a fresh burst on every sweep.
        if let Some(bucket) = self.previous.get_mut(&source) {
            let allowed = bucket.take(now_ms, self.burst, self.rate);
            self.current.insert(source, *bucket);
            return allowed;
        }
        if self.current.len() >= ADMISSION_SOURCES {
            self.previous = std::mem::take(&mut self.current);
        }
        let mut bucket = Bucket {
            tokens: self.burst,
            last_ms: now_ms,
        };
        let allowed = bucket.take(now_ms, self.burst, self.rate);
        self.current.insert(source, bucket);
        allowed
    }
}

impl Bucket {
    fn take(&mut self, now_ms: u64, burst: f64, rate: f64) -> bool {
        let elapsed = now_ms.saturating_sub(self.last_ms) as f64;
        self.tokens = (self.tokens + elapsed * rate / 1000.0).min(burst);
        self.last_ms = now_ms;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub fn run(
    device: Device,
    attached: Attached,
    rng: &mut dyn Randomness,
    log: Logger,
    policy: Loop,
    shutdown: Shutdown,
) -> Result<LoopStats, Error> {
    let Attached {
        parts,
        socket,
        clock,
        budget,
        control,
        addresses,
        forward,
    } = attached;
    let mut device = device;
    let mut stats = LoopStats::default();
    // One segmenter for the whole device: outbound it cuts a message that does
    // not fit a datagram into fragments, inbound it puts them back together, so
    // the device below only ever sees whole messages and nothing depends on IP
    // fragmentation to get a handshake across.
    let mut segments = Segments::with_budget(budget);
    // The smallest budget that can still carry an envelope; a path narrower
    // than this cannot run the protocol at all, so narrowing stops here.
    let min_budget = usize::from(crate::tun::MIN_MTU) + crate::tun::DATA_OVERHEAD;

    let queued = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = mpsc::sync_channel::<Input>(QUEUE_CAPACITY);

    // The control socket holds its own sender, so the channel is not closed by
    // the readers going away; the loop still exits on the shutdown flag. The
    // context stays on this thread: the server thread only parses and forwards.
    let mut control = control;
    let shared_stats = control.as_ref().map_or_else(
        || Arc::new(SharedStats::default()),
        |server| Arc::clone(&server.context.stats),
    );
    let control_path = control.as_ref().map(|server| server.path.clone());
    let control_tx = control_path.as_ref().map(|_| tx.clone());
    let mut control_shutdown = Shutdown::new();
    let mut _control_handle = if let Some(path) = &control_path {
        Some(control::serve(
            path.clone(),
            tx.clone(),
            control_shutdown.clone(),
            shutdown.clone(),
        )?)
    } else {
        // A daemon with no control socket cannot be reconfigured, inspected, or
        // asked for metrics. Say so once, at startup: silence here is what makes
        // `vallum peer add` look like it worked when it did not. See ADR-0017.
        log_warn!(
            log,
            "no control socket: this daemon cannot be reconfigured or inspected at \
             runtime; set `control` in the config to enable it"
        );
        None
    };

    spawn_tun_reader(&tx, Arc::clone(&queued), parts.reader, parts.mtu, &log)?;
    // The reader owns the allowance now: refusing before the buffer is
    // allocated and before the channel hop is where the cost is (ADR-0032).
    // It needs two things the loop owns — the clock, and the set of endpoints
    // that belong to configured peers, which it may only trust as a snapshot.
    let reader_clock: Arc<dyn TimeSource> = Arc::clone(&clock) as Arc<dyn TimeSource>;
    let peer_endpoints: Arc<std::sync::Mutex<HashSet<SocketAddr>>> =
        Arc::new(std::sync::Mutex::new(HashSet::new()));
    let rate_limited: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));

    spawn_udp_reader(
        &tx,
        Arc::clone(&queued),
        Arc::clone(&socket),
        &log,
        Arc::clone(&peer_endpoints),
        Arc::clone(&rate_limited),
        Arc::clone(&reader_clock),
    )?;
    drop(tx);

    log_info!(log, "tunnel up on interface `{}`", parts.name);

    // Tell systemd the unit is alive: READY when the interface is serving,
    // WATCHDOG at half the configured interval while the loop turns, STOPPING
    // on the way out. No `$NOTIFY_SOCKET` (foreground run, tests) makes all
    // three no-ops.
    let mut notify = crate::notify::Notify::from_env();
    notify.ready();

    let mut writer = parts.writer;
    let tick = Duration::from_millis(policy.tick_ms);
    // One warning per destination for a too-large datagram: the condition is a
    // configuration mistake, not a per-packet event, and a log line per packet
    // would bury it.
    let mut mtu_warned: HashSet<SocketAddr> = HashSet::new();
    // Sources already reported as not belonging to this interface: one line per
    // source, because the condition is a local misconfiguration rather than a
    // per-packet event.
    let mut foreign_source_warned: HashSet<std::net::IpAddr> = HashSet::new();
    // Sources relayed because this interface forwards: one line per source,
    // once, for the same reason. Every subsequent packet is silent.
    let mut relayed_sources_noted: HashSet<std::net::IpAddr> = HashSet::new();
    // Destinations whose sends are failing. Once per destination, like the two
    // sets above: a send that fails is the difference between "the path is gone"
    // and "the peer is silent", and UDP reports neither — the kernel says only
    // that the write failed, and at debug level nobody sees it.
    let mut next_endpoint_refresh: u64 = 0;
    let mut send_failed: HashSet<SocketAddr> = HashSet::new();
    // Destinations whose path MTU has already been read from the routing table.
    let mut probed: HashSet<SocketAddr> = HashSet::new();
    // Peers currently in one-way silence, so the warning is a transition and
    // not a line per loop iteration. The failure it names is the one every
    // other signal here misses: sends keep succeeding (the kernel accepts them,
    // so `datagrams_failed` stays 0), nothing comes back, and the daemon looks
    // perfectly healthy from the inside.
    let mut silent: HashSet<usize> = HashSet::new();

    let mut last_control_check = Instant::now();
    // Times the control socket could not be re-bound because the runtime
    // directory became unreachable, and whether that has been explained once.
    // The daemon cannot heal this — it has already dropped to `interface.user` —
    // so the honest behaviour is to count it, say what to do exactly once, and
    // let a scraper page on the counter.
    let mut control_rebind_failures: u64 = 0;
    let mut control_unreachable_warned = false;
    // The repeating case: a socket that is gone and cannot be re-bound stays
    // gone, and the tick that finds it runs every couple of seconds. Explaining
    // it every tick is how the reference server's journal became 99.8% one
    // message — 26,564 identical pairs in 24 h, with the seven real restarts
    // buried between them. Say it once, then on a long reminder deadline, and
    // carry the count so a skim still shows the duration.
    let mut control_rebind_warned: Option<Instant> = None;
    let control_rebind_remind = Duration::from_secs(3600);

    loop {
        if shutdown.is_triggered() {
            break;
        }
        notify.pet_watchdog();

        if let (Some(path), Some(tx)) = (&control_path, &control_tx) {
            if last_control_check.elapsed() >= tick {
                last_control_check = Instant::now();
                // `Path::exists()` answers `false` for *every* error, and one of
                // them is "you may not look": the daemon drops to
                // `interface.user`, so a `/run/vallum` whose group was reset —
                // `systemd-tmpfiles --create` does that on every boot and on
                // every install that runs it — makes `exists()` lie. The daemon
                // then believes its socket was deleted, retries a bind it cannot
                // win, and logs the same two warnings every tick while the
                // control plane is dead. `systemctl is-active` still says
                // active, `peer list` still works (it reads the config, not the
                // socket), and the only symptom is `vallum_up 0`.
                match socket_state(path) {
                    SocketState::Present => {}
                    SocketState::Unreachable(error) => {
                        control_rebind_failures = control_rebind_failures.saturating_add(1);
                        if !control_unreachable_warned {
                            control_unreachable_warned = true;
                            let dir = path.parent().unwrap_or(path);
                            log_warn!(
                                log,
                                "control socket `{}` is not reachable: {error}. \
                                 The runtime directory `{}` is no longer accessible to this \
                                 process, which runs as `interface.user`; the socket is \
                                 probably still there. Fix the directory and restart: \
                                 `sudo chgrp <interface.group> {}` then \
                                 `sudo systemctl restart vallum@<stem>` — this process cannot \
                                 recover on its own, and it will not retry loudly again. \
                                 `vallum_up` is 0 until then.",
                                path.display(),
                                dir.display(),
                                dir.display()
                            );
                        }
                    }
                    SocketState::Gone => {
                        let now = Instant::now();
                        let remind =
                            rebind_should_warn(control_rebind_warned, now, control_rebind_remind);
                        if remind {
                            control_rebind_warned = Some(now);
                            log_warn!(
                                log,
                                "control socket `{}` was removed; re-binding (occurrence {}; \
                                 this message repeats at most hourly while the condition holds)",
                                path.display(),
                                control_rebind_failures.saturating_add(1)
                            );
                        }
                        control_shutdown.trigger();
                        control_shutdown = Shutdown::new();
                        match control::serve(
                            path.clone(),
                            tx.clone(),
                            control_shutdown.clone(),
                            shutdown.clone(),
                        ) {
                            Ok(handle) => {
                                _control_handle = Some(handle);
                            }
                            Err(error) => {
                                control_rebind_failures = control_rebind_failures.saturating_add(1);
                                // The count is the durable signal — `vallum_up 0`
                                // plus `vallum_control_rebind_failures_total` —
                                // and it is what the alert reads. The line below
                                // is the human explanation, on the same deadline.
                                if remind {
                                    log_warn!(
                                        log,
                                        "failed to re-bind control socket `{}` ({} failures so far): {error}",
                                        path.display(),
                                        control_rebind_failures
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        // Refresh the reader's exemption set on a deadline, not on idleness.
        // Refreshing in the timeout arm looked cheap and was wrong: under load
        // the queue is never empty, so the arm never fires, the set stays empty,
        // and every configured peer is bucketed — the throttle then removes the
        // idleness that would have lifted it (review, 2026-11-11). One u64
        // compare per iteration; the rebuild itself runs at most every 100 ms.
        let now_ms = clock.monotonic_ms();
        if now_ms >= next_endpoint_refresh {
            next_endpoint_refresh = now_ms.saturating_add(ENDPOINT_REFRESH_MS);
            if let Ok(mut set) = peer_endpoints.lock() {
                set.clear();
                for (id, _) in device.peers() {
                    if let Some(endpoint) = device.endpoint(id) {
                        set.insert(endpoint);
                    }
                }
            }
        }

        let event = match rx.recv_timeout(tick) {
            Ok(Input::Control {
                request,
                privileged,
                reply,
            }) => {
                // Reassembly counters live in `segments`, so fold them in before
                // the request handler takes its snapshot.
                stats.reassembled = segments.reassembled();
                stats.fragments_dropped = segments.dropped();
                stats.fragments_rate_limited = rate_limited.load(Ordering::Relaxed);
                stats.control_rebind_failures = control_rebind_failures;
                stats.dropped_malformed = device.dropped_malformed();
                stats.dropped_unknown_index = device.dropped_unknown_index();
                shared_stats.publish(&stats);
                let body = match control.as_mut() {
                    Some(server) => {
                        control::handle(&mut device, &mut server.context, request, privileged)
                    }
                    None => crate::uapi::render_errno(crate::uapi::errno::ENOSYS),
                };
                let _ = reply.send(body);
                continue;
            }
            Ok(Input::Ip(packet)) => {
                queued.fetch_sub(1, Ordering::Relaxed);
                // A packet may only leave this interface carrying an address it
                // owns — unless the interface forwards (ADR-0020), in which
                // case a relayed flow re-enters with a source that belongs to
                // nobody here. Anything else — a link-local source, or a
                // physical address a socket was bound to before the tunnel
                // came up — is discarded by the peer's `allowed_ips` check with
                // no counter, no ICMP and no log. Declining it here turns a
                // silent far-side loss into a local cause that names its
                // address; a gateway declines only what no role legitimises.
                let source = vallum_tunnel::packet_source(&packet);
                let owned =
                    source.is_some_and(|ip| addresses.iter().any(|prefix| prefix.contains(&ip)));
                if outbound_allows(source, &addresses, forward) {
                    if let (false, Some(ip)) = (owned, source) {
                        if relayed_sources_noted.insert(ip) {
                            log_info!(
                                log,
                                "relaying packet from {ip}: not an address here, and \
                                 `[interface] forward` is on (ADR-0020)"
                            );
                        }
                    }
                    Some(Event::OutboundIp { packet })
                } else if let Some(ip) = source {
                    if foreign_source_warned.insert(ip) {
                        if is_link_local(&ip) {
                            log_warn!(
                                log,
                                "dropping outbound packet from {ip}: a link-local source means \
                                 nothing across a link"
                            );
                        } else {
                            log_warn!(
                                log,
                                "dropping outbound packet from {ip}: this interface does not \
                                 own that address, so the peer would reject it — set \
                                 `forward = true` in [interface] if this host relays for a \
                                 peer (ADR-0020)"
                            );
                        }
                    }
                    None
                } else {
                    None
                }
            }
            Ok(Input::Datagram(source, bytes)) => {
                queued.fetch_sub(1, Ordering::Relaxed);
                // Strangers were already refused in the reader (ADR-0032), so
                // anything arriving here has been allowed once.
                //
                // A fragment is held here; only a whole message is an event.
                // The loop still ticks, which is what expires a half-assembled
                // message that never finished.
                segments
                    .inbound(clock.monotonic_ms(), source, bytes)
                    .map(|bytes| Event::Datagram { source, bytes })
            }
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => break,
        };

        // The device's own fail-closed admission rule is only useful if it is
        // told when the queue is deep.
        device.set_under_load(queued.load(Ordering::Relaxed) >= policy.under_load_depth);

        let reading = Clock::new(clock.monotonic_ms(), clock.wall());
        let actions = match event {
            Some(event) => device.handle(reading, event, rng),
            None => device.poll(reading, rng),
        };

        // One-way silence, said once per transition. A path that dies under a
        // live socket is invisible to every counter in the snapshot: the sends
        // succeed, so nothing fails, and the peer goes quiet without ever
        // saying so. This is the line the field journal was missing.
        for (id, config) in device.peers() {
            let Some(stats) = device.stats(id) else {
                continue;
            };
            let keepalive_ms = config.persistent_keepalive().map_or(0, |interval| {
                u64::try_from(interval.as_millis()).unwrap_or(u64::MAX)
            });
            let now = clock.monotonic_ms();
            let stalled = match (stats.last_received_ms, stats.last_sent_ms) {
                (Some(received), Some(sent)) => path_stalled(
                    now.saturating_sub(received),
                    now.saturating_sub(sent),
                    keepalive_ms,
                ),
                _ => false,
            };
            let index = id.index();
            if stalled {
                if silent.insert(index) {
                    log_warn!(
                        log,
                        "peer `{}`: still sending but nothing has arrived for {}s — the path \
                         is one-way. Check the route and source address toward it; the tunnel \
                         itself is up",
                        config.name(),
                        now.saturating_sub(stats.last_received_ms.unwrap_or(now)) / 1_000,
                    );
                }
            } else {
                silent.remove(&index);
            }
        }

        // Collect the datagrams one event produced, so a burst (a handshake's
        // fragments, or several peers' packets) is one `sendmmsg`.
        let mut outbound: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
        for action in actions {
            match action {
                Action::Send { destination, bytes } => {
                    // Size the path before the first datagram to a destination we
                    // have not measured. A responder has no configured endpoint:
                    // it learns the address from the handshake, and without this
                    // it would send its reply at the default budget and lose it.
                    if probed.len() < PROBED_PATH_LIMIT && probed.insert(destination) {
                        if let Some(fits) = crate::net::path_mtu(destination)
                            .ok()
                            .map(|mtu| {
                                usize::from(mtu)
                                    .saturating_sub(usize::from(crate::config::OUTER_HEADER_LEN))
                            })
                            .filter(|fits| *fits >= min_budget)
                        {
                            segments.narrow_budget(fits);
                        }
                    }
                    for datagram in segments.outbound(bytes, destination, rng) {
                        outbound.push((destination, datagram));
                    }
                }
                Action::Deliver { packet } => match writer.write_packet(&packet) {
                    Ok(_) => stats.packets_delivered += 1,
                    Err(error) => {
                        stats.packets_failed += 1;
                        log_warn!(log, "writing to the interface failed: {error}");
                    }
                },
                Action::Established { peer, epoch, role } => {
                    stats.established += 1;
                    let name = device
                        .peer(peer)
                        .map_or_else(|| peer.to_string(), |config| config.name().to_owned());
                    log_info!(
                        log,
                        "peer `{name}` established at epoch {epoch} as {role:?}"
                    );
                }
                Action::Refused { peer, reason } => {
                    stats.refusals += 1;
                    let name = device
                        .peer(peer)
                        .map_or_else(|| peer.to_string(), |config| config.name().to_owned());
                    log_warn!(log, "peer `{name}`: {}", reason.as_str());
                }
            }
        }

        if !outbound.is_empty() {
            let total = outbound.len();
            let sent = socket.send_many(&outbound).unwrap_or(0).min(total);
            stats.datagrams_sent += sent as u64;
            // The transport stops at the first failure; retry the rest one by
            // one so the per-destination `EMSGSIZE` warning is not lost.
            for (destination, datagram) in outbound.iter().skip(sent) {
                match send_datagram(&socket, datagram, *destination) {
                    Ok(()) => stats.datagrams_sent += 1,
                    Err(error) => {
                        stats.datagrams_failed += 1;
                        if is_message_too_long(&error) {
                            // The kernel knows what this path carries; ask it
                            // rather than dropping every later datagram the same
                            // way. A responder has no configured endpoint to
                            // probe at startup, so this is where it learns.
                            if let Some(fits) = crate::net::path_mtu(*destination)
                                .ok()
                                .map(|mtu| {
                                    usize::from(mtu).saturating_sub(usize::from(
                                        crate::config::OUTER_HEADER_LEN,
                                    ))
                                })
                                .filter(|fits| *fits >= min_budget)
                            {
                                segments.narrow_budget(fits);
                            }
                            if mtu_warned.insert(*destination) {
                                log_warn!(
                                    log,
                                    "send to {destination} exceeded the path MTU; \
                                     datagrams are now cut to a {}-byte budget",
                                    segments.budget()
                                );
                            }
                        } else {
                            if send_failed.insert(*destination) {
                                log_warn!(
                                    log,
                                    "send to {destination} failed: {error} — the tunnel \
                                     cannot reach its endpoint; this repeats silently \
                                     until the path comes back"
                                );
                            } else {
                                log_debug!(log, "send to {destination} failed: {error}");
                            }
                        }
                    }
                }
            }
        }
    }

    notify.stopping();
    control_shutdown.trigger();
    if let Some(path) = &control_path {
        let _ = std::fs::remove_file(path);
    }
    stats.reassembled = segments.reassembled();
    stats.fragments_dropped = segments.dropped();
    stats.fragments_rate_limited = rate_limited.load(Ordering::Relaxed);
    stats.dropped_malformed = device.dropped_malformed();
    stats.dropped_unknown_index = device.dropped_unknown_index();

    log_info!(
        log,
        "tunnel down: {} datagrams out ({} failed), {} packets delivered ({} failed), \
         {} handshakes ({} refused), {} messages reassembled ({} fragment drops, {} malformed, {} unknown index)",
        stats.datagrams_sent,
        stats.datagrams_failed,
        stats.packets_delivered,
        stats.packets_failed,
        stats.established,
        stats.refusals,
        stats.reassembled,
        stats.fragments_dropped,
        stats.dropped_malformed,
        stats.dropped_unknown_index,
    );
    Ok(stats)
}

/// Send one datagram on the current socket, retrying once across a rebind.
fn send_datagram(socket: &SharedSocket, bytes: &[u8], destination: SocketAddr) -> io::Result<()> {
    let (generation, current) = socket.current();
    match current.send_to(bytes, destination) {
        Ok(()) => Ok(()),
        Err(error)
            if error.kind() == io::ErrorKind::NotConnected
                || error.kind() == io::ErrorKind::BrokenPipe =>
        {
            let (next_generation, next) = socket.current();
            if next_generation != generation {
                next.send_to(bytes, destination)
            } else {
                Err(error)
            }
        }
        Err(error) => Err(error),
    }
}

/// Did the kernel refuse a datagram because it is larger than the path?
///
/// `EMSGSIZE` on a UDP send is the one error that means "the operator's
/// `interface.outer_mtu` is larger than this path", so it gets its own warning
/// rather than a debug line. On platforms without the Linux backend the check
/// is false; the daemon is Linux-only this effort.
#[cfg(target_os = "linux")]
fn is_message_too_long(error: &io::Error) -> bool {
    error.raw_os_error() == Some(nix::errno::Errno::EMSGSIZE as i32)
}

/// See the Linux definition; no equivalent is claimed elsewhere.
#[cfg(not(target_os = "linux"))]
fn is_message_too_long(_error: &io::Error) -> bool {
    false
}

/// One thread reading the interface.
fn spawn_tun_reader(
    tx: &mpsc::SyncSender<Input>,
    queued: Arc<AtomicUsize>,
    mut reader: Box<dyn crate::tun::TunReader>,
    mtu: usize,
    log: &Logger,
) -> Result<(), Error> {
    let tx = tx.clone();
    let log = *log;
    // One buffer, reused: an inner packet never exceeds the inner MTU, and the
    // mock backend makes an over-long packet a loud error rather than a
    // truncation.
    let mut buf = vec![0u8; mtu];
    thread::Builder::new()
        .name("vallum-tun".to_owned())
        .spawn(move || loop {
            match reader.read_packet(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    queued.fetch_add(1, Ordering::Relaxed);
                    if tx.send(Input::Ip(buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
                Err(error) => {
                    log_debug!(log, "interface read stopped: {error}");
                    break;
                }
            }
        })
        .map(|_| ())
        .map_err(Error::Io)
}

/// One thread reading the socket.
fn spawn_udp_reader(
    tx: &mpsc::SyncSender<Input>,
    queued: Arc<AtomicUsize>,
    socket: Arc<SharedSocket>,
    log: &Logger,
    peer_endpoints: Arc<std::sync::Mutex<HashSet<SocketAddr>>>,
    rate_limited: Arc<AtomicU64>,
    clock: Arc<dyn TimeSource>,
) -> Result<(), Error> {
    let tx = tx.clone();
    let log = *log;
    let mut buf = vec![0u8; UDP_BUFFER];
    thread::Builder::new()
        .name("vallum-udp".to_owned())
        .spawn(move || {
            let mut admission = Admission::new();
            let mut peer_admission = Admission::with(PEER_BURST, PEER_PER_SECOND);
            loop {
                let (generation, current) = socket.current();
                match current.recv_from(&mut buf) {
                    Ok((n, source)) => {
                        // A configured peer's traffic is exempt — its fragments
                        // are the tunnel's own, and a bucket a peer trips is
                        // worse than none. The set is a snapshot the loop
                        // refreshes on its tick, so a peer that has just roamed
                        // may be bucketed for up to one tick. Everything else
                        // gets an allowance here, before the allocation and the
                        // channel hop, because that path is what a replayed
                        // fragment actually costs (ADR-0032).
                        let known = peer_endpoints
                            .lock()
                            .map(|set| set.contains(&source))
                            // Fail closed: a poisoned lock must not turn the
                            // bucket off for the life of the process.
                            .unwrap_or(false);
                        // A configured peer gets a large but finite allowance
                        // rather than a free pass: the exemption is keyed on a
                        // `SocketAddr` that is public config on a client, so an
                        // off-path attacker could otherwise skip admission
                        // entirely (review, 2026-11-11).
                        let bucket = if known {
                            &mut peer_admission
                        } else {
                            &mut admission
                        };
                        if !bucket.allow(source.ip(), clock.monotonic_ms()) {
                            rate_limited.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        queued.fetch_add(1, Ordering::Relaxed);
                        if tx.send(Input::Datagram(source, buf[..n].to_vec())).is_err() {
                            break;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            || error.kind() == io::ErrorKind::TimedOut =>
                    {
                        // A rebind wakes the reader here; an unchanged socket is
                        // simply idle.
                        if socket.generation() != generation {
                            continue;
                        }
                    }
                    Err(error) => {
                        log_debug!(log, "socket read stopped: {error}");
                        break;
                    }
                }
            }
        })
        .map(|_| ())
        .map_err(Error::Io)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        path_stalled, rebind_should_warn, socket_state, SocketState, DEFAULT_UNDER_LOAD_DEPTH,
        QUEUE_CAPACITY, UDP_BUFFER,
    };
    use std::time::{Duration, Instant};

    #[test]
    fn the_read_buffer_is_one_byte_past_the_message_cap() {
        // Not 65 535: one byte past the cap is what makes an over-long datagram
        // arrive as `MAX + 1` (and be refused) while never truncating a message
        // that could be valid. A regression to a larger buffer would not fail
        // any other test, so pin it.
        assert_eq!(UDP_BUFFER, vallum_core::wire::MAX_HANDSHAKE_MESSAGE + 1);
    }

    #[test]
    fn the_queue_is_deep_enough_to_engage_under_load() {
        // The device must be told it is under load (and start issuing cookies)
        // before the channel blocks a reader. If this relation inverts, the
        // first signal of a flood becomes a blocked producer instead of a
        // cookie.
        const { assert!(QUEUE_CAPACITY >= DEFAULT_UNDER_LOAD_DEPTH * 4) };
    }

    #[test]
    fn the_admission_bucket_grants_a_burst_then_refuses() {
        // Sized so one full initiation (~20 fragments) and a peer's first
        // contact fit; past that a stranger is refused until it refills.
        let mut admission = super::Admission::new();
        let source = std::net::IpAddr::from([198, 51, 100, 7]);
        let allowed = (0..64).filter(|_| admission.allow(source, 1_000)).count();
        assert_eq!(allowed, 64, "the burst must be granted in full");
        assert!(
            !admission.allow(source, 1_000),
            "past the burst, at the same instant, it must refuse"
        );
        // A second later the refill is 50 packets.
        let refilled = (0..50).filter(|_| admission.allow(source, 2_000)).count();
        assert_eq!(refilled, 50, "the bucket must refill at its stated rate");
        assert!(!admission.allow(source, 2_000), "and then refuse again");
    }

    #[test]
    fn the_admission_bucket_is_per_source() {
        let mut admission = super::Admission::new();
        let attacker = std::net::IpAddr::from([198, 51, 100, 7]);
        let peer = std::net::IpAddr::from([203, 0, 113, 9]);
        for _ in 0..64 {
            admission.allow(attacker, 1_000);
        }
        assert!(!admission.allow(attacker, 1_000));
        assert!(
            admission.allow(peer, 1_000),
            "one source exhausting its allowance must not touch another's"
        );
    }

    #[test]
    fn a_stall_is_sending_into_silence_not_merely_being_quiet() {
        // Both directions silent: an idle tunnel. Nothing is being sent, so
        // nothing can be lost — this must not warn, or every quiet night pages.
        assert!(!path_stalled(300_000, 300_000, 25_000));
        // Sending every keepalive and hearing nothing for two of them: the
        // failure that cost a field outage 71 minutes of unexplained silence.
        assert!(path_stalled(300_000, 5_000, 25_000));
        // Healthy.
        assert!(!path_stalled(5_000, 5_000, 25_000));
        // Exactly at the threshold is not yet a stall: two keepalives of
        // silence is the boundary, and a strict comparison keeps one lost
        // datagram from being reported as a dead path.
        assert!(!path_stalled(50_000, 5_000, 25_000));
        // No persistent keepalive to calibrate against: fall back to a minute.
        assert!(path_stalled(90_000, 5_000, 0));
        assert!(!path_stalled(30_000, 5_000, 0));
    }

    #[test]
    fn a_repeating_condition_is_explained_once_then_on_a_deadline() {
        // The bug this encodes: the reference server logged the same two control
        // socket warnings every 18 s — 26,564 pairs in 24 h, 99.8% of the unit's
        // journal — so the seven real restarts were not findable. One line per
        // hour keeps the condition visible without hiding everything else.
        let interval = Duration::from_secs(3600);
        let t0 = Instant::now();
        assert!(rebind_should_warn(None, t0, interval));
        assert!(!rebind_should_warn(
            Some(t0),
            t0 + Duration::from_secs(1),
            interval
        ));
        assert!(!rebind_should_warn(
            Some(t0),
            t0 + Duration::from_secs(3599),
            interval
        ));
        assert!(rebind_should_warn(Some(t0), t0 + interval, interval));
        // A clock that goes backwards must not panic and must not re-warn.
        assert!(!rebind_should_warn(
            Some(t0),
            t0 - Duration::from_secs(5),
            interval
        ));
    }

    #[test]
    fn a_live_socket_reads_as_present_and_a_deleted_one_as_gone() {
        let dir = std::env::temp_dir().join(format!("vallum-sock-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("control.sock");
        std::fs::write(&path, b"").unwrap();

        assert!(matches!(socket_state(&path), SocketState::Present));

        std::fs::remove_file(&path).unwrap();
        assert!(matches!(socket_state(&path), SocketState::Gone));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_unreadable_directory_is_unreachable_not_gone() {
        // The bug this encodes: `Path::exists()` answers false for EACCES, so a
        // daemon that lost access to its runtime directory reads its own live
        // socket as deleted and re-binds forever. `socket_state` must separate
        // the two, because only one of them is worth re-binding.
        //
        // The directory is created 0000 and owned by this process, so the
        // traversal failure is real without needing another user — and root in a
        // container ignores the mode, which is why the assertion accepts Present
        // as well: what it forbids is reporting Gone.
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("vallum-sock-deny-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("control.sock");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();

        let state = socket_state(&path);
        // Restore before asserting, so a failure cannot leave an unremovable
        // directory behind.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            !matches!(state, SocketState::Gone),
            "an unreadable directory must never read as \"the socket was deleted\""
        );
    }
}
