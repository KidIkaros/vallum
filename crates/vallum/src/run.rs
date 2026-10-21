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

use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

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

/// Queued events past which the device is told it is under load.
pub const DEFAULT_UNDER_LOAD_DEPTH: usize = 64;

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
    /// A control request, answered on the loop thread.
    Control {
        request: crate::uapi::Request,
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
/// If a reader thread cannot be spawned. A socket or interface that fails while
/// running is logged and counted, not fatal: a tunnel does not exit because one
/// datagram did not go.
#[must_use = "the run loop returns only when the tunnel has stopped"]
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
    } = attached;
    let mut device = device;
    let mut stats = LoopStats::default();
    // One segmenter for the whole device: outbound it cuts a message that does
    // not fit a datagram into fragments, inbound it puts them back together, so
    // the device below only ever sees whole messages and nothing depends on IP
    // fragmentation to get a handshake across.
    let mut segments = Segments::with_budget(budget);

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
    if let Some(path) = &control_path {
        control::serve(path.clone(), tx.clone(), shutdown.clone())?;
    }

    spawn_tun_reader(&tx, Arc::clone(&queued), parts.reader, parts.mtu, &log)?;
    spawn_udp_reader(&tx, Arc::clone(&queued), Arc::clone(&socket), &log)?;
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

    loop {
        if shutdown.is_triggered() {
            break;
        }
        notify.pet_watchdog();

        let event = match rx.recv_timeout(tick) {
            Ok(Input::Control { request, reply }) => {
                // Reassembly counters live in `segments`, so fold them in before
                // the request handler takes its snapshot.
                stats.reassembled = segments.reassembled();
                stats.fragments_dropped = segments.dropped();
                shared_stats.publish(&stats);
                let body = match control.as_mut() {
                    Some(server) => control::handle(&mut device, &mut server.context, request),
                    None => crate::uapi::render_errno(crate::uapi::errno::ENOSYS),
                };
                let _ = reply.send(body);
                continue;
            }
            Ok(Input::Ip(packet)) => {
                queued.fetch_sub(1, Ordering::Relaxed);
                Some(Event::OutboundIp { packet })
            }
            Ok(Input::Datagram(source, bytes)) => {
                queued.fetch_sub(1, Ordering::Relaxed);
                // A fragment is held here; only a whole message is an event. The
                // loop still ticks, which is what expires a half-assembled
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

        // Collect the datagrams one event produced, so a burst (a handshake's
        // fragments, or several peers' packets) is one `sendmmsg`.
        let mut outbound: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
        for action in actions {
            match action {
                Action::Send { destination, bytes } => {
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
                            if mtu_warned.insert(*destination) {
                                log_warn!(
                                    log,
                                    "send to {destination} exceeded the path MTU; \
                                     lower interface.outer_mtu (currently a \
                                     {budget}-byte datagram budget)"
                                );
                            }
                        } else {
                            log_debug!(log, "send to {destination} failed: {error}");
                        }
                    }
                }
            }
        }
    }

    notify.stopping();
    if let Some(path) = &control_path {
        let _ = std::fs::remove_file(path);
    }
    stats.reassembled = segments.reassembled();
    stats.fragments_dropped = segments.dropped();

    log_info!(
        log,
        "tunnel down: {} datagrams out ({} failed), {} packets delivered ({} failed), \
         {} handshakes ({} refused), {} messages reassembled ({} fragment drops)",
        stats.datagrams_sent,
        stats.datagrams_failed,
        stats.packets_delivered,
        stats.packets_failed,
        stats.established,
        stats.refusals,
        stats.reassembled,
        stats.fragments_dropped,
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
) -> Result<(), Error> {
    let tx = tx.clone();
    let log = *log;
    let mut buf = vec![0u8; UDP_BUFFER];
    thread::Builder::new()
        .name("vallum-udp".to_owned())
        .spawn(move || loop {
            let (generation, current) = socket.current();
            match current.recv_from(&mut buf) {
                Ok((n, source)) => {
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
        })
        .map(|_| ())
        .map_err(Error::Io)
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_UNDER_LOAD_DEPTH, QUEUE_CAPACITY, UDP_BUFFER};

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
}
