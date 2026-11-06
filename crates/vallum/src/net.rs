// SPDX-License-Identifier: Apache-2.0

//! The datagram socket, and an in-process network to replace it in a test.
//!
//! [`DatagramSocket`] is the whole interface the loop needs: send bytes to an
//! address, receive bytes and the address they came from. That is also the exact
//! shape of [`vallum_tunnel::Event::Datagram`], which is why the loop is a
//! straight-line translation and a test can substitute [`MemoryNetwork`] for the
//! kernel.
//!
//! # Why a whole network, not a mock socket
//!
//! A tunnel's correctness depends on *addresses* — a peer roams to the source of
//! authenticated traffic, and a spoofed source must not be believed. A mock that
//! returns a canned address would not exercise any of that. `MemoryNetwork` binds
//! each socket to a real `SocketAddr` and delivers with the sender's own address,
//! so roaming and source-address checks behave exactly as they do on a wire.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// A connectionless, unreliable-ish datagram transport.
///
/// `&self`, not `&mut self`, because the sender and receiver halves are used from
/// two threads and a socket is safe to share — as [`UdpSocket`] already is.
pub trait DatagramSocket: Send + Sync {
    /// Send one datagram. `destination` is where it is addressed to.
    ///
    /// # Errors
    ///
    /// Whatever the transport reports — an unreachable address, a full buffer, a
    /// closed socket.
    fn send_to(&self, bytes: &[u8], destination: SocketAddr) -> io::Result<()>;

    /// Send several datagrams, returning how many the transport accepted.
    ///
    /// The default is a loop; a real transport may batch. A return below
    /// `batch.len()` means the rest were not sent and the caller may retry them.
    ///
    /// # Errors
    ///
    /// If the first send fails, or the transport refuses the batch.
    fn send_many(&self, batch: &[(SocketAddr, Vec<u8>)]) -> io::Result<usize> {
        for (destination, bytes) in batch {
            self.send_to(bytes, *destination)?;
        }
        Ok(batch.len())
    }

    /// Receive one datagram, blocking until one arrives or the socket closes.
    ///
    /// A datagram larger than `buf` is truncated the way [`UdpSocket`] truncates
    /// it; the returned length is what fit.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::Interrupted`] once the socket is closed, so a reader
    /// thread can tell a shutdown from a failure.
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;

    /// The address this socket is bound to.
    ///
    /// # Errors
    ///
    /// If the transport cannot say.
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

// ── the real socket ──────────────────────────────────────────────────

/// A [`UdpSocket`] behind [`DatagramSocket`].
#[derive(Debug)]
pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    /// Bind a UDP socket.
    ///
    /// # Errors
    ///
    /// If the address is in use, or cannot be bound.
    pub fn bind(address: SocketAddr) -> io::Result<Self> {
        Self::bind_with_fwmark(address, 0)
    }

    /// Bind with an `SO_MARK`, for policy routing.
    ///
    /// # Errors
    ///
    /// If the address cannot be bound, or the mark cannot be set (it needs
    /// `CAP_NET_ADMIN`).
    pub fn bind_with_fwmark(address: SocketAddr, fwmark: u32) -> io::Result<Self> {
        let socket = UdpSocket::bind(address)?;
        // A short read timeout is what lets the reader notice a rebind: it
        // wakes, checks the shared socket's generation, and switches.
        socket.set_read_timeout(Some(Duration::from_millis(250)))?;
        #[cfg(target_os = "linux")]
        if fwmark != 0 {
            nix::sys::socket::setsockopt(&socket, nix::sys::socket::sockopt::Mark, &fwmark)
                .map_err(|e| io::Error::other(format!("SO_MARK: {e}")))?;
        }
        // Ask the kernel to report an oversize datagram with `EMSGSIZE` instead
        // of fragmenting it. This is the other half of H6's "loud failure": the
        // `outer_mtu` knob bounds what is emitted, and this makes a path that
        // disagrees say so rather than silently splitting the datagram.
        //
        // Both are fatal: the daemon is Linux-only, the options are old, and a
        // daemon that cannot make the guarantee should not pretend it did.
        #[cfg(target_os = "linux")]
        if address.is_ipv4() {
            // `rustix` is the safe wrapper; `nix` exposes `IP_MTU_DISCOVER` as
            // a getter only, and `socket2` not at all.
            rustix::net::sockopt::set_ip_mtu_discover(
                &socket,
                rustix::net::sockopt::Ipv4PathMtuDiscovery::DO,
            )
            .map_err(|e| io::Error::other(format!("IP_MTU_DISCOVER: {e}")))?;
        }
        #[cfg(target_os = "linux")]
        if address.is_ipv6() {
            nix::sys::socket::setsockopt(&socket, nix::sys::socket::sockopt::Ipv6DontFrag, &true)
                .map_err(|e| io::Error::other(format!("IPV6_DONTFRAG: {e}")))?;
        }
        Ok(Self { socket })
    }
}

impl DatagramSocket for UdpTransport {
    fn send_to(&self, bytes: &[u8], destination: SocketAddr) -> io::Result<()> {
        // The count is deliberately dropped: a datagram either goes or it does
        // not, and a short write to a connectionless socket is not a thing.
        self.socket.send_to(bytes, destination).map(|_| ())
    }

    #[cfg(target_os = "linux")]
    fn send_many(&self, batch: &[(SocketAddr, Vec<u8>)]) -> io::Result<usize> {
        use std::io::IoSlice;
        use std::os::fd::AsRawFd;

        use nix::sys::socket::{sendmmsg, ControlMessage, MsgFlags, MultiHeaders, SockaddrStorage};

        if batch.is_empty() {
            return Ok(0);
        }
        let mut headers = MultiHeaders::preallocate(batch.len(), None);
        let slices: Vec<[IoSlice<'_>; 1]> = batch
            .iter()
            .map(|(_, bytes)| [IoSlice::new(bytes)])
            .collect();
        let addresses: Vec<Option<SockaddrStorage>> = batch
            .iter()
            .map(|(destination, _)| Some(SockaddrStorage::from(*destination)))
            .collect();
        let cmsgs: &[ControlMessage<'_>] = &[];
        let results = sendmmsg(
            self.socket.as_raw_fd(),
            &mut headers,
            slices.iter(),
            &addresses,
            cmsgs,
            MsgFlags::empty(),
        )
        .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
        Ok(results.count())
    }

    #[cfg(not(target_os = "linux"))]
    fn send_many(&self, batch: &[(SocketAddr, Vec<u8>)]) -> io::Result<usize> {
        for (destination, bytes) in batch {
            self.send_to(bytes, *destination)?;
        }
        Ok(batch.len())
    }

    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

/// A socket that can be replaced while the reader is blocked on it.
///
/// `listen_port` and `fwmark` are runtime properties, so the daemon needs to
/// swap the socket without restarting. The reader holds a clone of the current
/// socket and a short read timeout; after each timeout it compares the
/// generation and, if it changed, reads from the new one. The old `Arc` drops
/// when the last reader releases it.
struct SocketState {
    current: Arc<dyn DatagramSocket>,
    generation: u64,
}

/// A socket that can be replaced while the reader is blocked on it.
///
/// `listen_port` and `fwmark` are runtime properties, so the daemon needs to
/// swap the socket without restarting. The reader holds a clone of the current
/// socket and a short read timeout; after each timeout it compares the
/// generation and, if it changed, reads from the new one. The old `Arc` drops
/// when the last reader releases it.
///
/// The socket and its generation are one value in one lock: a reader can never
/// see a new socket with an old generation, or the reverse.
pub struct SharedSocket {
    state: Mutex<SocketState>,
}

impl std::fmt::Debug for SharedSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (generation, socket) = self.current();
        f.debug_struct("SharedSocket")
            .field("generation", &generation)
            .field("local_addr", &socket.local_addr().ok())
            .finish()
    }
}

impl SharedSocket {
    /// Wrap the initial socket.
    #[must_use]
    pub fn new(socket: Arc<dyn DatagramSocket>) -> Self {
        Self {
            state: Mutex::new(SocketState {
                current: socket,
                generation: 0,
            }),
        }
    }

    /// The current generation and socket.
    #[must_use]
    pub fn current(&self) -> (u64, Arc<dyn DatagramSocket>) {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (state.generation, Arc::clone(&state.current))
    }

    /// The current generation, without cloning the socket.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .generation
    }

    /// Replace the socket and bump the generation.
    pub fn replace(&self, socket: Arc<dyn DatagramSocket>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.current = socket;
        state.generation = state.generation.wrapping_add(1);
    }

    /// Send a batch on the current socket.
    ///
    /// # Errors
    ///
    /// As the transport reports.
    pub fn send_many(&self, batch: &[(SocketAddr, Vec<u8>)]) -> io::Result<usize> {
        self.current().1.send_many(batch)
    }

    /// The current socket's local address.
    ///
    /// # Errors
    ///
    /// If the socket cannot say.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.current().1.local_addr()
    }
}

// ── the in-process network ───────────────────────────────────────────

/// One socket's queue, and the lock a blocked receiver waits on.
#[derive(Debug)]
struct Mailbox {
    queue: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
    ready: Condvar,
    closed: AtomicBool,
}

impl Mailbox {
    fn new() -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            ready: Condvar::new(),
            closed: AtomicBool::new(false),
        }
    }

    fn push(&self, datagram: (Vec<u8>, SocketAddr)) -> io::Result<()> {
        let mut queue = self.queue.lock().map_err(poisoned)?;
        if self.closed.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "destination socket is closed",
            ));
        }
        queue.push_back(datagram);
        self.ready.notify_one();
        Ok(())
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.ready.notify_all();
    }
}

/// Every bound address, so a send can find its destination.
#[derive(Debug, Default)]
struct Registry {
    mailboxes: Mutex<HashMap<SocketAddr, Arc<Mailbox>>>,
}

impl Registry {
    fn bind(&self, address: SocketAddr) -> io::Result<Arc<Mailbox>> {
        let mut mailboxes = self.mailboxes.lock().map_err(poisoned)?;
        if mailboxes.contains_key(&address) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "address already bound in the memory network",
            ));
        }
        let mailbox = Arc::new(Mailbox::new());
        mailboxes.insert(address, Arc::clone(&mailbox));
        Ok(mailbox)
    }

    fn route(&self, address: SocketAddr) -> io::Result<Arc<Mailbox>> {
        let mailboxes = self.mailboxes.lock().map_err(poisoned)?;
        mailboxes.get(&address).cloned().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "no socket bound at that address in the memory network",
            )
        })
    }
}

/// An in-process network: a set of addresses that can reach each other.
///
/// Cloning a `MemoryNetwork` shares it, which is how two hosts are given the same
/// one.
#[derive(Debug, Clone, Default)]
pub struct MemoryNetwork {
    registry: Arc<Registry>,
}

impl MemoryNetwork {
    /// An empty network.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind one address.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::AddrInUse`] if the address is already bound.
    pub fn bind(&self, address: SocketAddr) -> io::Result<MemorySocket> {
        let mailbox = self.registry.bind(address)?;
        Ok(MemorySocket {
            address,
            mailbox,
            registry: Arc::clone(&self.registry),
        })
    }
}

/// A socket on a [`MemoryNetwork`].
#[derive(Debug)]
pub struct MemorySocket {
    address: SocketAddr,
    mailbox: Arc<Mailbox>,
    registry: Arc<Registry>,
}

impl MemorySocket {
    /// Close the socket: further receives return [`io::ErrorKind::Interrupted`]
    /// and further sends *to* it fail. Idempotent.
    pub fn close(&self) {
        self.mailbox.close();
    }
}

impl DatagramSocket for MemorySocket {
    fn send_to(&self, bytes: &[u8], destination: SocketAddr) -> io::Result<()> {
        let mailbox = self.registry.route(destination)?;
        mailbox.push((bytes.to_vec(), self.address))
    }

    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut queue = self.mailbox.queue.lock().map_err(poisoned)?;
        loop {
            if let Some((bytes, source)) = queue.pop_front() {
                let fit = bytes.len().min(buf.len());
                buf[..fit].copy_from_slice(&bytes[..fit]);
                return Ok((fit, source));
            }
            if self.mailbox.closed.load(Ordering::Relaxed) {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "socket closed"));
            }
            // A timeout rather than a bare wait, so a close that races the wait
            // is still noticed. The poll costs nothing measurable at this rate.
            let (guard, _) = self
                .mailbox
                .ready
                .wait_timeout(queue, Duration::from_millis(50))
                .map_err(poisoned)?;
            queue = guard;
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.address)
    }
}

/// A poisoned lock is a bug in this crate, not a condition to recover from. It is
/// reported as an I/O error so it surfaces at the socket boundary rather than
/// becoming a panic in a reader thread.
fn poisoned<T>(_: T) -> io::Error {
    io::Error::other("memory network lock poisoned")
}

/// The path MTU the kernel currently believes leads to `endpoint`.
///
/// A connected UDP socket carries the route's MTU, so this reads the routing
/// table rather than probing: no packet is sent and no state is disturbed.
///
/// The daemon sizes its datagrams before the first handshake, and a handshake
/// cut to a budget the path cannot carry is dropped by the kernel — the tunnel
/// then never comes up at all. `interface.outer_mtu` prevents that only for an
/// operator who already knew the number, which is not the same as discovering
/// it.
#[cfg(target_os = "linux")]
pub fn path_mtu(endpoint: SocketAddr) -> io::Result<u16> {
    let any = SocketAddr::new(
        if endpoint.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        },
        0,
    );
    let socket = UdpSocket::bind(any)?;
    socket.connect(endpoint)?;
    let mtu = if endpoint.is_ipv4() {
        rustix::net::sockopt::ip_mtu(&socket)
    } else {
        rustix::net::sockopt::ipv6_mtu(&socket)
    }
    .map_err(|e| io::Error::other(format!("path MTU: {e}")))?;
    u16::try_from(mtu).map_err(|_| io::Error::other(format!("path MTU {mtu} does not fit in u16")))
}

/// The largest ICMP payload that crosses the path, by bisection.
///
/// Bisects between `min` and `max`. Nine probes at most.
pub fn bisect_mtu_bounds(min: u16, max: u16, mut fits: impl FnMut(u16) -> bool) -> Option<u16> {
    if !fits(min) {
        return None;
    }
    if fits(max) {
        return Some(max);
    }
    let mut good = min;
    let mut bad = max;
    while bad - good > 1 {
        let middle = good + (bad - good) / 2;
        if fits(middle) {
            good = middle;
        } else {
            bad = middle;
        }
    }
    Some(good)
}

/// The largest ICMP payload that crosses the path, by bisection on standard IPv4 bounds.
///
/// Bounds are the IPv4 minimum reassembly buffer (576 - 28 = 548) and a
/// 1500-byte Ethernet path (1500 - 28 = 1472). Nine probes at most.
pub fn bisect_mtu(fits: impl FnMut(u16) -> bool) -> Option<u16> {
    const MIN: u16 = 548;
    const MAX: u16 = 1472;
    bisect_mtu_bounds(MIN, MAX, fits)
}

/// Parse `mtu=<digits>` from ping output if reported by kernel or router ICMP error.
fn parse_reported_mtu(output: &str) -> Option<u16> {
    let tag = "mtu=";
    let idx = output.find(tag)?;
    let rest = &output[idx + tag.len()..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// Test whether an ICMP packet with `payload` bytes fits the path to `host` with DF set.
///
/// Returns `(fits, reported_mtu)`.
fn default_ping_probe(host: &str, payload: u16) -> (bool, Option<u16>) {
    let output = std::process::Command::new("ping")
        .args([
            "-M",
            "do",
            "-s",
            &payload.to_string(),
            "-c",
            "1",
            "-W",
            "1",
            host,
        ])
        .output();
    let Ok(output) = output else {
        return (false, None);
    };
    if output.status.success() {
        return (true, None);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stderr}\n{stdout}");
    (false, parse_reported_mtu(&combined))
}

/// Probe the path MTU to `host` using PMTUD with a custom probe function.
///
/// Returns `Some(mtu)` if the path was measured, or `None` if inconclusive (all probes failed).
pub fn probe_path_mtu_with(
    host: &str,
    is_ipv6: bool,
    mut prober: impl FnMut(&str, u16) -> (bool, Option<u16>),
) -> Option<u16> {
    let (min, max, overhead) = if is_ipv6 {
        (1232u16, 1452u16, 48u16)
    } else {
        (548u16, 1472u16, 28u16)
    };

    // 1. Probe the ceiling first (1500 byte path).
    let (fits_max, reported_mtu) = prober(host, max);
    if fits_max {
        return Some(max + overhead);
    }

    // 2. If the kernel or an intermediate router reported the next-hop MTU directly,
    // verify it with a single probe rather than bisecting.
    if let Some(reported) = reported_mtu {
        if reported >= min + overhead && reported <= max + overhead {
            let target_payload = reported - overhead;
            let (verified, _) = prober(host, target_payload);
            if verified {
                return Some(reported);
            }
        }
    }

    // 3. Probe the floor. If the minimum packet also fails, ICMP is blocked or
    // the host is unreachable.
    let (fits_min, _) = prober(host, min);
    if !fits_min {
        return None;
    }

    // 4. Bisect between min and max.
    let payload = bisect_mtu_bounds(min, max, |size| prober(host, size).0)?;
    Some(payload + overhead)
}

/// Parse a destination host string or endpoint, stripping brackets and port if present.
pub fn parse_probe_host(host_or_endpoint: &str) -> (String, bool) {
    let trimmed = host_or_endpoint.trim();
    if let Ok(addr) = trimmed.parse::<SocketAddr>() {
        return (addr.ip().to_string(), addr.is_ipv6());
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return (ip.to_string(), ip.is_ipv6());
    }
    if trimmed.starts_with('[') {
        if let Some(end) = trimmed.find(']') {
            let inner = &trimmed[1..end];
            return (inner.to_owned(), true);
        }
    }
    if let Some((h, _)) = trimmed.split_once(':') {
        if !h.contains(':') {
            return (h.to_owned(), false);
        }
    }
    let is_v6 = trimmed.contains(':');
    (trimmed.to_owned(), is_v6)
}

/// Probe the path MTU to an IP address / socket destination.
pub fn probe_path_mtu(destination: SocketAddr) -> Option<u16> {
    probe_path_mtu_with(
        &destination.ip().to_string(),
        destination.is_ipv6(),
        within_budget(default_ping_probe),
    )
}

/// Total time a path-MTU probe may spend before settling for what it has proved.
///
/// Each ICMP probe costs up to a second when the path silently swallows it, and
/// the bisection needs about ten. `run` probes before the TUN interface exists,
/// so an unreachable endpoint would otherwise delay every daemon start by ~10 s,
/// and N endpoints by N times that — against systemd's 90 s `TimeoutStartSec`.
///
/// When the budget runs out the prober stops probing and reports "does not
/// fit", so the bisection converges on the largest size it actually confirmed.
/// Conservative, and never a stall: an unmeasured path keeps the configured
/// default rather than blocking the interface from coming up.
pub const PROBE_BUDGET: Duration = Duration::from_secs(3);

fn within_budget(
    prober: impl FnMut(&str, u16) -> (bool, Option<u16>),
) -> impl FnMut(&str, u16) -> (bool, Option<u16>) {
    within_budget_with(PROBE_BUDGET, prober)
}

fn within_budget_with(
    budget: Duration,
    mut prober: impl FnMut(&str, u16) -> (bool, Option<u16>),
) -> impl FnMut(&str, u16) -> (bool, Option<u16>) {
    let start = Instant::now();
    move |host, payload| {
        if start.elapsed() >= budget {
            return (false, None);
        }
        prober(host, payload)
    }
}

/// Probe the path MTU to a host name, IP, or endpoint string.
pub fn probe_path_mtu_host(host_or_endpoint: &str) -> Option<u16> {
    let (host, is_ipv6) = parse_probe_host(host_or_endpoint);
    probe_path_mtu_with(&host, is_ipv6, within_budget(default_ping_probe))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn send_many_delivers_every_datagram() {
        let receiver =
            UdpTransport::bind("127.0.0.1:0".parse().expect("receiver")).expect("bind receiver");
        let address = receiver.local_addr().expect("local addr");
        let sender =
            UdpTransport::bind("127.0.0.1:0".parse().expect("sender")).expect("bind sender");
        let batch = vec![
            (address, b"one".to_vec()),
            (address, b"two".to_vec()),
            (address, b"three".to_vec()),
        ];
        assert_eq!(sender.send_many(&batch).expect("send batch"), 3);

        let mut buffer = [0u8; 16];
        for expected in [b"one".as_slice(), b"two", b"three"] {
            let (n, _) = receiver.recv_from(&mut buffer).expect("receive");
            assert_eq!(&buffer[..n], expected);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_v4_socket_asks_the_kernel_not_to_fragment() {
        // The option is set in `bind`; read it back rather than trust the call.
        let transport = UdpTransport::bind("127.0.0.1:0".parse().expect("a v4 address"))
            .expect("bind a v4 socket");
        let value = rustix::net::sockopt::ip_mtu_discover(&transport.socket)
            .expect("IP_MTU_DISCOVER is readable");
        assert_eq!(
            value.as_raw(),
            rustix::net::sockopt::Ipv4PathMtuDiscovery::DO.as_raw(),
            "a v4 socket must report an oversize datagram, not fragment it"
        );
    }

    #[test]
    fn the_path_mtu_of_loopback_is_the_loopback_mtu() {
        // 65536 is what the kernel reports for `lo`; the point is that the
        // function reads a real number out of the routing table rather than
        // failing or guessing.
        let mtu = path_mtu("127.0.0.1:9".parse().expect("a v4 address"))
            .expect("loopback has a path MTU");
        assert!(mtu >= 1500, "loopback reported an implausible MTU of {mtu}");
    }

    #[test]
    fn parse_probe_host_handles_various_formats() {
        assert_eq!(
            parse_probe_host("198.51.100.1:51820"),
            ("198.51.100.1".to_owned(), false)
        );
        assert_eq!(
            parse_probe_host("198.51.100.1"),
            ("198.51.100.1".to_owned(), false)
        );
        assert_eq!(
            parse_probe_host("vpn.example.com:51820"),
            ("vpn.example.com".to_owned(), false)
        );
        assert_eq!(
            parse_probe_host("vpn.example.com"),
            ("vpn.example.com".to_owned(), false)
        );
        assert_eq!(
            parse_probe_host("[2001:db8::1]:51820"),
            ("2001:db8::1".to_owned(), true)
        );
        assert_eq!(
            parse_probe_host("2001:db8::1"),
            ("2001:db8::1".to_owned(), true)
        );
    }

    #[test]
    fn probe_mtu_discovers_full_1500_in_single_probe() {
        let mut count = 0;
        let mtu = probe_path_mtu_with("host", false, |_host, _payload| {
            count += 1;
            (true, None)
        });
        assert_eq!(mtu, Some(1500));
        assert_eq!(count, 1);
    }

    #[test]
    fn probe_mtu_uses_reported_icmp_ptb_mtu() {
        let mut probed = Vec::new();
        let mtu = probe_path_mtu_with("host", false, |_host, payload| {
            probed.push(payload);
            if payload == 1472 {
                (false, Some(1400))
            } else if payload == 1400 - 28 {
                (true, None)
            } else {
                (false, None)
            }
        });
        assert_eq!(mtu, Some(1400));
        assert_eq!(probed, vec![1472, 1372]);
    }

    #[test]
    fn probe_mtu_bisects_pppoe_when_drops_are_silent() {
        // Silent drop above 1464 (1492 MTU) without ICMP error
        let mtu = probe_path_mtu_with("host", false, |_host, payload| (payload <= 1464, None));
        assert_eq!(mtu, Some(1492));
    }

    #[test]
    fn an_exhausted_budget_stops_probing_rather_than_stalling() {
        use std::cell::Cell;
        use std::rc::Rc;

        let calls = Rc::new(Cell::new(0u32));
        let seen = Rc::clone(&calls);
        let mut prober = within_budget_with(Duration::ZERO, move |_host, _payload| {
            seen.set(seen.get() + 1);
            (true, None)
        });

        // A probe past the budget must not shell out, and must not claim the
        // size fits: "unknown" has to read as "not confirmed" so the bisection
        // settles on what it actually proved.
        assert_eq!(prober("192.0.2.1", 1400), (false, None));
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn probe_mtu_returns_none_when_inconclusive() {
        // Complete block of ICMP
        let mtu = probe_path_mtu_with("host", false, |_host, _payload| (false, None));
        assert_eq!(mtu, None);
    }

    #[test]
    fn probe_mtu_ipv6_discovers_1400() {
        // IPv6 min 1232 (1280), max 1452 (1500)
        let mtu = probe_path_mtu_with("host", true, |_host, payload| (payload <= 1352, None));
        assert_eq!(mtu, Some(1400));
    }
}
