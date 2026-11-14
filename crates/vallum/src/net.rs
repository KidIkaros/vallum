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

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use vallum_tunnel::lwo::{self, PacketEncoding};
use vallum_tunnel::stream::{frame, upgrade_request, FrameReader};

use crate::config::Carrier;

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

/// Bind the transport the config names.
///
/// One function for both places a socket is created — startup and the control
/// plane's rebind — so a `tcp` interface cannot silently become a UDP one when an
/// operator changes its port at runtime.
///
/// # Errors
///
/// Whatever the chosen transport reports.
pub fn bind(
    carrier: Carrier,
    address: SocketAddr,
    fwmark: u32,
) -> io::Result<Arc<dyn DatagramSocket>> {
    bind_with_upgrade(carrier, address, fwmark, None)
}

/// Bind the transport for `carrier` with an optional HTTP/1.1 `Upgrade: vallum`
/// `Host` header value for outbound TCP dials.
pub fn bind_with_upgrade(
    carrier: Carrier,
    address: SocketAddr,
    fwmark: u32,
    tcp_upgrade: Option<&str>,
) -> io::Result<Arc<dyn DatagramSocket>> {
    Ok(match carrier {
        Carrier::Udp => Arc::new(UdpTransport::bind_with_fwmark(address, fwmark)?),
        Carrier::Lwo => Arc::new(LwoTransport::bind_with_fwmark(address, fwmark)?),
        Carrier::Auto => Arc::new(AutoTransport::bind_with_upgrade(
            address,
            fwmark,
            tcp_upgrade,
        )?),
        Carrier::Tcp => Arc::new(TcpTransport::bind_with_upgrade(
            address,
            fwmark,
            tcp_upgrade,
        )?),
    })
}

/// A [`UdpSocket`] behind [`DatagramSocket`].
///
/// Automatically detects inbound LWO-masked packets from `lwo` or `auto`
/// peers and masks replies back to those peers, so an unmodified plain `udp`
/// listener works transparently with obfuscated clients.
#[derive(Debug)]
pub struct UdpTransport {
    socket: UdpSocket,
    lwo_peers: Mutex<HashSet<SocketAddr>>,
    has_lwo_peers: AtomicBool,
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
        // SO_MARK is a Linux routing hook; off Linux the mark is simply not
        // applied — policy routing there belongs to a different mechanism.
        #[cfg(not(target_os = "linux"))]
        let _ = fwmark;
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
        Ok(Self {
            socket,
            lwo_peers: Mutex::new(HashSet::new()),
            has_lwo_peers: AtomicBool::new(false),
        })
    }

    fn is_lwo_peer(&self, destination: SocketAddr) -> bool {
        self.has_lwo_peers.load(Ordering::Acquire)
            && self
                .lwo_peers
                .lock()
                .map(|peers| peers.contains(&destination))
                .unwrap_or(false)
    }

    fn record_peer_encoding(&self, source: SocketAddr, encoding: PacketEncoding) {
        match encoding {
            PacketEncoding::LwoUnmasked => {
                if let Ok(mut peers) = self.lwo_peers.lock() {
                    peers.insert(source);
                    self.has_lwo_peers.store(true, Ordering::Release);
                }
            }
            PacketEncoding::Plain => {
                if self.has_lwo_peers.load(Ordering::Acquire) {
                    if let Ok(mut peers) = self.lwo_peers.lock() {
                        peers.remove(&source);
                        self.has_lwo_peers
                            .store(!peers.is_empty(), Ordering::Release);
                    }
                }
            }
            PacketEncoding::Unrecognized => {}
        }
    }

    fn send_raw(&self, bytes: &[u8], destination: SocketAddr) -> io::Result<()> {
        // The count is deliberately dropped: a datagram either goes or it does
        // not, and a short write to a connectionless socket is not a thing.
        self.socket.send_to(bytes, destination).map(|_| ())
    }

    #[cfg(target_os = "linux")]
    fn send_raw_many(&self, batch: &[(SocketAddr, Vec<u8>)]) -> io::Result<usize> {
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
    fn send_raw_many(&self, batch: &[(SocketAddr, Vec<u8>)]) -> io::Result<usize> {
        for (destination, bytes) in batch {
            self.send_raw(bytes, *destination)?;
        }
        Ok(batch.len())
    }
}

impl DatagramSocket for UdpTransport {
    fn send_to(&self, bytes: &[u8], destination: SocketAddr) -> io::Result<()> {
        if self.is_lwo_peer(destination) {
            let mut masked = bytes.to_vec();
            lwo::pad_and_mask_in_place(&mut masked, vallum_tunnel::segment::MAX_OUTER_DATAGRAM);
            self.send_raw(&masked, destination)
        } else {
            self.send_raw(bytes, destination)
        }
    }

    fn send_many(&self, batch: &[(SocketAddr, Vec<u8>)]) -> io::Result<usize> {
        if !self.has_lwo_peers.load(Ordering::Acquire) {
            return self.send_raw_many(batch);
        }
        let masked_batch: Vec<(SocketAddr, Vec<u8>)> = batch
            .iter()
            .map(|(destination, bytes)| {
                let mut copy = bytes.clone();
                if self.is_lwo_peer(*destination) {
                    lwo::pad_and_mask_in_place(
                        &mut copy,
                        vallum_tunnel::segment::MAX_OUTER_DATAGRAM,
                    );
                }
                (*destination, copy)
            })
            .collect();
        self.send_raw_many(&masked_batch)
    }

    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (n, source) = self.socket.recv_from(buf)?;
        let (logical_len, encoding) = lwo::classify_and_unpad(&mut buf[..n]);
        self.record_peer_encoding(source, encoding);
        Ok((logical_len, source))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

/// Zero-overhead LWO v2 obfuscated UDP transport behind [`DatagramSocket`].
///
/// Outbound packets mask their leading 8-byte Vallum header using a SplitMix64
/// keystream keyed by the packet's own trailing bytes and length. Inbound
/// packets accept both LWO-masked and plain Vallum headers.
#[derive(Debug)]
pub struct LwoTransport {
    udp: UdpTransport,
}

impl LwoTransport {
    /// Bind an LWO-obfuscated UDP socket.
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
    /// If the address cannot be bound, or the mark cannot be set.
    pub fn bind_with_fwmark(address: SocketAddr, fwmark: u32) -> io::Result<Self> {
        Ok(Self {
            udp: UdpTransport::bind_with_fwmark(address, fwmark)?,
        })
    }
}

impl DatagramSocket for LwoTransport {
    fn send_to(&self, bytes: &[u8], destination: SocketAddr) -> io::Result<()> {
        let mut masked = bytes.to_vec();
        lwo::pad_and_mask_in_place(&mut masked, vallum_tunnel::segment::MAX_OUTER_DATAGRAM);
        self.udp.send_raw(&masked, destination)
    }

    fn send_many(&self, batch: &[(SocketAddr, Vec<u8>)]) -> io::Result<usize> {
        let masked_batch: Vec<(SocketAddr, Vec<u8>)> = batch
            .iter()
            .map(|(destination, bytes)| {
                let mut copy = bytes.clone();
                lwo::pad_and_mask_in_place(&mut copy, vallum_tunnel::segment::MAX_OUTER_DATAGRAM);
                (*destination, copy)
            })
            .collect();
        self.udp.send_raw_many(&masked_batch)
    }

    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (n, source) = self.udp.socket.recv_from(buf)?;
        let (logical_len, _) = lwo::classify_and_unpad(&mut buf[..n]);
        Ok((logical_len, source))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.udp.local_addr()
    }
}

// ── a stream carrier ────────────────────────────────────────────────

/// How long a dial to a peer's endpoint may take before the datagram is lost.
///
/// Short on purpose: the writer thread is one thread, so a dial is a stall for
/// every other destination. A peer that is not reachable in three seconds is not
/// reachable *now*, and the next datagram will try again.
pub const CARRIER_DIAL_TIMEOUT: Duration = Duration::from_secs(3);

/// How deep the carrier's own queues are, in packets.
///
/// The same order as [`crate::run::QUEUE_CAPACITY`]: the loop already holds a
/// queue between its readers and itself, and a second, larger one would only
/// move the drop point away from where the counters are.
const CARRIER_QUEUE: usize = 1_024;

/// How much a reader takes from a stream per read. Larger than any frame, so a
/// read is a frame or a few of them and never a half in normal operation.
const STREAM_READ_BUFFER: usize = 64 * 1024;

/// TCP with length framing, behind [`DatagramSocket`].
///
/// This is the carrier ADR-0026 defers: the same sealed packets, the same device,
/// the same loop — the datagrams just travel inside one connection per peer
/// instead of one packet per datagram. It is for paths that drop UDP and nothing
/// else, and its costs are measured in `tests/carrier.rs`: two bytes of frame per
/// packet, and one order for everything, so one lost segment holds every later
/// packet behind its retransmission.
///
/// # How it presents as a datagram socket
///
/// - **Outbound**: `send_to` enqueues, and one writer thread frames and writes. A
///   destination with no connection is dialled on first use, marked with
///   `SO_MARK` *before* the connect so the handshake takes the same route as the
///   data. A connection is keyed by the peer's address as seen on the wire, so a
///   responder's reply to the source of a handshake lands on the connection that
///   handshake arrived on.
/// - **Inbound**: one reader thread per connection unframes and queues, and
///   `recv_from` hands a whole packet back with the address it came from. The
///   device's endpoint learning therefore sees the TCP peer, which is also the
///   only address that connection can come from: under this carrier an endpoint
///   cannot roam, because the connection *is* the endpoint.
/// - **Loss**: both queues drop the newest packet when full and count it, the
///   same policy as the daemon's own queue. A stream does not lose packets on its
///   own; a queue overflow is the only loss here.
///
/// It is `Debug`, `Send` and `Sync`, and it never blocks the loop: the only
/// blocking calls are inside its own threads and inside `recv_from`.
pub struct TcpTransport {
    local: SocketAddr,
    closed: Arc<AtomicBool>,
    /// One reader may wait here at a time, which is one more than exists.
    inbound: Mutex<mpsc::Receiver<(SocketAddr, Vec<u8>)>>,
    outbound: mpsc::SyncSender<(SocketAddr, Vec<u8>)>,
    /// The write half of every live connection, by peer address.
    connections: Arc<Mutex<HashMap<SocketAddr, Arc<TcpStream>>>>,
    inbound_dropped: Arc<AtomicU64>,
    outbound_dropped: Arc<AtomicU64>,
}

impl std::fmt::Debug for TcpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpTransport")
            .field("local", &self.local)
            .field(
                "connections",
                &self.connections.lock().map(|map| map.len()).unwrap_or(0),
            )
            .field(
                "dropped",
                &(self.inbound_dropped.load(Ordering::Relaxed)
                    + self.outbound_dropped.load(Ordering::Relaxed)),
            )
            .finish()
    }
}

impl TcpTransport {
    /// Listen on `address` and dial peers on demand.
    ///
    /// # Errors
    ///
    /// If the address cannot be bound, or the mark cannot be set (it needs
    /// `CAP_NET_ADMIN`).
    pub fn bind(address: SocketAddr) -> io::Result<Self> {
        Self::bind_with_fwmark(address, 0)
    }

    /// Bind with an `SO_MARK`, for policy routing.
    ///
    /// The mark is set on the listener, on every accepted connection, and on a
    /// dial *before* the connect: a tunnel that routes a default route into
    /// itself would otherwise dial its peer through itself.
    ///
    /// # Errors
    ///
    /// If the socket cannot be created, marked, bound or listened on.
    pub fn bind_with_fwmark(address: SocketAddr, fwmark: u32) -> io::Result<Self> {
        Self::bind_with_upgrade(address, fwmark, None)
    }

    /// Bind the TCP carrier with an optional HTTP/1.1 `Upgrade: vallum` `Host`
    /// preamble written at the start of outbound dialed connections.
    pub fn bind_with_upgrade(
        address: SocketAddr,
        fwmark: u32,
        tcp_upgrade: Option<&str>,
    ) -> io::Result<Self> {
        let listener = listen_socket(address, fwmark)?;
        let local = listener.local_addr()?;
        let closed = Arc::new(AtomicBool::new(false));
        let connections: Arc<Mutex<HashMap<SocketAddr, Arc<TcpStream>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let inbound_dropped = Arc::new(AtomicU64::new(0));
        let outbound_dropped = Arc::new(AtomicU64::new(0));
        let upgrade_host: Option<Arc<str>> = tcp_upgrade.map(Arc::from);

        // The inbound queue keeps one sender of its own, so it stays open for the
        // socket's whole life instead of closing the moment no peer is connected.
        let (inbound_tx, inbound_rx) = mpsc::sync_channel::<(SocketAddr, Vec<u8>)>(CARRIER_QUEUE);
        let (outbound_tx, outbound_rx) = mpsc::sync_channel::<(SocketAddr, Vec<u8>)>(CARRIER_QUEUE);

        spawn_acceptor(
            listener,
            Arc::clone(&closed),
            Arc::clone(&connections),
            inbound_tx.clone(),
            inbound_dropped.clone(),
            fwmark,
            local,
        );
        spawn_writer(
            outbound_rx,
            Arc::clone(&closed),
            Arc::clone(&connections),
            inbound_tx,
            inbound_dropped.clone(),
            outbound_dropped.clone(),
            fwmark,
            local,
            upgrade_host,
        );

        Ok(Self {
            local,
            closed,
            inbound: Mutex::new(inbound_rx),
            outbound: outbound_tx,
            connections,
            inbound_dropped,
            outbound_dropped,
        })
    }

    /// Packets dropped because a queue was full, incoming and outgoing.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.inbound_dropped.load(Ordering::Relaxed) + self.outbound_dropped.load(Ordering::Relaxed)
    }

    /// The peer addresses with a live connection.
    #[must_use]
    pub fn peers(&self) -> Vec<SocketAddr> {
        self.connections
            .lock()
            .map(|map| map.keys().copied().collect())
            .unwrap_or_default()
    }
}

impl DatagramSocket for TcpTransport {
    fn send_to(&self, bytes: &[u8], destination: SocketAddr) -> io::Result<()> {
        // A full queue is a drop, not an error: the loop's contract is that a
        // packet either goes or is lost, and the caller has no retry to offer.
        if self
            .outbound
            .try_send((destination, bytes.to_vec()))
            .is_err()
        {
            self.outbound_dropped.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let Ok(inbound) = self.inbound.lock() else {
            return Err(io::Error::other("carrier inbound queue is poisoned"));
        };
        // A timeout, not a block: the loop's reader compares the socket's
        // generation on one, which is how a rebind reaches a blocked reader.
        match inbound.recv_timeout(Duration::from_millis(250)) {
            Ok((source, bytes)) => {
                let n = bytes.len().min(buf.len());
                buf[..n].copy_from_slice(&bytes[..n]);
                Ok((n, source))
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                Err(io::Error::new(io::ErrorKind::TimedOut, "no frame waiting"))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "carrier closed"))
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

impl TcpTransport {
    /// Tear down active streams and unblock `accept` so bound ports free immediately.
    pub(crate) fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Ok(connections) = self.connections.lock() {
            for stream in connections.values() {
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
        }
        let _ = TcpStream::connect_timeout(&wake_addr(self.local), Duration::from_millis(200));
    }
}

impl Drop for TcpTransport {
    fn drop(&mut self) {
        // Three things hold threads: the listener blocked in `accept`, readers
        // blocked in `read`, and a writer waiting on its queue. Shut the
        // connections down so the readers see EOF, and dial ourselves so the
        // listener returns once — otherwise a rebind would find the port still
        // taken by a carrier nobody owns.
        self.close();
    }
}

fn wake_addr(local: SocketAddr) -> SocketAddr {
    if local.ip().is_unspecified() {
        let ip = if local.is_ipv4() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        };
        SocketAddr::new(ip, local.port())
    } else {
        local
    }
}

/// Delay before `AutoTransport` staggers a parallel TCP dial if UDP-LWO has
/// not yet answered a peer handshake or probe.
pub const AUTO_TCP_STAGGER: Duration = Duration::from_millis(500);

/// Duration `AutoTransport` stays pinned to UDP-LWO after receiving an authentic
/// inbound datagram from a peer before re-evaluating the race.
pub const AUTO_UDP_LOCK: Duration = Duration::from_secs(15);

/// Maximum initial packets buffered per peer during `AutoTransport`'s UDP
/// racing window so multi-fragment handshake bursts replay cleanly onto TCP
/// when the stagger timer fires.
pub const AUTO_MAX_INITIAL_PACKETS: usize = 100;

#[derive(Debug)]
enum PeerRaceMode {
    RacingUdp {
        first_attempt: Instant,
        tcp_kicked: bool,
        initial_packets: Vec<Vec<u8>>,
        pending_indices: Vec<u32>,
    },
    LockedUdp {
        until: Instant,
    },
    LockedTcp,
}

fn record_initial_packet(
    initial_packets: &mut Vec<Vec<u8>>,
    pending_indices: &mut Vec<u32>,
    bytes: &[u8],
) {
    if let Some(sender_index) = lwo::extract_initiation_sender_index(bytes) {
        if !pending_indices.contains(&sender_index) {
            if pending_indices.len() >= AUTO_MAX_INITIAL_PACKETS {
                pending_indices.remove(0);
            }
            pending_indices.push(sender_index);
        }
    }
    if initial_packets.len() < AUTO_MAX_INITIAL_PACKETS {
        initial_packets.push(bytes.to_vec());
    }
}

fn pending_indices_for(
    peers: &Mutex<HashMap<SocketAddr, PeerRaceMode>>,
    source: SocketAddr,
) -> Vec<u32> {
    let Ok(map) = peers.lock() else {
        return Vec::new();
    };
    match map.get(&source) {
        Some(PeerRaceMode::RacingUdp {
            pending_indices, ..
        }) => pending_indices.clone(),
        _ => Vec::new(),
    }
}

/// Happy-eyeballs carrier racer combining [`LwoTransport`] and [`TcpTransport`].
///
/// Outbound traffic starts immediately on LWO-obfuscated UDP. If a peer does
/// not reply on UDP within [`AUTO_TCP_STAGGER`] (500ms), a background stagger
/// worker automatically transmits the probe over TCP without waiting for an
/// upper-layer retransmission. Whichever path answers first becomes the peer's
/// active path; a winning UDP path stays locked for [`AUTO_UDP_LOCK`] (15s).
pub struct AutoTransport {
    local: SocketAddr,
    lwo: Arc<LwoTransport>,
    tcp: Arc<TcpTransport>,
    stagger: Duration,
    closed: Arc<AtomicBool>,
    inbound: Mutex<mpsc::Receiver<(SocketAddr, Vec<u8>)>>,
    inbound_dropped: Arc<AtomicU64>,
    peers: Arc<(Mutex<HashMap<SocketAddr, PeerRaceMode>>, Condvar)>,
}

impl std::fmt::Debug for AutoTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let peer_count = self.peers.0.lock().map(|map| map.len()).unwrap_or(0);
        f.debug_struct("AutoTransport")
            .field("local", &self.local)
            .field("peers", &peer_count)
            .field("dropped", &self.inbound_dropped.load(Ordering::Relaxed))
            .finish()
    }
}

impl AutoTransport {
    /// Bind both LWO-UDP and TCP listeners on `address`.
    ///
    /// # Errors
    ///
    /// If either socket fails to bind cleanly.
    pub fn bind(address: SocketAddr) -> io::Result<Self> {
        Self::bind_with_fwmark(address, 0)
    }

    /// Bind with an `SO_MARK`, for policy routing.
    ///
    /// # Errors
    ///
    /// If either transport cannot be bound or marked.
    pub fn bind_with_fwmark(address: SocketAddr, fwmark: u32) -> io::Result<Self> {
        Self::bind_with_upgrade(address, fwmark, None)
    }

    /// Bind `AutoTransport` with an optional HTTP/1.1 `Upgrade: vallum` `Host`
    /// preamble for staggered/locked TCP dials.
    pub fn bind_with_upgrade(
        address: SocketAddr,
        fwmark: u32,
        tcp_upgrade: Option<&str>,
    ) -> io::Result<Self> {
        Self::bind_with_timings_and_upgrade(
            address,
            fwmark,
            AUTO_TCP_STAGGER,
            AUTO_UDP_LOCK,
            tcp_upgrade,
        )
    }

    #[cfg(test)]
    pub(crate) fn bind_with_timings(
        address: SocketAddr,
        fwmark: u32,
        stagger: Duration,
        udp_lock: Duration,
    ) -> io::Result<Self> {
        Self::bind_with_timings_and_upgrade(address, fwmark, stagger, udp_lock, None)
    }

    pub(crate) fn bind_with_timings_and_upgrade(
        address: SocketAddr,
        fwmark: u32,
        stagger: Duration,
        udp_lock: Duration,
        tcp_upgrade: Option<&str>,
    ) -> io::Result<Self> {
        // When `address.port() == 0`, bind UDP first and match TCP to that
        // exact ephemeral port so peers only need a single endpoint address.
        let mut last_err = None;
        let attempts = if address.port() == 0 { 4 } else { 1 };
        let mut bound = None;
        for attempt in 0..attempts {
            let lwo = Arc::new(LwoTransport::bind_with_fwmark(address, fwmark)?);
            let actual = lwo.local_addr()?;
            match TcpTransport::bind_with_upgrade(actual, fwmark, tcp_upgrade) {
                Ok(tcp) => {
                    bound = Some((lwo, Arc::new(tcp), actual));
                    break;
                }
                Err(err)
                    if address.port() == 0
                        && err.kind() == io::ErrorKind::AddrInUse
                        && attempt + 1 < attempts =>
                {
                    last_err = Some(err);
                }
                Err(err) => return Err(err),
            }
        }
        let (lwo, tcp, local) = match bound {
            Some(parts) => parts,
            None => {
                return Err(last_err
                    .unwrap_or_else(|| io::Error::new(io::ErrorKind::AddrInUse, "port busy")));
            }
        };

        let closed = Arc::new(AtomicBool::new(false));
        let (inbound_tx, inbound_rx) = mpsc::sync_channel(CARRIER_QUEUE);
        let inbound_dropped = Arc::new(AtomicU64::new(0));
        let peers = Arc::new((Mutex::new(HashMap::new()), Condvar::new()));

        spawn_auto_udp_reader(
            Arc::clone(&lwo),
            Arc::clone(&closed),
            inbound_tx.clone(),
            Arc::clone(&inbound_dropped),
            Arc::clone(&peers),
            udp_lock,
        );
        spawn_auto_tcp_reader(
            Arc::clone(&tcp),
            Arc::clone(&closed),
            inbound_tx,
            Arc::clone(&inbound_dropped),
            Arc::clone(&peers),
        );
        spawn_auto_stagger_worker(
            Arc::clone(&tcp),
            Arc::clone(&closed),
            Arc::clone(&peers),
            stagger,
        );

        Ok(Self {
            local,
            lwo,
            tcp,
            stagger,
            closed,
            inbound: Mutex::new(inbound_rx),
            inbound_dropped,
            peers,
        })
    }

    fn decide_outbound(&self, destination: SocketAddr, bytes: &[u8]) -> (bool, bool, Vec<Vec<u8>>) {
        let now = Instant::now();
        let (lock, cv) = &*self.peers;
        let Ok(mut map) = lock.lock() else {
            return (true, false, Vec::new());
        };
        match map.get_mut(&destination) {
            None => {
                let mut initial_packets = Vec::new();
                let mut pending_indices = Vec::new();
                record_initial_packet(&mut initial_packets, &mut pending_indices, bytes);
                map.insert(
                    destination,
                    PeerRaceMode::RacingUdp {
                        first_attempt: now,
                        tcp_kicked: false,
                        initial_packets,
                        pending_indices,
                    },
                );
                cv.notify_all();
                (true, false, Vec::new())
            }
            Some(PeerRaceMode::RacingUdp {
                first_attempt,
                tcp_kicked,
                initial_packets,
                pending_indices,
            }) => {
                if *tcp_kicked {
                    if let Some(sender_index) = lwo::extract_initiation_sender_index(bytes) {
                        if !pending_indices.contains(&sender_index) {
                            if pending_indices.len() >= AUTO_MAX_INITIAL_PACKETS {
                                pending_indices.remove(0);
                            }
                            pending_indices.push(sender_index);
                        }
                    }
                    (true, true, Vec::new())
                } else if now.duration_since(*first_attempt) >= self.stagger {
                    *tcp_kicked = true;
                    if let Some(sender_index) = lwo::extract_initiation_sender_index(bytes) {
                        if !pending_indices.contains(&sender_index) {
                            if pending_indices.len() >= AUTO_MAX_INITIAL_PACKETS {
                                pending_indices.remove(0);
                            }
                            pending_indices.push(sender_index);
                        }
                    }
                    let replay = std::mem::take(initial_packets);
                    (true, true, replay)
                } else {
                    record_initial_packet(initial_packets, pending_indices, bytes);
                    (true, false, Vec::new())
                }
            }
            Some(PeerRaceMode::LockedUdp { until }) => {
                if now < *until {
                    (true, false, Vec::new())
                } else {
                    let mut initial_packets = Vec::new();
                    let mut pending_indices = Vec::new();
                    record_initial_packet(&mut initial_packets, &mut pending_indices, bytes);
                    map.insert(
                        destination,
                        PeerRaceMode::RacingUdp {
                            first_attempt: now,
                            tcp_kicked: false,
                            initial_packets,
                            pending_indices,
                        },
                    );
                    cv.notify_all();
                    (true, false, Vec::new())
                }
            }
            Some(PeerRaceMode::LockedTcp) => (false, true, Vec::new()),
        }
    }
}

impl DatagramSocket for AutoTransport {
    fn send_to(&self, bytes: &[u8], destination: SocketAddr) -> io::Result<()> {
        let (send_udp, send_tcp, replay_tcp) = self.decide_outbound(destination, bytes);
        match (send_udp, send_tcp) {
            (true, false) => self.lwo.send_to(bytes, destination),
            (false, true) => {
                for pkt in replay_tcp {
                    self.tcp.send_to(&pkt, destination)?;
                }
                self.tcp.send_to(bytes, destination)
            }
            (true, true) => {
                let udp_res = self.lwo.send_to(bytes, destination);
                for pkt in replay_tcp {
                    let _ = self.tcp.send_to(&pkt, destination);
                }
                let tcp_res = self.tcp.send_to(bytes, destination);
                udp_res.or(tcp_res)
            }
            (false, false) => Ok(()),
        }
    }

    fn send_many(&self, batch: &[(SocketAddr, Vec<u8>)]) -> io::Result<usize> {
        if batch.is_empty() {
            return Ok(0);
        }
        let mut udp_batch = Vec::new();
        let mut tcp_batch = Vec::new();
        for (dst, payload) in batch {
            let (send_udp, send_tcp, replay_tcp) = self.decide_outbound(*dst, payload);
            if send_udp {
                udp_batch.push((*dst, payload.clone()));
            }
            for pkt in replay_tcp {
                tcp_batch.push((*dst, pkt));
            }
            if send_tcp {
                tcp_batch.push((*dst, payload.clone()));
            }
        }
        if !udp_batch.is_empty() {
            let _ = self.lwo.send_many(&udp_batch);
        }
        if !tcp_batch.is_empty() {
            self.tcp.send_many(&tcp_batch)?;
        }
        Ok(batch.len())
    }

    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let Ok(inbound) = self.inbound.lock() else {
            return Err(io::Error::other("auto carrier inbound queue is poisoned"));
        };
        match inbound.recv_timeout(Duration::from_millis(250)) {
            Ok((source, bytes)) => {
                let n = bytes.len().min(buf.len());
                buf[..n].copy_from_slice(&bytes[..n]);
                Ok((n, source))
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "no datagram waiting",
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "auto carrier closed",
            )),
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

impl Drop for AutoTransport {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        self.peers.1.notify_all();
        self.tcp.close();
        // Send a 0-byte self-wakeup packet so the UDP reader breaks out of
        // `recv_from` immediately instead of waiting for the 250ms read timeout.
        let _ = self.lwo.udp.socket.send_to(&[], wake_addr(self.local));
    }
}

fn push_auto_inbound(
    inbound_tx: &mpsc::SyncSender<(SocketAddr, Vec<u8>)>,
    inbound_dropped: &AtomicU64,
    source: SocketAddr,
    payload: Vec<u8>,
) -> bool {
    match inbound_tx.try_send((source, payload)) {
        Ok(()) => true,
        Err(mpsc::TrySendError::Full(_)) => {
            inbound_dropped.fetch_add(1, Ordering::Relaxed);
            true
        }
        Err(mpsc::TrySendError::Disconnected(_)) => false,
    }
}

fn is_transient_recv_err(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

fn spawn_auto_udp_reader(
    lwo: Arc<LwoTransport>,
    closed: Arc<AtomicBool>,
    inbound_tx: mpsc::SyncSender<(SocketAddr, Vec<u8>)>,
    inbound_dropped: Arc<AtomicU64>,
    peers: Arc<(Mutex<HashMap<SocketAddr, PeerRaceMode>>, Condvar)>,
    udp_lock: Duration,
) {
    let _ = thread::Builder::new()
        .name("vallum-auto-udp-rx".to_owned())
        .spawn(move || {
            let mut buf = vec![0u8; STREAM_READ_BUFFER];
            while !closed.load(Ordering::Acquire) {
                match lwo.recv_from(&mut buf) {
                    Ok((n, source)) => {
                        if closed.load(Ordering::Acquire) {
                            break;
                        }
                        let pending = pending_indices_for(&peers.0, source);
                        if !lwo::is_authentic_handshake_packet(&buf[..n], &pending, None) {
                            if n > 0 {
                                inbound_dropped.fetch_add(1, Ordering::Relaxed);
                            }
                            continue;
                        }
                        if let Ok(mut map) = peers.0.lock() {
                            map.insert(
                                source,
                                PeerRaceMode::LockedUdp {
                                    until: Instant::now() + udp_lock,
                                },
                            );
                            peers.1.notify_all();
                        }
                        if !push_auto_inbound(
                            &inbound_tx,
                            &inbound_dropped,
                            source,
                            buf[..n].to_vec(),
                        ) {
                            break;
                        }
                    }
                    Err(err) if is_transient_recv_err(&err) => continue,
                    Err(_) => break,
                }
            }
        });
}

fn spawn_auto_tcp_reader(
    tcp: Arc<TcpTransport>,
    closed: Arc<AtomicBool>,
    inbound_tx: mpsc::SyncSender<(SocketAddr, Vec<u8>)>,
    inbound_dropped: Arc<AtomicU64>,
    peers: Arc<(Mutex<HashMap<SocketAddr, PeerRaceMode>>, Condvar)>,
) {
    let _ = thread::Builder::new()
        .name("vallum-auto-tcp-rx".to_owned())
        .spawn(move || {
            let mut buf = vec![0u8; STREAM_READ_BUFFER];
            while !closed.load(Ordering::Acquire) {
                match tcp.recv_from(&mut buf) {
                    Ok((n, source)) => {
                        if closed.load(Ordering::Acquire) {
                            break;
                        }
                        let pending = pending_indices_for(&peers.0, source);
                        if !lwo::is_authentic_handshake_packet(&buf[..n], &pending, None) {
                            if n > 0 {
                                inbound_dropped.fetch_add(1, Ordering::Relaxed);
                            }
                            continue;
                        }
                        if let Ok(mut map) = peers.0.lock() {
                            let now = Instant::now();
                            let keep_udp = matches!(
                                map.get(&source),
                                Some(PeerRaceMode::LockedUdp { until }) if now < *until
                            );
                            if !keep_udp {
                                map.insert(source, PeerRaceMode::LockedTcp);
                                peers.1.notify_all();
                            }
                        }
                        if !push_auto_inbound(
                            &inbound_tx,
                            &inbound_dropped,
                            source,
                            buf[..n].to_vec(),
                        ) {
                            break;
                        }
                    }
                    Err(err) if is_transient_recv_err(&err) => continue,
                    Err(_) => break,
                }
            }
        });
}

fn spawn_auto_stagger_worker(
    tcp: Arc<TcpTransport>,
    closed: Arc<AtomicBool>,
    peers: Arc<(Mutex<HashMap<SocketAddr, PeerRaceMode>>, Condvar)>,
    stagger: Duration,
) {
    let _ = thread::Builder::new()
        .name("vallum-auto-stagger".to_owned())
        .spawn(move || {
            let (lock, cv) = &*peers;
            let Ok(mut map) = lock.lock() else {
                return;
            };
            while !closed.load(Ordering::Acquire) {
                let now = Instant::now();
                let mut due = Vec::new();
                let mut next_deadline: Option<Instant> = None;

                for (&destination, mode) in map.iter_mut() {
                    if let PeerRaceMode::RacingUdp {
                        first_attempt,
                        tcp_kicked,
                        initial_packets,
                        ..
                    } = mode
                    {
                        if *tcp_kicked {
                            continue;
                        }
                        let deadline = *first_attempt + stagger;
                        if now >= deadline {
                            *tcp_kicked = true;
                            let replay = std::mem::take(initial_packets);
                            if !replay.is_empty() {
                                due.push((destination, replay));
                            }
                        } else {
                            next_deadline = Some(match next_deadline {
                                Some(earliest) => earliest.min(deadline),
                                None => deadline,
                            });
                        }
                    }
                }

                if !due.is_empty() {
                    drop(map);
                    for (destination, replay) in due {
                        for probe in replay {
                            let _ = tcp.send_to(&probe, destination);
                        }
                    }
                    map = match lock.lock() {
                        Ok(guard) => guard,
                        Err(_) => return,
                    };
                    continue;
                }

                map = match next_deadline {
                    Some(deadline) => {
                        let wait = deadline.saturating_duration_since(Instant::now());
                        let (guard, _) = match cv.wait_timeout(map, wait) {
                            Ok(res) => res,
                            Err(_) => return,
                        };
                        guard
                    }
                    None => match cv.wait_timeout(map, Duration::from_millis(250)) {
                        Ok((guard, _)) => guard,
                        Err(_) => return,
                    },
                };
            }
        });
}

/// Bind, mark and listen: a `TcpListener` that policy routing can see.
fn listen_socket(address: SocketAddr, fwmark: u32) -> io::Result<TcpListener> {
    #[cfg(target_os = "linux")]
    if fwmark != 0 {
        let fd = marked_socket(address, fwmark)?;
        rustix::net::bind(&fd, &address)
            .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))?;
        rustix::net::listen(&fd, 128)
            .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))?;
        return Ok(TcpListener::from(fd));
    }
    let _ = fwmark;
    TcpListener::bind(address)
}

/// An unconnected, non-blocking stream socket with `SO_MARK` already set.
///
/// Marked *before* the connect on purpose: a full tunnel routes a default route
/// into itself, so an unmarked SYN would be captured by the interface it is
/// trying to establish. `nix` is the wrapper here because `SO_MARK` is not a
/// portable socket option and `rustix` does not expose it.
#[cfg(target_os = "linux")]
fn marked_socket(address: SocketAddr, fwmark: u32) -> io::Result<std::os::fd::OwnedFd> {
    use nix::sys::socket::{socket, AddressFamily, SockFlag, SockProtocol, SockType};

    let family = if address.is_ipv4() {
        AddressFamily::Inet
    } else {
        AddressFamily::Inet6
    };
    let fd = socket(
        family,
        SockType::Stream,
        SockFlag::SOCK_NONBLOCK,
        SockProtocol::Tcp,
    )
    .map_err(errno)?;
    if fwmark != 0 {
        nix::sys::socket::setsockopt(&fd, nix::sys::socket::sockopt::Mark, &fwmark)
            .map_err(errno)?;
    }
    Ok(fd)
}

/// A `nix` error as the `io::Error` the rest of the module speaks.
#[cfg(target_os = "linux")]
fn errno(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

/// Accept loop: one connection per peer address, one reader per connection.
fn spawn_acceptor(
    listener: TcpListener,
    closed: Arc<AtomicBool>,
    connections: Arc<Mutex<HashMap<SocketAddr, Arc<TcpStream>>>>,
    inbound: mpsc::SyncSender<(SocketAddr, Vec<u8>)>,
    dropped: Arc<AtomicU64>,
    fwmark: u32,
    local: SocketAddr,
) {
    let _ = thread::Builder::new()
        .name("vallum-tcp-accept".to_owned())
        .spawn(move || {
            let _ = fwmark;
            let _ = local;
            loop {
                match listener.accept() {
                    Ok((stream, remote)) => {
                        if closed.load(Ordering::Relaxed) {
                            break;
                        }
                        register(stream, remote, &connections, &inbound, &dropped, &closed);
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) if closed.load(Ordering::Relaxed) => break,
                    Err(_) => {
                        // An accept failure is transient (a wake connect, a
                        // backlog race). The socket stays open; anything fatal
                        // will show as a dead listener and a dial that fails.
                        thread::sleep(Duration::from_millis(50));
                    }
                }
            }
        });
}

/// Write loop: frame, dial on first use, write, forget a broken connection.
#[allow(clippy::too_many_arguments)]
fn spawn_writer(
    outbound: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    closed: Arc<AtomicBool>,
    connections: Arc<Mutex<HashMap<SocketAddr, Arc<TcpStream>>>>,
    inbound: mpsc::SyncSender<(SocketAddr, Vec<u8>)>,
    inbound_dropped: Arc<AtomicU64>,
    outbound_dropped: Arc<AtomicU64>,
    fwmark: u32,
    local: SocketAddr,
    upgrade_host: Option<Arc<str>>,
) {
    let _ = thread::Builder::new()
        .name("vallum-tcp-write".to_owned())
        .spawn(move || {
            let _ = local;
            while let Ok((destination, bytes)) = outbound.recv() {
                if closed.load(Ordering::Relaxed) {
                    break;
                }
                let Ok(framed) = frame(&bytes) else {
                    // A packet past the frame ceiling cannot be carried, and
                    // silently splitting it would re-implement segmentation.
                    outbound_dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                let stream = match connection(
                    destination,
                    &connections,
                    &inbound,
                    &inbound_dropped,
                    &closed,
                    fwmark,
                    upgrade_host.as_deref(),
                ) {
                    Some(stream) => stream,
                    None => {
                        outbound_dropped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                if let Err(error) = (&*stream).write_all(&framed) {
                    // The connection is gone; the next datagram for this peer
                    // dials again. Dropping the packet is the honest outcome:
                    // the stream cannot tell us whether it arrived.
                    outbound_dropped.fetch_add(1, Ordering::Relaxed);
                    let _ = error;
                    forget(destination, &stream, &connections);
                }
            }
        });
}

/// The connection for `destination`, dialling and registering a reader if new.
fn connection(
    destination: SocketAddr,
    connections: &Arc<Mutex<HashMap<SocketAddr, Arc<TcpStream>>>>,
    inbound: &mpsc::SyncSender<(SocketAddr, Vec<u8>)>,
    dropped: &Arc<AtomicU64>,
    closed: &Arc<AtomicBool>,
    fwmark: u32,
    upgrade_host: Option<&str>,
) -> Option<Arc<TcpStream>> {
    if let Ok(map) = connections.lock() {
        if let Some(stream) = map.get(&destination) {
            return Some(Arc::clone(stream));
        }
    }
    let mut stream = dial(destination, fwmark).ok()?;
    if let Some(host) = upgrade_host {
        let preamble = upgrade_request(host);
        if stream.write_all(&preamble).is_err() {
            return None;
        }
    }
    register(stream, destination, connections, inbound, dropped, closed);
    connections
        .lock()
        .ok()
        .and_then(|map| map.get(&destination).map(Arc::clone))
}

/// Dial with the mark already on the socket, and a bounded wait.
fn dial(destination: SocketAddr, fwmark: u32) -> io::Result<TcpStream> {
    #[cfg(target_os = "linux")]
    if fwmark != 0 {
        let fd = marked_socket(destination, fwmark)?;
        return connect_marked(fd, destination);
    }
    let _ = fwmark;
    TcpStream::connect_timeout(&destination, CARRIER_DIAL_TIMEOUT)
}

/// Non-blocking connect with a deadline, so a marked dial cannot hang the writer.
#[cfg(target_os = "linux")]
fn connect_marked(fd: std::os::fd::OwnedFd, destination: SocketAddr) -> io::Result<TcpStream> {
    use rustix::event::{poll, PollFd, PollFlags};

    match rustix::net::connect(&fd, &destination) {
        Ok(()) => {}
        Err(rustix::io::Errno::INPROGRESS) => {
            let mut fds = [PollFd::new(&fd, PollFlags::OUT)];
            let ready = poll(
                &mut fds,
                Some(&rustix::time::Timespec {
                    tv_sec: CARRIER_DIAL_TIMEOUT.as_secs() as i64,
                    tv_nsec: 0,
                }),
            )
            .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))?;
            if ready == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "carrier dial timed out",
                ));
            }
            match rustix::net::sockopt::socket_error(&fd)
                .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))?
            {
                Ok(()) => {}
                Err(error) => return Err(io::Error::from_raw_os_error(error.raw_os_error())),
            }
        }
        Err(error) => return Err(io::Error::from_raw_os_error(error.raw_os_error())),
    }
    // Back to blocking: the writer thread does one write at a time and would
    // rather wait than spin.
    nix::fcntl::fcntl(
        &fd,
        nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::empty()),
    )
    .map_err(errno)?;
    Ok(TcpStream::from(fd))
}

/// Take a connected stream, start its reader, and remember its write half.
fn register(
    stream: TcpStream,
    remote: SocketAddr,
    connections: &Arc<Mutex<HashMap<SocketAddr, Arc<TcpStream>>>>,
    inbound: &mpsc::SyncSender<(SocketAddr, Vec<u8>)>,
    dropped: &Arc<AtomicU64>,
    closed: &Arc<AtomicBool>,
) {
    let write_half = match stream.try_clone() {
        Ok(clone) => Arc::new(clone),
        Err(_) => return,
    };
    if let Ok(mut map) = connections.lock() {
        // One connection per peer address. A second dial or a peer dialling in
        // while a connection is live would only split the order in two.
        if map.contains_key(&remote) {
            let _ = write_half.shutdown(std::net::Shutdown::Both);
            return;
        }
        map.insert(remote, Arc::clone(&write_half));
    } else {
        return;
    }
    spawn_reader(
        stream,
        remote,
        write_half,
        Arc::clone(connections),
        inbound.clone(),
        Arc::clone(dropped),
        Arc::clone(closed),
    );
}

/// Read loop for one connection: unframe, queue, and forget the connection on EOF.
fn spawn_reader(
    stream: TcpStream,
    remote: SocketAddr,
    registered: Arc<TcpStream>,
    connections: Arc<Mutex<HashMap<SocketAddr, Arc<TcpStream>>>>,
    inbound: mpsc::SyncSender<(SocketAddr, Vec<u8>)>,
    dropped: Arc<AtomicU64>,
    closed: Arc<AtomicBool>,
) {
    let _ = thread::Builder::new()
        .name(format!("vallum-tcp-read {remote}"))
        .spawn(move || {
            // A timeout on each read is how this thread notices the carrier being
            // dropped while it waits; `shutdown` covers the fast path.
            let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
            let mut reader = FrameReader::new();
            let mut buffer = vec![0u8; STREAM_READ_BUFFER];
            loop {
                if closed.load(Ordering::Relaxed) {
                    break;
                }
                match (&stream).read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        reader.push(&buffer[..n]);
                        loop {
                            let next = reader.next_frame();
                            if let Some(reply) = reader.take_upgrade_reply() {
                                if (&*registered).write_all(reply).is_err() {
                                    break;
                                }
                            }
                            match next {
                                Ok(Some(packet)) => {
                                    if inbound.try_send((remote, packet)).is_err() {
                                        dropped.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                Ok(None) => break,
                                Err(_) => break,
                            }
                        }
                    }
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            || error.kind() == io::ErrorKind::TimedOut => {}
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
            // Only forget the connection this reader owns: a newer one for the
            // same address may already have been registered by a redial.
            forget(remote, &registered, &connections);
        });
}

/// Remove `stream` from the map if it is still the one registered there.
fn forget(
    remote: SocketAddr,
    stream: &Arc<TcpStream>,
    connections: &Arc<Mutex<HashMap<SocketAddr, Arc<TcpStream>>>>,
) {
    if let Ok(mut map) = connections.lock() {
        if let Some(current) = map.get(&remote) {
            if Arc::ptr_eq(current, stream) {
                map.remove(&remote);
            }
        }
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
/// Every IP address this host currently holds, CIDR stripped.
///
/// The same `ip -o addr` shell-out the health probes use: std has no
/// `getifaddrs`, and a wrong answer here would refuse a legitimate config.
pub fn local_addresses() -> Vec<String> {
    let output = match std::process::Command::new("ip")
        .args(["-o", "addr", "show"])
        .output()
    {
        Ok(output) => output,
        Err(_) => return Vec::new(),
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            // "2: eth0    inet 10.0.0.2/24 brd ..." — the address is the token
            // after inet/inet6.
            let mut fields = line.split_whitespace();
            let mut previous = "";
            for field in fields.by_ref() {
                if previous == "inet" || previous == "inet6" {
                    return field.split('/').next().map(str::to_owned);
                }
                previous = field;
            }
            None
        })
        .collect()
}

/// The route's MTU as the kernel reports it. `IP_MTU`/`IPV6_MTU` are Linux
/// sockopts; off Linux the callers' `Option`/`io::Result` handling already
/// treats an unsupported probe as "unknown" rather than wrong.
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

/// As [`path_mtu`], for a build whose kernel does not report route MTUs.
#[cfg(not(target_os = "linux"))]
pub fn path_mtu(_endpoint: SocketAddr) -> io::Result<u16> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "route MTU discovery is only implemented for Linux",
    ))
}

/// Every IP address this host holds. `getifaddrs` is the portable Unix answer;
/// the Linux version above shells out to `ip` only because it predates this.
#[cfg(not(target_os = "linux"))]
pub fn local_addresses() -> Vec<String> {
    nix::ifaddrs::getifaddrs()
        .map(|addrs| {
            addrs
                .filter_map(|a| a.address)
                .filter_map(|a| {
                    a.as_sockaddr_in()
                        .map(|s| IpAddr::V4(s.ip()))
                        .or_else(|| a.as_sockaddr_in6().map(|s| IpAddr::V6(s.ip())))
                })
                .map(|ip| ip.to_string())
                .collect()
        })
        .unwrap_or_default()
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

/// Parse `time=<ms>` from `ping` stdout and convert it to integer microseconds.
pub fn parse_ping_rtt_micros(output: &str) -> Option<u32> {
    let tag = "time=";
    let idx = output.find(tag)?;
    let rest = output[idx + tag.len()..].trim_start();
    let token: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    if token.is_empty() {
        return None;
    }
    let (whole_str, frac_str) = match token.split_once('.') {
        Some((w, f)) => (w, f),
        None => (token.as_str(), ""),
    };
    let whole_ms: u32 = if whole_str.is_empty() {
        0
    } else {
        whole_str.parse().ok()?
    };
    let mut frac_digits = frac_str.bytes().filter(u8::is_ascii_digit);
    let d1 = u32::from(frac_digits.next().map_or(0, |b| b - b'0'));
    let d2 = u32::from(frac_digits.next().map_or(0, |b| b - b'0'));
    let d3 = u32::from(frac_digits.next().map_or(0, |b| b - b'0'));
    let mut frac_us = d1 * 100 + d2 * 10 + d3;
    if frac_digits.next().is_some_and(|b| b >= b'5') {
        frac_us += 1;
    }
    whole_ms.checked_mul(1_000)?.checked_add(frac_us)
}

/// Test whether an ICMP packet with `payload` bytes fits the path to `host` with DF set,
/// returning `(fits, reported_mtu, rtt_us)`.
fn default_ping_probe_with_rtt(host: &str, payload: u16) -> (bool, Option<u16>, Option<u32>) {
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
        return (false, None, None);
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    if output.status.success() {
        return (true, None, parse_ping_rtt_micros(&stdout));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stderr}\n{stdout}");
    (false, parse_reported_mtu(&combined), None)
}

/// Test whether an ICMP packet with `payload` bytes fits the path to `host` with DF set.
///
/// Returns `(fits, reported_mtu)`.
fn default_ping_probe(host: &str, payload: u16) -> (bool, Option<u16>) {
    let (fits, reported, _) = default_ping_probe_with_rtt(host, payload);
    (fits, reported)
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

/// Standard outer encapsulation overhead (IPv4/UDP + Vallum transport header + AEAD tag)
/// mapping `1420` inner MTU to `1484` outer wire MTU.
pub const WIRE_ENCAP_OVERHEAD: u16 = 64;

/// Operating profile selected by the telemetry-driven adaptive MTU optimizer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MtuProfile {
    /// `1280` inner MTU: minimizes tail jitter and buffer straddling on USB Ethernet,
    /// Wi-Fi, cellular, or lossy driver paths.
    LowJitterUsb1280,
    /// `1380` inner MTU: balances ~1300-byte real-time game/voice UDP datagrams with
    /// outer headroom against path fragmentation.
    GamingLowFrag1380,
    /// `1420` inner MTU: maximizes bulk TCP/UDP goodput on clean, low-jitter paths.
    BulkStandard1420,
    /// Path MTU ceiling is below `1344`, forcing the inner MTU down to fit.
    ConstrainedPath,
}

impl MtuProfile {
    /// Machine-readable identifier emitted in `doctor --json` and telemetry logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LowJitterUsb1280 => "low-jitter-1280",
            Self::GamingLowFrag1380 => "gaming-pq-1380",
            Self::BulkStandard1420 => "bulk-1420",
            Self::ConstrainedPath => "constrained-path",
        }
    }
}

/// Measured latency, jitter, and loss metrics for a candidate inner/outer MTU pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtuCandidateSample {
    pub inner_mtu: u16,
    pub outer_mtu: u16,
    pub rtt_p50_us: u32,
    pub rtt_jitter_us: u32,
    pub loss_pct: u8,
}

/// Output of the adaptive MTU optimizer, including MSS alignment for JA4T/TCP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtuTuneRecommendation {
    pub ceiling_outer_mtu: u16,
    pub recommended_inner_mtu: u16,
    pub recommended_outer_mtu: u16,
    pub ipv4_tcp_mss: u16,
    pub ipv6_tcp_mss: u16,
    pub profile: MtuProfile,
    pub samples: Vec<MtuCandidateSample>,
    pub rationale: String,
}

fn build_recommendation(
    ceiling_outer_mtu: u16,
    inner_mtu: u16,
    profile: MtuProfile,
    samples: Vec<MtuCandidateSample>,
    rationale: String,
) -> MtuTuneRecommendation {
    let outer_mtu = inner_mtu.saturating_add(WIRE_ENCAP_OVERHEAD);
    MtuTuneRecommendation {
        ceiling_outer_mtu,
        recommended_inner_mtu: inner_mtu,
        recommended_outer_mtu: outer_mtu,
        ipv4_tcp_mss: inner_mtu.saturating_sub(40),
        ipv6_tcp_mss: inner_mtu.saturating_sub(60),
        profile,
        samples,
        rationale,
    }
}

/// Score measured candidate MTU probes alongside live fragmentation counters
/// (`fragments_dropped`, `reassembled`, `packets_delivered`) to recommend an optimal MTU.
#[must_use]
pub fn recommend_mtu_from_telemetry(
    ceiling_outer_mtu: u16,
    samples: &[MtuCandidateSample],
    fragments_dropped: u64,
    reassembled: u64,
    packets_delivered: u64,
) -> MtuTuneRecommendation {
    let owned_samples = samples.to_vec();
    let min_standard_outer = 1280u16.saturating_add(WIRE_ENCAP_OVERHEAD);
    if ceiling_outer_mtu < min_standard_outer {
        let clamped_inner = ceiling_outer_mtu
            .saturating_sub(WIRE_ENCAP_OVERHEAD)
            .max(576);
        return build_recommendation(
            ceiling_outer_mtu,
            clamped_inner,
            MtuProfile::ConstrainedPath,
            owned_samples,
            format!(
                "path ceiling {ceiling_outer_mtu} B is below {min_standard_outer} B; \
                 clamping inner MTU to {clamped_inner}"
            ),
        );
    }

    let usable: Vec<&MtuCandidateSample> = samples
        .iter()
        .filter(|s| s.outer_mtu <= ceiling_outer_mtu && s.loss_pct < 100)
        .collect();

    let s1280 = usable.iter().copied().find(|s| s.inner_mtu == 1280);
    let s1380 = usable.iter().copied().find(|s| s.inner_mtu == 1380);
    let s1420 = usable.iter().copied().find(|s| s.inner_mtu == 1420);

    let frag_pressure = fragments_dropped > 0
        || (packets_delivered > 0 && reassembled.saturating_mul(100) / packets_delivered >= 2);

    // USB Ethernet URB straddling or driver buffer pressure shows up as packet loss
    // or a >1.0 ms (>2x baseline) tail jitter jump at larger frame sizes vs 1280.
    let larger_lossy = [s1380, s1420].into_iter().flatten().any(|s| s.loss_pct > 0)
        && s1280.is_some_and(|s| s.loss_pct == 0);
    let larger_jitter_spike = s1280.is_some_and(|base| {
        let spike_threshold = base
            .rtt_jitter_us
            .saturating_add(1_000)
            .max(base.rtt_jitter_us.saturating_mul(2).saturating_add(300));
        [s1380, s1420]
            .into_iter()
            .flatten()
            .any(|larger| larger.rtt_jitter_us > spike_threshold)
    });

    if larger_lossy || larger_jitter_spike {
        return build_recommendation(
            ceiling_outer_mtu,
            1280,
            MtuProfile::LowJitterUsb1280,
            owned_samples,
            "1280 MTU eliminates larger-frame jitter spikes / loss (USB NIC URB or access link profile)"
                .to_owned(),
        );
    }

    let fit_1420 = ceiling_outer_mtu >= 1420 + WIRE_ENCAP_OVERHEAD;
    let fit_1380 = ceiling_outer_mtu >= 1380 + WIRE_ENCAP_OVERHEAD;
    let degraded_1420 = s1420.is_some_and(|s| s.loss_pct > 0)
        || (s1380.is_some()
            && s1420.is_some_and(|l| {
                let b = s1380.map_or(0, |s| s.rtt_jitter_us);
                l.rtt_jitter_us > b.saturating_add(1_000)
            }));

    if fit_1380 && (frag_pressure || !fit_1420 || degraded_1420) {
        let reason = if frag_pressure {
            "inner fragmentation/reassembly pressure detected; 1380 keeps ~1300B gaming/UDP frames unfragmented"
        } else if !fit_1420 {
            "path ceiling fits 1380 (1444B outer) without hitting 1484B overflow"
        } else {
            "1380 delivers lower tail jitter than 1420 while preserving gaming UDP headroom"
        };
        return build_recommendation(
            ceiling_outer_mtu,
            1380,
            MtuProfile::GamingLowFrag1380,
            owned_samples,
            reason.to_owned(),
        );
    }

    if !fit_1380 && ceiling_outer_mtu >= 1340 + WIRE_ENCAP_OVERHEAD {
        return build_recommendation(
            ceiling_outer_mtu,
            1340,
            MtuProfile::GamingLowFrag1380,
            owned_samples,
            "path ceiling fits 1340 (1404B outer) for PPPoE/cellular links without fragmenting"
                .to_owned(),
        );
    }

    if fit_1420 {
        return build_recommendation(
            ceiling_outer_mtu,
            1420,
            MtuProfile::BulkStandard1420,
            owned_samples,
            "clean low-jitter path with negligible inner fragmentation favors 1420 bulk goodput"
                .to_owned(),
        );
    }

    build_recommendation(
        ceiling_outer_mtu,
        1280,
        MtuProfile::LowJitterUsb1280,
        owned_samples,
        "selecting 1280 safe baseline within path MTU ceiling".to_owned(),
    )
}

fn tune_path_mtu_with_counters_and_overhead(
    ceiling_outer_mtu: u16,
    icmp_overhead: u16,
    fragments_dropped: u64,
    reassembled: u64,
    packets_delivered: u64,
    mut probe_rtt_us: impl FnMut(u16) -> Option<u32>,
) -> MtuTuneRecommendation {
    let mut samples = Vec::new();
    if ceiling_outer_mtu >= 1280 + WIRE_ENCAP_OVERHEAD {
        for inner_mtu in [1280u16, 1380, 1420] {
            let outer_mtu = inner_mtu.saturating_add(WIRE_ENCAP_OVERHEAD);
            if outer_mtu > ceiling_outer_mtu {
                continue;
            }
            let payload = outer_mtu.saturating_sub(icmp_overhead);
            let mut rtts = Vec::with_capacity(3);
            let mut lost = 0u8;
            for _ in 0..3 {
                match probe_rtt_us(payload) {
                    Some(rtt) => rtts.push(rtt),
                    None => lost += 1,
                }
            }
            rtts.sort_unstable();
            let loss_pct = ((u16::from(lost) * 100) / 3) as u8;
            let (rtt_p50_us, rtt_jitter_us) = if rtts.is_empty() {
                (0, 0)
            } else {
                let p50 = rtts[rtts.len() / 2];
                let min = rtts[0];
                let max = rtts[rtts.len() - 1];
                (p50, max.saturating_sub(min))
            };
            samples.push(MtuCandidateSample {
                inner_mtu,
                outer_mtu,
                rtt_p50_us,
                rtt_jitter_us,
                loss_pct,
            });
        }
    }
    recommend_mtu_from_telemetry(
        ceiling_outer_mtu,
        &samples,
        fragments_dropped,
        reassembled,
        packets_delivered,
    )
}

/// Sweep candidate MTUs (`1280`, `1380`, `1420`) capped by `ceiling_outer_mtu` using
/// a caller-supplied IPv4 ICMP payload RTT prober (`payload -> Option<rtt_us>`).
pub fn tune_path_mtu_with(
    ceiling_outer_mtu: u16,
    probe_rtt_us: impl FnMut(u16) -> Option<u32>,
) -> MtuTuneRecommendation {
    tune_path_mtu_with_counters_and_overhead(ceiling_outer_mtu, 28, 0, 0, 0, probe_rtt_us)
}

/// Discover the path MTU ceiling to `host_or_endpoint`, sweep candidate payloads, and
/// combine with live UAPI fragmentation counters (`fragments_dropped`, `reassembled`,
/// `packets_delivered`) to return a closed-loop MTU profile recommendation.
pub fn tune_path_mtu_host_with_counters(
    host_or_endpoint: &str,
    fragments_dropped: u64,
    reassembled: u64,
    packets_delivered: u64,
) -> Option<MtuTuneRecommendation> {
    let ceiling_outer_mtu = probe_path_mtu_host(host_or_endpoint)?;
    let (host, is_ipv6) = parse_probe_host(host_or_endpoint);
    let icmp_overhead = if is_ipv6 { 48 } else { 28 };
    let started = Instant::now();
    Some(tune_path_mtu_with_counters_and_overhead(
        ceiling_outer_mtu,
        icmp_overhead,
        fragments_dropped,
        reassembled,
        packets_delivered,
        |payload| {
            if started.elapsed() >= PROBE_BUDGET {
                return None;
            }
            let (fits, _, rtt_us) = default_ping_probe_with_rtt(&host, payload);
            if fits {
                Some(rtt_us.unwrap_or(500))
            } else {
                None
            }
        },
    ))
}

/// Discover the path MTU ceiling to `host_or_endpoint`, sweep candidate payloads, and
/// return a telemetry-backed MTU profile recommendation.
pub fn tune_path_mtu_host(host_or_endpoint: &str) -> Option<MtuTuneRecommendation> {
    tune_path_mtu_host_with_counters(host_or_endpoint, 0, 0, 0)
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

    /// One received packet, waiting up to a second for the carrier's threads.
    fn recv(carrier: &TcpTransport) -> (Vec<u8>, SocketAddr) {
        let mut buffer = [0u8; 2_048];
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            match carrier.recv_from(&mut buffer) {
                Ok((n, source)) => return (buffer[..n].to_vec(), source),
                Err(error)
                    if error.kind() == io::ErrorKind::TimedOut
                        || error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("carrier read failed: {error}"),
            }
        }
        panic!("no packet arrived within two seconds");
    }

    #[test]
    fn a_stream_carrier_carries_datagrams_whole_and_in_order() {
        let receiver = TcpTransport::bind("127.0.0.1:0".parse().expect("receiver")).expect("bind");
        let sender = TcpTransport::bind("127.0.0.1:0".parse().expect("sender")).expect("bind");
        let destination = receiver.local_addr().expect("local addr");

        // A frame boundary is not a read boundary: three sends may arrive as one
        // read, and each must still come back as the packet that was sent.
        for packet in [b"one".as_slice(), b"two", b"three"] {
            sender
                .send_to(packet, destination)
                .expect("enqueue a packet");
        }

        let sender_address = sender.local_addr().expect("sender addr");
        for expected in [b"one".as_slice(), b"two", b"three"] {
            let (packet, source) = recv(&receiver);
            assert_eq!(packet, expected);
            // The source is the sender's address as the connection came from:
            // the host, and the ephemeral port the dial chose — not the port the
            // sender listens on. That is also the address a reply is written
            // back to, because it is the connection's own far end.
            assert_eq!(source.ip(), sender_address.ip());
            assert_eq!(source.port(), receiver.peers()[0].port());
        }
        assert_eq!(sender.dropped() + receiver.dropped(), 0);
    }

    #[test]
    fn a_stream_carrier_keeps_two_peers_on_separate_connections() {
        let first = TcpTransport::bind("127.0.0.1:0".parse().expect("first")).expect("bind");
        let second = TcpTransport::bind("127.0.0.1:0".parse().expect("second")).expect("bind");
        let sender = TcpTransport::bind("127.0.0.1:0".parse().expect("sender")).expect("bind");

        sender
            .send_to(b"to-first", first.local_addr().expect("addr"))
            .expect("send");
        sender
            .send_to(b"to-second", second.local_addr().expect("addr"))
            .expect("send");

        assert_eq!(recv(&first).0, b"to-first");
        assert_eq!(recv(&second).0, b"to-second");
        // One connection per destination, not one connection for everything.
        assert_eq!(sender.peers().len(), 2);
    }

    #[test]
    fn a_stream_carrier_frees_its_port_when_dropped() {
        // A rebind replaces the socket at runtime, so a dropped carrier that kept
        // its listener alive would make `listen_port` a one-way trip.
        let address: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let first = TcpTransport::bind(address).expect("bind");
        let bound = first.local_addr().expect("local addr");
        drop(first);
        thread::sleep(Duration::from_millis(50));
        let second = TcpTransport::bind(bound).expect("rebind the same port");
        assert_eq!(second.local_addr().expect("local addr"), bound);
    }

    #[test]
    fn a_stream_carrier_reports_a_closed_socket_rather_than_blocking_forever() {
        let carrier = TcpTransport::bind("127.0.0.1:0".parse().expect("addr")).expect("bind");
        let mut buffer = [0u8; 64];
        // Nothing has arrived: the read times out, which is what lets the loop's
        // reader notice a rebind instead of blocking on a dead socket.
        let error = carrier.recv_from(&mut buffer).expect_err("empty carrier");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
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

    #[test]
    fn parse_ping_rtt_micros_extracts_submillisecond_and_millisecond_times() {
        let subms = "64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.042 ms";
        assert_eq!(parse_ping_rtt_micros(subms), Some(42));

        let multi = "1460 bytes from 203.0.113.10: icmp_seq=1 ttl=55 time=24.856 ms";
        assert_eq!(parse_ping_rtt_micros(multi), Some(24_856));

        let rounded = "64 bytes from 10.7.0.1: icmp_seq=1 ttl=64 time=1.2346 ms";
        assert_eq!(parse_ping_rtt_micros(rounded), Some(1_235));

        assert_eq!(
            parse_ping_rtt_micros("Request timeout for icmp_seq 0"),
            None
        );
    }

    #[test]
    fn mtu_optimizer_selects_1280_when_larger_frames_cause_usb_jitter_spike() {
        let samples = vec![
            MtuCandidateSample {
                inner_mtu: 1280,
                outer_mtu: 1344,
                rtt_p50_us: 1_200,
                rtt_jitter_us: 180,
                loss_pct: 0,
            },
            MtuCandidateSample {
                inner_mtu: 1380,
                outer_mtu: 1444,
                rtt_p50_us: 2_900,
                rtt_jitter_us: 2_600,
                loss_pct: 0,
            },
            MtuCandidateSample {
                inner_mtu: 1420,
                outer_mtu: 1484,
                rtt_p50_us: 3_400,
                rtt_jitter_us: 3_800,
                loss_pct: 0,
            },
        ];
        let rec = recommend_mtu_from_telemetry(1500, &samples, 0, 0, 10_000);
        assert_eq!(rec.recommended_inner_mtu, 1280);
        assert_eq!(rec.recommended_outer_mtu, 1344);
        assert_eq!(rec.ipv4_tcp_mss, 1240);
        assert_eq!(rec.ipv6_tcp_mss, 1220);
        assert_eq!(rec.profile, MtuProfile::LowJitterUsb1280);
    }

    #[test]
    fn mtu_optimizer_selects_1380_when_inner_fragmentation_pressure_is_present() {
        let samples = vec![
            MtuCandidateSample {
                inner_mtu: 1280,
                outer_mtu: 1344,
                rtt_p50_us: 14_000,
                rtt_jitter_us: 300,
                loss_pct: 0,
            },
            MtuCandidateSample {
                inner_mtu: 1380,
                outer_mtu: 1444,
                rtt_p50_us: 14_100,
                rtt_jitter_us: 320,
                loss_pct: 0,
            },
            MtuCandidateSample {
                inner_mtu: 1420,
                outer_mtu: 1484,
                rtt_p50_us: 14_200,
                rtt_jitter_us: 350,
                loss_pct: 0,
            },
        ];
        // Reassembly at >=2% of delivered packets triggers the gaming / PQ-safe 1380 profile.
        let rec = recommend_mtu_from_telemetry(1500, &samples, 0, 250, 10_000);
        assert_eq!(rec.recommended_inner_mtu, 1380);
        assert_eq!(rec.recommended_outer_mtu, 1444);
        assert_eq!(rec.ipv4_tcp_mss, 1340);
        assert_eq!(rec.profile, MtuProfile::GamingLowFrag1380);
    }

    #[test]
    fn mtu_optimizer_selects_1420_on_clean_low_jitter_ethernet_path() {
        let mut idx = 0usize;
        let rtts = [500u32, 520, 510, 515, 530, 525, 520, 540, 535];
        let rec = tune_path_mtu_with(1500, |_payload| {
            let v = rtts[idx % rtts.len()];
            idx += 1;
            Some(v)
        });
        assert_eq!(rec.recommended_inner_mtu, 1420);
        assert_eq!(rec.recommended_outer_mtu, 1484);
        assert_eq!(rec.ipv4_tcp_mss, 1380);
        assert_eq!(rec.profile, MtuProfile::BulkStandard1420);
        assert_eq!(rec.samples.len(), 3);
    }

    #[test]
    fn mtu_optimizer_selects_1280_with_empirical_wingman_vps_jitter_profile() {
        // Empirical live measurement (ikaaros -> 203.0.113.10):
        // 1280 had 0.4ms jitter while 1380/1420 jumped 4.25x-4.5x to 1.7-1.8ms.
        let samples = vec![
            MtuCandidateSample {
                inner_mtu: 1280,
                outer_mtu: 1344,
                rtt_p50_us: 69_800,
                rtt_jitter_us: 400,
                loss_pct: 0,
            },
            MtuCandidateSample {
                inner_mtu: 1380,
                outer_mtu: 1444,
                rtt_p50_us: 69_600,
                rtt_jitter_us: 1_700,
                loss_pct: 0,
            },
            MtuCandidateSample {
                inner_mtu: 1420,
                outer_mtu: 1484,
                rtt_p50_us: 69_200,
                rtt_jitter_us: 1_800,
                loss_pct: 0,
            },
        ];
        let rec = recommend_mtu_from_telemetry(1500, &samples, 0, 0, 0);
        assert_eq!(rec.recommended_inner_mtu, 1280);
        assert_eq!(rec.recommended_outer_mtu, 1344);
        assert_eq!(rec.profile, MtuProfile::LowJitterUsb1280);
    }

    #[test]
    fn mtu_optimizer_clamps_to_constrained_path_below_1344() {
        let rec = recommend_mtu_from_telemetry(1300, &[], 0, 0, 0);
        assert_eq!(rec.recommended_inner_mtu, 1236);
        assert_eq!(rec.recommended_outer_mtu, 1300);
        assert_eq!(rec.profile, MtuProfile::ConstrainedPath);
    }

    fn sample_vallum_packet(tag: u8) -> Vec<u8> {
        let mut pkt = vec![0u8; 64];
        pkt[0] = 0x01; // PROTOCOL_VERSION
        pkt[1] = 0x04; // Data
        pkt[2] = 0x01; // Suite
        for (i, b) in pkt.iter_mut().enumerate().skip(3) {
            *b = tag.wrapping_add((i as u8).wrapping_mul(31));
        }
        pkt
    }

    #[test]
    fn lwo_transport_masks_wire_and_interoperates_with_plain_udp() {
        let raw_sniffer = UdpSocket::bind("127.0.0.1:0").expect("sniffer bind");
        raw_sniffer
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("sniffer timeout");
        let lwo_client = LwoTransport::bind("127.0.0.1:0".parse().expect("addr")).expect("lwo");

        let pkt = sample_vallum_packet(7);
        lwo_client
            .send_to(&pkt, raw_sniffer.local_addr().expect("addr"))
            .expect("send masked");

        let mut wire = [0u8; 256];
        let (n, _) = raw_sniffer.recv_from(&mut wire).expect("recv wire");
        assert_eq!(n, pkt.len(), "LWO adds zero bytes on the wire");
        assert_ne!(wire[0], 0x01, "LWO header byte must be obfuscated on wire");

        // Now test full round-trip against an unmodified UdpTransport listener.
        let udp_server = UdpTransport::bind("127.0.0.1:0".parse().expect("addr")).expect("udp");
        lwo_client
            .send_to(&pkt, udp_server.local_addr().expect("addr"))
            .expect("client -> server");

        let mut buf = [0u8; 256];
        let (n, peer) = udp_server.recv_from(&mut buf).expect("server recv");
        assert_eq!(
            &buf[..n],
            pkt.as_slice(),
            "server unmasks LWO transparently"
        );

        let reply = sample_vallum_packet(99);
        udp_server.send_to(&reply, peer).expect("server -> client");
        let (rn, _) = lwo_client.recv_from(&mut buf).expect("client recv");
        assert_eq!(&buf[..rn], reply.as_slice());
    }

    #[test]
    fn auto_transport_prefers_lwo_udp_and_locks_without_tcp_dial() {
        let udp_server = UdpTransport::bind("127.0.0.1:0".parse().expect("addr")).expect("udp");
        let server_addr = udp_server.local_addr().expect("addr");
        let auto_client = AutoTransport::bind("127.0.0.1:0".parse().expect("addr")).expect("auto");

        let req = sample_vallum_packet(11);
        auto_client.send_to(&req, server_addr).expect("auto send");

        let mut buf = [0u8; 256];
        let (n, peer) = udp_server.recv_from(&mut buf).expect("udp recv");
        assert_eq!(&buf[..n], req.as_slice());

        let resp = sample_vallum_packet(22);
        udp_server.send_to(&resp, peer).expect("udp reply");

        let (rn, rsrc) = loop {
            match auto_client.recv_from(&mut buf) {
                Ok(ok) => break ok,
                Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
                Err(e) => panic!("auto recv failed: {e}"),
            }
        };
        assert_eq!(rsrc, server_addr);
        assert_eq!(&buf[..rn], resp.as_slice());
    }

    #[test]
    fn auto_transport_staggers_to_tcp_when_udp_is_blackholed() {
        // Bind a UDP socket we never reply from (simulates firewall dropping UDP replies),
        // and bind a TcpTransport on the exact same address:port.
        let blackhole_udp = UdpSocket::bind("127.0.0.1:0").expect("blackhole udp");
        blackhole_udp
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let target = blackhole_udp.local_addr().expect("addr");
        let tcp_server = TcpTransport::bind(target).expect("tcp server");

        let auto_client = AutoTransport::bind_with_timings(
            "127.0.0.1:0".parse().expect("addr"),
            0,
            Duration::from_millis(80),
            Duration::from_millis(250),
        )
        .expect("auto client");

        let req = sample_vallum_packet(55);
        auto_client.send_to(&req, target).expect("send race probe");

        // UDP attempt fires first as LWO on the blackhole socket.
        let mut wire = [0u8; 256];
        let (wn, _) = blackhole_udp
            .recv_from(&mut wire)
            .expect("blackhole got udp");
        assert_eq!(wn, req.len());
        assert_ne!(wire[0], 0x01);

        // Stagger worker automatically dials TCP after 80ms without a second send_to.
        let mut buf = [0u8; 256];
        let (tn, tcp_peer) = loop {
            match tcp_server.recv_from(&mut buf) {
                Ok(ok) => break ok,
                Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
                Err(e) => panic!("tcp server recv failed: {e}"),
            }
        };
        assert_eq!(&buf[..tn], req.as_slice());

        let resp = sample_vallum_packet(88);
        tcp_server.send_to(&resp, tcp_peer).expect("tcp reply");

        let (cn, csrc) = loop {
            match auto_client.recv_from(&mut buf) {
                Ok(ok) => break ok,
                Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
                Err(e) => panic!("auto recv failed: {e}"),
            }
        };
        assert_eq!(csrc, target);
        assert_eq!(&buf[..cn], resp.as_slice());
    }

    #[test]
    fn lwo_transport_pads_handshakes_on_wire_and_unpads_at_udp_server() {
        let raw_sniffer = UdpSocket::bind("127.0.0.1:0").expect("sniffer");
        raw_sniffer
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let lwo_client = LwoTransport::bind("127.0.0.1:0".parse().expect("addr")).expect("lwo");

        let mut init_hello = sample_vallum_packet(41);
        init_hello[1] = 0x01; // InitHello
        lwo_client
            .send_to(&init_hello, raw_sniffer.local_addr().expect("addr"))
            .expect("send init hello");

        let mut wire = [0u8; 512];
        let (wire_len, _) = raw_sniffer.recv_from(&mut wire).expect("recv wire");
        assert!(wire_len > init_hello.len(), "handshake must be padded");
        assert!(wire_len <= init_hello.len() + lwo::MAX_HANDSHAKE_PAD);

        let udp_server = UdpTransport::bind("127.0.0.1:0".parse().expect("addr")).expect("udp");
        lwo_client
            .send_to(&init_hello, udp_server.local_addr().expect("addr"))
            .expect("send init hello to udp server");

        let (logical_len, _) = udp_server.recv_from(&mut wire).expect("server recv");
        assert_eq!(logical_len, init_hello.len());
        assert_eq!(&wire[..logical_len], init_hello.as_slice());
    }

    #[test]
    fn tcp_transport_completes_http_101_upgrade_before_carrying_frames() {
        let tcp_server =
            TcpTransport::bind("127.0.0.1:0".parse().expect("addr")).expect("tcp server");
        let server_addr = tcp_server.local_addr().expect("server addr");

        let mut client = TcpStream::connect(server_addr).expect("connect to tcp server");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");

        let req = vallum_tunnel::stream::upgrade_request("wingman.gold");
        client.write_all(&req).expect("write upgrade request");

        let mut raw_resp = [0u8; 256];
        let mut total = 0usize;
        let mut client_reader = FrameReader::new();
        while !raw_resp[..total].windows(4).any(|w| w == b"\r\n\r\n") {
            let n = client.read(&mut raw_resp[total..]).expect("read 101");
            assert!(n > 0, "unexpected EOF waiting for 101 response");
            client_reader.push(&raw_resp[total..total + n]);
            total += n;
        }
        assert!(
            raw_resp[..total].starts_with(vallum_tunnel::stream::UPGRADE_RESPONSE),
            "expected HTTP/1.1 101 response, got {:?}",
            String::from_utf8_lossy(&raw_resp[..total])
        );

        let req_pkt = sample_vallum_packet(77);
        client
            .write_all(&frame(&req_pkt).expect("frame request"))
            .expect("send framed packet");

        let mut srv_buf = [0u8; 512];
        let (sn, client_addr) = loop {
            match tcp_server.recv_from(&mut srv_buf) {
                Ok(ok) => break ok,
                Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
                Err(e) => panic!("tcp_server recv failed: {e}"),
            }
        };
        assert_eq!(&srv_buf[..sn], req_pkt.as_slice());

        let resp_pkt = sample_vallum_packet(88);
        tcp_server
            .send_to(&resp_pkt, client_addr)
            .expect("send reply frame");

        let mut reply = None;
        while reply.is_none() {
            let mut tmp = [0u8; 512];
            let n = client.read(&mut tmp).expect("read reply frame");
            assert!(n > 0, "unexpected EOF waiting for reply frame");
            client_reader.push(&tmp[..n]);
            reply = client_reader.next_frame().expect("unframe reply");
        }
        assert_eq!(reply.as_deref(), Some(resp_pkt.as_slice()));
    }

    #[test]
    fn mtu_optimizer_selects_1340_when_ceiling_is_between_1404_and_1443() {
        let rec = recommend_mtu_from_telemetry(1420, &[], 0, 0, 0);
        assert_eq!(rec.recommended_inner_mtu, 1340);
        assert_eq!(rec.recommended_outer_mtu, 1404);
        assert_eq!(rec.ipv4_tcp_mss, 1300);
        assert_eq!(rec.ipv6_tcp_mss, 1280);
        assert_eq!(rec.profile, MtuProfile::GamingLowFrag1380);
    }

    #[test]
    fn tcp_transport_with_upgrade_host_emits_prelude_and_roundtrips_frames() {
        // 1. Verify raw wire prelude emitted on outbound TCP dial when tcp_upgrade is configured.
        let raw_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("raw listener");
        let raw_addr = raw_listener.local_addr().expect("raw addr");
        let probe_client = TcpTransport::bind_with_upgrade(
            "127.0.0.1:0".parse().expect("addr"),
            0,
            Some("edge.wingman.gold:443"),
        )
        .expect("probe client");
        let req_pkt = sample_vallum_packet(77);
        probe_client
            .send_to(&req_pkt, raw_addr)
            .expect("send to raw");

        let (mut srv_stream, _) = raw_listener.accept().expect("accept raw");
        srv_stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let expected_req = vallum_tunnel::stream::upgrade_request("edge.wingman.gold:443");
        let mut wire = Vec::new();
        let mut chunk = [0u8; 512];
        while wire.len() < expected_req.len() + req_pkt.len() + 2 {
            let n = std::io::Read::read(&mut srv_stream, &mut chunk).expect("read prelude+frame");
            assert!(n > 0, "unexpected EOF waiting for prelude and frame");
            wire.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(&wire[..expected_req.len()], expected_req.as_slice());
        let mut reader = FrameReader::new();
        reader.push(&wire[expected_req.len()..]);
        assert_eq!(
            reader.next_frame().expect("valid frame").as_deref(),
            Some(req_pkt.as_slice())
        );

        // 2. End-to-end bidirectional exchange between client (with tcp_upgrade) and TcpTransport server.
        let tcp_server = TcpTransport::bind("127.0.0.1:0".parse().expect("addr")).expect("server");
        let server_addr = tcp_server.local_addr().expect("server addr");
        let tcp_client = TcpTransport::bind_with_upgrade(
            "127.0.0.1:0".parse().expect("addr"),
            0,
            Some("cdn.example.com"),
        )
        .expect("client");

        tcp_client.send_to(&req_pkt, server_addr).expect("send req");
        let mut srv_buf = [0u8; 512];
        let (sn, client_peer) = loop {
            match tcp_server.recv_from(&mut srv_buf) {
                Ok(ok) => break ok,
                Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
                Err(e) => panic!("server recv failed: {e}"),
            }
        };
        assert_eq!(&srv_buf[..sn], req_pkt.as_slice());

        let resp_pkt = sample_vallum_packet(88);
        tcp_server
            .send_to(&resp_pkt, client_peer)
            .expect("send resp");
        let mut cli_buf = [0u8; 512];
        let (cn, rsrc) = loop {
            match tcp_client.recv_from(&mut cli_buf) {
                Ok(ok) => break ok,
                Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
                Err(e) => panic!("client recv failed: {e}"),
            }
        };
        assert_eq!(rsrc, server_addr);
        assert_eq!(&cli_buf[..cn], resp_pkt.as_slice());
    }

    #[test]
    fn auto_transport_handshake_filter_ignores_garbage_udp_and_staggers_to_tcp() {
        let blackhole_udp = UdpSocket::bind("127.0.0.1:0").expect("blackhole udp");
        blackhole_udp
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let target = blackhole_udp.local_addr().expect("target");
        let tcp_server = TcpTransport::bind(target).expect("tcp server");

        let auto_client = AutoTransport::bind_with_timings_and_upgrade(
            "127.0.0.1:0".parse().expect("addr"),
            0,
            Duration::from_millis(80),
            Duration::from_millis(250),
            Some("cdn.example.com"),
        )
        .expect("auto client");

        let req = sample_vallum_packet(55);
        auto_client.send_to(&req, target).expect("send race probe");

        let mut wire = [0u8; 256];
        let (wn, peer) = blackhole_udp.recv_from(&mut wire).expect("udp probe");
        assert_eq!(wn, req.len());

        // Inject non-Vallum UDP noise before the 80ms stagger fires: none of these
        // should lock AutoTransport onto UDP or surface via recv_from.
        blackhole_udp
            .send_to(b"HTTP/1.1 200 OK\r\n\r\n", peer)
            .expect("send http noise");
        blackhole_udp
            .send_to(&[0x01, 0x7f, 0, 0, 0, 0, 0, 0, 9, 9], peer)
            .expect("send invalid type noise");
        blackhole_udp
            .send_to(&[0x01, 0x04], peer)
            .expect("send truncated packet");

        let mut buf = [0u8; 512];
        let (tn, tcp_peer) = loop {
            match tcp_server.recv_from(&mut buf) {
                Ok(ok) => break ok,
                Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
                Err(e) => panic!("tcp server recv failed: {e}"),
            }
        };
        assert_eq!(&buf[..tn], req.as_slice());

        // Also send a non-Vallum framed payload over TCP before the valid reply;
        // AutoTransport's TCP arm must drop it and only deliver the valid envelope.
        tcp_server
            .send_to(&[0x99; 24], tcp_peer)
            .expect("send garbage tcp frame");
        let resp = sample_vallum_packet(88);
        tcp_server
            .send_to(&resp, tcp_peer)
            .expect("send valid resp");

        let (cn, csrc) = loop {
            match auto_client.recv_from(&mut buf) {
                Ok(ok) => break ok,
                Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
                Err(e) => panic!("auto recv failed: {e}"),
            }
        };
        assert_eq!(csrc, target);
        assert_eq!(&buf[..cn], resp.as_slice());
        assert!(auto_client.inbound_dropped.load(Ordering::Relaxed) >= 4);
    }

    #[test]
    fn auto_transport_replays_multi_fragment_initial_burst_on_tcp_stagger() {
        let mut buf_cap = Vec::new();
        let mut idx_cap = Vec::new();
        for n in 0..(AUTO_MAX_INITIAL_PACKETS + 15) {
            let mut pkt = sample_vallum_packet((n & 0xff) as u8);
            pkt[4..8].copy_from_slice(&(n as u32).to_be_bytes());
            record_initial_packet(&mut buf_cap, &mut idx_cap, &pkt);
        }
        assert_eq!(buf_cap.len(), AUTO_MAX_INITIAL_PACKETS);

        let blackhole_udp = UdpSocket::bind("127.0.0.1:0").expect("blackhole udp");
        blackhole_udp
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let target = blackhole_udp.local_addr().expect("target");
        let tcp_server = TcpTransport::bind(target).expect("tcp server");

        let auto_client = AutoTransport::bind_with_timings(
            "127.0.0.1:0".parse().expect("addr"),
            0,
            Duration::from_millis(80),
            Duration::from_millis(250),
        )
        .expect("auto client");

        // Build 4 fragments of an oversized handshake burst and transmit as a batch.
        let fragments: Vec<Vec<u8>> = (0..4u16)
            .map(|i| {
                let hdr = vallum_tunnel::segment::Fragment {
                    message_id: 9001,
                    offset: i * 64,
                    total: 256,
                };
                let mut f = hdr.encode().to_vec();
                f.extend(std::iter::repeat_n(0x40 + i as u8, 64));
                if i == 0 {
                    // Overlay an InitHello header inside fragment 0 payload.
                    f[vallum_tunnel::segment::FRAGMENT_HEADER_LEN] =
                        vallum_core::wire::PROTOCOL_VERSION;
                    f[vallum_tunnel::segment::FRAGMENT_HEADER_LEN + 1] =
                        vallum_core::wire::MessageType::InitHello.code();
                    f[vallum_tunnel::segment::FRAGMENT_HEADER_LEN + 4
                        ..vallum_tunnel::segment::FRAGMENT_HEADER_LEN + 8]
                        .copy_from_slice(&0xCAFE_BABEu32.to_be_bytes());
                }
                f
            })
            .collect();

        let batch: Vec<(SocketAddr, Vec<u8>)> =
            fragments.iter().map(|f| (target, f.clone())).collect();
        assert_eq!(auto_client.send_many(&batch).expect("send burst"), 4);

        // Drain the 4 LWO-masked UDP fragments at the blackhole socket.
        let mut wire = [0u8; 512];
        for _ in 0..4 {
            let (wn, _) = blackhole_udp
                .recv_from(&mut wire)
                .expect("blackhole udp frag");
            assert!(wn >= fragments[0].len());
        }

        // After the 80ms stagger, TCP must receive all 4 buffered fragments in order.
        let mut tcp_received = Vec::new();
        let mut tbuf = [0u8; 512];
        while tcp_received.len() < 4 {
            match tcp_server.recv_from(&mut tbuf) {
                Ok((tn, _)) => tcp_received.push(tbuf[..tn].to_vec()),
                Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
                Err(e) => panic!("tcp server recv failed: {e}"),
            }
        }
        assert_eq!(tcp_received, fragments);
    }

    #[test]
    fn auto_transport_rejects_forged_resp_hello_and_only_locks_on_authentic_response() {
        use vallum_core::handshake::RESP_TAG_SIZE;
        use vallum_core::wire::{
            tag, MessageBuilder, MessageHeader, MessageType, CONFIRMATION_SIZE, PROTOCOL_VERSION,
            TIMESTAMP_SIZE,
        };

        let udp_server = UdpTransport::bind("127.0.0.1:0".parse().expect("addr")).expect("udp");
        let target = udp_server.local_addr().expect("target");
        let auto_client = AutoTransport::bind_with_timings(
            "127.0.0.1:0".parse().expect("addr"),
            0,
            Duration::from_millis(500),
            Duration::from_secs(1),
        )
        .expect("auto client");

        let mut init_b = MessageBuilder::new(MessageHeader {
            version: PROTOCOL_VERSION,
            message_type: MessageType::InitHello,
            suite_id: 0x0001,
            sender_index: 0x1122_3344,
        });
        init_b.field(tag::STATIC_CT, &[0x11; 32]).unwrap();
        init_b.field(tag::EPHEMERAL_PK, &[0x22; 32]).unwrap();
        init_b
            .field(tag::TIMESTAMP, &[0x33; TIMESTAMP_SIZE])
            .unwrap();
        init_b.field(tag::PEER_HINT, &[0x44; 24]).unwrap();
        let init_pkt = init_b.finish().unwrap();

        auto_client.send_to(&init_pkt, target).expect("send init");
        let mut rbuf = [0u8; 512];
        let (rn, peer) = udp_server.recv_from(&mut rbuf).expect("server recv init");
        assert_eq!(&rbuf[..rn], init_pkt.as_slice());

        // 1. Non-TLV forged RespHello even echoing matching index must be dropped.
        let mut forged_raw = vec![0x77; 96];
        forged_raw[0] = PROTOCOL_VERSION;
        forged_raw[1] = MessageType::RespHello.code();
        forged_raw[4..8].copy_from_slice(&0x1122_3344u32.to_be_bytes());
        udp_server
            .send_to(&forged_raw, peer)
            .expect("send raw forged resp");

        // 2. Syntactically valid TLV RespHello for the WRONG sender_index must be dropped.
        let mut wrong_idx_b = MessageBuilder::new(MessageHeader {
            version: PROTOCOL_VERSION,
            message_type: MessageType::RespHello,
            suite_id: 0x0001,
            sender_index: 0x5566_7788,
        });
        wrong_idx_b.field(tag::EPHEMERAL_CT, &[0xaa; 32]).unwrap();
        wrong_idx_b.field(tag::STATIC_CT, &[0xbb; 32]).unwrap();
        wrong_idx_b
            .field(tag::RECEIVER_INDEX, &0x9999_8888u32.to_be_bytes())
            .unwrap();
        wrong_idx_b
            .field(tag::CONFIRMATION, &[0xcc; CONFIRMATION_SIZE])
            .unwrap();
        wrong_idx_b
            .field(tag::PRE_TAG, &[0xdd; RESP_TAG_SIZE])
            .unwrap();
        let wrong_idx_resp = wrong_idx_b.finish().unwrap();
        udp_server
            .send_to(&wrong_idx_resp, peer)
            .expect("send wrong-index resp");

        // 3. Genuine TLV RespHello matching our pending InitHello sender_index must pass and lock.
        let mut good_b = MessageBuilder::new(MessageHeader {
            version: PROTOCOL_VERSION,
            message_type: MessageType::RespHello,
            suite_id: 0x0001,
            sender_index: 0x5566_7788,
        });
        good_b.field(tag::EPHEMERAL_CT, &[0xaa; 32]).unwrap();
        good_b.field(tag::STATIC_CT, &[0xbb; 32]).unwrap();
        good_b
            .field(tag::RECEIVER_INDEX, &0x1122_3344u32.to_be_bytes())
            .unwrap();
        good_b
            .field(tag::CONFIRMATION, &[0xcc; CONFIRMATION_SIZE])
            .unwrap();
        good_b.field(tag::PRE_TAG, &[0xdd; RESP_TAG_SIZE]).unwrap();
        let good_resp = good_b.finish().unwrap();
        udp_server
            .send_to(&good_resp, peer)
            .expect("send good resp");

        let mut cbuf = [0u8; 512];
        let (cn, csrc) = loop {
            match auto_client.recv_from(&mut cbuf) {
                Ok(ok) => break ok,
                Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
                Err(e) => panic!("auto recv failed: {e}"),
            }
        };
        assert_eq!(csrc, target);
        assert_eq!(&cbuf[..cn], good_resp.as_slice());
        assert!(auto_client.inbound_dropped.load(Ordering::Relaxed) >= 2);
    }
}
