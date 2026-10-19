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
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

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
pub struct SharedSocket {
    current: Mutex<Arc<dyn DatagramSocket>>,
    generation: AtomicU64,
}

impl std::fmt::Debug for SharedSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedSocket")
            .field("generation", &self.generation())
            .field("local_addr", &self.local_addr().ok())
            .finish()
    }
}

impl SharedSocket {
    /// Wrap the initial socket.
    #[must_use]
    pub fn new(socket: Arc<dyn DatagramSocket>) -> Self {
        Self {
            current: Mutex::new(socket),
            generation: AtomicU64::new(0),
        }
    }

    /// The current generation and socket.
    #[must_use]
    pub fn current(&self) -> (u64, Arc<dyn DatagramSocket>) {
        let socket = match self.current.lock() {
            Ok(current) => Arc::clone(&current),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        };
        (self.generation.load(Ordering::Acquire), socket)
    }

    /// The current generation, without cloning the socket.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Replace the socket and bump the generation.
    pub fn replace(&self, socket: Arc<dyn DatagramSocket>) {
        match self.current.lock() {
            Ok(mut current) => *current = socket,
            Err(poisoned) => *poisoned.into_inner() = socket,
        }
        self.generation.fetch_add(1, Ordering::Release);
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
}
