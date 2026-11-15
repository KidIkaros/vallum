// SPDX-License-Identifier: Apache-2.0

//! Rebindable [`SharedSocket`] wrapper and the in-process [`MemoryNetwork`]
//! used by tests to exercise roaming and source-address validation.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use super::DatagramSocket;

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
