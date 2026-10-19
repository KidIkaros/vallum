// SPDX-License-Identifier: Apache-2.0

//! The layer-3 interface, split into a reader and a writer.
//!
//! # Why two traits and not one device
//!
//! The loop reads packets on one thread and writes them on another, and it must
//! do both at once: a tunnel that cannot read while it writes stalls under load,
//! which is the exact condition P2's admission rules exist for. A single
//! `&mut self` device would force a mutex around every packet and make the reader
//! wait on the writer. So the interface is handed over as two halves, and the
//! backend is free to split a file descriptor or hand out two channels.
//!
//! # The Linux backend
//!
//! [`open`] wraps `tun2`, which does the `TUNSETIFF` dance and sets the address
//! and MTU through `ioctl`s — no shelling out to `ip`, and so no `PATH` to
//! hijack. It needs `CAP_NET_ADMIN`. `tun2`'s own `unsafe` lives in `tun2`; this
//! crate forbids `unsafe`, so the boundary is a trait and not a `transmute`.
//!
//! # MTU
//!
//! The inner MTU is not the outer one. A data packet costs
//! `HEADER_LEN(8) + 4 + COUNTER(8) + 4 + PAYLOAD_LEN(2) + tag(32)` = 58 bytes of
//! Vallum overhead, and the outer path costs up to 48 more (IPv6 + UDP). So the
//! default inner MTU is `1500 - 48 - 58 = 1394`, rounded down to
//! [`DEFAULT_MTU`]: an inner packet that fits is one outer packet that fits, and
//! nothing fragments on the data plane.

use std::fmt;
use std::io;

use vallum_core::segment::MAX_OUTER_DATAGRAM;

/// The default inner MTU. See the module docs for the arithmetic.
pub const DEFAULT_MTU: u16 = 1380;

/// The smallest inner MTU a config may name.
///
/// 576 is IPv4's minimum reassembly buffer (RFC 1122 §3.3.3): an inner MTU below
/// it can be configured but is a request to break IPv4, not to run a tunnel.
pub const MIN_MTU: u16 = 576;

/// Bytes of Vallum framing around one inner packet in a data message.
///
/// `HEADER_LEN(8) + 4 + COUNTER(8) + 4 + PAYLOAD_LEN(2) + tag(32)`: the fixed
/// header, the counter TLV, the ciphertext TLV, the authenticated length prefix
/// inside the AEAD, and the tag. The tag is the one term a suite supplies, which
/// is why [`vallum_core::segment`] caps the *datagram* rather than trusting this
/// number: a padded or larger-tagged message that overruns the budget is fragmented
/// instead of put on the wire too big.
pub const DATA_OVERHEAD: usize = 58;

/// The largest inner MTU that never fragments on a 1500-byte IPv6 outer path.
///
/// `1500 - 40 (IPv6) - 8 (UDP) = 1452` is the largest datagram either plane
/// emits ([`MAX_OUTER_DATAGRAM`]), so the inner MTU whose data message is exactly
/// that is `1452 - 58 = 1394`. Above this a data packet is still correct, but it
/// is one IP fragment on a v6 path, which is exactly what [`DEFAULT_MTU`] exists
/// to avoid.
pub const SAFE_MTU_IPV6_OUTER: u16 = (MAX_OUTER_DATAGRAM - DATA_OVERHEAD) as u16;

const _: () = assert!(SAFE_MTU_IPV6_OUTER == 1394);

// The default MTU's data message is one datagram, so segmentation is a no-op on
// the data plane as configured and costs nothing: it exists for the handshake,
// whose messages are three times the budget.
const _: () = assert!(DEFAULT_MTU as usize + DATA_OVERHEAD <= MAX_OUTER_DATAGRAM);

/// The reading half.
pub trait TunReader: Send {
    /// Read one layer-3 packet, blocking until one arrives.
    ///
    /// # Errors
    ///
    /// Any I/O failure, and (by convention) a closed interface, which tells the
    /// reader thread to stop.
    fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize>;
}

/// The writing half.
pub trait TunWriter: Send {
    /// Write one layer-3 packet.
    ///
    /// # Errors
    ///
    /// Any I/O failure.
    fn write_packet(&mut self, packet: &[u8]) -> io::Result<usize>;
}

/// What to open.
#[derive(Debug, Clone, Default)]
pub struct InterfaceSpec {
    /// The kernel interface name, if the operator pinned one.
    pub name: Option<String>,
    /// The address and prefix to assign to the interface.
    ///
    /// A prefix that covers the peers' `allowed_ips` makes the kernel install the
    /// connected route, which is why a two-host deployment needs no route
    /// command at all.
    pub address: Option<ipnet::IpNet>,
    /// The inner MTU.
    pub mtu: u16,
}

/// An open interface, in the two halves the loop needs.
pub struct InterfaceParts {
    /// The name the kernel actually gave it (a pinned name may be qualified).
    pub name: String,
    /// The inner MTU.
    pub mtu: usize,
    /// The reading half.
    pub reader: Box<dyn TunReader>,
    /// The writing half.
    pub writer: Box<dyn TunWriter>,
}

impl fmt::Debug for InterfaceParts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InterfaceParts")
            .field("name", &self.name)
            .field("mtu", &self.mtu)
            .finish_non_exhaustive()
    }
}

/// The MTU to actually use, given a spec that may not name one.
#[must_use]
pub fn effective_mtu(spec: &InterfaceSpec) -> u16 {
    if spec.mtu == 0 {
        DEFAULT_MTU
    } else {
        spec.mtu
    }
}

// ── the Linux backend ────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod platform {
    use std::io::{self, Read, Write};

    use super::{effective_mtu, InterfaceParts, InterfaceSpec, TunReader, TunWriter};

    /// The reading half of a `tun2` device.
    struct FdReader<R>(R);

    impl<R: Read + Send> TunReader for FdReader<R> {
        fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    /// The writing half of a `tun2` device.
    struct FdWriter<W>(W);

    impl<W: Write + Send> TunWriter for FdWriter<W> {
        fn write_packet(&mut self, packet: &[u8]) -> io::Result<usize> {
            // A layer-3 TUN is a datagram device: a short write is a dropped
            // packet, not a partial one. Insist on the whole packet.
            let written = self.0.write(packet)?;
            if written != packet.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short write to the tunnel interface",
                ));
            }
            Ok(written)
        }
    }

    /// Open a TUN interface.
    ///
    /// # Errors
    ///
    /// If the device cannot be created or configured — most often because the
    /// process lacks `CAP_NET_ADMIN`.
    pub fn open(spec: &InterfaceSpec, warn: &mut dyn FnMut(String)) -> io::Result<InterfaceParts> {
        use tun2::AbstractDevice;

        let mtu = effective_mtu(spec);
        let mut config = tun2::Configuration::default();
        if let Some(name) = spec.name.as_deref() {
            config.tun_name(name);
        }
        config.mtu(mtu);
        // An interface that is created but left down has no connected route, so
        // the kernel refuses to route anything to it — the tunnel would look
        // healthy and carry nothing. There is no reason to ever create this
        // interface down.
        config.up();

        // A `tun2` address is an `AF_INET` ioctl, so IPv4 (including a /32
        // point-to-point address, whose netmask is 255.255.255.255) is what it
        // can set. IPv6 is assigned after creation, over netlink — see
        // `assign_ipv6`.
        if let Some(ipnet::IpNet::V4(net)) = spec.address {
            config.address(net.addr());
            config.netmask(net.netmask());
        }
        let _ = &warn; // the v6 path no longer needs to hand work back

        // `ensure_root_privileges` defaults to true, so `create` both makes the
        // device and applies the configuration above.
        let device = tun2::create(&config)?;
        let name = device.tun_name()?;

        // The v6 address needs the interface index, so it happens here. A
        // failure is fatal: a half-configured interface is exactly the state
        // this replaces.
        if let Some(ipnet::IpNet::V6(net)) = spec.address {
            assign_ipv6(&name, &net)?;
        }

        let (reader, writer) = device.split();

        Ok(InterfaceParts {
            name,
            mtu: usize::from(mtu),
            reader: Box::new(FdReader(reader)),
            writer: Box::new(FdWriter(writer)),
        })
    }

    /// Add an IPv6 address to an existing interface over netlink.
    ///
    /// `tun2` configures addresses with `SIOCSIFADDR` and an `AF_INET` sockaddr,
    /// which cannot express a v6 address. `RTM_NEWADDR` can, and `netlink-sys`
    /// owns the socket so this stays inside `unsafe_code = "forbid"`.
    ///
    /// `IFA_LOCAL` is the attribute `ip addr add` sends for a normal prefix;
    /// `IFA_ADDRESS` is for a peer address and is not used here.
    fn assign_ipv6(name: &str, net: &ipnet::Ipv6Net) -> io::Result<()> {
        use netlink_packet_core::{
            NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL,
            NLM_F_REQUEST,
        };
        use netlink_packet_route::address::{
            AddressAttribute, AddressHeader, AddressHeaderFlags, AddressMessage,
        };
        use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
        use netlink_sys::{protocols::NETLINK_ROUTE, Socket};

        let index = nix::net::if_::if_nametoindex(name)
            .map_err(|e| io::Error::other(format!("if_nametoindex(`{name}`) for {net}: {e}")))?;

        let mut message = AddressMessage::default();
        message.header = AddressHeader {
            family: AddressFamily::Inet6,
            prefix_len: net.prefix_len(),
            // `nodad`: a TUN has no link-layer neighbour discovery, so duplicate
            // address detection's solicitations go nowhere and leave the address
            // tentative for about a second — during which the kernel drops
            // traffic to it. `ip addr add ... nodad` is the same choice.
            flags: AddressHeaderFlags::Nodad,
            index,
            ..AddressHeader::default()
        };
        // `IFA_LOCAL` only: that is what `ip addr add` sends for a normal
        // (non-peer) address, and the kernel derives the peer attribute from it.
        message.attributes = vec![AddressAttribute::Local(net.addr().into())];

        let mut header = NetlinkHeader::default();
        header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
        header.sequence_number = 1;
        let mut request = NetlinkMessage::new(
            header,
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(message)),
        );
        request.finalize();
        let mut buffer = vec![0u8; request.buffer_len()];
        request.serialize(&mut buffer);

        let mut socket = Socket::new(NETLINK_ROUTE)?;
        socket.bind_auto()?;
        socket.send(&buffer, 0)?;

        // `recv` takes a `BufMut` and fills its *spare* capacity, so this must be
        // an empty `Vec` with room — a pre-filled one has none, and the read
        // would be zero bytes long.
        let mut reply = Vec::with_capacity(4_096);
        let len = socket.recv(&mut reply, 0)?;
        let reply = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&reply[..len])
            .map_err(|e| io::Error::other(format!("parse netlink reply for {net}: {e}")))?;

        match reply.payload {
            // An ACK: no error code.
            NetlinkPayload::Error(error) => match error.code {
                None => Ok(()),
                // Already assigned: idempotent, and the state the operator asked
                // for either way.
                Some(code) if code.get() == -(nix::errno::Errno::EEXIST as i32) => Ok(()),
                Some(code) => Err(io::Error::other(format!(
                    "assigning {net} to `{name}` failed: netlink errno {}",
                    code.get()
                ))),
            },
            _ => Err(io::Error::other(format!(
                "assigning {net} to `{name}`: unexpected netlink reply"
            ))),
        }
    }
}

/// Open the platform's layer-3 interface.
///
/// Linux is the only target this phase. Anywhere else the daemon refuses to
/// start rather than pretend: a tunnel with no interface is not a degraded
/// tunnel, it is a daemon that silently drops every packet.
///
/// # Errors
///
/// [`io::ErrorKind::Unsupported`] off Linux; otherwise whatever the backend
/// reports.
#[cfg(target_os = "linux")]
pub fn open(spec: &InterfaceSpec, warn: &mut dyn FnMut(String)) -> io::Result<InterfaceParts> {
    platform::open(spec, warn)
}

/// Open the platform's layer-3 interface.
///
/// # Errors
///
/// Always, on this target.
#[cfg(not(target_os = "linux"))]
pub fn open(_spec: &InterfaceSpec, _warn: &mut dyn FnMut(String)) -> io::Result<InterfaceParts> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Vallum's TUN backend is Linux-only this phase",
    ))
}

// ── the in-memory backend ────────────────────────────────────────────

/// An interface that is a pair of channels.
///
/// This is the seam the two-host gate runs on: the device cannot tell a channel
/// from a file descriptor, and a test can inject one packet and read the next
/// without root, without a kernel, and without a timing assumption.
pub mod mock {
    use std::io;
    use std::sync::mpsc::{self, Receiver, Sender};

    use super::{InterfaceParts, TunReader, TunWriter};

    /// The test's end of a mock interface.
    #[derive(Debug)]
    pub struct MockInterface {
        /// Packets the device wrote, in order.
        delivered: Receiver<Vec<u8>>,
        /// Packets to hand the device.
        inject: Sender<Vec<u8>>,
        name: String,
        mtu: usize,
    }

    impl MockInterface {
        /// The interface name.
        #[must_use]
        pub fn name(&self) -> &str {
            &self.name
        }

        /// The MTU the mock enforces.
        #[must_use]
        pub fn mtu(&self) -> usize {
            self.mtu
        }

        /// Hand the device one inbound packet, as the kernel would.
        ///
        /// # Errors
        ///
        /// If the interface's reader half has gone away.
        pub fn inject(&self, packet: Vec<u8>) -> io::Result<()> {
            self.inject
                .send(packet)
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "mock interface closed"))
        }

        /// Wait for the next packet the device delivered.
        ///
        /// # Errors
        ///
        /// If the interface's writer half has gone away.
        pub fn next_delivered(&self) -> io::Result<Vec<u8>> {
            self.delivered
                .recv()
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "mock interface closed"))
        }

        /// Wait up to `timeout` for a packet, then give up.
        ///
        /// A gate that blocks forever on a packet that will never come reports a
        /// hang, not a failure; a bound turns it into an assertion.
        #[must_use]
        pub fn next_delivered_within(&self, timeout: std::time::Duration) -> Option<Vec<u8>> {
            self.delivered.recv_timeout(timeout).ok()
        }

        /// Take a delivered packet if one is waiting.
        pub fn try_delivered(&self) -> Option<Vec<u8>> {
            self.delivered.try_recv().ok()
        }
    }

    /// A reader fed by [`MockInterface::inject`].
    struct ChannelReader {
        inbound: Receiver<Vec<u8>>,
        mtu: usize,
    }

    impl TunReader for ChannelReader {
        fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let packet = self
                .inbound
                .recv()
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "mock interface closed"))?;
            if packet.len() > buf.len() {
                // Louder than a real device, on purpose: in a test this is an MTU
                // mismatch, and silently truncating would hide it.
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "injected packet is {} bytes but the read buffer is {} (MTU {})",
                        packet.len(),
                        buf.len(),
                        self.mtu
                    ),
                ));
            }
            buf[..packet.len()].copy_from_slice(&packet);
            Ok(packet.len())
        }
    }

    /// A writer that hands packets to [`MockInterface::next_delivered`].
    struct ChannelWriter {
        delivered: Sender<Vec<u8>>,
    }

    impl TunWriter for ChannelWriter {
        fn write_packet(&mut self, packet: &[u8]) -> io::Result<usize> {
            self.delivered
                .send(packet.to_vec())
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "mock interface closed"))?;
            Ok(packet.len())
        }
    }

    /// A mock interface and the device end of it.
    #[must_use]
    pub fn pair(name: &str, mtu: usize) -> (InterfaceParts, MockInterface) {
        let (inject_tx, inject_rx) = mpsc::channel();
        let (deliver_tx, deliver_rx) = mpsc::channel();

        let parts = InterfaceParts {
            name: name.to_owned(),
            mtu,
            reader: Box::new(ChannelReader {
                inbound: inject_rx,
                mtu,
            }),
            writer: Box::new(ChannelWriter {
                delivered: deliver_tx,
            }),
        };
        let handle = MockInterface {
            delivered: deliver_rx,
            inject: inject_tx,
            name: name.to_owned(),
            mtu,
        };
        (parts, handle)
    }
}
