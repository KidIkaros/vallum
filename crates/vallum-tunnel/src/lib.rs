// SPDX-License-Identifier: Apache-2.0

//! # vallum-tunnel
//!
//! Vallum's transport. It takes everything the lower crates established in
//! isolation — the hybrid handshake, the epoch axis, the cookie gate, the
//! traffic-shaping machines — and drives them for a table of peers, from events,
//! without touching the network itself.
//!
//! ```text
//!   UDP datagram ─┐                                   ┌─ send this datagram
//!   IP packet    ─┼─▶  Device::handle  ──▶ Vec<Action> ─┼─ deliver this IP packet
//!   timer tick   ─┘   (clock, rng)                     └─ a session was established
//! ```
//!
//! The transport reads no clock, opens no socket, generates no randomness and
//! speaks to no interface. A caller supplies a [`Clock`], a [`Randomness`], and
//! the events it has observed, and performs the [`Action`]s it gets back. The
//! payoff is a two-host interoperability test that runs *in memory*, and a whole
//! transport that can be replayed byte for byte.
//!
//! # The shape of a tunnel
//!
//! A [`Device`] holds a [`vallum_core::StaticIdentity`] and a table of
//! [`PeerConfig`]s. Each peer's `allowed_ips` are both the destinations routed
//! to it and the source addresses accepted from it — WireGuard's cryptokey
//! routing, with the inbound direction enforced as the anti-spoofing rule.
//! Nothing about the crypto is
//! negotiated: the peer table is policy, and a mismatch fails the handshake
//! closed.
//!
//! ```
//! use std::sync::Arc;
//! use vallum_core::identity::StaticIdentity;
//! use vallum_core::Tai64n;
//! use vallum_tunnel::{Clock, Device, Randomness};
//!
//! // A caller-supplied suite and RNG: the tunnel depends on neither.
//! # fn suite() -> Arc<dyn vallum_crypto::CryptoSuite> { unimplemented!() }
//! struct Rng;
//! impl Randomness for Rng {
//!     fn fill(&mut self, out: &mut [u8]) {
//!         out.fill(0x42);
//!     }
//! }
//!
//! # fn make(suite: Arc<dyn vallum_crypto::CryptoSuite>) -> Device {
//! let identity = StaticIdentity::generate(&*suite, &[1u8; 32]).unwrap();
//! let mut device = Device::new(suite, identity, Vec::new(), &mut Rng, 0).unwrap();
//! // ... add peers, then:
//! let clock = Clock::new(0, Tai64n::from_unix(0, 0));
//! let _actions = device.poll(clock, &mut Rng);
//! device
//! # }
//! ```
//!
//! # Modules
//!
//! - [`routing`] — cryptokey routing: prefix membership and the two address
//!   checks that keep a peer from speaking for a host it was not given.
//! - [`peer`] — the public peer configuration and its handle.
//! - [`device`] — the peer table, the handshake driver, and the data plane.
//! - [`segment`] — the envelope that keeps a large message off the IP fragment
//!   path: splits outbound messages, reassembles inbound fragments.

#![forbid(unsafe_code)]

pub mod device;
pub mod error;
pub mod peer;
pub mod rng;
pub mod routing;
pub mod segment;

pub use device::{
    Action, Clock, Device, Event, PeerStats, MAX_INJECTION_BURST, MAX_QUEUED_BYTES,
    MAX_QUEUED_PACKETS,
};
pub use error::ConfigError;
pub use peer::{PeerConfig, PeerId};
pub use rng::Randomness;
pub use routing::{packet_destination, packet_source, AllowedIps, Prefix};
pub use segment::{Segments, MAX_REASSEMBLIES};
