// SPDX-License-Identifier: Apache-2.0

//! # vallum
//!
//! Vallum's daemon. Everything below it is sans-IO on purpose: [`vallum_core`]
//! owns the crypto, [`vallum_tunnel`] owns the peer table and turns events into
//! actions. This crate is the only place that touches the operating system —
//! a TUN interface, a UDP socket, a clock, and random bytes — and it is
//! deliberately thin, because that is where the untestable surface lives.
//!
//! ```text
//!   /dev/net/tun ──▶ [tun.rs]   ─┐
//!   UDP socket   ──▶ [net.rs]   ─┼─▶ run.rs ──▶ Device ──▶ Action ──▶ socket / TUN
//!   time         ──▶ [clock.rs] ─┘
//! ```
//!
//! # The pieces, and why each is a trait
//!
//! - [`tun`] — the interface, behind [`tun::TunReader`] / [`tun::TunWriter`]. The
//!   Linux backend wraps `tun2`; [`tun::mock`] is an in-memory pair, which is how
//!   the two-host gate runs without root.
//! - [`net`] — the datagram socket, behind [`net::DatagramSocket`]. The real one
//!   is a `UdpSocket`; [`net::MemoryNetwork`] is an in-process network with
//!   per-address mailboxes, so a test can model source addresses, loss, and
//!   roaming.
//! - [`clock`] — the two clocks the transport asks for. A test supplies both.
//! - [`config`] — the TOML file, parsed with `serde`, validated by
//!   [`vallum_tunnel`]'s own rules rather than re-implemented here.
//! - [`keys`] — long-term identity files, and the text encoding of a public key
//!   that an operator pastes between two hosts.
//!
//! # What this crate must not do
//!
//! The crypto boundary is `vallum-core`. Nothing here names a KEM, a signature
//! scheme, or an AEAD: it asks [`vallum_crypto_sdk::SdkSuite`] for a suite by id
//! and hands the resulting `Arc<dyn CryptoSuite>` to the transport. When the SDK
//! is replaced, nothing in this crate changes except the one line that builds the
//! suite.

#![forbid(unsafe_code)]

pub mod bundle;
pub mod clock;
pub mod commands;
pub mod config;
pub mod config_edit;
pub mod control;
pub mod enroll;
pub mod entropy;
pub mod error;
pub mod form;
pub mod hostnet;
pub mod keys;
pub mod logging;
pub mod net;
pub mod notify;
pub mod policy;
pub mod privileges;
pub mod run;
pub mod style;
pub mod tun;

#[cfg(feature = "tui")]
pub mod tui;
pub mod uapi;

pub use error::Error;

/// Write a line to stdout, ignoring a closed pipe.
///
/// `println!` panics when the reader goes away (`vallum peer list | head`), and
/// a command that did its work should not die because a pager stopped reading.
#[macro_export]
macro_rules! say {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout(), $($arg)*);
    }};
}
