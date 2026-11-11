// SPDX-License-Identifier: Apache-2.0

//! The WireGuard-style userspace UAPI, as key/value lines.
//!
//! `get=1` asks for the device and its peers; `set=1` applies a transaction.
//! The names and semantics are WireGuard's for the common surface, so tooling
//! and habits transfer; Vallum-specific fields are `vallum_`-prefixed.
//!
//! The codec is pure: it parses text and renders text, and knows nothing about
//! sockets or the device. `control` owns the socket, `run` owns the application.

use std::net::SocketAddr;

use vallum_crypto::SharedSecret;
use vallum_tunnel::Prefix;

use crate::keys::{hex_decode, hex_encode};

/// The errno values the control protocol uses.
///
/// Shared by the daemon's transition and the CLI's message mapping, so the two
/// cannot drift apart.
pub mod errno {
    /// Operation not permitted (a rebind without the capability).
    pub const EPERM: i32 = 1;
    /// No such peer.
    pub const ENOENT: i32 = 2;
    /// The peer already exists.
    pub const EEXIST: i32 = 17;
    /// Malformed request, or overlapping prefixes.
    pub const EINVAL: i32 = 22;
    /// No control plane is configured.
    pub const ENOSYS: i32 = 38;
    /// The requested port is in use.
    pub const EADDRINUSE: i32 = 98;
    /// The requested address is not available.
    pub const EADDRNOTAVAIL: i32 = 99;
    /// The loop did not answer.
    pub const ETIMEDOUT: i32 = 110;
}

/// The wire field names, shared by the parser, the renderers, and the CLI.
///
/// A typo here is a compile error; a typo in a literal was a silent mismatch.
pub mod field {
    /// Device fields.
    pub const PRIVATE_KEY: &str = "private_key";
    /// Device fields.
    pub const VALLUM_PRIVATE_KEY_PATH: &str = "vallum_private_key_path";
    /// Device fields.
    pub const LISTEN_PORT: &str = "listen_port";
    /// Device fields.
    pub const FWMARK: &str = "fwmark";
    /// Device and peer.
    pub const PUBLIC_KEY: &str = "public_key";
    /// Device fields.
    pub const VALLUM_INTERFACE: &str = "vallum_interface";
    /// What the peer allowlists ask for: `full` when any peer routes
    /// 0.0.0.0/0 (or ::/0) through the tunnel, `split` otherwise. The one
    /// place this decision is made; every surface reads it.
    pub const VALLUM_EGRESS: &str = "vallum_egress";
    /// The build this daemon came from (git hash). Two ends on different
    /// builds are a fleet-parity problem; this makes it visible instead of
    /// discovered by a mismatched behaviour.
    pub const VALLUM_BUILD: &str = "vallum_build";
    /// Device and peer.
    pub const VALLUM_PUBLIC_LINE: &str = "vallum_public_line";
    /// Device and peer.
    pub const VALLUM_FINGERPRINT: &str = "vallum_fingerprint";
    /// Device fields.
    pub const VALLUM_LISTEN: &str = "vallum_listen";
    /// Device fields.
    pub const VALLUM_CONTROL: &str = "vallum_control";
    /// Device fields.
    pub const VALLUM_OFFLOAD: &str = "vallum_offload";
    /// Device fields.
    pub const VALLUM_BATCHING: &str = "vallum_batching";
    /// Device fields.
    pub const VALLUM_CAN_SET_PRIVATE_KEY: &str = "vallum_can_set_private_key";
    /// Device fields.
    pub const VALLUM_CAN_SET_LISTEN_PORT: &str = "vallum_can_set_listen_port";
    /// Device fields.
    pub const VALLUM_CAN_SET_FWMARK: &str = "vallum_can_set_fwmark";
    /// Device fields.
    pub const VALLUM_SUITE: &str = "vallum_suite";
    /// Device fields.
    pub const VALLUM_ADDRESS: &str = "vallum_address";
    /// Peer fields.
    pub const VALLUM_NAME: &str = "vallum_name";
    /// Peer fields.
    ///
    /// In a `set`, the identity a rotation moved aside: the referenced peer —
    /// matched by this key, not by the block's `public_key` — adopts the new
    /// identity and keeps the old one accepted (ADR-0019). `none` retires the
    /// window (`peer finalize`). Absent means the config says nothing about
    /// rotation for this peer, and the live window is left alone.
    pub const VALLUM_PREVIOUS_PUBLIC_KEY: &str = "vallum_previous_public_key";
    /// Peer fields.
    pub const PRESHARED_KEY: &str = "preshared_key";
    /// Peer fields.
    pub const ENDPOINT: &str = "endpoint";
    /// Peer fields.
    pub const LAST_HANDSHAKE_TIME_SEC: &str = "last_handshake_time_sec";
    /// Peer fields.
    pub const LAST_HANDSHAKE_TIME_NSEC: &str = "last_handshake_time_nsec";
    /// Peer fields.
    pub const TX_BYTES: &str = "tx_bytes";
    /// Peer fields.
    pub const RX_BYTES: &str = "rx_bytes";
    /// Peer fields.
    pub const PERSISTENT_KEEPALIVE_INTERVAL: &str = "persistent_keepalive_interval";
    /// Peer fields.
    pub const WINDOW_SENT: &str = "vallum_window_sent";
    /// Peer fields.
    pub const WINDOW_RECEIVED: &str = "vallum_window_received";
    /// When a datagram last arrived from this peer, on the host's monotonic
    /// clock, in milliseconds. Absent means nothing has ever arrived — which is
    /// a different fact from "it arrived a long time ago", and the one that
    /// distinguishes a peer that never answered from a path that died.
    pub const LAST_RECEIVED_MS: &str = "vallum_last_received_ms";
    /// When a datagram was last sent to this peer, same clock.
    pub const LAST_SENT_MS: &str = "vallum_last_sent_ms";
    /// Peer drop reasons, counted separately because they have different causes
    /// and an aggregate reads as a diagnosis when it is not one.
    pub const DROPPED_NO_SESSION: &str = "vallum_dropped_no_session";
    pub const DROPPED_REPLAY: &str = "vallum_dropped_replay";
    pub const DROPPED_ALLOWED_IPS: &str = "vallum_dropped_allowed_ips";
    /// Reactive re-handshake offers a peer was given (ADR-0019), rate-limited.
    pub const REINIT_OFFERED: &str = "vallum_reinit_offered";
    /// The most recent inner source rejected by `allowed_ips`; `none` if the
    /// packet did not parse as IP, `-` if nothing has been rejected.
    pub const LAST_REJECTED_SOURCE: &str = "vallum_last_rejected_source";
    /// Peer fields.
    pub const ALLOWED_IP: &str = "allowed_ip";
    /// Peer fields.
    /// The unix second a peer's identity document expires, when it has one.
    pub const VALLUM_VALID_UNTIL: &str = "vallum_valid_until";
    /// 1 when a rotation is open (a previous identity is still accepted).
    pub const VALLUM_ROTATING: &str = "vallum_rotating";
    pub const VALLUM_EPOCH: &str = "vallum_epoch";

    /// Datagrams handed to the socket.
    pub const VALLUM_DATAGRAMS_SENT: &str = "vallum_datagrams_sent";
    /// Datagrams that could not be sent.
    pub const VALLUM_DATAGRAMS_FAILED: &str = "vallum_datagrams_failed";
    /// Packets written to the interface.
    pub const VALLUM_PACKETS_DELIVERED: &str = "vallum_packets_delivered";
    /// Packets that could not be written.
    pub const VALLUM_PACKETS_FAILED: &str = "vallum_packets_failed";
    /// Completed handshakes.
    pub const VALLUM_HANDSHAKES: &str = "vallum_handshakes_established";
    /// Handshakes refused on policy.
    pub const VALLUM_REFUSALS: &str = "vallum_handshakes_refused";
    /// Messages reassembled from fragments.
    pub const VALLUM_REASSEMBLED: &str = "vallum_reassembled";
    /// Fragments refused or abandoned.
    pub const VALLUM_FRAGMENTS_DROPPED: &str = "vallum_fragments_dropped";
    /// Datagrams dropped because they did not parse as a transport message.
    pub const VALLUM_DROPPED_MALFORMED: &str = "vallum_dropped_malformed";
    /// Datagrams dropped because the sender index matched no peer session.
    pub const VALLUM_DROPPED_UNKNOWN_INDEX: &str = "vallum_dropped_unknown_index";
    /// Initiations the responder dropped, by reason. Silent on the wire by
    /// design — an unauthenticated datagram gets no oracle — so these counters
    /// are the only account of a refusal. A server that receives an initiation
    /// and ignores it is otherwise indistinguishable from one that never
    /// received it.
    pub const VALLUM_HANDSHAKE_DROPPED_NO_MAC: &str = "vallum_handshake_dropped_no_mac";
    /// See [`Self::VALLUM_HANDSHAKE_DROPPED_NO_MAC`].
    pub const VALLUM_HANDSHAKE_DROPPED_UNIDENTIFIABLE: &str =
        "vallum_handshake_dropped_unidentifiable";
    /// See [`Self::VALLUM_HANDSHAKE_DROPPED_NO_MAC`].
    pub const VALLUM_HANDSHAKE_DROPPED_UNKNOWN_PEER: &str =
        "vallum_handshake_dropped_unknown_peer";
    /// See [`Self::VALLUM_HANDSHAKE_DROPPED_NO_MAC`].
    pub const VALLUM_HANDSHAKE_DROPPED_ENDPOINT_CONFLICT: &str =
        "vallum_handshake_dropped_endpoint_conflict";
    /// See [`Self::VALLUM_HANDSHAKE_DROPPED_NO_MAC`].
    pub const VALLUM_HANDSHAKE_DROPPED_STALE: &str = "vallum_handshake_dropped_stale";
    /// Request markers and flags.
    pub const GET: &str = "get=1";
    /// Request markers and flags.
    pub const SET: &str = "set=1";
    /// Request markers and flags.
    pub const STOP: &str = "stop=1";
    /// Request markers and flags.
    pub const REPLACE_PEERS: &str = "replace_peers";
    /// Request markers and flags.
    pub const REMOVE: &str = "remove";
    /// Request markers and flags.
    pub const UPDATE_ONLY: &str = "update_only";
    /// Request markers and flags.
    pub const REPLACE_ALLOWED_IPS: &str = "replace_allowed_ips";
    /// The error line.
    pub const ERRNO: &str = "errno";
}

/// A parsed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// `get=1`.
    Get,
    /// `set=1`, with the transaction that followed.
    Set(Set),
    /// `stop=1`: ask the daemon to shut down.
    ///
    /// Answered where the request is read rather than on the tunnel thread, so
    /// the reply reaches the client before the loop stops — a stop that returns
    /// before its own acknowledgement is indistinguishable from a stop that
    /// failed. The socket is same-user and `0600`, so this is no wider a
    /// permission than signalling the pid, and it does not require finding one.
    Stop,
}

/// A `set=1` transaction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Set {
    /// Replace the device's private key.
    pub private_key: Option<[u8; 32]>,
    /// Change the listen port.
    pub listen_port: Option<u16>,
    /// Change the socket mark.
    pub fwmark: Option<u32>,
    /// Remove every peer before applying the rest.
    pub replace_peers: bool,
    /// Peers to add or update.
    pub peers: Vec<Peer>,
}

/// One peer in a `set=1` transaction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Peer {
    /// The peer's KEM public key; starts a new peer block.
    ///
    /// Suite-sized, not WireGuard's fixed 32 bytes: the tri-hybrid KEM public
    /// key is 2 374 bytes. The control layer validates the length against the
    /// suite.
    pub public_key: Option<Vec<u8>>,
    /// A human-readable name for the peer; omitted leaves it unchanged.
    pub name: Option<String>,
    /// `Some(None)` clears the PSK; `Some(Some(k))` sets it.
    pub preshared_key: Option<Option<[u8; 32]>>,
    /// `Some(None)` clears the endpoint (roam); `Some(Some(a))` sets it.
    pub endpoint: Option<Option<SocketAddr>>,
    /// Persistent keepalive in seconds; `0` disables it.
    pub keepalive: Option<u16>,
    /// `allowed_ip=` lines.
    pub allowed_ips: Vec<Prefix>,
    /// Remove this peer.
    pub remove: bool,
    /// Fail rather than add if the peer does not exist.
    pub update_only: bool,
    /// Replace the peer's allowed IPs rather than appending.
    pub replace_allowed_ips: bool,
    /// The rotation window, as a full-state statement: the identity the peer
    /// rotates from, an empty vector to retire the window, or absent when the
    /// config says nothing about rotation for this peer.
    pub previous_public_key: Option<Vec<u8>>,
}

/// Parse a request body.
///
/// # Errors
///
/// A human-readable reason for a malformed line, an unknown key, or a bad value.
/// The control server maps that to `EINVAL`.
pub fn parse(text: &str) -> Result<Request, String> {
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'));

    let first = lines.next().ok_or_else(|| "empty request".to_owned())?;
    match first {
        field::GET => {
            if lines.next().is_some() {
                return Err("`get=1` must be the only line".to_owned());
            }
            Ok(Request::Get)
        }
        field::STOP => {
            if lines.next().is_some() {
                return Err("`stop=1` must be the only line".to_owned());
            }
            Ok(Request::Stop)
        }
        field::SET => {
            let mut set = Set::default();
            let mut current: Option<Peer> = None;
            let mut seen_peer = false;
            for line in lines {
                let (key, value) = line
                    .split_once('=')
                    .ok_or_else(|| format!("`{line}` is not `key=value`"))?;
                match key {
                    field::PUBLIC_KEY => {
                        if let Some(peer) = current.take() {
                            set.peers.push(peer);
                        }
                        seen_peer = true;
                        current = Some(Peer {
                            public_key: Some(parse_any_key(value)?),
                            ..Peer::default()
                        });
                    }
                    field::PRIVATE_KEY if !seen_peer => {
                        set.private_key = Some(parse_fixed_key(value)?);
                    }
                    field::LISTEN_PORT if !seen_peer => {
                        set.listen_port = Some(
                            value
                                .parse()
                                .map_err(|_| format!("listen_port `{value}` is not a port"))?,
                        );
                    }
                    field::FWMARK if !seen_peer => {
                        set.fwmark = Some(
                            value
                                .parse()
                                .map_err(|_| format!("fwmark `{value}` is not a u32"))?,
                        );
                    }
                    field::REPLACE_PEERS if !seen_peer => {
                        set.replace_peers = parse_bool(value)?;
                    }
                    // Peer fields require an open peer block.
                    field::VALLUM_NAME
                    | field::VALLUM_PREVIOUS_PUBLIC_KEY
                    | field::PRESHARED_KEY
                    | field::ENDPOINT
                    | field::PERSISTENT_KEEPALIVE_INTERVAL
                    | field::ALLOWED_IP
                    | field::REMOVE
                    | field::UPDATE_ONLY
                    | field::REPLACE_ALLOWED_IPS => {
                        let peer = current
                            .as_mut()
                            .ok_or_else(|| format!("`{key}` before any `public_key`"))?;
                        match key {
                            field::VALLUM_NAME => {
                                peer.name = Some(value.to_owned());
                            }
                            field::VALLUM_PREVIOUS_PUBLIC_KEY => {
                                // `(none)` retires the window; a key names the
                                // identity to rotate from. Length is validated
                                // against the suite at apply time, like
                                // `public_key`.
                                peer.previous_public_key =
                                    Some(if value == "none" || value == "(none)" {
                                        Vec::new()
                                    } else {
                                        parse_any_key(value)?
                                    });
                            }
                            field::PRESHARED_KEY => {
                                let parsed = parse_fixed_key(value)?;
                                peer.preshared_key = Some((parsed != [0u8; 32]).then_some(parsed));
                            }
                            field::ENDPOINT => {
                                peer.endpoint = Some(if value == "(none)" {
                                    None
                                } else {
                                    Some(value.parse().map_err(|_| {
                                        format!("endpoint `{value}` is not an address")
                                    })?)
                                });
                            }
                            field::PERSISTENT_KEEPALIVE_INTERVAL => {
                                peer.keepalive =
                                    Some(value.parse().map_err(|_| {
                                        format!("keepalive `{value}` is not a u16")
                                    })?);
                            }
                            field::ALLOWED_IP => peer.allowed_ips.push(
                                value
                                    .parse()
                                    .map_err(|_| format!("allowed_ip `{value}` is not a prefix"))?,
                            ),
                            field::REMOVE => peer.remove = parse_bool(value)?,
                            field::UPDATE_ONLY => peer.update_only = parse_bool(value)?,
                            field::REPLACE_ALLOWED_IPS => {
                                peer.replace_allowed_ips = parse_bool(value)?;
                            }
                            // A key listed in the outer pattern but not here is
                            // a parser bug, not a reason to panic on input.
                            _ => return Err(format!("unhandled peer key `{key}`")),
                        }
                    }
                    _ => return Err(format!("unknown key `{key}`")),
                }
            }
            if let Some(peer) = current {
                set.peers.push(peer);
            }
            Ok(Request::Set(set))
        }
        other => Err(format!("expected `get=1` or `set=1`, got `{other}`")),
    }
}

fn parse_bool(value: &str) -> Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(format!("`{other}` is not true/false")),
    }
}

/// A suite-sized key: any non-empty, even-length hex string.
fn parse_any_key(value: &str) -> Result<Vec<u8>, String> {
    let bytes = hex_decode(value)?;
    if bytes.is_empty() {
        return Err("key is empty".to_owned());
    }
    Ok(bytes)
}

/// A fixed 32-byte key: the private seed and the PSK.
fn parse_fixed_key(value: &str) -> Result<[u8; 32], String> {
    let bytes = hex_decode(value)?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| format!("key is {len} bytes, not 32"))
}

/// The device and peers a `get` returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceState {
    /// The kernel interface name.
    pub interface: String,
    /// The private-key seed, as the daemon holds it.
    pub private_key: SharedSecret,
    /// The path the seed was read from, for a config export.
    pub private_key_path: String,
    /// The KEM public key.
    pub public_key: Vec<u8>,
    /// The peer public line (`vallum1:…`), for an export that a config can use.
    pub public_line: String,
    /// A short fingerprint of the device key.
    pub fingerprint: [u8; 8],
    /// The bound UDP address.
    pub listen: SocketAddr,
    /// The control socket path, if one is configured.
    pub control: Option<String>,
    /// The socket mark.
    pub fwmark: u32,
    /// The suite id.
    pub suite: u16,
    /// The interface addresses.
    pub addresses: Vec<Prefix>,
    /// Whether TUN offload (GSO/GRO) is active.
    pub offload: bool,
    /// Whether batched UDP I/O is active.
    pub batching: bool,
    /// What a `set` can actually change.
    pub capabilities: Capabilities,
    /// Live loop counters.
    pub stats: crate::run::LoopStats,
    /// Initiations dropped before a peer could be named, by reason.
    pub handshake_dropped_no_mac: u64,
    /// See [`Self::handshake_dropped_no_mac`].
    pub handshake_dropped_unidentifiable: u64,
    /// See [`Self::handshake_dropped_no_mac`].
    pub handshake_dropped_unknown_peer: u64,
    /// See [`Self::handshake_dropped_no_mac`].
    pub handshake_dropped_endpoint_conflict: u64,
    /// See [`Self::handshake_dropped_no_mac`].
    pub handshake_dropped_stale: u64,
    /// The peers, in configuration order.
    pub peers: Vec<PeerState>,
}

/// The writable surface, stated rather than discovered by failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// A runtime `private_key` change is accepted (and tears down sessions).
    pub set_private_key: bool,
    /// A runtime `listen_port` change is accepted.
    pub set_listen_port: bool,
    /// A runtime `fwmark` change is accepted.
    pub set_fwmark: bool,
}

/// One peer in a `get` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerState {
    /// The configured name, or the generated one.
    pub name: String,
    /// The peer's KEM public key.
    pub public_key: Vec<u8>,
    /// The peer public line (`vallum1:…`).
    pub public_line: String,
    /// The identity still accepted besides the current one, when a rotation is
    /// open; empty when the window is closed.
    pub previous_public_key: Vec<u8>,
    /// A short fingerprint of the peer key.
    pub fingerprint: [u8; 8],
    /// The configured PSK, if any.
    pub preshared_key: Option<[u8; 32]>,
    /// The current endpoint.
    pub endpoint: Option<SocketAddr>,
    /// The last completed handshake, as unix seconds and nanoseconds.
    pub last_handshake: Option<(u64, u32)>,
    /// Wire bytes sent.
    pub tx_bytes: u64,
    /// Wire bytes received.
    pub rx_bytes: u64,
    /// Datagrams sent in the most recent delivery window.
    pub window_sent: u64,
    /// Datagrams received and opened in the most recent delivery window.
    pub window_received: u64,
    /// Milliseconds since a datagram from this peer last opened; `None` when
    /// nothing has ever arrived. Aged by the daemon, because the stamps live on
    /// its monotonic origin and no other process shares it.
    pub last_received_age_ms: Option<u64>,
    /// Milliseconds since a datagram was last sent to this peer.
    pub last_sent_age_ms: Option<u64>,
    /// Datagrams dropped because this peer had no live session.
    pub dropped_no_session: u64,
    /// Datagrams that failed to open.
    pub dropped_replay: u64,
    /// Datagrams dropped by the `allowed_ips` check.
    pub dropped_allowed_ips: u64,
    /// Reactive re-handshake offers this peer was given (ADR-0019).
    pub reinit_offered: u64,
    /// The most recent inner source rejected by `allowed_ips`.
    pub last_rejected_source: Option<std::net::IpAddr>,
    /// Persistent keepalive, in seconds.
    pub keepalive: Option<u16>,
    /// Allowed prefixes.
    pub allowed_ips: Vec<Prefix>,
    /// The unix second this peer's identity expires, when it is a document.
    pub valid_until: Option<u64>,
    /// Whether a previous identity is still accepted (a rotation is open).
    pub rotating: bool,
    /// The current epoch.
    pub epoch: u64,
}

/// Render a `get` response.
#[must_use]
pub fn render_get(state: &DeviceState) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{}={}\n",
        field::PRIVATE_KEY,
        hex_encode(state.private_key.as_bytes())
    ));
    out.push_str(&format!(
        "{}={}\n",
        field::VALLUM_PRIVATE_KEY_PATH,
        state.private_key_path
    ));
    out.push_str(&format!("{}={}\n", field::LISTEN_PORT, state.listen.port()));
    out.push_str(&format!("{}={}\n", field::FWMARK, state.fwmark));
    out.push_str(&format!(
        "{}={}\n",
        field::PUBLIC_KEY,
        hex_encode(&state.public_key)
    ));
    out.push_str(&format!(
        "{}={}\n",
        field::VALLUM_INTERFACE,
        state.interface
    ));
    out.push_str(&format!(
        "{}={}\n",
        field::VALLUM_PUBLIC_LINE,
        state.public_line
    ));
    out.push_str(&format!(
        "{}={}\n",
        field::VALLUM_FINGERPRINT,
        hex_encode(&state.fingerprint)
    ));
    out.push_str(&format!("{}={}\n", field::VALLUM_LISTEN, state.listen));
    if let Some(control) = &state.control {
        out.push_str(&format!("{}={control}\n", field::VALLUM_CONTROL));
    }
    let egress = if state.peers.iter().any(|peer| {
        peer.allowed_ips
            .iter()
            .any(|ip| matches!(ip.to_string().as_str(), "0.0.0.0/0" | "::/0"))
    }) {
        "full"
    } else {
        "split"
    };
    out.push_str(&format!("{}={egress}\n", field::VALLUM_EGRESS));
    out.push_str(&format!(
        "{}={}\n",
        field::VALLUM_BUILD,
        env!("VALLUM_BUILD_ID")
    ));
    out.push_str(&format!("{}={}\n", field::VALLUM_OFFLOAD, state.offload));
    out.push_str(&format!("{}={}\n", field::VALLUM_BATCHING, state.batching));
    for address in &state.addresses {
        out.push_str(&format!("{}={address}\n", field::VALLUM_ADDRESS));
    }
    out.push_str(&format!(
        "{}={}\n",
        field::VALLUM_CAN_SET_PRIVATE_KEY,
        state.capabilities.set_private_key
    ));
    out.push_str(&format!(
        "{}={}\n",
        field::VALLUM_CAN_SET_LISTEN_PORT,
        state.capabilities.set_listen_port
    ));
    out.push_str(&format!(
        "{}={}\n",
        field::VALLUM_CAN_SET_FWMARK,
        state.capabilities.set_fwmark
    ));
    out.push_str(&format!("{}={:#06x}\n", field::VALLUM_SUITE, state.suite));
    let stats = state.stats;
    for (key, value) in [
        (field::VALLUM_DATAGRAMS_SENT, stats.datagrams_sent),
        (field::VALLUM_DATAGRAMS_FAILED, stats.datagrams_failed),
        (field::VALLUM_PACKETS_DELIVERED, stats.packets_delivered),
        (field::VALLUM_PACKETS_FAILED, stats.packets_failed),
        (field::VALLUM_HANDSHAKES, stats.established),
        (field::VALLUM_REFUSALS, stats.refusals),
        (field::VALLUM_REASSEMBLED, stats.reassembled),
        (field::VALLUM_FRAGMENTS_DROPPED, stats.fragments_dropped),
        (field::VALLUM_DROPPED_MALFORMED, stats.dropped_malformed),
        (
            field::VALLUM_DROPPED_UNKNOWN_INDEX,
            stats.dropped_unknown_index,
        ),
        (
            field::VALLUM_HANDSHAKE_DROPPED_NO_MAC,
            state.handshake_dropped_no_mac,
        ),
        (
            field::VALLUM_HANDSHAKE_DROPPED_UNIDENTIFIABLE,
            state.handshake_dropped_unidentifiable,
        ),
        (
            field::VALLUM_HANDSHAKE_DROPPED_UNKNOWN_PEER,
            state.handshake_dropped_unknown_peer,
        ),
        (
            field::VALLUM_HANDSHAKE_DROPPED_ENDPOINT_CONFLICT,
            state.handshake_dropped_endpoint_conflict,
        ),
        (
            field::VALLUM_HANDSHAKE_DROPPED_STALE,
            state.handshake_dropped_stale,
        ),
    ] {
        out.push_str(&format!("{key}={value}\n"));
    }
    for peer in &state.peers {
        out.push_str(&format!(
            "\n{}={}\n",
            field::PUBLIC_KEY,
            hex_encode(&peer.public_key)
        ));
        out.push_str(&format!("{}={}\n", field::VALLUM_NAME, peer.name));
        if peer.previous_public_key.is_empty() {
            out.push_str(&format!("{}=(none)\n", field::VALLUM_PREVIOUS_PUBLIC_KEY));
        } else {
            out.push_str(&format!(
                "{}={}\n",
                field::VALLUM_PREVIOUS_PUBLIC_KEY,
                hex_encode(&peer.previous_public_key)
            ));
        }
        out.push_str(&format!(
            "{}={}\n",
            field::VALLUM_FINGERPRINT,
            hex_encode(&peer.fingerprint)
        ));
        out.push_str(&format!(
            "{}={}\n",
            field::VALLUM_PUBLIC_LINE,
            peer.public_line
        ));
        if let Some(psk) = peer.preshared_key {
            out.push_str(&format!("{}={}\n", field::PRESHARED_KEY, hex_encode(&psk)));
        }
        match peer.endpoint {
            Some(endpoint) => out.push_str(&format!("{}={endpoint}\n", field::ENDPOINT)),
            None => out.push_str(&format!("{}=(none)\n", field::ENDPOINT)),
        }
        if let Some((sec, nsec)) = peer.last_handshake {
            out.push_str(&format!("{}={sec}\n", field::LAST_HANDSHAKE_TIME_SEC));
            out.push_str(&format!("{}={nsec}\n", field::LAST_HANDSHAKE_TIME_NSEC));
        }
        out.push_str(&format!("{}={}\n", field::TX_BYTES, peer.tx_bytes));
        out.push_str(&format!("{}={}\n", field::RX_BYTES, peer.rx_bytes));
        // The only two numbers that say whether the tunnel is carrying traffic,
        // as opposed to whether it has handshaked recently.
        out.push_str(&format!("{}={}\n", field::WINDOW_SENT, peer.window_sent));
        out.push_str(&format!(
            "{}={}\n",
            field::WINDOW_RECEIVED,
            peer.window_received
        ));
        // Ages, not stamps: a human reading `vallum show` wants "how long", and
        // the daemon already did the subtraction against a clock that keeps
        // ticking even when the data plane has stopped. Absent means "never",
        // which is a different fact from "a long time ago".
        if let Some(age) = peer.last_received_age_ms {
            out.push_str(&format!("{}={age}\n", field::LAST_RECEIVED_MS));
        }
        if let Some(age) = peer.last_sent_age_ms {
            out.push_str(&format!("{}={age}\n", field::LAST_SENT_MS));
        }
        // Split drop reasons: "accepted nothing" is a symptom, not a cause.
        out.push_str(&format!(
            "{}={}\n",
            field::DROPPED_NO_SESSION,
            peer.dropped_no_session
        ));
        out.push_str(&format!(
            "{}={}\n",
            field::DROPPED_REPLAY,
            peer.dropped_replay
        ));
        out.push_str(&format!(
            "{}={}\n",
            field::DROPPED_ALLOWED_IPS,
            peer.dropped_allowed_ips
        ));
        out.push_str(&format!(
            "{}={}\n",
            field::REINIT_OFFERED,
            peer.reinit_offered
        ));
        let rejected = match (peer.dropped_allowed_ips, peer.last_rejected_source) {
            (0, _) => "-".to_owned(),
            (_, None) => "none".to_owned(),
            (_, Some(ip)) => ip.to_string(),
        };
        out.push_str(&format!("{}={}\n", field::LAST_REJECTED_SOURCE, rejected));
        out.push_str(&format!(
            "{}={}\n",
            field::PERSISTENT_KEEPALIVE_INTERVAL,
            peer.keepalive.unwrap_or(0)
        ));
        for prefix in &peer.allowed_ips {
            out.push_str(&format!("{}={prefix}\n", field::ALLOWED_IP));
        }
        out.push_str(&format!("{}={}\n", field::VALLUM_EPOCH, peer.epoch));
        if let Some(valid_until) = peer.valid_until {
            out.push_str(&format!("{}={valid_until}\n", field::VALLUM_VALID_UNTIL));
        }
        out.push_str(&format!(
            "{}={}\n",
            field::VALLUM_ROTATING,
            u8::from(peer.rotating)
        ));
    }
    out.push_str(&format!("{}=0\n", field::ERRNO));
    out
}

/// A parsed `get` response: the device section, then one section per peer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Response {
    /// Device fields, in wire order.
    pub device: Vec<(String, String)>,
    /// Peer sections, in wire order.
    pub peers: Vec<Vec<(String, String)>>,
}

impl Response {
    /// One device field.
    #[must_use]
    pub fn field(&self, key: &str) -> Option<&str> {
        field(&self.device, key)
    }

    /// One peer field.
    #[must_use]
    pub fn peer_field(&self, index: usize, key: &str) -> Option<&str> {
        self.peers.get(index).and_then(|peer| field(peer, key))
    }
}

fn field<'a>(fields: &'a [(String, String)], key: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
}

/// Parse a `get` response. Sections are separated by a blank line; the first is
/// the device, the rest are peers.
#[must_use]
pub fn parse_response(text: &str) -> Response {
    let mut sections: Vec<Vec<(String, String)>> = Vec::new();
    let mut current: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            if !current.is_empty() {
                sections.push(std::mem::take(&mut current));
            }
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            current.push((key.to_owned(), value.to_owned()));
        }
    }
    if !current.is_empty() {
        sections.push(current);
    }
    let mut sections = sections.into_iter();
    let device = sections.next().unwrap_or_default();
    Response {
        device,
        peers: sections.collect(),
    }
}

/// A human view: short identifiers, and no secrets.
///
/// `wg show` deliberately omits the private and preshared keys; so does this.
/// They remain available through `--field private-key` or `--dump`, which are
/// explicit requests.
#[must_use]
pub fn render_human(response: &Response) -> String {
    let mut out = String::new();
    let fingerprint = response.field(field::VALLUM_FINGERPRINT).unwrap_or("?");
    out.push_str(&format!("interface {fingerprint}\n"));
    for (key, value) in &response.device {
        if hidden(key) {
            continue;
        }
        out.push_str(&format!("  {key}={value}\n"));
    }
    for peer in &response.peers {
        let fingerprint = field(peer, field::VALLUM_FINGERPRINT).unwrap_or("?");
        let name = field(peer, field::VALLUM_NAME).unwrap_or("");
        out.push_str(&format!("\npeer {fingerprint} ({name})\n"));
        for (key, value) in peer {
            if hidden(key) {
                continue;
            }
            out.push_str(&format!("  {key}={value}\n"));
        }
    }
    out
}

fn hidden(key: &str) -> bool {
    matches!(
        key,
        field::PRIVATE_KEY
            | field::PRESHARED_KEY
            | field::PUBLIC_KEY
            | field::VALLUM_PUBLIC_LINE
            | field::VALLUM_FINGERPRINT
            | field::VALLUM_NAME
            | field::ERRNO
    )
}

/// Export a running device as a config a human can edit.
///
/// Secrets are not exported: `private_key` is a placeholder path and the PSK is
/// omitted with a comment. Everything else comes from the public lines and the
/// device state.
#[must_use]
pub fn render_config(response: &Response, include_secrets: bool) -> String {
    let mut out = String::from(
        "# generated by `vallum showconf`; set private_key to your key file\n\
         # and add any preshared keys by hand — secrets are not exported\n\
         [interface]\n",
    );
    out.push_str(&format!(
        "name = \"{}\"\n",
        escape(response.field(field::VALLUM_INTERFACE).unwrap_or("vallum0"))
    ));
    let key_path = if include_secrets {
        response
            .field(field::VALLUM_PRIVATE_KEY_PATH)
            .unwrap_or("private.key")
    } else {
        "private.key"
    };
    out.push_str(&format!("private_key = \"{}\"\n", escape(key_path)));
    if let Some(listen) = response.field(field::VALLUM_LISTEN) {
        out.push_str(&format!("listen = \"{listen}\"\n"));
    }
    if let Some(fwmark) = response.field(field::FWMARK) {
        if fwmark != "0" {
            out.push_str(&format!("fwmark = {fwmark}\n"));
        }
    }
    if let Some(control) = response.field(field::VALLUM_CONTROL) {
        out.push_str(&format!("control = \"{}\"\n", escape(control)));
    }
    let addresses: Vec<String> = response
        .device
        .iter()
        .filter(|(key, _)| key == field::VALLUM_ADDRESS)
        .map(|(_, value)| format!("\"{}\"", escape(value)))
        .collect();
    if !addresses.is_empty() {
        out.push_str(&format!("addresses = [{}]\n", addresses.join(", ")));
    }
    for peer in &response.peers {
        out.push_str("\n[[peer]]\n");
        if let Some(name) = field(peer, field::VALLUM_NAME) {
            out.push_str(&format!("name = \"{}\"\n", escape(name)));
        }
        if let Some(line) = field(peer, field::VALLUM_PUBLIC_LINE) {
            out.push_str(&format!("public_key = \"{}\"\n", escape(line)));
        }
        if let Some(endpoint) = field(peer, field::ENDPOINT) {
            if endpoint != "(none)" {
                out.push_str(&format!("endpoint = \"{endpoint}\"\n"));
            }
        }
        let allowed: Vec<String> = peer
            .iter()
            .filter(|(key, _)| key == field::ALLOWED_IP)
            .map(|(_, value)| format!("\"{}\"", escape(value)))
            .collect();
        if !allowed.is_empty() {
            out.push_str(&format!("allowed_ips = [{}]\n", allowed.join(", ")));
        }
        if let Some(keepalive) = field(peer, field::PERSISTENT_KEEPALIVE_INTERVAL) {
            if keepalive != "0" {
                out.push_str(&format!("persistent_keepalive = {keepalive}\n"));
            }
        }
        match (include_secrets, field(peer, field::PRESHARED_KEY)) {
            (true, Some(psk)) => out.push_str(&format!("preshared_key = \"{psk}\"\n")),
            _ => out.push_str("# preshared_key is not exported\n"),
        }
    }
    out
}

fn escape(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Render a `set` request, the inverse of [`parse`].
#[must_use]
pub fn render_set(set: &Set) -> String {
    let mut out = String::from("set=1\n");
    if let Some(key) = set.private_key {
        out.push_str(&format!("{}={}\n", field::PRIVATE_KEY, hex_encode(&key)));
    }
    if let Some(port) = set.listen_port {
        out.push_str(&format!("{}={port}\n", field::LISTEN_PORT));
    }
    if let Some(mark) = set.fwmark {
        out.push_str(&format!("{}={mark}\n", field::FWMARK));
    }
    if set.replace_peers {
        out.push_str(&format!("{}=true\n", field::REPLACE_PEERS));
    }
    for peer in &set.peers {
        if let Some(public_key) = &peer.public_key {
            out.push_str(&format!(
                "{}={}\n",
                field::PUBLIC_KEY,
                hex_encode(public_key)
            ));
        }
        if let Some(name) = &peer.name {
            out.push_str(&format!("{}={name}\n", field::VALLUM_NAME));
        }
        if let Some(previous) = &peer.previous_public_key {
            let value = if previous.is_empty() {
                "(none)".to_owned()
            } else {
                hex_encode(previous)
            };
            out.push_str(&format!("{}={value}\n", field::VALLUM_PREVIOUS_PUBLIC_KEY));
        }
        if let Some(psk) = peer.preshared_key {
            let value = psk.map_or_else(|| "00".repeat(32), |key| hex_encode(&key));
            out.push_str(&format!("{}={value}\n", field::PRESHARED_KEY));
        }
        if let Some(endpoint) = peer.endpoint {
            match endpoint {
                Some(address) => out.push_str(&format!("{}={address}\n", field::ENDPOINT)),
                None => out.push_str(&format!("{}=(none)\n", field::ENDPOINT)),
            }
        }
        if let Some(keepalive) = peer.keepalive {
            out.push_str(&format!(
                "{}={keepalive}\n",
                field::PERSISTENT_KEEPALIVE_INTERVAL
            ));
        }
        for prefix in &peer.allowed_ips {
            out.push_str(&format!("{}={prefix}\n", field::ALLOWED_IP));
        }
        if peer.remove {
            out.push_str(&format!("{}=true\n", field::REMOVE));
        }
        if peer.update_only {
            out.push_str(&format!("{}=true\n", field::UPDATE_ONLY));
        }
        if peer.replace_allowed_ips {
            out.push_str(&format!("{}=true\n", field::REPLACE_ALLOWED_IPS));
        }
    }
    out
}

/// A secret-free JSON view of a `get` response.
#[must_use]
pub fn response_json(response: &Response) -> serde_json::Value {
    let get = |key: &str| response.field(key).unwrap_or("");
    let addresses: Vec<&str> = response
        .device
        .iter()
        .filter(|(key, _)| key == field::VALLUM_ADDRESS)
        .map(|(_, value)| value.as_str())
        .collect();
    let peers: Vec<serde_json::Value> = response
        .peers
        .iter()
        .map(|peer| {
            let peer_field = |key: &str| {
                peer.iter()
                    .find(|(name, _)| name == key)
                    .map(|(_, value)| value.as_str())
                    .unwrap_or("")
            };
            let allowed: Vec<&str> = peer
                .iter()
                .filter(|(key, _)| key == field::ALLOWED_IP)
                .map(|(_, value)| value.as_str())
                .collect();
            let last = peer_field(field::LAST_HANDSHAKE_TIME_SEC);
            serde_json::json!({
                "name": peer_field(field::VALLUM_NAME),
                "fingerprint": peer_field(field::VALLUM_FINGERPRINT),
                "public_line": peer_field(field::VALLUM_PUBLIC_LINE),
                "endpoint": peer_field(field::ENDPOINT),
                "allowed_ips": allowed,
                "last_handshake": if last.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::json!({
                        "sec": last.parse::<u64>().unwrap_or(0),
                        "nsec": peer_field(field::LAST_HANDSHAKE_TIME_NSEC).parse::<u32>().unwrap_or(0),
                    })
                },
                "tx_bytes": peer_field(field::TX_BYTES).parse::<u64>().unwrap_or(0),
                "rx_bytes": peer_field(field::RX_BYTES).parse::<u64>().unwrap_or(0),
                "keepalive": peer_field(field::PERSISTENT_KEEPALIVE_INTERVAL).parse::<u16>().ok(),
                "epoch": peer_field(field::VALLUM_EPOCH).parse::<u64>().unwrap_or(0),
                "preshared_key": !peer_field(field::PRESHARED_KEY).is_empty(),
            })
        })
        .collect();
    serde_json::json!({
        "interface": get(field::VALLUM_INTERFACE),
        "listen_port": get(field::LISTEN_PORT).parse::<u16>().ok(),
        "fwmark": get(field::FWMARK).parse::<u32>().ok(),
        "suite": get(field::VALLUM_SUITE),
        "fingerprint": get(field::VALLUM_FINGERPRINT),
        "public_line": get(field::VALLUM_PUBLIC_LINE),
        "addresses": addresses,
        "offload": get(field::VALLUM_OFFLOAD) == "true",
        "batching": get(field::VALLUM_BATCHING) == "true",
        "capabilities": {
            "set_private_key": get(field::VALLUM_CAN_SET_PRIVATE_KEY) == "true",
            "set_listen_port": get(field::VALLUM_CAN_SET_LISTEN_PORT) == "true",
            "set_fwmark": get(field::VALLUM_CAN_SET_FWMARK) == "true",
        },
        "peers": peers,
    })
}

/// The success reply to a `set`.
#[must_use]
pub fn render_ok() -> String {
    "errno=0\n".to_owned()
}

/// An error reply.
#[must_use]
pub fn render_errno(errno: i32) -> String {
    format!("errno={errno}\n")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn a_prefix() -> impl Strategy<Value = Prefix> {
        prop::sample::select(vec![
            "10.7.0.1/24",
            "10.7.0.2/32",
            "0.0.0.0/0",
            "fd00:7::1/64",
            "fd00:7::2/128",
        ])
        .prop_map(|text| text.parse().expect("a valid prefix"))
    }

    fn an_address() -> impl Strategy<Value = SocketAddr> {
        (0u16..=65535).prop_map(|port| SocketAddr::from(([127, 0, 0, 1], port)))
    }

    fn a_name() -> impl Strategy<Value = String> {
        "[A-Za-z0-9._:/-]{0,32}"
    }

    fn a_peer() -> impl Strategy<Value = PeerState> {
        (
            a_name(),
            proptest::collection::vec(any::<u8>(), 0..64),
            a_name(),
            prop::array::uniform8(any::<u8>()),
            prop::option::of(prop::array::uniform32(any::<u8>())),
            prop::option::of(an_address()),
            prop::option::of((any::<u64>(), any::<u32>())),
            (
                any::<u64>(),
                any::<u64>(),
                any::<u64>(),
                any::<u64>(),
                any::<u64>(),
                any::<u64>(),
                any::<u64>(),
                any::<u64>(),
            ),
            prop::option::of(any::<u16>()),
            proptest::collection::vec(a_prefix(), 0..3),
            prop::option::of((any::<u64>(), any::<bool>())),
            any::<u64>(),
        )
            .prop_map(
                |(
                    name,
                    public_key,
                    public_line,
                    fingerprint,
                    preshared_key,
                    endpoint,
                    last_handshake,
                    (
                        tx_bytes,
                        rx_bytes,
                        window_sent,
                        window_received,
                        dropped_no_session,
                        dropped_replay,
                        dropped_allowed_ips,
                        reinit_offered,
                    ),
                    keepalive,
                    allowed_ips,
                    identity,
                    epoch,
                )| PeerState {
                    name,
                    public_key,
                    public_line,
                    fingerprint,
                    preshared_key,
                    endpoint,
                    last_handshake,
                    tx_bytes,
                    rx_bytes,
                    window_sent,
                    window_received,
                    last_received_age_ms: None,
                    last_sent_age_ms: None,
                    dropped_no_session,
                    dropped_replay,
                    dropped_allowed_ips,
                    reinit_offered,
                    last_rejected_source: None,
                    keepalive,
                    allowed_ips,
                    valid_until: identity.map(|(valid_until, _)| valid_until),
                    rotating: identity.is_some_and(|(_, rotating)| rotating),
                    previous_public_key: Vec::new(),
                    epoch,
                },
            )
    }

    fn a_state() -> impl Strategy<Value = DeviceState> {
        (
            a_name(),
            prop::array::uniform32(any::<u8>()),
            proptest::collection::vec(any::<u8>(), 0..64),
            a_name(),
            prop::array::uniform8(any::<u8>()),
            an_address(),
            any::<u32>(),
            any::<u16>(),
            proptest::collection::vec(a_prefix(), 0..3),
            (any::<bool>(), any::<bool>(), any::<bool>()),
            proptest::collection::vec(a_peer(), 0..3),
        )
            .prop_map(
                |(
                    interface,
                    seed,
                    public_key,
                    public_line,
                    fingerprint,
                    listen,
                    fwmark,
                    suite,
                    addresses,
                    (set_private_key, set_listen_port, set_fwmark),
                    peers,
                )| DeviceState {
                    interface,
                    private_key: SharedSecret::new(seed),
                    private_key_path: "test.key".to_owned(),
                    public_key,
                    public_line,
                    fingerprint,
                    listen,
                    control: None,
                    fwmark,
                    suite,
                    addresses,
                    offload: false,
                    batching: false,
                    stats: crate::run::LoopStats::default(),
                    handshake_dropped_no_mac: 0,
                    handshake_dropped_unidentifiable: 0,
                    handshake_dropped_unknown_peer: 0,
                    handshake_dropped_endpoint_conflict: 0,
                    handshake_dropped_stale: 0,
                    capabilities: Capabilities {
                        set_private_key,
                        set_listen_port,
                        set_fwmark,
                    },
                    peers,
                },
            )
    }

    proptest! {
        #[test]
        fn parse_never_panics(text in ".*") {
            let _ = parse(&text);
        }

        #[test]
        fn parse_response_never_panics(text in ".*") {
            let _ = parse_response(&text);
        }

        #[test]
        fn a_get_response_round_trips(state in a_state()) {
            let response = parse_response(&render_get(&state));
            let port = state.listen.port().to_string();
            let fwmark = state.fwmark.to_string();
            prop_assert_eq!(response.peers.len(), state.peers.len());
            prop_assert_eq!(response.field("listen_port"), Some(port.as_str()));
            prop_assert_eq!(response.field(field::VALLUM_INTERFACE), Some(state.interface.as_str()));
            prop_assert_eq!(response.field(field::FWMARK), Some(fwmark.as_str()));
            for (index, peer) in state.peers.iter().enumerate() {
                let tx = peer.tx_bytes.to_string();
                prop_assert_eq!(response.peer_field(index, "vallum_name"), Some(peer.name.as_str()));
                prop_assert_eq!(response.peer_field(index, "tx_bytes"), Some(tx.as_str()));
            }
        }
    }

    #[test]
    fn a_get_is_one_line() {
        assert_eq!(parse("get=1\n"), Ok(Request::Get));
        assert!(parse("get=1\nlisten_port=1\n").is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn a_stop_is_one_line_and_nothing_else() {
        assert_eq!(parse("stop=1\n"), Ok(Request::Stop));
        // A stop that carried a transaction would be a request whose second half
        // nobody reads: refuse it rather than stop and ignore the rest.
        assert!(parse("stop=1\nlisten_port=1\n").is_err());
        assert!(parse("stop=0\n").is_err());
    }

    #[test]
    fn a_set_carries_device_and_peer_fields() {
        let text = "set=1\n\
                    private_key=1111111111111111111111111111111111111111111111111111111111111111\n\
                    listen_port=51820\n\
                    fwmark=7\n\
                    replace_peers=true\n\
                    public_key=2222222222222222222222222222222222222222222222222222222222222222\n\
                    preshared_key=3333333333333333333333333333333333333333333333333333333333333333\n\
                    endpoint=203.0.113.9:51820\n\
                    persistent_keepalive_interval=25\n\
                    allowed_ip=10.7.0.2/32\n\
                    allowed_ip=fd00:7::2/128\n\
                    replace_allowed_ips=true\n";
        let Request::Set(set) = parse(text).expect("a legal set") else {
            panic!("not a set");
        };
        assert_eq!(set.listen_port, Some(51820));
        assert_eq!(set.fwmark, Some(7));
        assert!(set.replace_peers);
        assert_eq!(set.peers.len(), 1);
        let peer = &set.peers[0];
        assert_eq!(peer.keepalive, Some(25));
        assert_eq!(peer.allowed_ips.len(), 2);
        assert!(peer.replace_allowed_ips);
    }

    #[test]
    fn clearing_a_psk_and_an_endpoint_is_expressible() {
        let zero = "0".repeat(64);
        let text = format!(
            "set=1\npublic_key={}\npreshared_key={zero}\nendpoint=(none)\n",
            "44".repeat(32)
        );
        let Request::Set(set) = parse(&text).expect("a legal set") else {
            panic!("not a set");
        };
        assert_eq!(set.peers[0].preshared_key, Some(None));
        assert_eq!(set.peers[0].endpoint, Some(None));
    }

    #[test]
    fn unknown_keys_and_bad_values_are_refused() {
        assert!(parse("set=1\nnonsense=1\n").is_err());
        assert!(parse("set=1\npublic_key=zz\n").is_err());
        assert!(parse("set=1\nallowed_ip=10.7.0.2/32\n").is_err());
        assert!(parse("set=1\nlisten_port=nope\n").is_err());
    }

    #[test]
    fn a_tri_hybrid_set_with_a_name_parses() {
        let key = "ab".repeat(2374);
        let text = format!("set=1\npublic_key={key}\nvallum_name=third\nallowed_ip=10.7.0.3/32\n");
        let request = parse(&text).expect("parse");
        let Request::Set(set) = request else {
            panic!("not a set");
        };
        assert_eq!(set.peers[0].public_key.as_ref().unwrap().len(), 2374);
        assert_eq!(set.peers[0].name.as_deref(), Some("third"));
        assert_eq!(set.peers[0].allowed_ips.len(), 1);
    }

    #[test]
    fn a_set_renders_and_parses_back() {
        let set = Set {
            private_key: Some([0x11; 32]),
            listen_port: Some(51820),
            fwmark: Some(7),
            replace_peers: true,
            peers: vec![Peer {
                public_key: Some(vec![0x22; 32]),
                name: Some("laptop".to_owned()),
                preshared_key: Some(Some([0x33; 32])),
                endpoint: Some(Some("203.0.113.9:51820".parse().unwrap())),
                keepalive: Some(25),
                allowed_ips: vec!["10.7.0.2/32".parse().unwrap()],
                remove: false,
                update_only: true,
                replace_allowed_ips: true,
                previous_public_key: None,
            }],
        };
        let text = render_set(&set);
        assert_eq!(parse(&text), Ok(Request::Set(set)));
    }

    #[test]
    fn the_json_view_has_no_secrets() {
        let response = Response {
            device: vec![
                ("private_key".to_owned(), "aa".repeat(32)),
                ("vallum_interface".to_owned(), "vallum0".to_owned()),
                ("listen_port".to_owned(), "51820".to_owned()),
                (
                    "vallum_fingerprint".to_owned(),
                    "0011223344556677".to_owned(),
                ),
            ],
            peers: vec![vec![
                ("vallum_name".to_owned(), "laptop".to_owned()),
                ("preshared_key".to_owned(), "cc".repeat(32)),
                ("tx_bytes".to_owned(), "10".to_owned()),
            ]],
        };
        let json = response_json(&response);
        let text = json.to_string();
        assert!(!text.contains(&"aa".repeat(32)));
        assert!(!text.contains(&"cc".repeat(32)));
        assert_eq!(json["interface"], "vallum0");
        assert_eq!(json["peers"][0]["preshared_key"], true);
    }

    #[test]
    fn a_get_response_is_parseable_by_eye_and_ends_with_errno() {
        let state = DeviceState {
            interface: "vallum0".to_owned(),
            private_key: SharedSecret::new([1u8; 32]),
            private_key_path: "test.key".to_owned(),
            public_key: vec![2u8; 32],
            public_line: "vallum1:0003:02:-".to_owned(),
            fingerprint: [4u8; 8],
            listen: "0.0.0.0:51820".parse().unwrap(),
            control: Some("/run/vallum/vallum0.sock".to_owned()),
            fwmark: 0,
            suite: 0x0003,
            addresses: vec!["10.7.0.1/24".parse().unwrap()],
            offload: false,
            batching: false,
            stats: crate::run::LoopStats::default(),
            handshake_dropped_no_mac: 0,
            handshake_dropped_unidentifiable: 0,
            handshake_dropped_unknown_peer: 0,
            handshake_dropped_endpoint_conflict: 0,
            handshake_dropped_stale: 0,
            capabilities: Capabilities {
                set_private_key: true,
                set_listen_port: false,
                set_fwmark: false,
            },
            peers: vec![PeerState {
                name: "laptop".to_owned(),
                public_key: vec![3u8; 32],
                public_line: "vallum1:0003:03:-".to_owned(),
                fingerprint: [5u8; 8],
                preshared_key: None,
                endpoint: Some("203.0.113.9:51820".parse().unwrap()),
                last_handshake: Some((1_700_000_000, 42)),
                tx_bytes: 10,
                rx_bytes: 20,
                window_sent: 40,
                window_received: 30,
                last_received_age_ms: Some(1_500),
                last_sent_age_ms: Some(250),
                dropped_no_session: 1,
                dropped_replay: 2,
                dropped_allowed_ips: 3,
                reinit_offered: 4,
                last_rejected_source: None,
                keepalive: Some(25),
                allowed_ips: vec!["10.7.0.2/32".parse().unwrap()],
                valid_until: Some(1_800_000_000),
                rotating: true,
                epoch: 2,
                previous_public_key: vec![3u8; 32],
            }],
        };
        let text = render_get(&state);
        assert!(text.contains("private_key=0101"));
        assert!(text.contains("vallum_interface=vallum0"));
        // An expiring credential and an open rotation are visible to a client
        // of the control socket, not just to the config file.
        assert!(text.contains("vallum_valid_until=1800000000"));
        assert!(text.contains("vallum_rotating=1"));
        assert!(text.contains("vallum_can_set_listen_port=false"));
        assert!(text.contains("endpoint=203.0.113.9:51820"));
        assert!(text.contains("allowed_ip=10.7.0.2/32"));
        // How long since anything moved, in milliseconds. A stalled tunnel is
        // diagnosed by this growing while handshake age stays flat.
        assert!(text.contains("vallum_last_received_ms=1500"));
        assert!(text.contains("vallum_last_sent_ms=250"));
        assert!(text.ends_with("errno=0\n"));
    }

    #[test]
    fn a_response_splits_device_and_peers() {
        let state = DeviceState {
            interface: "vallum0".to_owned(),
            private_key: SharedSecret::new([1u8; 32]),
            private_key_path: "test.key".to_owned(),
            public_key: vec![2u8; 32],
            public_line: "vallum1:0003:02:-".to_owned(),
            fingerprint: [4u8; 8],
            listen: "0.0.0.0:51820".parse().unwrap(),
            control: Some("/run/vallum/vallum0.sock".to_owned()),
            fwmark: 0,
            suite: 0x0003,
            addresses: Vec::new(),
            offload: false,
            batching: false,
            stats: crate::run::LoopStats::default(),
            handshake_dropped_no_mac: 0,
            handshake_dropped_unidentifiable: 0,
            handshake_dropped_unknown_peer: 0,
            handshake_dropped_endpoint_conflict: 0,
            handshake_dropped_stale: 0,
            capabilities: Capabilities {
                set_private_key: true,
                set_listen_port: false,
                set_fwmark: false,
            },
            peers: vec![PeerState {
                name: "laptop".to_owned(),
                public_key: vec![3u8; 32],
                public_line: "vallum1:0003:03:-".to_owned(),
                fingerprint: [5u8; 8],
                preshared_key: None,
                endpoint: None,
                last_handshake: None,
                tx_bytes: 0,
                rx_bytes: 0,
                window_sent: 0,
                window_received: 0,
                last_received_age_ms: None,
                last_sent_age_ms: None,
                dropped_no_session: 0,
                dropped_replay: 0,
                dropped_allowed_ips: 0,
                reinit_offered: 0,
                last_rejected_source: None,
                keepalive: None,
                allowed_ips: Vec::new(),
                valid_until: None,
                rotating: false,
                epoch: 0,
                previous_public_key: Vec::new(),
            }],
        };
        let response = parse_response(&render_get(&state));
        assert_eq!(response.field(field::VALLUM_INTERFACE), Some("vallum0"));
        assert_eq!(response.peers.len(), 1);
        assert_eq!(response.peer_field(0, "vallum_name"), Some("laptop"));
        // A peer with no document says nothing about a window, and reports a
        // closed rotation explicitly.
        assert_eq!(response.peer_field(0, "vallum_valid_until"), None);
        assert_eq!(response.peer_field(0, "vallum_rotating"), Some("0"));
        assert_eq!(
            response.peer_field(0, field::VALLUM_PREVIOUS_PUBLIC_KEY),
            Some("(none)")
        );
    }

    #[test]
    fn the_config_export_can_include_secrets_explicitly() {
        let response = Response {
            device: vec![
                ("vallum_interface".to_owned(), "vallum0".to_owned()),
                (
                    "vallum_control".to_owned(),
                    "/run/vallum/vallum0.sock".to_owned(),
                ),
                (
                    "vallum_private_key_path".to_owned(),
                    "/etc/vallum/server.key".to_owned(),
                ),
            ],
            peers: vec![vec![
                ("vallum_name".to_owned(), "laptop".to_owned()),
                (
                    "vallum_public_line".to_owned(),
                    "vallum1:0003:ab:-".to_owned(),
                ),
                ("preshared_key".to_owned(), "cc".repeat(32)),
            ]],
        };
        let text = render_config(&response, true);
        assert!(text.contains("private_key = \"/etc/vallum/server.key\""));
        assert!(text.contains("control = \"/run/vallum/vallum0.sock\""));
        assert!(text.contains(&format!("preshared_key = \"{}\"", "cc".repeat(32))));
    }

    #[test]
    fn the_human_view_hides_secrets_and_uses_short_ids() {
        let response = Response {
            device: vec![
                ("private_key".to_owned(), "aa".repeat(32)),
                (
                    "vallum_fingerprint".to_owned(),
                    "0011223344556677".to_owned(),
                ),
                ("vallum_interface".to_owned(), "vallum0".to_owned()),
            ],
            peers: vec![vec![
                ("public_key".to_owned(), "bb".repeat(1187)),
                (
                    "vallum_fingerprint".to_owned(),
                    "8899aabbccddeeff".to_owned(),
                ),
                ("vallum_name".to_owned(), "laptop".to_owned()),
                ("preshared_key".to_owned(), "cc".repeat(32)),
            ]],
        };
        let text = render_human(&response);
        assert!(text.contains("interface 0011223344556677"));
        assert!(text.contains("peer 8899aabbccddeeff (laptop)"));
        assert!(!text.contains("private_key"));
        assert!(!text.contains("preshared_key"));
        assert!(!text.contains(&"bb".repeat(1187)));
    }

    #[test]
    fn the_config_export_uses_the_public_line() {
        let response = Response {
            device: vec![
                ("vallum_interface".to_owned(), "vallum0".to_owned()),
                ("vallum_listen".to_owned(), "0.0.0.0:51820".to_owned()),
                (
                    "vallum_control".to_owned(),
                    "/run/vallum/vallum0.sock".to_owned(),
                ),
                ("vallum_address".to_owned(), "10.7.0.1/24".to_owned()),
            ],
            peers: vec![vec![
                ("vallum_name".to_owned(), "laptop".to_owned()),
                (
                    "vallum_public_line".to_owned(),
                    "vallum1:0003:ab:-".to_owned(),
                ),
                ("endpoint".to_owned(), "203.0.113.9:51820".to_owned()),
                ("allowed_ip".to_owned(), "10.7.0.2/32".to_owned()),
                ("preshared_key".to_owned(), "cc".repeat(32)),
            ]],
        };
        let text = render_config(&response, false);
        assert!(text.contains("name = \"vallum0\""));
        assert!(text.contains("control = \"/run/vallum/vallum0.sock\""));
        assert!(text.contains("public_key = \"vallum1:0003:ab:-\""));
        assert!(text.contains("allowed_ips = [\"10.7.0.2/32\"]"));
        assert!(!text.contains("cc".repeat(32).as_str()));
    }
}
