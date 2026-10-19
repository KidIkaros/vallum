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

use vallum_tunnel::Prefix;

use crate::keys::{hex_decode, hex_encode};

/// A parsed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// `get=1`.
    Get,
    /// `set=1`, with the transaction that followed.
    Set(Set),
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
        "get=1" => {
            if lines.next().is_some() {
                return Err("`get=1` must be the only line".to_owned());
            }
            Ok(Request::Get)
        }
        "set=1" => {
            let mut set = Set::default();
            let mut current: Option<Peer> = None;
            let mut seen_peer = false;
            for line in lines {
                let (key, value) = line
                    .split_once('=')
                    .ok_or_else(|| format!("`{line}` is not `key=value`"))?;
                match key {
                    "public_key" => {
                        if let Some(peer) = current.take() {
                            set.peers.push(peer);
                        }
                        seen_peer = true;
                        current = Some(Peer {
                            public_key: Some(parse_any_key(value)?),
                            ..Peer::default()
                        });
                    }
                    "private_key" if !seen_peer => {
                        set.private_key = Some(parse_fixed_key(value)?);
                    }
                    "listen_port" if !seen_peer => {
                        set.listen_port = Some(
                            value
                                .parse()
                                .map_err(|_| format!("listen_port `{value}` is not a port"))?,
                        );
                    }
                    "fwmark" if !seen_peer => {
                        set.fwmark = Some(
                            value
                                .parse()
                                .map_err(|_| format!("fwmark `{value}` is not a u32"))?,
                        );
                    }
                    "replace_peers" if !seen_peer => set.replace_peers = parse_bool(value)?,
                    // Peer fields require an open peer block.
                    "preshared_key"
                    | "endpoint"
                    | "persistent_keepalive_interval"
                    | "allowed_ip"
                    | "remove"
                    | "update_only"
                    | "replace_allowed_ips" => {
                        let peer = current
                            .as_mut()
                            .ok_or_else(|| format!("`{key}` before any `public_key`"))?;
                        match key {
                            "preshared_key" => {
                                let parsed = parse_fixed_key(value)?;
                                peer.preshared_key = Some((parsed != [0u8; 32]).then_some(parsed));
                            }
                            "endpoint" => {
                                peer.endpoint = Some(if value == "(none)" {
                                    None
                                } else {
                                    Some(value.parse().map_err(|_| {
                                        format!("endpoint `{value}` is not an address")
                                    })?)
                                });
                            }
                            "persistent_keepalive_interval" => {
                                peer.keepalive =
                                    Some(value.parse().map_err(|_| {
                                        format!("keepalive `{value}` is not a u16")
                                    })?);
                            }
                            "allowed_ip" => peer.allowed_ips.push(
                                value
                                    .parse()
                                    .map_err(|_| format!("allowed_ip `{value}` is not a prefix"))?,
                            ),
                            "remove" => peer.remove = parse_bool(value)?,
                            "update_only" => peer.update_only = parse_bool(value)?,
                            "replace_allowed_ips" => {
                                peer.replace_allowed_ips = parse_bool(value)?;
                            }
                            _ => unreachable!("the outer match lists every peer key"),
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
    /// The private-key seed, as the daemon holds it.
    pub private_key: [u8; 32],
    /// The KEM public key.
    pub public_key: Vec<u8>,
    /// The bound UDP port.
    pub listen_port: u16,
    /// The socket mark.
    pub fwmark: u32,
    /// The suite id.
    pub suite: u16,
    /// The peers, in configuration order.
    pub peers: Vec<PeerState>,
}

/// One peer in a `get` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerState {
    /// The peer's KEM public key.
    pub public_key: Vec<u8>,
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
    /// Persistent keepalive, in seconds.
    pub keepalive: Option<u16>,
    /// Allowed prefixes.
    pub allowed_ips: Vec<Prefix>,
    /// The current epoch.
    pub epoch: u64,
}

/// Render a `get` response.
#[must_use]
pub fn render_get(state: &DeviceState) -> String {
    let mut out = String::new();
    out.push_str(&format!("private_key={}\n", hex_encode(&state.private_key)));
    out.push_str(&format!("listen_port={}\n", state.listen_port));
    out.push_str(&format!("fwmark={}\n", state.fwmark));
    out.push_str(&format!("public_key={}\n", hex_encode(&state.public_key)));
    out.push_str(&format!("vallum_suite={:#06x}\n", state.suite));
    for peer in &state.peers {
        out.push_str(&format!("\npublic_key={}\n", hex_encode(&peer.public_key)));
        if let Some(psk) = peer.preshared_key {
            out.push_str(&format!("preshared_key={}\n", hex_encode(&psk)));
        }
        match peer.endpoint {
            Some(endpoint) => out.push_str(&format!("endpoint={endpoint}\n")),
            None => out.push_str("endpoint=(none)\n"),
        }
        if let Some((sec, nsec)) = peer.last_handshake {
            out.push_str(&format!("last_handshake_time_sec={sec}\n"));
            out.push_str(&format!("last_handshake_time_nsec={nsec}\n"));
        }
        out.push_str(&format!("tx_bytes={}\n", peer.tx_bytes));
        out.push_str(&format!("rx_bytes={}\n", peer.rx_bytes));
        out.push_str(&format!(
            "persistent_keepalive_interval={}\n",
            peer.keepalive.unwrap_or(0)
        ));
        for prefix in &peer.allowed_ips {
            out.push_str(&format!("allowed_ip={prefix}\n"));
        }
        out.push_str(&format!("vallum_epoch={}\n", peer.epoch));
    }
    out.push_str("errno=0\n");
    out
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

    #[test]
    fn a_get_is_one_line() {
        assert_eq!(parse("get=1\n"), Ok(Request::Get));
        assert!(parse("get=1\nlisten_port=1\n").is_err());
        assert!(parse("").is_err());
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
    fn a_get_response_is_parseable_by_eye_and_ends_with_errno() {
        let state = DeviceState {
            private_key: [1u8; 32],
            public_key: vec![2u8; 32],
            listen_port: 51820,
            fwmark: 0,
            suite: 0x0003,
            peers: vec![PeerState {
                public_key: vec![3u8; 32],
                preshared_key: None,
                endpoint: Some("203.0.113.9:51820".parse().unwrap()),
                last_handshake: Some((1_700_000_000, 42)),
                tx_bytes: 10,
                rx_bytes: 20,
                keepalive: Some(25),
                allowed_ips: vec!["10.7.0.2/32".parse().unwrap()],
                epoch: 2,
            }],
        };
        let text = render_get(&state);
        assert!(text.contains("private_key=0101"));
        assert!(text.contains("endpoint=203.0.113.9:51820"));
        assert!(text.contains("allowed_ip=10.7.0.2/32"));
        assert!(text.ends_with("errno=0\n"));
    }
}
