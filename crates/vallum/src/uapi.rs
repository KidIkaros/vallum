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
    out.push_str(&format!(
        "private_key={}\n",
        hex_encode(state.private_key.as_bytes())
    ));
    out.push_str(&format!(
        "vallum_private_key_path={}\n",
        state.private_key_path
    ));
    out.push_str(&format!("listen_port={}\n", state.listen.port()));
    out.push_str(&format!("fwmark={}\n", state.fwmark));
    out.push_str(&format!("public_key={}\n", hex_encode(&state.public_key)));
    out.push_str(&format!("vallum_interface={}\n", state.interface));
    out.push_str(&format!("vallum_public_line={}\n", state.public_line));
    out.push_str(&format!(
        "vallum_fingerprint={}\n",
        hex_encode(&state.fingerprint)
    ));
    out.push_str(&format!("vallum_listen={}\n", state.listen));
    out.push_str(&format!("vallum_offload={}\n", state.offload));
    out.push_str(&format!("vallum_batching={}\n", state.batching));
    for address in &state.addresses {
        out.push_str(&format!("vallum_address={address}\n"));
    }
    out.push_str(&format!(
        "vallum_can_set_private_key={}\n",
        state.capabilities.set_private_key
    ));
    out.push_str(&format!(
        "vallum_can_set_listen_port={}\n",
        state.capabilities.set_listen_port
    ));
    out.push_str(&format!(
        "vallum_can_set_fwmark={}\n",
        state.capabilities.set_fwmark
    ));
    out.push_str(&format!("vallum_suite={:#06x}\n", state.suite));
    for peer in &state.peers {
        out.push_str(&format!("\npublic_key={}\n", hex_encode(&peer.public_key)));
        out.push_str(&format!("vallum_name={}\n", peer.name));
        out.push_str(&format!(
            "vallum_fingerprint={}\n",
            hex_encode(&peer.fingerprint)
        ));
        out.push_str(&format!("vallum_public_line={}\n", peer.public_line));
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
    let fingerprint = response.field("vallum_fingerprint").unwrap_or("?");
    out.push_str(&format!("interface {fingerprint}\n"));
    for (key, value) in &response.device {
        if hidden(key) {
            continue;
        }
        out.push_str(&format!("  {key}={value}\n"));
    }
    for peer in &response.peers {
        let fingerprint = field(peer, "vallum_fingerprint").unwrap_or("?");
        let name = field(peer, "vallum_name").unwrap_or("");
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
        "private_key"
            | "preshared_key"
            | "public_key"
            | "vallum_public_line"
            | "vallum_fingerprint"
            | "vallum_name"
            | "errno"
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
        escape(response.field("vallum_interface").unwrap_or("vallum0"))
    ));
    let key_path = if include_secrets {
        response
            .field("vallum_private_key_path")
            .unwrap_or("private.key")
    } else {
        "private.key"
    };
    out.push_str(&format!("private_key = \"{}\"\n", escape(key_path)));
    if let Some(listen) = response.field("vallum_listen") {
        out.push_str(&format!("listen = \"{listen}\"\n"));
    }
    if let Some(fwmark) = response.field("fwmark") {
        if fwmark != "0" {
            out.push_str(&format!("fwmark = {fwmark}\n"));
        }
    }
    let addresses: Vec<String> = response
        .device
        .iter()
        .filter(|(key, _)| key == "vallum_address")
        .map(|(_, value)| format!("\"{}\"", escape(value)))
        .collect();
    if !addresses.is_empty() {
        out.push_str(&format!("addresses = [{}]\n", addresses.join(", ")));
    }
    for peer in &response.peers {
        out.push_str("\n[[peer]]\n");
        if let Some(name) = field(peer, "vallum_name") {
            out.push_str(&format!("name = \"{}\"\n", escape(name)));
        }
        if let Some(line) = field(peer, "vallum_public_line") {
            out.push_str(&format!("public_key = \"{}\"\n", escape(line)));
        }
        if let Some(endpoint) = field(peer, "endpoint") {
            if endpoint != "(none)" {
                out.push_str(&format!("endpoint = \"{endpoint}\"\n"));
            }
        }
        let allowed: Vec<String> = peer
            .iter()
            .filter(|(key, _)| key == "allowed_ip")
            .map(|(_, value)| format!("\"{}\"", escape(value)))
            .collect();
        if !allowed.is_empty() {
            out.push_str(&format!("allowed_ips = [{}]\n", allowed.join(", ")));
        }
        if let Some(keepalive) = field(peer, "persistent_keepalive_interval") {
            if keepalive != "0" {
                out.push_str(&format!("persistent_keepalive = {keepalive}\n"));
            }
        }
        match (include_secrets, field(peer, "preshared_key")) {
            (true, Some(psk)) => out.push_str(&format!("preshared_key = \"{psk}\"\n")),
            _ => out.push_str("# preshared_key is not exported\n"),
        }
    }
    out
}

fn escape(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
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
            any::<u64>(),
            any::<u64>(),
            prop::option::of(any::<u16>()),
            proptest::collection::vec(a_prefix(), 0..3),
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
                    tx_bytes,
                    rx_bytes,
                    keepalive,
                    allowed_ips,
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
                    keepalive,
                    allowed_ips,
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
                    fwmark,
                    suite,
                    addresses,
                    offload: false,
                    batching: false,
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
            prop_assert_eq!(response.field("vallum_interface"), Some(state.interface.as_str()));
            prop_assert_eq!(response.field("fwmark"), Some(fwmark.as_str()));
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
            interface: "vallum0".to_owned(),
            private_key: SharedSecret::new([1u8; 32]),
            private_key_path: "test.key".to_owned(),
            public_key: vec![2u8; 32],
            public_line: "vallum1:0003:02:-".to_owned(),
            fingerprint: [4u8; 8],
            listen: "0.0.0.0:51820".parse().unwrap(),
            fwmark: 0,
            suite: 0x0003,
            addresses: vec!["10.7.0.1/24".parse().unwrap()],
            offload: false,
            batching: false,
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
                keepalive: Some(25),
                allowed_ips: vec!["10.7.0.2/32".parse().unwrap()],
                epoch: 2,
            }],
        };
        let text = render_get(&state);
        assert!(text.contains("private_key=0101"));
        assert!(text.contains("vallum_interface=vallum0"));
        assert!(text.contains("vallum_can_set_listen_port=false"));
        assert!(text.contains("endpoint=203.0.113.9:51820"));
        assert!(text.contains("allowed_ip=10.7.0.2/32"));
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
            fwmark: 0,
            suite: 0x0003,
            addresses: Vec::new(),
            offload: false,
            batching: false,
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
                keepalive: None,
                allowed_ips: Vec::new(),
                epoch: 0,
            }],
        };
        let response = parse_response(&render_get(&state));
        assert_eq!(response.field("vallum_interface"), Some("vallum0"));
        assert_eq!(response.peers.len(), 1);
        assert_eq!(response.peer_field(0, "vallum_name"), Some("laptop"));
    }

    #[test]
    fn the_config_export_can_include_secrets_explicitly() {
        let response = Response {
            device: vec![
                ("vallum_interface".to_owned(), "vallum0".to_owned()),
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
        assert!(text.contains("public_key = \"vallum1:0003:ab:-\""));
        assert!(text.contains("allowed_ips = [\"10.7.0.2/32\"]"));
        assert!(!text.contains("cc".repeat(32).as_str()));
    }
}
