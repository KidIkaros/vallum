// SPDX-License-Identifier: Apache-2.0

//! The one shape a snapshot can take on its way to the WebView.
//!
//! ADR-0024 draws a hard line at the IPC boundary: the daemon's reply contains
//! `private_key` and `preshared_key`, and neither may cross. That is enforced by
//! construction here — [`Snapshot`] has no field for them and [`Snapshot::from_reply`]
//! reads the reply through an allowlist of named fields, so a future protocol
//! field cannot leak by being "just carried along".
//!
//! Parsing is [`vallum::uapi`]'s, not a second implementation: this module only
//! decides which of the parsed fields are allowed out.

use serde::Serialize;
use vallum::uapi::{self, field};

/// One device snapshot, safe to serialise.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Snapshot {
    pub interface: String,
    pub addresses: Vec<String>,
    pub listen_port: Option<u32>,
    pub suite: String,
    pub fwmark: Option<u32>,
    pub fingerprint: String,
    pub public_line: String,
    pub offload: bool,
    pub batching: bool,
    pub counters: Counters,
    /// `full` when the daemon's peer allowlists route everything through the
    /// tunnel; the daemon decides, this just carries it.
    pub expected_egress: String,
    /// The daemon's build (git hash) — fleet parity, visible.
    pub build: String,
    pub peers: Vec<Peer>,
}

/// The telemetry block, absent as a whole when the daemon does not report it.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Counters {
    pub datagrams_sent: u64,
    pub datagrams_failed: u64,
    pub packets_delivered: u64,
    pub packets_failed: u64,
    pub established: u64,
    pub refusals: u64,
    pub reassembled: u64,
    pub fragments_dropped: u64,
}

/// One peer, safe to serialise.
///
/// A preshared key is reported only as [`Peer::has_preshared_key`]: the console
/// needs to say "PSK set", never what it is.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Peer {
    pub name: String,
    pub fingerprint: String,
    pub public_line: String,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
    pub keepalive: Option<u16>,
    pub last_handshake_sec: u64,
    pub last_handshake_nsec: u32,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub epoch: u64,
    pub rotating: bool,
    pub valid_until: Option<u64>,
    pub has_preshared_key: bool,
}

impl Snapshot {
    /// The suite the daemon reported, as an id.
    ///
    /// The UAPI renders it as `0x0003`. An unparseable value reads as `0`, which
    /// matches no real suite — a form validated against it fails closed rather
    /// than accepting a peer of another suite.
    #[must_use]
    pub fn suite_id(&self) -> u16 {
        let text = self.suite.trim();
        let hex = text
            .strip_prefix("0x")
            .or_else(|| text.strip_prefix("0X"))
            .unwrap_or(text);
        u16::from_str_radix(hex, 16).unwrap_or(0)
    }

    /// Decode a `get=1` reply into the allowlisted shape.
    ///
    /// Unknown fields are dropped; a malformed number is absent rather than zero
    /// where "absent" is representable, because a rendered `0` for a missing
    /// counter reads like a measurement.
    #[must_use]
    pub fn from_reply(text: &str) -> Self {
        let response = uapi::parse_response(text);
        let device = |key: &str| response.field(key);
        Self {
            interface: device(field::VALLUM_INTERFACE)
                .unwrap_or_default()
                .to_owned(),
            addresses: values(&response.device, field::VALLUM_ADDRESS)
                .map(str::to_owned)
                .collect(),
            listen_port: device(field::LISTEN_PORT).and_then(|value| value.parse().ok()),
            suite: device(field::VALLUM_SUITE).unwrap_or_default().to_owned(),
            fwmark: device(field::FWMARK).and_then(|value| value.parse().ok()),
            fingerprint: device(field::VALLUM_FINGERPRINT)
                .unwrap_or_default()
                .to_owned(),
            public_line: device(field::VALLUM_PUBLIC_LINE)
                .unwrap_or_default()
                .to_owned(),
            offload: device(field::VALLUM_OFFLOAD) == Some("1"),
            batching: device(field::VALLUM_BATCHING) == Some("1"),
            build: device(field::VALLUM_BUILD)
                .map(str::to_owned)
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "unknown".to_owned()),
            expected_egress: device(field::VALLUM_EGRESS)
                .map(str::to_owned)
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "split".to_owned()),
            counters: Counters {
                datagrams_sent: number(&response.device, field::VALLUM_DATAGRAMS_SENT),
                datagrams_failed: number(&response.device, field::VALLUM_DATAGRAMS_FAILED),
                packets_delivered: number(&response.device, field::VALLUM_PACKETS_DELIVERED),
                packets_failed: number(&response.device, field::VALLUM_PACKETS_FAILED),
                established: number(&response.device, field::VALLUM_HANDSHAKES),
                refusals: number(&response.device, field::VALLUM_REFUSALS),
                reassembled: number(&response.device, field::VALLUM_REASSEMBLED),
                fragments_dropped: number(&response.device, field::VALLUM_FRAGMENTS_DROPPED),
            },
            peers: response.peers.iter().map(|section| peer(section)).collect(),
        }
    }
}

fn peer(section: &[(String, String)]) -> Peer {
    let get = |key: &str| {
        section
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    };
    Peer {
        name: get(field::VALLUM_NAME).unwrap_or_default().to_owned(),
        fingerprint: get(field::VALLUM_FINGERPRINT)
            .unwrap_or_default()
            .to_owned(),
        public_line: get(field::VALLUM_PUBLIC_LINE)
            .unwrap_or_default()
            .to_owned(),
        endpoint: get(field::ENDPOINT).unwrap_or_default().to_owned(),
        allowed_ips: values(section, field::ALLOWED_IP)
            .map(str::to_owned)
            .collect(),
        keepalive: get(field::PERSISTENT_KEEPALIVE_INTERVAL).and_then(|value| value.parse().ok()),
        last_handshake_sec: number(section, field::LAST_HANDSHAKE_TIME_SEC),
        last_handshake_nsec: get(field::LAST_HANDSHAKE_TIME_NSEC)
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
        tx_bytes: number(section, field::TX_BYTES),
        rx_bytes: number(section, field::RX_BYTES),
        epoch: number(section, field::VALLUM_EPOCH),
        rotating: get(field::VALLUM_ROTATING) == Some("1"),
        valid_until: get(field::VALLUM_VALID_UNTIL).and_then(|value| value.parse().ok()),
        // Presence only. The value never leaves the daemon.
        has_preshared_key: matches!(get(field::PRESHARED_KEY), Some(value) if !value.is_empty()),
    }
}

fn values<'a>(section: &'a [(String, String)], key: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    section
        .iter()
        .filter(move |(name, _)| name == key)
        .map(|(_, value)| value.as_str())
}

fn number(section: &[(String, String)], key: &str) -> u64 {
    values(section, key)
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

/// Ask one socket for a snapshot.
///
/// # Errors
///
/// If the socket cannot be reached, the reply is too large, or the daemon
/// answered with a non-zero `errno`.
pub fn fetch(path: &std::path::Path) -> Result<Snapshot, String> {
    let reply = vallum::control::request(path, "get=1\n").map_err(|error| error.to_string())?;
    if !reply.lines().any(|line| line == "errno=0") {
        return Err(format!("control request failed: {}", reply.trim()));
    }
    Ok(Snapshot::from_reply(&reply))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "cHJpdmF0ZS1rZXktbWF0ZXJpYWw=";
    const PSK: &str = "cHNrLW1hdGVyaWFs";

    fn reply() -> String {
        format!(
            concat!(
                "private_key={secret}\n",
                "vallum_private_key_path=/etc/vallum/private.key\n",
                "vallum_interface=vallum0\n",
                "listen_port=51820\n",
                "fwmark=51820\n",
                "vallum_suite=hybrid-x25519-mlkem768\n",
                "vallum_address=10.9.0.1/24\n",
                "vallum_address=fd00:9::1/64\n",
                "vallum_offload=1\n",
                "vallum_batching=0\n",
                "vallum_datagrams_sent=42\n",
                "vallum_handshakes_established=7\n",
                "errno=0\n",
                "\n",
                "public_key=peerpub==\n",
                "preshared_key={psk}\n",
                "vallum_name=laptop\n",
                "vallum_fingerprint=ab:cd\n",
                "endpoint=203.0.113.9:51820\n",
                "allowed_ip=10.9.0.2/32\n",
                "allowed_ip=fd00:9::2/128\n",
                "last_handshake_time_sec=1700000000\n",
                "last_handshake_time_nsec=5\n",
                "tx_bytes=1024\n",
                "rx_bytes=2048\n",
                "vallum_epoch=3\n",
                "vallum_rotating=1\n",
                "errno=0\n",
            ),
            secret = SECRET,
            psk = PSK,
        )
    }

    #[test]
    fn decodes_the_documented_fields() {
        let snapshot = Snapshot::from_reply(&reply());
        assert_eq!(snapshot.interface, "vallum0");
        assert_eq!(snapshot.listen_port, Some(51820));
        assert_eq!(snapshot.addresses.len(), 2);
        assert!(snapshot.offload);
        assert!(!snapshot.batching);
        assert_eq!(snapshot.counters.datagrams_sent, 42);
        assert_eq!(snapshot.counters.established, 7);

        let peer = &snapshot.peers[0];
        assert_eq!(peer.name, "laptop");
        assert_eq!(peer.endpoint, "203.0.113.9:51820");
        assert_eq!(peer.allowed_ips, ["10.9.0.2/32", "fd00:9::2/128"]);
        assert_eq!(peer.last_handshake_sec, 1_700_000_000);
        assert_eq!(peer.last_handshake_nsec, 5);
        assert_eq!(peer.tx_bytes, 1024);
        assert_eq!(peer.rx_bytes, 2048);
        assert_eq!(peer.epoch, 3);
        assert!(peer.rotating);
    }

    /// The ADR's requirement, asserted at the boundary rather than trusted: the
    /// serialised snapshot must not contain the secret values, and must not even
    /// name the fields that carry them.
    #[test]
    fn secrets_never_cross_the_boundary() {
        let json = serde_json::to_string(&Snapshot::from_reply(&reply()))
            .unwrap_or_else(|error| panic!("serialise: {error}"));
        assert!(!json.contains(SECRET));
        assert!(!json.contains(PSK));
        // The field names are checked with their quotes so that the deliberate
        // `has_preshared_key` boolean is not mistaken for a leaked key.
        assert!(!json.contains("\"private_key\""));
        assert!(!json.contains("\"preshared_key\""));
        // Presence is still reported, because the UI says "PSK set".
        assert!(json.contains("\"has_preshared_key\":true"));
    }

    /// The whole read path, over a real Unix socket: `vallum::control::request`
    /// sends `get=1`, this crate decodes the reply. The fake daemon also asserts
    /// the request body, so a change to what the console asks for is caught here
    /// rather than by a daemon that quietly answers `errno`.
    #[test]
    fn reads_a_real_control_socket() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;

        let dir = std::env::temp_dir().join(format!("vallum-gui-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("control.sock");
        let _ = std::fs::remove_file(&path);

        let listener = UnixListener::bind(&path)
            .unwrap_or_else(|error| panic!("bind the fake socket: {error}"));
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener
                .accept()
                .unwrap_or_else(|error| panic!("accept: {error}"));
            let mut request = String::new();
            let _ = stream.read_to_string(&mut request);
            assert_eq!(request, "get=1\n");
            let _ = stream.write_all(b"vallum_interface=vallum0\nlisten_port=51820\nerrno=0\n\n");
        });

        let snapshot = fetch(&path).unwrap_or_else(|error| panic!("fetch: {error}"));
        server
            .join()
            .unwrap_or_else(|_| panic!("the fake daemon panicked"));

        assert_eq!(snapshot.interface, "vallum0");
        assert_eq!(snapshot.listen_port, Some(51820));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Peer names and endpoints are attacker-influenced. The host must pass them
    /// through as data, unchanged and unescaped-at-this-layer; escaping is the
    /// renderer's job (`textContent`), and mangling here would corrupt names.
    #[test]
    fn hostile_strings_are_passed_through_as_data() {
        let hostile = r#"<img src=x onerror=alert(1)>"#;
        let reply =
            format!("vallum_interface=vallum0\nerrno=0\n\nvallum_name={hostile}\nerrno=0\n");
        let snapshot = Snapshot::from_reply(&reply);
        assert_eq!(snapshot.peers[0].name, hostile);

        let json = serde_json::to_string(&snapshot).unwrap_or_default();
        let round_trip: serde_json::Value =
            serde_json::from_str(&json).unwrap_or(serde_json::Value::Null);
        assert_eq!(round_trip["peers"][0]["name"], hostile);
    }
}
