// SPDX-License-Identifier: Apache-2.0

//! TUI state. Rendering is a pure function of this; actions mutate it.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::uapi::{field, Response};

use super::qr::QrState;

/// One peer row.
#[derive(Debug, Clone, Default)]
pub struct PeerView {
    pub name: String,
    pub fingerprint: String,
    pub public_line: String,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
    pub keepalive: Option<u16>,
    pub last_handshake: Option<(u64, u32)>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub window_sent: u64,
    pub window_received: u64,
    pub last_received_ms: Option<u64>,
    pub last_sent_ms: Option<u64>,
    pub dropped_no_session: u64,
    pub dropped_replay: u64,
    pub dropped_allowed_ips: u64,
    pub dropped_after_auth: u64,
    pub reinit_offered: u64,
    pub last_rejected_source: Option<String>,
    pub epoch: u64,
    pub preshared_key: bool,
    /// Unix second the peer's identity expires, when it is a document.
    pub valid_until: Option<u64>,
    /// Whether a rotation is open (a previous identity is still accepted).
    pub rotating: bool,
}

/// One device snapshot.
#[derive(Debug, Clone, Default)]
pub struct DeviceView {
    pub interface: String,
    pub listen: String,
    /// Live loop counters from the control socket; `None` when the daemon is
    /// older than the telemetry fields.
    pub stats: Option<LoopStatsView>,
    pub fwmark: u32,
    pub suite: String,
    pub suite_id: u16,
    pub fingerprint: String,
    pub public_line: String,
    pub addresses: Vec<String>,
    pub offload: bool,
    pub batching: bool,
    /// `full` / `split`, decided by the daemon's allowlists.
    pub egress: String,
    pub peers: Vec<PeerView>,
}

/// The dataplane counters, for the detail pane.
#[derive(Debug, Clone, Copy, Default)]
pub struct LoopStatsView {
    pub datagrams_sent: u64,
    pub datagrams_failed: u64,
    pub packets_delivered: u64,
    pub packets_failed: u64,
    pub established: u64,
    pub refusals: u64,
    pub reassembled: u64,
    pub fragments_dropped: u64,
    pub dropped_malformed: u64,
    pub dropped_unknown_index: u64,
    pub fragments_rate_limited: u64,
    pub handshake_dropped_no_mac: u64,
    pub handshake_dropped_unidentifiable: u64,
    pub handshake_dropped_unknown_peer: u64,
    pub handshake_dropped_endpoint_conflict: u64,
    pub handshake_dropped_stale: u64,
}

impl LoopStatsView {
    fn from_response(response: &Response) -> Option<Self> {
        // Honest-missing: only a fully populated block counts as telemetry.
        let counter = |key: &str| response.field(key)?.parse::<u64>().ok();
        let opt = |key: &str| {
            response
                .field(key)
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0)
        };
        Some(Self {
            datagrams_sent: counter(field::VALLUM_DATAGRAMS_SENT)?,
            datagrams_failed: counter(field::VALLUM_DATAGRAMS_FAILED)?,
            packets_delivered: counter(field::VALLUM_PACKETS_DELIVERED)?,
            packets_failed: counter(field::VALLUM_PACKETS_FAILED)?,
            established: counter(field::VALLUM_HANDSHAKES)?,
            refusals: counter(field::VALLUM_REFUSALS)?,
            reassembled: counter(field::VALLUM_REASSEMBLED)?,
            fragments_dropped: counter(field::VALLUM_FRAGMENTS_DROPPED)?,
            dropped_malformed: opt(field::VALLUM_DROPPED_MALFORMED),
            dropped_unknown_index: opt(field::VALLUM_DROPPED_UNKNOWN_INDEX),
            fragments_rate_limited: opt(field::VALLUM_FRAGMENTS_RATE_LIMITED),
            handshake_dropped_no_mac: opt(field::VALLUM_HANDSHAKE_DROPPED_NO_MAC),
            handshake_dropped_unidentifiable: opt(field::VALLUM_HANDSHAKE_DROPPED_UNIDENTIFIABLE),
            handshake_dropped_unknown_peer: opt(field::VALLUM_HANDSHAKE_DROPPED_UNKNOWN_PEER),
            handshake_dropped_endpoint_conflict: opt(
                field::VALLUM_HANDSHAKE_DROPPED_ENDPOINT_CONFLICT,
            ),
            handshake_dropped_stale: opt(field::VALLUM_HANDSHAKE_DROPPED_STALE),
        })
    }
}

impl DeviceView {
    #[must_use]
    pub fn from_response(response: &Response) -> Self {
        let get = |key: &str| response.field(key).unwrap_or("").to_owned();
        let flag = |key: &str| response.field(key) == Some("true");
        let addresses = response
            .device
            .iter()
            .filter(|(key, _)| key == field::VALLUM_ADDRESS)
            .map(|(_, value)| value.clone())
            .collect();
        let peers = response
            .peers
            .iter()
            .map(|peer| {
                let peer_field = |key: &str| {
                    peer.iter()
                        .find(|(name, _)| name == key)
                        .map(|(_, value)| value.clone())
                        .unwrap_or_default()
                };
                let last = peer_field(field::LAST_HANDSHAKE_TIME_SEC)
                    .parse::<u64>()
                    .ok()
                    .map(|sec| {
                        (
                            sec,
                            peer_field(field::LAST_HANDSHAKE_TIME_NSEC)
                                .parse()
                                .unwrap_or(0),
                        )
                    });
                let public_line = peer_field(field::VALLUM_PUBLIC_LINE);
                let mut fingerprint = peer_field(field::VALLUM_FINGERPRINT);
                if fingerprint.is_empty() {
                    if let Some(extracted) = public_line.split(':').nth(2) {
                        fingerprint = extracted.to_owned();
                    }
                }
                let last_rejected_raw = peer_field(field::LAST_REJECTED_SOURCE);
                PeerView {
                    name: peer_field(field::VALLUM_NAME),
                    fingerprint,
                    public_line,
                    endpoint: peer_field(field::ENDPOINT),
                    allowed_ips: peer
                        .iter()
                        .filter(|(key, _)| key == field::ALLOWED_IP)
                        .map(|(_, value)| value.clone())
                        .collect(),
                    keepalive: peer_field(field::PERSISTENT_KEEPALIVE_INTERVAL)
                        .parse::<u16>()
                        .ok()
                        .filter(|value| *value > 0),
                    last_handshake: last,
                    tx_bytes: peer_field(field::TX_BYTES).parse().unwrap_or(0),
                    rx_bytes: peer_field(field::RX_BYTES).parse().unwrap_or(0),
                    window_sent: peer_field(field::WINDOW_SENT).parse().unwrap_or(0),
                    window_received: peer_field(field::WINDOW_RECEIVED).parse().unwrap_or(0),
                    last_received_ms: peer_field(field::LAST_RECEIVED_MS).parse().ok(),
                    last_sent_ms: peer_field(field::LAST_SENT_MS).parse().ok(),
                    dropped_no_session: peer_field(field::DROPPED_NO_SESSION).parse().unwrap_or(0),
                    dropped_replay: peer_field(field::DROPPED_REPLAY).parse().unwrap_or(0),
                    dropped_allowed_ips: peer_field(field::DROPPED_ALLOWED_IPS)
                        .parse()
                        .unwrap_or(0),
                    dropped_after_auth: peer_field(field::VALLUM_DROPPED_AFTER_AUTH)
                        .parse()
                        .unwrap_or(0),
                    reinit_offered: peer_field(field::REINIT_OFFERED).parse().unwrap_or(0),
                    last_rejected_source: if last_rejected_raw.is_empty()
                        || last_rejected_raw == "-"
                    {
                        None
                    } else {
                        Some(last_rejected_raw)
                    },
                    epoch: peer_field(field::VALLUM_EPOCH).parse().unwrap_or(0),
                    preshared_key: !peer_field(field::PRESHARED_KEY).is_empty(),
                    valid_until: peer_field(field::VALLUM_VALID_UNTIL).parse().ok(),
                    rotating: peer_field(field::VALLUM_ROTATING) == "1",
                }
            })
            .collect();
        let suite = get(field::VALLUM_SUITE);
        let suite_id = u16::from_str_radix(suite.trim_start_matches("0x"), 16).unwrap_or(0);
        Self {
            interface: get(field::VALLUM_INTERFACE),
            listen: get(field::VALLUM_LISTEN),
            stats: LoopStatsView::from_response(response),
            fwmark: get(field::FWMARK).parse().unwrap_or(0),
            suite,
            suite_id,
            fingerprint: get(field::VALLUM_FINGERPRINT),
            public_line: get(field::VALLUM_PUBLIC_LINE),
            addresses,
            egress: get(field::VALLUM_EGRESS),
            offload: flag(field::VALLUM_OFFLOAD),
            batching: flag(field::VALLUM_BATCHING),
            peers,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Active,
    Inactive,
    Failed,
    Activating,
    Deactivating,
}

impl ServiceState {
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "active" => Some(Self::Active),
            "inactive" => Some(Self::Inactive),
            "failed" => Some(Self::Failed),
            "activating" => Some(Self::Activating),
            "deactivating" => Some(Self::Deactivating),
            _ => None,
        }
    }

    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Inactive => "inactive",
            Self::Failed => "failed",
            Self::Activating => "starting",
            Self::Deactivating => "stopping",
        }
    }
}

/// One discovered interface.
#[derive(Debug, Clone)]
pub struct Interface {
    pub name: String,
    pub config_path: Option<PathBuf>,
    pub control_path: PathBuf,
    pub device: Option<DeviceView>,
    pub error: Option<String>,
    pub service_state: Option<ServiceState>,
    /// The egress guard's unit state — only meaningful when full tunnel is
    /// armed; None until the first check.
    pub guard_state: Option<ServiceState>,
    prev_tx: u64,
    prev_rx: u64,
    prev_at: Instant,
    last_successful_poll: Option<Instant>,
    last_service_check: Option<Instant>,
    pub tx_rate: f64,
    pub rx_rate: f64,
    pub rx_history: Vec<u64>,
    pub tx_history: Vec<u64>,
}

impl Interface {
    #[must_use]
    pub fn new(name: String, config_path: Option<PathBuf>, control_path: PathBuf) -> Self {
        Self {
            name,
            config_path,
            control_path,
            device: None,
            error: None,
            service_state: None,
            guard_state: None,
            prev_tx: 0,
            prev_rx: 0,
            prev_at: Instant::now(),
            last_successful_poll: None,
            last_service_check: None,
            tx_rate: 0.0,
            rx_rate: 0.0,
            rx_history: Vec::new(),
            tx_history: Vec::new(),
        }
    }

    pub fn set_device(&mut self, device: DeviceView) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.prev_at).as_secs_f64().max(0.001);
        let tx: u64 = device.peers.iter().map(|peer| peer.tx_bytes).sum();
        let rx: u64 = device.peers.iter().map(|peer| peer.rx_bytes).sum();
        if self.device.is_some() {
            self.tx_rate = tx.saturating_sub(self.prev_tx) as f64 / elapsed;
            self.rx_rate = rx.saturating_sub(self.prev_rx) as f64 / elapsed;
            self.rx_history.push(self.rx_rate as u64);
            if self.rx_history.len() > 30 {
                self.rx_history.remove(0);
            }
            self.tx_history.push(self.tx_rate as u64);
            if self.tx_history.len() > 30 {
                self.tx_history.remove(0);
            }
        }
        self.prev_tx = tx;
        self.prev_rx = rx;
        self.prev_at = now;
        self.last_successful_poll = Some(now);
        self.name = device.interface.clone();
        self.device = Some(device);
        self.error = None;
    }

    pub fn set_error(&mut self, error: String) {
        self.error = Some(error);
    }

    #[must_use]
    pub fn last_successful_poll_age(&self) -> Option<Duration> {
        self.last_successful_poll
            .map(|at| Instant::now().saturating_duration_since(at))
    }

    #[must_use]
    pub fn should_check_service(&self, now: Instant) -> bool {
        self.config_path.is_some()
            && self
                .last_service_check
                .is_none_or(|at| now.saturating_duration_since(at) >= Duration::from_secs(5))
    }

    pub fn set_service_state(&mut self, state: Option<ServiceState>) {
        self.service_state = state;
        self.last_service_check = Some(Instant::now());
    }

    pub fn set_guard_state(&mut self, state: Option<ServiceState>) {
        self.guard_state = state;
    }

    pub fn invalidate_service_state(&mut self) {
        self.last_service_check = None;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Dashboard,
    Help,
    Logs,
    Diff,
    Trial,
    Health,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffKind {
    Equal,
    Delete,
    Insert,
    Replace,
}

#[derive(Debug, Clone)]
pub struct DiffRow {
    pub left: Option<String>,
    pub right: Option<String>,
    pub kind: DiffKind,
}

#[derive(Debug, Clone)]
pub struct DiffView {
    pub rows: Vec<DiffRow>,
    pub backup: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Interfaces,
    Peers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeFreshness {
    Never,
    Recent,
    Aging,
    Old,
}

impl HandshakeFreshness {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Never => "NEVER",
            Self::Recent => "RECENT",
            Self::Aging => "AGING",
            Self::Old => "OLD",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortMode {
    #[default]
    Natural,
    RecentHandshake,
    Transfer,
    Name,
}

impl SortMode {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Natural => "default",
            Self::RecentHandshake => "recent handshake",
            Self::Transfer => "transfer (rx+tx)",
            Self::Name => "name (a-z)",
        }
    }

    #[must_use]
    pub fn next(self) -> Self {
        match self {
            Self::Natural => Self::RecentHandshake,
            Self::RecentHandshake => Self::Transfer,
            Self::Transfer => Self::Name,
            Self::Name => Self::Natural,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormKind {
    AddPeer,
    InvitePeer,
    EditPeer(usize),
    RotatePeer(usize),
    Device,
    ExportBundle,
    ImportBundle,
    Interface,
}

#[derive(Debug, Clone)]
pub struct Field {
    pub label: &'static str,
    pub value: String,
    pub masked: bool,
    pub placeholder: &'static str,
}

#[derive(Debug, Clone)]
pub struct FormError {
    pub field: Option<&'static str>,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct Form {
    pub title: String,
    pub fields: Vec<Field>,
    pub focus: usize,
    pub cursor: usize,
    pub error: Option<FormError>,
    pub kind: FormKind,
}

impl Form {
    #[must_use]
    pub fn add_peer() -> Self {
        Self {
            title: "Add peer".to_owned(),
            fields: vec![
                Field {
                    label: "name",
                    value: String::new(),
                    masked: false,
                    placeholder: "e.g. laptop, phone, office-router",
                },
                Field {
                    label: "public line",
                    value: String::new(),
                    masked: false,
                    placeholder: "suite + identity from keygen or peer",
                },
                Field {
                    label: "endpoint",
                    value: String::new(),
                    masked: false,
                    placeholder: "e.g. 198.51.100.1:51820 (optional)",
                },
                Field {
                    label: "allowed IPs",
                    value: String::new(),
                    masked: false,
                    placeholder: "e.g. 10.7.0.2/32, 192.168.1.0/24 (auto /32 if omitted)",
                },
                Field {
                    label: "keepalive",
                    value: "0".to_owned(),
                    masked: false,
                    placeholder: "seconds (0 = off, 25 for NAT)",
                },
                Field {
                    label: "PSK (hex, optional)",
                    value: String::new(),
                    masked: true,
                    placeholder: "32-byte hex pre-shared key",
                },
            ],
            focus: 0,
            cursor: 0,
            error: None,
            kind: FormKind::AddPeer,
        }
    }

    #[must_use]
    pub fn interface(values: [String; 6]) -> Self {
        let labels = [
            "listen",
            "mtu",
            "fwmark",
            "addresses (comma)",
            "dns (comma)",
            "table",
        ];
        let placeholders = [
            "e.g. 0.0.0.0:51820",
            "e.g. 1420",
            "e.g. 51820 or 0",
            "e.g. 10.7.0.1/24, fd00::1/64",
            "e.g. 1.1.1.1, 8.8.8.8",
            "e.g. auto, off, or table number",
        ];
        let cursor = values[0].chars().count();
        let error = Self::validate_interface(&values).err();
        Self {
            title: "Interface config".to_owned(),
            fields: labels
                .into_iter()
                .zip(values)
                .zip(placeholders)
                .map(|((label, value), placeholder)| Field {
                    label,
                    value,
                    masked: false,
                    placeholder,
                })
                .collect(),
            focus: 0,
            cursor,
            error,
            kind: FormKind::Interface,
        }
    }

    pub(crate) fn validate_interface(values: &[String]) -> Result<(), FormError> {
        const LABELS: &[&str] = &[
            "listen",
            "mtu",
            "fwmark",
            "addresses (comma)",
            "dns (comma)",
            "table",
        ];

        for (index, value) in values.iter().enumerate() {
            // An empty field means "leave the current value unchanged".
            if value.trim().is_empty() {
                continue;
            }
            match LABELS.get(index).copied() {
                Some("listen") => {
                    if !value.contains(':') {
                        return Err(FormError {
                            field: Some("listen"),
                            message: "must be an address:port (e.g. 0.0.0.0:51820)".to_string(),
                        });
                    }
                }
                Some("mtu") => {
                    if let Ok(n) = value.parse::<u16>() {
                        if n == 0 {
                            continue; // auto
                        }
                        if n < 1280 {
                            return Err(FormError {
                                field: Some("mtu"),
                                message: "must be 1280-65535 or 0 (auto)".to_string(),
                            });
                        }
                    } else {
                        return Err(FormError {
                            field: Some("mtu"),
                            message: "must be a number".to_string(),
                        });
                    }
                }
                Some("fwmark") => {
                    if value.parse::<u32>().is_err() {
                        return Err(FormError {
                            field: Some("fwmark"),
                            message: "must be a number or 0".to_string(),
                        });
                    }
                }
                Some("addresses (comma)") => {
                    for cidr in value.split(',') {
                        let cidr = cidr.trim();
                        if cidr.is_empty() {
                            continue;
                        }
                        match cidr.find('/') {
                            Some(slash) => {
                                let ip = &cidr[..slash];
                                if ip.contains('.') {
                                    if ip.split('.').count() != 4 {
                                        return Err(FormError {
                                            field: Some("addresses (comma)"),
                                            message: "invalid IPv4 address".to_string(),
                                        });
                                    }
                                } else {
                                    if ip.contains(':') {
                                        let colon_count = ip.chars().filter(|&c| c == ':').count();
                                        if colon_count > 7 {
                                            return Err(FormError {
                                                field: Some("addresses (comma)"),
                                                message: "invalid IPv6 address".to_string(),
                                            });
                                        }
                                    } else {
                                        return Err(FormError {
                                            field: Some("addresses (comma)"),
                                            message: "invalid address".to_string(),
                                        });
                                    }
                                }
                            }
                            None => {
                                return Err(FormError {
                                    field: Some("addresses (comma)"),
                                    message: "must be CIDR notation (e.g. 10.7.0.1/24)".to_string(),
                                });
                            }
                        }
                    }
                }
                Some("dns (comma)") => {
                    for ip in value.split(',') {
                        let ip = ip.trim();
                        if ip.is_empty() {
                            continue;
                        }
                        if ip.contains(':') {
                            let colon_count = ip.chars().filter(|&c| c == ':').count();
                            if colon_count > 7 {
                                return Err(FormError {
                                    field: Some("dns (comma)"),
                                    message: "invalid IPv6 address".to_string(),
                                });
                            }
                        } else {
                            if ip.split('.').count() != 4 {
                                return Err(FormError {
                                    field: Some("dns (comma)"),
                                    message: "invalid IPv4 address".to_string(),
                                });
                            }
                        }
                    }
                }
                Some("table") => {
                    if matches!(value.as_str(), "auto" | "off") || value.parse::<i32>().is_ok() {
                        // valid
                    } else {
                        return Err(FormError {
                            field: Some("table"),
                            message: "must be 'auto', 'off', or a number".to_string(),
                        });
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn invite_peer() -> Self {
        Self {
            title: "Invite peer (one-time token)".to_owned(),
            fields: vec![
                Field {
                    label: "name",
                    value: String::new(),
                    masked: false,
                    placeholder: "e.g. laptop, phone",
                },
                Field {
                    label: "TTL (minutes)",
                    value: "15".to_owned(),
                    masked: false,
                    placeholder: "e.g. 15",
                },
                Field {
                    label: "pinned public line",
                    value: String::new(),
                    masked: false,
                    placeholder: "optional vallum1:... to bind token to one key",
                },
            ],
            focus: 0,
            cursor: 0,
            error: None,
            kind: FormKind::InvitePeer,
        }
    }

    #[must_use]
    pub fn rotate_peer(index: usize, peer: &PeerView) -> Self {
        Self {
            title: format!("Rotate key for {}", peer.name),
            fields: vec![Field {
                label: "new public line",
                value: String::new(),
                masked: false,
                placeholder: "vallum1:... replacement public line from device",
            }],
            focus: 0,
            cursor: 0,
            error: None,
            kind: FormKind::RotatePeer(index),
        }
    }

    #[must_use]
    pub fn export_bundle(device: &DeviceView) -> Self {
        Self {
            title: "Export client bundle".to_owned(),
            fields: vec![Field {
                label: "server endpoint",
                value: device.listen.clone(),
                masked: false,
                placeholder: "public IP/hostname:port (e.g. vpn.example.com:51820)",
            }],
            focus: 0,
            cursor: device.listen.chars().count(),
            error: None,
            kind: FormKind::ExportBundle,
        }
    }

    #[must_use]
    pub fn import_bundle(default_dir: &str) -> Self {
        let cursor = default_dir.chars().count();
        Self {
            title: "Import client bundle".to_owned(),
            fields: vec![
                Field {
                    label: "bundle file",
                    value: String::new(),
                    masked: false,
                    placeholder: "path to .vallum-bundle file (e.g. peer.vallum-bundle)",
                },
                Field {
                    label: "output dir",
                    value: default_dir.to_owned(),
                    masked: false,
                    placeholder: "destination config directory (e.g. /etc/vallum)",
                },
            ],
            focus: 0,
            cursor,
            error: None,
            kind: FormKind::ImportBundle,
        }
    }

    #[must_use]
    pub fn device(device: &DeviceView) -> Self {
        let port = device
            .listen
            .rsplit_once(':')
            .map_or_else(|| device.listen.clone(), |(_, port)| port.to_owned());
        let cursor = port.chars().count();
        Self {
            title: "Runtime device".to_owned(),
            fields: vec![
                Field {
                    label: "listen port",
                    value: port,
                    masked: false,
                    placeholder: "e.g. 51820",
                },
                Field {
                    label: "fwmark",
                    value: device.fwmark.to_string(),
                    masked: false,
                    placeholder: "e.g. 0 or 51820",
                },
            ],
            focus: 0,
            cursor,
            error: None,
            kind: FormKind::Device,
        }
    }

    #[must_use]
    pub fn edit_peer(index: usize, peer: &PeerView) -> Self {
        Self {
            title: format!("Edit {}", peer.name),
            fields: vec![
                Field {
                    label: "name",
                    value: peer.name.clone(),
                    masked: false,
                    placeholder: "e.g. laptop, phone",
                },
                Field {
                    label: "endpoint",
                    value: peer.endpoint.clone(),
                    masked: false,
                    placeholder: "e.g. 198.51.100.1:51820 (optional)",
                },
                Field {
                    label: "allowed IPs",
                    value: peer.allowed_ips.join(", "),
                    masked: false,
                    placeholder: "e.g. 10.7.0.2/32, 192.168.1.0/24",
                },
                Field {
                    label: "keepalive",
                    value: peer.keepalive.unwrap_or(0).to_string(),
                    masked: false,
                    placeholder: "seconds (0 = off, 25 for NAT)",
                },
                Field {
                    label: "PSK (hex, blank = keep)",
                    value: String::new(),
                    masked: true,
                    placeholder: "32-byte hex or leave blank",
                },
            ],
            focus: 0,
            cursor: peer.name.chars().count(),
            error: None,
            kind: FormKind::EditPeer(index),
        }
    }

    pub fn field(&self, label: &str) -> &str {
        self.fields
            .iter()
            .find(|field| field.label == label)
            .map_or("", |field| field.value.as_str())
    }
}

#[derive(Debug, Clone)]
pub enum ConfirmAction {
    RemovePeer { index: usize, label: String },
    FinalizePeer { name: String },
    ApplyConfig,
}

#[derive(Debug, Clone)]
pub struct Confirm {
    pub action: ConfirmAction,
    pub config: String,
}

#[derive(Debug, Clone)]
pub struct Toast {
    pub message: String,
    pub until: Instant,
}

/// The `:` command palette state.
#[derive(Debug, Default)]
pub struct PaletteState {
    pub input: String,
    pub selected: usize,
}

#[derive(Debug)]
pub struct App {
    pub interfaces: Vec<Interface>,
    pub selected: usize,
    pub peer_selected: usize,
    pub focus: Focus,
    pub view: View,
    pub form: Option<Form>,
    pub confirm: Option<Confirm>,
    pub toast: Option<Toast>,
    pub quit: bool,
    /// A ping running off the event loop; polled each tick.
    pub pending_ping: Option<std::sync::mpsc::Receiver<String>>,
    /// Dashboard key bindings (defaults plus `tui-keys.toml` overrides).
    pub keymap: super::keymap::KeyMap,
    /// The `:` command palette, when open.
    pub palette: Option<PaletteState>,
    pub logs: Vec<String>,
    pub trial_lines: Vec<String>,
    pub health_lines: Vec<String>,
    pub health_tone: super::health::Level,
    pub last_refresh: Instant,
    pub refresh_rate: u64,
    pub pending_key: Option<PathBuf>,
    pub qr: Option<QrState>,
    pub editor: Option<PathBuf>,
    pub editor_backup: Option<PathBuf>,
    pub logs_follow: bool,
    pub last_logs: Instant,
    /// The wall-clock second this frame is read as. Advanced with the state, and
    /// pinned by a snapshot so the published media regenerate byte for byte.
    pub now: u64,
    pub diff: Option<DiffView>,
    pub logs_scroll: usize,
    pub trial_scroll: usize,
    pub health_scroll: usize,
    pub diff_scroll: usize,
    pub help_scroll: usize,
    pub peer_filter: String,
    pub filtering: bool,
    pub sort_mode: SortMode,
    pub status_bar: StatusBar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusBar {
    /// No status bar
    Hidden,
    /// Status bar showing selection and filter
    Filter,
    /// Status bar showing selection and sort mode
    Selection,
    /// Status bar showing all info
    Full,
}

/// The host's wall-clock second.
///
/// The only clock read on the render path: [`App::now`] is set from it when the
/// state is refreshed, so every age in a frame is computed against one instant.
#[must_use]
pub fn wall_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

impl App {
    #[must_use]
    pub fn new(interfaces: Vec<Interface>) -> Self {
        Self {
            interfaces,
            selected: 0,
            peer_selected: 0,
            focus: Focus::Peers,
            view: View::Dashboard,
            form: None,
            confirm: None,
            toast: None,
            quit: false,
            pending_ping: None,
            keymap: super::keymap::KeyMap::default(),
            palette: None,
            logs: Vec::new(),
            trial_lines: Vec::new(),
            health_lines: Vec::new(),
            health_tone: super::health::Level::Warn,
            last_refresh: Instant::now() - Duration::from_secs(2),
            pending_key: None,
            qr: None,
            editor: None,
            editor_backup: None,
            logs_follow: false,
            last_logs: Instant::now(),
            now: wall_now(),
            diff: None,
            logs_scroll: 0,
            trial_scroll: 0,
            health_scroll: 0,
            diff_scroll: 0,
            help_scroll: 0,
            peer_filter: String::new(),
            filtering: false,
            sort_mode: SortMode::Natural,
            refresh_rate: 1000,
            status_bar: StatusBar::Filter,
        }
    }

    #[must_use]
    pub fn current(&self) -> Option<&Interface> {
        self.interfaces.get(self.selected)
    }

    pub fn current_mut(&mut self) -> Option<&mut Interface> {
        self.interfaces.get_mut(self.selected)
    }

    #[must_use]
    pub fn current_device(&self) -> Option<&DeviceView> {
        self.current()
            .and_then(|interface| interface.device.as_ref())
    }

    pub fn cycle_sort(&mut self) {
        self.sort_mode = self.sort_mode.next();
        self.peer_selected = 0;
        self.notify(format!("sort: {}", self.sort_mode.label()));
    }

    #[must_use]
    pub fn filtered_peers(&self) -> Vec<(usize, &PeerView)> {
        let Some(device) = self.current_device() else {
            return Vec::new();
        };
        let mut list: Vec<(usize, &PeerView)> = if self.peer_filter.is_empty() {
            device.peers.iter().enumerate().collect()
        } else {
            let filter = self.peer_filter.to_lowercase();
            device
                .peers
                .iter()
                .enumerate()
                .filter(|(_, peer)| {
                    peer.name.to_lowercase().contains(&filter)
                        || peer.fingerprint.to_lowercase().contains(&filter)
                        || peer.endpoint.to_lowercase().contains(&filter)
                        || peer
                            .allowed_ips
                            .iter()
                            .any(|ip| ip.to_lowercase().contains(&filter))
                        || Self::handshake_freshness_at(peer, self.now)
                            .label()
                            .to_lowercase()
                            .contains(&filter)
                        || (peer.preshared_key && "psk".contains(&filter))
                })
                .collect()
        };

        match self.sort_mode {
            SortMode::Natural => {}
            SortMode::RecentHandshake => {
                list.sort_by(|(_, a), (_, b)| {
                    let a_time = a.last_handshake.unwrap_or((0, 0));
                    let b_time = b.last_handshake.unwrap_or((0, 0));
                    b_time.cmp(&a_time)
                });
            }
            SortMode::Transfer => {
                list.sort_by(|(_, a), (_, b)| {
                    let a_total = a.rx_bytes.saturating_add(a.tx_bytes);
                    let b_total = b.rx_bytes.saturating_add(b.tx_bytes);
                    b_total.cmp(&a_total)
                });
            }
            SortMode::Name => {
                list.sort_by_key(|(_, a)| a.name.to_lowercase());
            }
        }

        list
    }

    #[must_use]
    pub fn current_peer(&self) -> Option<&PeerView> {
        let peers = self.filtered_peers();
        peers.get(self.peer_selected).map(|(_, peer)| *peer)
    }

    #[must_use]
    pub fn current_peer_original_index(&self) -> Option<usize> {
        let peers = self.filtered_peers();
        peers.get(self.peer_selected).map(|(orig, _)| *orig)
    }

    pub fn next_interface(&mut self) {
        if !self.interfaces.is_empty() {
            self.selected = (self.selected + 1) % self.interfaces.len();
            self.peer_selected = 0;
            self.peer_filter.clear();
            self.filtering = false;
        }
    }

    pub fn previous_interface(&mut self) {
        if !self.interfaces.is_empty() {
            self.selected = (self.selected + self.interfaces.len() - 1) % self.interfaces.len();
            self.peer_selected = 0;
            self.peer_filter.clear();
            self.filtering = false;
        }
    }

    pub fn next_peer(&mut self) {
        let count = self.filtered_peers().len();
        if count > 0 {
            self.peer_selected = (self.peer_selected + 1) % count;
        }
    }

    pub fn previous_peer(&mut self) {
        let count = self.filtered_peers().len();
        if count > 0 {
            self.peer_selected = (self.peer_selected + count - 1) % count;
        }
    }

    pub fn select_first_peer(&mut self) {
        self.peer_selected = 0;
    }

    pub fn select_last_peer(&mut self) {
        let count = self.filtered_peers().len();
        if count > 0 {
            self.peer_selected = count - 1;
        }
    }

    pub fn scroll_peers(&mut self, delta: isize) {
        let count = self.filtered_peers().len();
        if count > 0 {
            let current = self.peer_selected as isize;
            let next = (current + delta).clamp(0, (count - 1) as isize);
            self.peer_selected = next as usize;
        }
    }

    /// Deliver a finished background ping's toast, or re-arm the receiver.
    pub fn poll_ping(&mut self) {
        let Some(receiver) = self.pending_ping.take() else {
            return;
        };
        match receiver.try_recv() {
            Ok(message) => self.notify(message),
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                self.pending_ping = Some(receiver);
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.notify("ping worker exited without a result");
            }
        }
    }

    pub fn notify(&mut self, message: impl Into<String>) {
        self.toast = Some(Toast {
            message: message.into(),
            until: Instant::now() + Duration::from_secs(5),
        });
    }

    pub fn expire_toast(&mut self) {
        if self
            .toast
            .as_ref()
            .is_some_and(|toast| toast.until <= Instant::now())
        {
            self.toast = None;
        }
    }

    /// How long ago the peer's handshake was, at the caller's `now`.
    ///
    /// `now` is a parameter rather than a clock read so a frame drawn from a
    /// pinned clock (a snapshot) and a frame drawn from the host clock agree.
    #[must_use]
    pub fn handshake_age_at(peer: &PeerView, now: u64) -> String {
        let Some((sec, _)) = peer.last_handshake else {
            return "—".to_owned();
        };
        let age = now.saturating_sub(sec);
        if age < 60 {
            format!("{age}s")
        } else if age < 3600 {
            format!("{}m", age / 60)
        } else {
            format!("{}h", age / 3600)
        }
    }

    /// One-line diagnosis for the detail pane: every peer gets a verdict, not
    /// just the sick ones, so a healthy peer reads as healthy. The same words
    /// as the GUI console's peer verdict; the age renders in this surface's
    /// units (`handshake_age_at`), and the finalize hint names this surface's
    /// key. An idle tunnel goes quiet on its own — only the never and stale
    /// cases name a next step.
    #[must_use]
    pub fn peer_verdict_at(peer: &PeerView, now: u64) -> String {
        if peer.rotating {
            return "rotation in progress — finalize (f) once the far end uses the new key"
                .to_owned();
        }
        let freshness = Self::handshake_freshness_at(peer, now);
        match freshness {
            HandshakeFreshness::Never => {
                if peer.endpoint.is_empty() {
                    "no handshake yet — the far end has never connected; check it is running"
                        .to_owned()
                } else {
                    "no handshake yet — check the far end is running and reachable at this endpoint"
                        .to_owned()
                }
            }
            HandshakeFreshness::Recent => {
                format!(
                    "live — last handshake {} ago",
                    Self::handshake_age_at(peer, now)
                )
            }
            HandshakeFreshness::Aging => {
                format!(
                    "quiet — last handshake {} ago; idle tunnels go quiet, ping if it should be carrying traffic",
                    Self::handshake_age_at(peer, now)
                )
            }
            HandshakeFreshness::Old => {
                let keepalive = if peer.keepalive.is_none() {
                    ", and keepalive is set if it roams"
                } else {
                    ""
                };
                format!(
                    "stale — last handshake {} ago; check the far end is up, the endpoint is right{keepalive}",
                    Self::handshake_age_at(peer, now)
                )
            }
        }
    }

    #[must_use]
    pub fn handshake_freshness_at(peer: &PeerView, now: u64) -> HandshakeFreshness {
        let Some((sec, _)) = peer.last_handshake else {
            return HandshakeFreshness::Never;
        };
        let age = now.saturating_sub(sec);
        if age < 5 * 60 {
            HandshakeFreshness::Recent
        } else if age < 60 * 60 {
            HandshakeFreshness::Aging
        } else {
            HandshakeFreshness::Old
        }
    }
}
