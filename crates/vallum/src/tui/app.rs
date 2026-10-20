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
    pub epoch: u64,
    pub preshared_key: bool,
}

/// One device snapshot.
#[derive(Debug, Clone, Default)]
pub struct DeviceView {
    pub interface: String,
    pub listen: String,
    pub fwmark: u32,
    pub suite: String,
    pub suite_id: u16,
    pub fingerprint: String,
    pub public_line: String,
    pub addresses: Vec<String>,
    pub offload: bool,
    pub batching: bool,
    pub peers: Vec<PeerView>,
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
                PeerView {
                    name: peer_field(field::VALLUM_NAME),
                    fingerprint: peer_field(field::VALLUM_FINGERPRINT),
                    public_line: peer_field(field::VALLUM_PUBLIC_LINE),
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
                    epoch: peer_field(field::VALLUM_EPOCH).parse().unwrap_or(0),
                    preshared_key: !peer_field(field::PRESHARED_KEY).is_empty(),
                }
            })
            .collect();
        let suite = get(field::VALLUM_SUITE);
        let suite_id = u16::from_str_radix(suite.trim_start_matches("0x"), 16).unwrap_or(0);
        Self {
            interface: get(field::VALLUM_INTERFACE),
            listen: get(field::VALLUM_LISTEN),
            fwmark: get(field::FWMARK).parse().unwrap_or(0),
            suite,
            suite_id,
            fingerprint: get(field::VALLUM_FINGERPRINT),
            public_line: get(field::VALLUM_PUBLIC_LINE),
            addresses,
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
    EditPeer(usize),
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
            error: None,
            kind: FormKind::Interface,
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
    ApplyConfig,
}

#[derive(Debug, Clone)]
pub struct Confirm {
    pub action: ConfirmAction,
}

#[derive(Debug, Clone)]
pub struct Toast {
    pub message: String,
    pub until: Instant,
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
    pub logs: Vec<String>,
    pub last_refresh: Instant,
    pub pending_key: Option<PathBuf>,
    pub qr: Option<QrState>,
    pub editor: Option<PathBuf>,
    pub editor_backup: Option<PathBuf>,
    pub logs_follow: bool,
    pub last_logs: Instant,
    pub diff: Option<DiffView>,
    pub logs_scroll: usize,
    pub diff_scroll: usize,
    pub help_scroll: usize,
    pub peer_filter: String,
    pub filtering: bool,
    pub sort_mode: SortMode,
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
            logs: Vec::new(),
            last_refresh: Instant::now() - Duration::from_secs(2),
            pending_key: None,
            qr: None,
            editor: None,
            editor_backup: None,
            logs_follow: false,
            last_logs: Instant::now(),
            diff: None,
            logs_scroll: 0,
            diff_scroll: 0,
            help_scroll: 0,
            peer_filter: String::new(),
            filtering: false,
            sort_mode: SortMode::Natural,
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
                        || Self::handshake_freshness(peer)
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

    #[must_use]
    pub fn handshake_age(peer: &PeerView) -> String {
        let Some((sec, _)) = peer.last_handshake else {
            return "—".to_owned();
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        let age = now.saturating_sub(sec);
        if age < 60 {
            format!("{age}s")
        } else if age < 3600 {
            format!("{}m", age / 60)
        } else {
            format!("{}h", age / 3600)
        }
    }

    #[must_use]
    pub fn handshake_freshness(peer: &PeerView) -> HandshakeFreshness {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        Self::handshake_freshness_at(peer, now)
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
