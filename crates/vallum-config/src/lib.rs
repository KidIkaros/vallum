// SPDX-License-Identifier: Apache-2.0

//! The TOML schema, and nothing else.
//!
//! This crate is what `vallum-quick` needs: the types an operator edits, parsed
//! with `deny_unknown_fields`. Resolution — reading the key, expanding the
//! identity, validating prefixes, resolving privileges — lives in the daemon,
//! because it needs the crypto suite and the OS. Keeping the schema separate
//! means the admin tool does not depend on the daemon's TUN, socket, or
//! privilege layer.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use vallum_core::shaping::Machine;

mod migrate;
mod preset;
pub use migrate::{migrate_toml, MigrationError, MigrationReport, CURRENT_SCHEMA_VERSION};
pub use preset::ShapingPreset;

/// A parsed configuration file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Configuration schema version (omitted = legacy v0, current = 1).
    #[serde(default)]
    pub schema_version: Option<u32>,
    /// The interface and the daemon's own identity.
    pub interface: Interface,
    /// The peers, in `[[peer]]` order.
    #[serde(default, rename = "peer")]
    pub peers: Vec<PeerEntry>,
    /// Logging.
    #[serde(default)]
    pub log: Log,
    /// Options only `vallum-quick` uses. The daemon parses and ignores them.
    #[serde(default)]
    pub quick: Quick,

    /// See [`Enroll`].
    #[serde(default)]
    pub enroll: Enroll,
    /// See [`Account`].
    #[serde(default)]
    pub account: Account,
}

/// The `[quick]` table: OS-level work done by `vallum-quick`, never the daemon.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quick {
    /// DNS servers to install on the interface, through `resolvconf`.
    #[serde(default)]
    pub dns: Vec<String>,
    /// The routing domain to claim when the interface owns the resolvers.
    ///
    /// `~.` makes the tunnel the default route for every name, which is what
    /// stops a query from leaking to the local resolver on a full tunnel. A
    /// split tunnel usually wants no domain at all, so the field is optional.
    /// Ignored by the `resolvconf` backend, which has no such concept.
    #[serde(default)]
    pub dns_domain: Option<String>,
    /// `auto`, `off`, or a routing-table number.
    #[serde(default)]
    pub table: Option<String>,
    /// Commands run by `vallum-quick` before and after the interface.
    #[serde(default)]
    pub pre_up: Vec<String>,
    /// See [`Quick::pre_up`].
    #[serde(default)]
    pub post_up: Vec<String>,
    /// See [`Quick::pre_up`].
    #[serde(default)]
    pub pre_down: Vec<String>,
    /// See [`Quick::pre_up`].
    #[serde(default)]
    pub post_down: Vec<String>,
    /// What the egress guard enforces: `off`, `on`, or `auto`.
    ///
    /// `auto` turns the guard on for a full tunnel and off for a split tunnel.
    /// See ADR-0018: the guard exists so that a dead tunnel cannot leak, and it
    /// only makes sense where everything is supposed to be inside the tunnel.
    #[serde(default)]
    pub policy: Option<String>,
    /// What happens when the tunnel session fails: `block` (or `block-on-failure`) or `restore`.
    ///
    /// `block` (the default) replaces tunnel routes with blackhole routes so traffic cannot
    /// leak outside the tunnel when the session dies. `restore` withdraws the tunnel routes,
    /// returning traffic to the physical gateway (fail-open).
    #[serde(default)]
    pub failure_policy: Option<String>,
    /// Let traffic to private ranges leave outside the tunnel.
    ///
    /// Needed on a host that reaches a printer, a NAS, or a router admin page
    /// directly. Off by default: a LAN exception is still an exception.
    #[serde(default)]
    pub allow_lan: bool,
    /// Extra destinations that may leave outside the tunnel, as addresses or
    /// CIDR prefixes.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Tunnel only the processes launched into the member namespace (ADR-0023).
    ///
    /// When true, `vallum-quick attach` creates one shared mount+net namespace,
    /// binds a private `resolv.conf` naming `[quick] dns` inside it, and moves
    /// the tunnel device there. The host installs no routes and rewrites no
    /// resolver, so a process outside the namespace keeps exactly the
    /// networking it had. `vallum-quick app CONFIG NAME -- CMD` is the only way
    /// in. The daemon parses and ignores this: the namespace is host-level
    /// work, owned by `vallum-quick` alone.
    ///
    /// A full tunnel only — the namespace's default route is the tunnel device,
    /// so `allowed_ips` must claim `0.0.0.0/0` (or `::/0`), and the interface
    /// needs an address to carry inside; `attach` refuses anything else.
    /// Tunnel only the processes launched into the member namespace (ADR-0023).
    ///
    /// When true, `vallum-quick attach` creates one shared mount+net namespace,
    /// binds a private `resolv.conf` naming `[quick] dns` inside it, and moves
    /// the tunnel device there. The host installs no routes and rewrites no
    /// resolver, so a process outside the namespace keeps exactly the
    /// networking it had. `vallum-quick app CONFIG NAME -- CMD` is the only way
    /// in. The daemon parses and ignores this: the namespace is host-level
    /// work, owned by `vallum-quick` alone.
    ///
    /// A full tunnel only — the namespace's default route is the tunnel device,
    /// so `allowed_ips` must claim `0.0.0.0/0` (or `::/0`), and the interface
    /// needs an address to carry inside; `attach` refuses anything else.
    #[serde(default)]
    pub app_class: bool,
    /// Server-side DNS content-blocker categories (`ads`, `trackers`, `malware`,
    /// `adult`, `gambling`, `social`), encoded into the tunnel resolver IP
    /// `100.64.0.<bitmask>` (Mullvad §8.2 convention).
    #[serde(default)]
    pub content_blockers: Vec<String>,
    /// Run a local loopback DNS proxy (bound to `127.0.0.1:53`) instead of
    /// pointing the resolver straight at the tunnel's servers.
    ///
    /// `attach` starts the proxy as a child of `vallum-quick@<stem>.service`,
    /// points the resolver at `127.0.0.1`, and records the pid in
    /// `/run/vallum/<interface>.dns-proxy.pid`; `detach` and `systemctl stop`
    /// kill it. While the session is dead past the watchdog window the proxy
    /// answers `A` queries with the captive-portal address (`198.51.100.1`),
    /// so apps see a blocked network instead of a resolver that times out.
    /// Off by default: enabling it claims port 53 on loopback, which a host
    /// running its own resolver (dnsmasq, bind) must not spare.
    #[serde(default)]
    pub dns_proxy: bool,
    /// Optional entry-hop configuration path for 2-hop multihop (`Client -> Entry -> Exit`).
    ///
    /// When set, `vallum-quick up` / `attach` brings up the entry tunnel first
    /// (which should route `<exit_endpoint>/32`) before starting this exit
    /// tunnel, and `down` / `detach` tears them down in reverse order.
    #[serde(default)]
    pub via: Option<PathBuf>,
}

/// Resolve a `[quick] via` path relative to the exit config's parent directory.
#[must_use]
pub fn resolve_via_path(config_path: &Path, via: &Path) -> PathBuf {
    if via.is_absolute() {
        via.to_path_buf()
    } else {
        config_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .join(via)
    }
}

/// Server-side DNS content-blocker categories and their bit positions in the
/// fourth octet of `100.64.0.<bitmask>` (Mullvad §8.2 convention).
pub const CONTENT_BLOCKER_CATEGORIES: &[(&str, u8)] = &[
    ("ads", 1 << 0),
    ("trackers", 1 << 1),
    ("malware", 1 << 2),
    ("adult", 1 << 3),
    ("gambling", 1 << 4),
    ("social", 1 << 5),
];

/// Map a `[quick] content_blockers` category name to its bitmask bit, or `None`
/// if the category is unknown.
#[must_use]
pub fn content_blocker_bit(name: &str) -> Option<u8> {
    match name.trim().to_ascii_lowercase().as_str() {
        "ads" | "ad" => Some(1 << 0),
        "trackers" | "tracker" => Some(1 << 1),
        "malware" => Some(1 << 2),
        "adult" | "adult_content" => Some(1 << 3),
        "gambling" => Some(1 << 4),
        "social" | "social_media" => Some(1 << 5),
        _ => None,
    }
}

/// Encode `[quick] content_blockers` into the CGNAT magic resolver address
/// `100.64.0.<bitmask>`, returning `None` if no valid category is active.
#[must_use]
pub fn content_blocker_resolver_ip<S: AsRef<str>>(blockers: &[S]) -> Option<std::net::Ipv4Addr> {
    let mut mask = 0u8;
    for raw in blockers {
        if let Some(bit) = content_blocker_bit(raw.as_ref()) {
            mask |= bit;
        }
    }
    (mask != 0).then(|| std::net::Ipv4Addr::new(100, 64, 0, mask))
}

/// Decode a `100.64.0.<bitmask>` content-blocker resolver IP back into its
/// enabled category names (empty when `ip` is outside `100.64.0.1..=100.64.0.63`).
#[must_use]
pub fn decode_content_blocker_ip(ip: std::net::IpAddr) -> Vec<&'static str> {
    let std::net::IpAddr::V4(v4) = ip else {
        return Vec::new();
    };
    let octets = v4.octets();
    if octets[0] != 100 || octets[1] != 64 || octets[2] != 0 {
        return Vec::new();
    }
    let mask = octets[3];
    if mask == 0 || mask >= (1 << CONTENT_BLOCKER_CATEGORIES.len()) {
        return Vec::new();
    }
    CONTENT_BLOCKER_CATEGORIES
        .iter()
        .filter_map(|&(name, bit)| ((mask & bit) != 0).then_some(name))
        .collect()
}

impl Quick {
    /// Effective DNS servers to install inside the tunnel: prepends the
    /// `100.64.0.<bitmask>` content-blocker resolver when `[quick] content_blockers`
    /// is non-empty and not already present in [`Self::dns`].
    #[must_use]
    pub fn effective_dns_servers(&self) -> Vec<String> {
        let mut servers = Vec::with_capacity(self.dns.len() + 1);
        if let Some(blocker_ip) = content_blocker_resolver_ip(&self.content_blockers) {
            let formatted = blocker_ip.to_string();
            if !self.dns.iter().any(|entry| entry.trim() == formatted) {
                servers.push(formatted);
            }
        }
        for entry in &self.dns {
            let trimmed = entry.trim();
            if !trimmed.is_empty() && !servers.iter().any(|existing| existing == trimmed) {
                servers.push(trimmed.to_owned());
            }
        }
        servers
    }
}

/// The `[enroll]` table: the optional token-gated enrolment responder.
///
/// Off by default — a stock install answers nothing on this port.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enroll {
    /// Whether `vallum enroll-serve` may answer requests for this interface.
    #[serde(default)]
    pub enabled: bool,
    /// The UDP port to answer on. Defaults to the interface's `listen + 1`.
    #[serde(default)]
    pub port: Option<u16>,
    /// Optional TCP port for the HTTP/HTTPS API fronting enrolment listener
    /// (`POST /_vallum/enroll`).
    #[serde(default)]
    pub front_port: Option<u16>,
    /// Whether `front_port` terminates TLS 1.3 directly (`true`, default) or
    /// serves plain HTTP on `127.0.0.1` behind a local reverse proxy (`false`).
    #[serde(default)]
    pub front_tls: Option<bool>,
    /// Optional TLS SNI / certificate hostname used when `front_tls` is enabled.
    #[serde(default)]
    pub front_sni: Option<String>,
}

/// Which transport the tunnel's packets travel in.
///
/// UDP is the protocol; this exists for the one case UDP cannot serve, a path
/// that drops it. It is opt-in per interface because the fallback is strictly
/// worse: every packet costs a TCP header, everything on a connection travels in
/// one order, and a lost segment holds every packet behind it. See ADR-0026.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Carrier {
    /// Datagrams, one packet each. The default, and the only mode with measured
    /// path-MTU handling and roaming.
    #[default]
    Udp,
    /// Zero-overhead UDP header obfuscation (LWO v2): masks the first 8 header
    /// bytes using a SplitMix64 keystream keyed by the packet's own trailing bytes.
    Lwo,
    /// Happy-eyeballs carrier racer: begins on LWO-obfuscated UDP, staggers a
    /// TCP connection after 500ms if the peer has not replied, and locks onto
    /// UDP for 15s when UDP answers.
    Auto,
    /// Frames inside TCP, one connection per peer.
    ///
    /// A peer cannot roam under this carrier — the connection is the endpoint —
    /// and every packet is two bytes larger plus the header difference. It
    /// exists so a network that drops UDP has something to fall back to, not as
    /// an equal choice.
    Tcp,
    /// Shadowsocks-style AEAD-obfuscated UDP datagrams (`[24B nonce || AEAD]`).
    ///
    /// Wraps every packet in fresh-nonce committing AEAD ciphertext so wire
    /// traffic carries no plaintext Vallum header or fixed magic bytes.
    Ss,
    /// TLS 1.3 stream carrier over TCP.
    ///
    /// Wraps framed Vallum packets inside a genuine TLS 1.3 session so DPI sees
    /// standard TLS handshake + ApplicationData records.
    Tls,
    /// QUIC v1 DATAGRAM (RFC 9221) carrier over UDP.
    ///
    /// Carries Vallum packets as unreliable QUIC datagrams inside a real QUIC
    /// encrypted connection without TCP head-of-line blocking.
    Quic,
}

impl Carrier {
    /// The name as it appears in a config.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Carrier::Udp => "udp",
            Carrier::Lwo => "lwo",
            Carrier::Auto => "auto",
            Carrier::Tcp => "tcp",
            Carrier::Ss => "ss",
            Carrier::Tls => "tls",
            Carrier::Quic => "quic",
        }
    }

    /// The primary transport protocol name, for firewall rules and probes.
    ///
    /// Same spellings as `/etc/services` and `ufw`, which is what an operator
    /// types after the port.
    #[must_use]
    pub fn protocol(self) -> &'static str {
        match self {
            Carrier::Udp | Carrier::Lwo | Carrier::Auto | Carrier::Ss | Carrier::Quic => "udp",
            Carrier::Tcp | Carrier::Tls => "tcp",
        }
    }

    /// Whether this carrier uses UDP datagrams as its primary or raced path.
    #[must_use]
    pub fn uses_udp(self) -> bool {
        matches!(
            self,
            Carrier::Udp | Carrier::Lwo | Carrier::Auto | Carrier::Ss | Carrier::Quic
        )
    }

    /// Whether this carrier uses TCP streams (exclusively or as a staggered race).
    #[must_use]
    pub fn uses_tcp(self) -> bool {
        matches!(self, Carrier::Tcp | Carrier::Auto | Carrier::Tls)
    }

    /// Whether this carrier uses an outer TLS 1.3 handshake (`tls` or `quic`).
    #[must_use]
    pub fn uses_tls(self) -> bool {
        matches!(self, Carrier::Tls | Carrier::Quic)
    }

    /// Whether the endpoint can be probed with a TCP connection attempt.
    ///
    /// A TCP listener answers a dial, so a refusal is information. UDP has no
    /// connection: a closed port is an ICMP message that may never come back,
    /// and a filtered one is silence either way.
    #[must_use]
    pub fn is_probeable(self) -> bool {
        matches!(self, Carrier::Tcp | Carrier::Auto | Carrier::Tls)
    }
}

/// The `[interface]` table.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interface {
    /// The kernel interface name. `vallum0` if absent.
    #[serde(default)]
    pub name: Option<String>,
    /// The private-key file.
    ///
    /// A relative path is resolved against the directory holding this config, not
    /// against the process's working directory: a config names its own files, so
    /// `-c /etc/vallum/vallum.toml` finds `/etc/vallum/private.key` from
    /// anywhere. An absolute path is used as written.
    pub private_key: PathBuf,
    /// The address and prefix to assign the interface.
    ///
    /// A single-address shorthand for [`Interface::addresses`]; both may be
    /// used. A dual-stack tunnel names one address of each family in
    /// `addresses`.
    #[serde(default)]
    pub address: Option<String>,
    /// Addresses to assign to the interface, of either or both families.
    ///
    /// Every entry is assigned over netlink after the device exists, so a
    /// dual-stack tunnel is one config:
    ///
    /// ```toml
    /// addresses = ["10.7.0.1/24", "fd00:7::1/64"]
    /// ```
    ///
    /// IPv4-mapped IPv6 prefixes (`::ffff:10.0.0.1/128`) are refused: they do
    /// not match a v4 source in `allowed_ips`, so they are a trap rather than a
    /// shorthand.
    #[serde(default)]
    pub addresses: Vec<String>,
    /// The inner MTU.
    #[serde(default)]
    pub mtu: Option<u16>,
    /// The address to listen on, for both transports.
    #[serde(default)]
    pub listen: Option<String>,
    /// The carrier: `udp` (default) or `tcp`.
    ///
    /// ```toml
    /// carrier = "tcp"
    /// ```
    ///
    /// `tcp` is for a path that drops UDP. It carries the same packets, framed,
    /// over one connection per peer, and costs two bytes of framing plus one
    /// order: a lost segment delays everything behind it. There is no automatic
    /// fallback in either direction — a `tcp` interface talks to a `tcp` peer, so
    /// both ends of a pair name it.
    #[serde(default)]
    pub carrier: Option<Carrier>,
    /// Whether this node relays flows for others — the gateway role.
    ///
    /// A server behind the forwarding rules `vallum server init` installs
    /// receives a packet destined to a peer, and the reply that comes back
    /// through conntrack re-enters the tunnel with a source that belongs to
    /// nobody here: an internet address. With forwarding off, the egress
    /// source check refuses such a reply and every forwarded TCP and UDP flow
    /// dies while ping still works — measured live, `verify-remote.sh`, where
    /// a relayed reply from 1.1.1.1 was dropped before it was ever sealed.
    /// With forwarding on, such a packet is relayed; the far side still
    /// decides by *its* `allowed_ips` whether to accept the source, so this
    /// does not let a host claim another's address — it only moves the
    /// refusal from a place where a relay looks like a claim to one where it
    /// is. A link-local source is refused either way: it means nothing across
    /// a link. See ADR-0020.
    #[serde(default)]
    pub forward: Option<bool>,
    /// A Unix socket to serve the control UAPI on.
    ///
    /// Absent means no control plane. The socket is `0600`; a relative path is
    /// resolved against the config, like the key file.
    #[serde(default)]
    pub control: Option<PathBuf>,
    /// A socket mark for policy routing, as `SO_MARK`. `0` means unset.
    ///
    /// Requires `CAP_NET_ADMIN`; it is applied before the privilege drop.
    #[serde(default)]
    pub fwmark: Option<u32>,
    /// The outer path's MTU. Defaults to 1500.
    ///
    /// This is how a narrower path — PPPoE at 1492, an IPsec tunnel at 1400 — is
    /// supported: every datagram is cut to `outer_mtu - 48` so the kernel is
    /// never asked to fragment. It does **not** discover anything; the operator
    /// states the path. Values above 1500 are refused, because the protocol's
    /// parse cap and the segmentation budget are both built on
    /// [`MAX_OUTER_DATAGRAM`].
    #[serde(default)]
    pub outer_mtu: Option<u16>,
    /// Optional pre-shared obfuscation key for `carrier = "ss"`.
    #[serde(default)]
    pub ss_psk: Option<String>,
    /// The user to become after the interface and socket are open.
    ///
    /// Absent means "keep the privileges the process started with", which is
    /// what every deployment before this field did.
    #[serde(default)]
    pub user: Option<String>,
    /// The group to become. Defaults to the user's primary group.
    ///
    /// A group without a user is legal — it drops the group id only — and is
    /// warned about, because it is rarely what an operator means.
    #[serde(default)]
    pub group: Option<String>,
    /// What the syscall filter does with a syscall the allow-list does not name.
    ///
    /// `log` installs the filter and asks the kernel to log — and allow —
    /// anything the list is missing; `enforce` kills the process instead.
    /// The default is `enforce` since 1.6.5: the list was derived by trace,
    /// held in CI against the binary on both carriers, and emptied by a real
    /// auditd window across the full exercise (ADR-0028 steps 1–4).
    /// `log` remains for debugging — a config that names it runs with the
    /// property off, and says so at startup.
    ///
    /// Only meaningful with `user` or `group`: the filter is installed as part
    /// of the privilege drop, and setting this without one is refused rather
    /// than ignored, because a security field the daemon quietly does not apply
    /// is worse than no field at all.
    #[serde(default)]
    pub seccomp: Option<Seccomp>,
    /// The CA's `vallum1:` public line, or the bare hex of its signing key.
    ///
    /// When set, every peer's identity document must verify against it. When
    /// absent, a document must be self-signed: a key binding with a window, not
    /// an authorisation.
    #[serde(default)]
    pub identity_issuer: Option<String>,
    /// The address clients should dial, as `host:port`.
    ///
    /// The daemon does not read this: a responder's own reachable address is a
    /// property of its peers' configs, not its interface. It exists so
    /// `vallum server init` can remember the `--endpoint` it was given and
    /// `vallum peer add` can put the same address in every client bundle,
    /// instead of guessing a source route that is often a private address.
    #[serde(default)]
    pub public_endpoint: Option<String>,
    /// Optional HTTP/1.1 `Host` header value for outbound `carrier = "tcp"` or
    /// `carrier = "auto"` dial preambles (`GET /_vallum HTTP/1.1` + `Upgrade: vallum`).
    #[serde(default)]
    pub tcp_upgrade: Option<String>,
    /// Optional TLS SNI hostname sent in `ClientHello` for `carrier = "tls"`
    /// and `carrier = "quic"` (defaults to `"localhost"` when unset).
    #[serde(default)]
    pub tls_sni: Option<String>,
}

/// `interface.seccomp`: what the syscall filter does with a syscall it does not
/// name. See ADR-0028.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Seccomp {
    /// Install the filter, log what it would have killed, and let it through.
    Log,
    /// Install the filter and kill the process on a syscall it does not name.
    Enforce,
}

/// One `[[peer]]` table.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerEntry {
    /// A name for logs.
    pub name: String,
    /// The peer's public line. See the `vallum1:` public line.
    ///
    /// Exactly one of `public_key`, `identity` or `identity_file` names the
    /// peer's identity.
    #[serde(default)]
    pub public_key: Option<String>,
    /// A CA-issued (or self-signed) identity document, hex-encoded.
    ///
    /// The document binds the peer's KEM key, its signing key, a label and a
    /// validity window, and replaces `public_key`. Whether it must be signed by
    /// `[interface] identity_issuer` or be self-signed is the interface's
    /// policy, not the document's.
    #[serde(default)]
    pub identity: Option<String>,
    /// A file holding the identity document, relative to the config.
    #[serde(default)]
    pub identity_file: Option<PathBuf>,
    /// The identity this peer used before a rotation.
    ///
    /// Accepted alongside the current one, so `peer rotate` can install the new
    /// key before the device has it and `peer finalize` can retire the old one.
    #[serde(default)]
    pub previous_public_key: Option<String>,
    /// A previous identity document, hex-encoded.
    #[serde(default)]
    pub previous_identity: Option<String>,
    /// A file holding the previous document.
    #[serde(default)]
    pub previous_identity_file: Option<PathBuf>,
    /// An address to dial, or absent to roam from the peer's handshakes.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// The addresses this peer may use.
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    /// Send an empty packet every this many seconds, even when idle, to hold a
    /// NAT binding open for a peer that has nothing to send. Omitted means off;
    /// `0` is refused rather than read as "off", because a field the operator
    /// wrote and the daemon ignores is how a security setting goes missing.
    #[serde(default)]
    pub persistent_keepalive: Option<u16>,
    /// Refuse a handshake whose source is not `endpoint`.
    ///
    /// Roaming is normally desirable: a laptop changes networks and the peer
    /// follows. It is also the one place an active man in the middle can
    /// redirect a tunnel (WireGuard calls this "roaming mischief"). A pinned
    /// peer does not roam, and a handshake from any other address is refused
    /// rather than accepted. Requires `endpoint`.
    #[serde(default)]
    pub pin_endpoint: bool,
    /// A 32-byte preshared key as 64 hex characters, mixed into the handshake.
    ///
    /// The secret sits in the config file, so prefer [`Self::preshared_key_file`]
    /// unless the file's own permissions already protect it. Both fields set is
    /// an error rather than a precedence rule.
    #[serde(default)]
    pub preshared_key: Option<String>,
    /// A file holding the PSK as 64 hex characters.
    ///
    /// The same permission policy as the private key applies: group/world bits
    /// are refused unless `--allow-insecure-key-permissions` is passed.
    #[serde(default)]
    pub preshared_key_file: Option<PathBuf>,
    /// Traffic-analysis shaping machines for this peer's tunnel.
    #[serde(default)]
    pub shaping: Vec<ShapingSpec>,
}

/// One entry in a peer's `shaping` list.
///
/// The shapes are named ones rather than raw machines; a raw state machine is
/// deliberately not expressible from a config file, because a config file that
/// can describe arbitrary machines is a config file that can describe a flood.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ShapingSpec {
    /// Pad every packet to `size` bytes of sealed plaintext.
    PadToSize {
        /// The target.
        size: u16,
    },
    /// Hold outgoing packets for `interval_ms` after each one.
    MinInterval {
        /// The hold, in milliseconds.
        interval_ms: u64,
    },
    /// Inject one padding packet after every `interval_ms` of silence.
    ///
    /// The constant-rate floor: the tunnel says something even when it has
    /// nothing to say, so silence stops being the cheapest thing to classify.
    /// Every packet that crosses the tunnel restarts the interval, so this only
    /// fills gaps and never adds to traffic that is already moving.
    ///
    /// It is off unless configured, and it costs bandwidth continuously —
    /// including at 3 a.m. with nobody using the tunnel. `interval_ms` below
    /// 100 ms is clamped up to 100 ms, which is the safety rail: the floor is
    /// the one shape whose rate is limited only by its own parameter. For the
    /// measured prices, see `docs/proof/traffic-shaping.md`; for worked examples,
    /// `docs/shaping.md`.
    ConstantRateFloor {
        /// The silence to allow before injecting, in milliseconds.
        interval_ms: u64,
        /// The sealed-plaintext length of each injected packet.
        size: u16,
        /// How far each drawn interval may wander from `interval_ms`.
        ///
        /// Zero — the default — is a metronome, which is a signature of its own.
        /// With noise, every interval is drawn from `interval_ms - jitter_ms`,
        /// `interval_ms` and `interval_ms + jitter_ms` (weights 1, 2, 1), so the
        /// mean rate is unchanged and the gaps are no longer a constant. Clamped
        /// to half the interval, so no draw can approach zero.
        #[serde(default)]
        jitter_ms: u64,
    },
    /// Normalise each window of outgoing packets up to the next power of two.
    ///
    /// Volume is the channel size and timing leave open: nine packets and eleven
    /// are different flows even when every packet is the same length. A window
    /// closes on a pause of `window_ms` or on a run of `max_packets`, and closing
    /// injects padding until the count is a power of two.
    ///
    /// `max_packets` is clamped to 32 and rounded down to a power of two, so the
    /// configured value bounds the cost rather than describing a target, and
    /// `window_ms` is clamped up to 1 000 ms. For the measured prices, see
    /// `docs/proof/traffic-shaping.md`.
    VolumePadding {
        /// The pause that ends a window, in milliseconds.
        window_ms: u64,
        /// The most packets a window may contain.
        max_packets: u32,
        /// The sealed-plaintext length of each injected packet.
        size: u16,
    },
    /// Inject a bounded burst of padding at the front of the peer's life.
    ///
    /// A flow's opening seconds are its most revealing, so this spends a fixed
    /// number of padding packets there and then stops for good: one per normal
    /// packet while the burst lasts, or one per `interval_ms` of silence if the
    /// front is quiet. It is the one shape whose cost is a one-off rather than a
    /// rate, which is why it is the cheapest thing to leave enabled.
    ///
    /// `count` is clamped to 60 packets and `interval_ms` to 1 000 ms, so the
    /// burst cannot be turned into a slow floor by configuration. For the
    /// measured prices, see `docs/proof/traffic-shaping.md`.
    FrontPadding {
        /// How many padding packets the burst may contain.
        count: u32,
        /// The silence to fill between them, in milliseconds.
        interval_ms: u64,
        /// The sealed-plaintext length of each injected packet.
        size: u16,
    },
    /// Normalise each window's **bytes** to a power of two.
    ///
    /// The byte-level form of [`Self::VolumePadding`]: every packet is padded to
    /// `size`, so a window's bytes are exactly its packet count times `size` and
    /// a power-of-two byte target is a power-of-two packet count. Packets larger
    /// than `size` cannot be padded down and count as more than the window
    /// accounts for, so choose a target above the largest payload.
    ///
    /// `window_bytes` is rounded down to a whole number of packets and clamped to
    /// 32 of them, and `window_ms` up to 1 000 ms. For the measured prices, see
    /// `docs/proof/traffic-shaping.md`.
    ByteVolumePadding {
        /// The pause that ends a window, in milliseconds.
        window_ms: u64,
        /// The window's target volume, in sealed plaintext bytes.
        window_bytes: u32,
        /// The size every packet in the window is padded to.
        size: u16,
    },
    /// Answer received packets with padding, probabilistically.
    RespondWithPadding {
        /// The payload size of an injected packet.
        size: u16,
        /// Weight of the "inject" branch against one unit of "pass".
        injections: u32,
        /// The most injections before the machine goes inert.
        cap: u32,
    },
}

impl ShapingSpec {
    /// The machine this describes.
    #[must_use]
    pub fn machine(&self) -> Machine {
        match *self {
            Self::PadToSize { size } => Machine::pad_to_size(size),
            Self::MinInterval { interval_ms } => Machine::min_interval(interval_ms),
            Self::ConstantRateFloor {
                interval_ms,
                size,
                jitter_ms,
            } => {
                if jitter_ms == 0 {
                    Machine::constant_rate_floor(interval_ms, size)
                } else {
                    Machine::jittered_floor(interval_ms, jitter_ms, size)
                }
            }
            Self::VolumePadding {
                window_ms,
                max_packets,
                size,
            } => Machine::volume_padding(window_ms, max_packets, size),
            Self::ByteVolumePadding {
                window_ms,
                window_bytes,
                size,
            } => Machine::byte_volume_padding(window_ms, window_bytes, size),
            Self::FrontPadding {
                count,
                interval_ms,
                size,
            } => Machine::front_padding(count, interval_ms, size),
            Self::RespondWithPadding {
                size,
                injections,
                cap,
            } => Machine::respond_with_padding(size, injections, cap),
        }
    }
}

/// The `[account]` table: the desk's bearer credential, recorded at join.
///
/// `vallum join` writes this when the enrolment carried a desk account
/// (`VALLUM_ACCOUNT`); the daemon ignores it — accounts are the desk's
/// concern (ADR-0045). `deny_unknown_fields` means a binary older than
/// this field refuses a config that carries it: that is the documented
/// compatibility cost, and it is why the join only writes the table when
/// a token was actually supplied.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Account {
    /// The account number — the desk's 32-hex bearer token.
    pub token: Option<String>,
    /// The desk origin (`https://host[:port]`) the account lives on,
    /// recorded at join from the URI's `desk=` param (ADR-0046). `vallum
    /// account` shows it before calling, so the user can see where the
    /// token goes. Absent in configs written before the field existed.
    pub endpoint: Option<String>,
}

/// The `[log]` table.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Log {
    /// `error`, `warn`, `info`, or `debug`.
    pub level: String,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            level: "info".to_owned(),
        }
    }
}

impl Config {
    /// Read and parse a configuration file.
    ///
    /// # Errors
    ///
    /// If the file cannot be read, or does not parse.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let config: Self = toml::from_str(&text).map_err(|source| ConfigError::Toml {
            path: path.to_path_buf(),
            source,
        })?;
        config.validate(path)?;
        Ok(config)
    }

    /// [`load`] with the settings migration chain ([`migrate_toml`]) and
    /// [`with_local_fwmark`] applied first: legacy unversioned (`v0`) configs
    /// upgrade cleanly in memory, while configs from a newer schema version
    /// are refused explicitly.
    pub fn load_normalized(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let migrated = match migrate_toml(&text) {
            Ok((out, _)) => out,
            Err(MigrationError::Parse(_)) => text,
            Err(err) => {
                return Err(ConfigError::Invalid {
                    path: path.to_path_buf(),
                    message: err.to_string(),
                });
            }
        };
        let config: Self =
            toml::from_str(&with_local_fwmark(&migrated)).map_err(|source| ConfigError::Toml {
                path: path.to_path_buf(),
                source,
            })?;
        config.validate(path)?;
        Ok(config)
    }

    /// Semantic checks TOML cannot express.
    fn validate(&self, path: &Path) -> Result<(), ConfigError> {
        if let Some(version) = self.schema_version {
            if version > CURRENT_SCHEMA_VERSION {
                return Err(ConfigError::Invalid {
                    path: path.to_path_buf(),
                    message: MigrationError::UnsupportedFutureVersion {
                        found: version,
                        supported: CURRENT_SCHEMA_VERSION,
                    }
                    .to_string(),
                });
            }
        }
        if let Some(name) = &self.interface.name {
            validate_interface_name(name).map_err(|message| ConfigError::Invalid {
                path: path.to_path_buf(),
                message,
            })?;
        }
        if let Some(host) = &self.interface.tcp_upgrade {
            validate_tcp_upgrade_host(host).map_err(|message| ConfigError::Invalid {
                path: path.to_path_buf(),
                message,
            })?;
        }
        if let Some(sni) = &self.interface.tls_sni {
            validate_tls_sni(sni).map_err(|message| ConfigError::Invalid {
                path: path.to_path_buf(),
                message,
            })?;
        }
        if self.enroll.front_port == Some(0) {
            return Err(ConfigError::Invalid {
                path: path.to_path_buf(),
                message: "[enroll] front_port cannot be 0".to_owned(),
            });
        }
        if let Some(sni) = &self.enroll.front_sni {
            validate_tls_sni(sni).map_err(|message| ConfigError::Invalid {
                path: path.to_path_buf(),
                message,
            })?;
        }
        if let Some(via) = &self.quick.via {
            if via.as_os_str().is_empty() {
                return Err(ConfigError::Invalid {
                    path: path.to_path_buf(),
                    message: "[quick] via cannot be empty".to_owned(),
                });
            }
            if self.quick.app_class {
                return Err(ConfigError::Invalid {
                    path: path.to_path_buf(),
                    message: "cannot combine [quick] via with app_class = true".to_owned(),
                });
            }
        }
        for raw in &self.quick.content_blockers {
            if content_blocker_bit(raw).is_none() {
                return Err(ConfigError::Invalid {
                    path: path.to_path_buf(),
                    message: format!(
                        "unknown [quick] content_blockers category `{raw}` \
                         (expected ads, trackers, malware, adult, gambling, or social)"
                    ),
                });
            }
        }
        Ok(())
    }
}

/// Validate a TLS SNI hostname for `[interface] tls_sni`.
pub fn validate_tls_sni(sni: &str) -> Result<(), String> {
    if sni.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("[interface] tls_sni must not contain control characters".to_owned());
    }
    let trimmed = sni.trim();
    if trimmed.is_empty() {
        return Err("[interface] tls_sni must not be empty".to_owned());
    }
    if !trimmed.is_ascii() || trimmed.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err("[interface] tls_sni must be an ASCII hostname without whitespace".to_owned());
    }
    if trimmed.contains('/') || trimmed.contains(':') {
        return Err(
            "[interface] tls_sni must be a bare hostname without scheme, port, or path".to_owned(),
        );
    }
    Ok(())
}

/// Validate an HTTP/1.1 `Host` header value for `[interface] tcp_upgrade`.
pub fn validate_tcp_upgrade_host(host: &str) -> Result<(), String> {
    if host.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(
            "[interface] tcp_upgrade must not contain control characters or newlines".to_owned(),
        );
    }
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Err("[interface] tcp_upgrade must not be empty".to_owned());
    }
    if trimmed
        .bytes()
        .any(|b| b <= 0x20 || b == 0x7f || !b.is_ascii())
    {
        return Err(
            "[interface] tcp_upgrade must be an ASCII host or host:port without whitespace"
                .to_owned(),
        );
    }
    if trimmed.contains(['/', '\\', '?', '#', '@'])
        || trimmed.starts_with(':')
        || trimmed.ends_with(':')
    {
        return Err(
            "[interface] tcp_upgrade must be a host or host:port, not a URL, path, or bare port"
                .to_owned(),
        );
    }
    Ok(())
}

/// The kernel's own limits on an interface name, checked here because the name
/// reaches file paths (`/run/vallum/<name>.…`) before the kernel ever sees it.
///
/// Without this, `name = "../.."` makes a root process create files outside
/// `/run/vallum` (security-redteam-round2.md R2-5).
pub fn validate_interface_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("interface name is empty".to_owned());
    }
    if name.len() > 15 {
        return Err(format!(
            "interface name `{name}` is {} bytes; the kernel allows 15",
            name.len()
        ));
    }
    if name == "." || name == ".." {
        return Err(format!("interface name `{name}` is a directory reference"));
    }
    if name.starts_with('-') {
        return Err(format!(
            "interface name `{name}` starts with `-`, which `ip` would read as a flag"
        ));
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '.'))
    {
        return Err(format!(
            "interface name `{name}` contains `{bad}`; only letters, digits, `_`, `-` and `.` are allowed"
        ));
    }
    Ok(())
}

/// A configuration file that could not be read or parsed.
#[derive(Debug)]
pub enum ConfigError {
    /// Parsed, but a value cannot be used.
    Invalid { path: PathBuf, message: String },
    /// The file could not be read.
    Io {
        /// The path involved.
        path: PathBuf,
        /// The underlying failure.
        source: std::io::Error,
    },
    /// The TOML did not parse.
    Toml {
        /// The path involved.
        path: PathBuf,
        /// The parse failure.
        source: toml::de::Error,
    },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "read config `{}`: {source}", path.display())
            }
            Self::Toml { path, source } => {
                // `toml::de::Error` quotes the offending line, which for a
                // misplaced `preshared_key` is the secret itself — and this
                // string is what lands in `vallum doctor`, `vallum status` and
                // every support bundle, i.e. the text users paste into issues.
                // Redact before it is formatted, not after someone notices.
                write!(
                    f,
                    "parse config `{}`: {}",
                    path.display(),
                    redact_secrets(&source.to_string())
                )
            }
            Self::Invalid { path, message } => {
                write!(f, "config `{}`: {message}", path.display())
            }
        }
    }
}

/// Field names whose values must never appear in an error message.
///
/// Only the fields that hold a *secret* — `private_key` holds a path, and the
/// path is the useful half of a config diagnosis, so it is deliberately absent.
const SECRET_FIELDS: [&str; 3] = ["preshared_key", "ss_psk", "token"];

/// Replace the value on any line that assigns one of [`SECRET_FIELDS`].
///
/// Line-oriented rather than a search for the secret's shape: a 64-hex pattern
/// would also catch a public key's fingerprint, and missing one secret is worse
/// than redacting one extra line. The key name is the only stable marker.
pub fn redact_secrets(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let bare = line.trim_start();
        // The key is the last identifier before `=`, not the whole left-hand
        // side: a `toml` parse error prefixes the line with a `6 | ` gutter, and
        // matching on the full left-hand side is how the first attempt at this
        // silently redacted nothing.
        let ident = bare.split_once('=').map(|(left, _)| {
            left.trim()
                .rsplit(|c: char| c == '|' || c.is_whitespace())
                .next()
                .unwrap_or("")
                .trim_matches('"')
        });
        if !ident.is_some_and(|key| SECRET_FIELDS.contains(&key)) {
            out.push_str(line);
            continue;
        }
        // Keep the layout the parse error describes: the gutter, the key, and
        // the caret lines that follow are what make the message readable.
        let (head, _) = bare.split_once('=').unwrap_or((bare, ""));
        out.push_str(&line[..line.len() - bare.len()]);
        out.push_str(head.trim_end());
        out.push_str(" = \"<redacted>\"");
        if line.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Toml { source, .. } => Some(source),
            Self::Invalid { .. } => None,
        }
    }
}

/// The policy-routing mark a full-tunnel client uses so its own packets can
/// escape the policy table to the real gateway. A local routing detail — the
/// server has no business dictating it — so it has a fixed default.
pub const DEFAULT_FWMARK: u32 = 51820;

/// The directory every control socket lives in.
///
/// A machine resource, not any one service's private state: created by
/// `tmpfiles.d` (`/usr/lib/tmpfiles.d/vallum.conf`) so that it exists before any
/// unit starts and survives any unit stopping. One daemon's exit must never
/// remove another's socket — see ADR-0017. The path is spelled here once
/// because the daemon, `vallum-quick`, the TUI and `uninstall` all need to
/// agree on it.
pub const RUNTIME_DIR: &str = "/run/vallum";

/// The runtime directory, for callers that need a `&Path`.
#[must_use]
pub fn runtime_dir() -> &'static Path {
    Path::new(RUNTIME_DIR)
}

/// The control socket for `interface`, e.g. `/run/vallum/vallum0.sock`.
#[must_use]
pub fn socket_path(interface: &str) -> PathBuf {
    runtime_dir().join(format!("{interface}.sock"))
}

/// Point a client config at the key file that actually sits beside it.
///
/// The server names the key by the PEER's name (`private_key = "laptop.key"`),
/// which is a coupling the client cannot satisfy if the operator named the
/// keyfile anything else - and the key never leaves the device, so the client
/// is the only party that can decide what the file is called. This is the same
/// kind of local rewrite as [`with_local_fwmark`]: a detail of THIS machine,
/// applied on this machine.
#[must_use]
pub fn with_local_private_key(config_text: &str, key_name: &str) -> String {
    let Ok(config) = toml::from_str::<Config>(config_text) else {
        return config_text.to_owned();
    };
    if config.interface.private_key.as_os_str() == key_name {
        return config_text.to_owned();
    }
    let mut out = String::with_capacity(config_text.len() + key_name.len() + 8);
    let mut placed = false;
    let mut in_interface = false;
    for line in config_text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_interface = trimmed == "[interface]";
        }
        if in_interface && !placed && trimmed.starts_with("private_key") {
            out.push_str(&format!("private_key = \"{key_name}\"\n"));
            placed = true;
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    if !placed {
        return config_text.to_owned();
    }
    out
}

/// Complete a full-tunnel client config for this machine: if a peer's
/// `allowed_ips` covers `0.0.0.0/0` or `::/0`, `vallum-quick` requires
/// `[interface] fwmark` or it refuses to attach (an unmarked full tunnel
/// would route the daemon's own packets into the dead tunnel). Configs minted
/// before the field existed lack it; the mark is local to the machine that
/// runs the tunnel, so the client fills it in rather than refusing the
/// server's answer. Text that does not parse is returned untouched — the
/// caller's own parse will report it.
#[must_use]
pub fn with_local_fwmark(config_text: &str) -> String {
    let Ok(config) = toml::from_str::<Config>(config_text) else {
        return config_text.to_owned();
    };
    if config.interface.fwmark.is_some() {
        return config_text.to_owned();
    }
    let full_tunnel = config.peers.iter().any(|peer| {
        peer.allowed_ips
            .iter()
            .any(|ip| ip == "0.0.0.0/0" || ip == "::/0")
    });
    if !full_tunnel {
        return config_text.to_owned();
    }
    let mut out = String::with_capacity(config_text.len() + 24);
    let mut placed = false;
    for line in config_text.lines() {
        out.push_str(line);
        out.push('\n');
        if !placed && line.trim() == "[interface]" {
            out.push_str(&format!("fwmark = {DEFAULT_FWMARK}\n"));
            placed = true;
        }
    }
    if placed {
        out
    } else {
        config_text.to_owned()
    }
}

/// Record the desk's account number in `config_text` as `[account] token`.
///
/// The token is the bearer credential for the desk's account surface; it
/// rides into the sealed config (0600, the same custody as the key) —
/// never a command line, where `ps` could read it. Idempotent: a config
/// already carrying `[account]` is left alone, and text that does not
/// parse is returned untouched for the caller's own parse to report.
#[must_use]
pub fn with_account_token(config_text: &str, token: &str) -> String {
    let Ok(config) = toml::from_str::<Config>(config_text) else {
        return config_text.to_owned();
    };
    if config.account.token.is_some() {
        return config_text.to_owned();
    }
    let mut out = String::with_capacity(config_text.len() + token.len() + 24);
    out.push_str(config_text);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&format!("\n[account]\ntoken = \"{token}\"\n"));
    out
}

/// Record the desk origin in `config_text` as `[account] endpoint`
/// (ADR-0046).
///
/// The endpoint is the transparency half of the account read: `vallum
/// account` shows which desk it is calling before the token leaves the
/// machine. Idempotent with the same semantics as [`with_account_token`]:
/// a config already carrying an endpoint keeps it on re-join, and text
/// that does not parse is returned untouched for the caller's own parse
/// to report. Creates the `[account]` table when absent.
#[must_use]
pub fn with_account_endpoint(config_text: &str, endpoint: &str) -> String {
    let Ok(config) = toml::from_str::<Config>(config_text) else {
        return config_text.to_owned();
    };
    if config.account.endpoint.is_some() {
        return config_text.to_owned();
    }
    let line = format!("endpoint = \"{endpoint}\"\n");
    let mut out = String::with_capacity(config_text.len() + line.len() + 16);
    let mut placed = false;
    for text_line in config_text.lines() {
        out.push_str(text_line);
        out.push('\n');
        if !placed && text_line.trim() == "[account]" {
            out.push_str(&line);
            placed = true;
        }
    }
    if placed {
        return out;
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str("\n[account]\n");
    out.push_str(&line);
    out
}

/// Insert `outer_mtu` into `[interface]` of `config_text` if not already present.
///
/// Preserves surrounding comments and fields. If the text does not parse or
/// `outer_mtu` is already present, returns the text untouched.
#[must_use]
pub fn with_outer_mtu(config_text: &str, outer_mtu: u16) -> String {
    let Ok(config) = toml::from_str::<Config>(config_text) else {
        return config_text.to_owned();
    };
    if config.interface.outer_mtu.is_some() {
        return config_text.to_owned();
    }
    let mut out = String::with_capacity(config_text.len() + 24);
    let mut placed = false;
    for line in config_text.lines() {
        out.push_str(line);
        out.push('\n');
        if !placed && line.trim() == "[interface]" {
            out.push_str(&format!("outer_mtu = {outer_mtu}\n"));
            placed = true;
        }
    }
    if placed {
        out
    } else {
        config_text.to_owned()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_parse_error_does_not_quote_a_preshared_key() {
        // `toml::de::Error` prints the offending line, and this string is what
        // `vallum doctor`/`status`/every support bundle carries — i.e. the text
        // that reaches an issue tracker. A misplaced `preshared_key` must not
        // take the key with it.
        let secret = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        let message = format!(
            "TOML parse error at line 6, column 1\n  |\n6 | preshared_key = \"{secret}\"\n  | ^^^^^^^^^^^^^"
        );
        let redacted = redact_secrets(&message);
        assert!(!redacted.contains(secret), "{redacted}");
        assert!(redacted.contains("6 | preshared_key = \"<redacted>\""));
        // The gutter and the caret lines are the diagnosis; they survive.
        assert!(redacted.contains("^^^"));
    }

    #[test]
    fn the_account_token_and_ss_psk_are_redacted_too() {
        let text = "[account]\ntoken = \"0123456789abcdef0123456789abcdef\"\n";
        assert!(!redact_secrets(text).contains("0123456789abcdef"));
        let text = "ss_psk = \"hunter2\"\n";
        assert!(!redact_secrets(text).contains("hunter2"));
    }

    #[test]
    fn a_config_path_and_public_keys_survive_redaction() {
        // `private_key` is a path — it is the useful half of the diagnosis.
        let text = "private_key = \"laptop.key\"\npublic_key = \"ABC=\"\n";
        assert_eq!(redact_secrets(text), text);
    }

    #[test]
    fn a_line_naming_a_secret_without_a_value_is_left_alone() {
        let text = "# preshared_key is set below\npreshared_key_file = \"/etc/vallum/psk\"\n";
        assert_eq!(redact_secrets(text), text);
    }

    #[test]
    fn a_local_private_key_rename_moves_only_the_interface_field() {
        // A real client config: the interface names the key, the peer names
        // the server. Only the interface's field may move.
        let text = "[interface]\nname = \"laptop\"\nprivate_key = \"desk.key\"\n\
                    addresses = [\"10.7.0.4/20\"]\n\n\
                    [[peer]]\nname = \"server\"\npublic_key = \"vallum1:0003:x:y:-\"\n\
                    allowed_ips = [\"0.0.0.0/0\"]\n";
        let out = with_local_private_key(text, "laptop.key");
        assert!(
            out.contains("private_key = \"laptop.key\""),
            "the interface's key is renamed: {out}"
        );
        assert!(!out.contains("desk.key"), "the old name is gone: {out}");
        assert!(
            out.contains("public_key = \"vallum1:0003:x:y:-\""),
            "the peer's own fields are untouched: {out}"
        );
    }

    #[test]
    fn a_local_private_key_rename_is_a_no_op_when_it_already_matches() {
        let text = "[interface]\nprivate_key = \"laptop.key\"\n";
        assert_eq!(with_local_private_key(text, "laptop.key"), text);
    }

    #[test]
    fn a_local_private_key_rename_leaves_unparsable_text_alone() {
        let text = "not toml at all";
        assert_eq!(with_local_private_key(text, "laptop.key"), text);
    }

    #[test]
    fn seccomp_accepts_only_the_two_stages() {
        let parse = |value: &str| {
            let text =
                format!("[interface]\nname = \"v0\"\nprivate_key = \"k\"\nseccomp = \"{value}\"\n");
            toml::from_str::<Config>(&text)
        };
        assert_eq!(
            parse("log").expect("log").interface.seccomp,
            Some(Seccomp::Log)
        );
        assert_eq!(
            parse("enforce").expect("enforce").interface.seccomp,
            Some(Seccomp::Enforce)
        );
        // A typo must be a parse error, not a silently unfiltered daemon.
        assert!(
            parse("enforced").is_err(),
            "interface.seccomp accepted a mode it does not implement"
        );
    }

    #[test]
    fn shaping_kinds_parse_and_build_the_machine_they_name() {
        let text = r#"
[interface]
name = "v0"
private_key = "k"

[[peer]]
name = "p"
public_key = "k"
allowed_ips = ["10.0.0.2/32"]

[[peer.shaping]]
kind = "pad_to_size"
size = 1400

[[peer.shaping]]
kind = "min_interval"
interval_ms = 20

[[peer.shaping]]
kind = "constant_rate_floor"
interval_ms = 1000
size = 1400

[[peer.shaping]]
kind = "constant_rate_floor"
interval_ms = 1000
jitter_ms = 250
size = 1400

[[peer.shaping]]
kind = "front_padding"
count = 8
interval_ms = 200
size = 1400

[[peer.shaping]]
kind = "volume_padding"
window_ms = 200
max_packets = 16
size = 1400

[[peer.shaping]]
kind = "byte_volume_padding"
window_ms = 1000
window_bytes = 5600
size = 1400

[[peer.shaping]]
kind = "respond_with_padding"
size = 300
injections = 1
cap = 4
"#;
        let config: Config = toml::from_str(text).expect("parses");
        let machines: Vec<_> = config.peers[0]
            .shaping
            .iter()
            .map(ShapingSpec::machine)
            .collect();
        assert_eq!(machines.len(), 8);

        // A plain floor is armed for its own interval; the noisy one is armed for
        // the shortest of its drawn intervals, which is what the transport uses.
        let shaper = vallum_core::Shaper::new(vec![machines[2].clone()]);
        assert_eq!(shaper.wake_after(), Some(1000));
        let shaper = vallum_core::Shaper::new(vec![machines[3].clone()]);
        assert_eq!(shaper.wake_after(), Some(750));
        // And the window's own pause: clamped up from 200 ms to the rail.
        let shaper = vallum_core::Shaper::new(vec![machines[5].clone()]);
        assert_eq!(shaper.wake_after(), Some(vallum_core::VOLUME_MIN_WINDOW_MS));
        // The byte window is a window too, and it pads rather than only counting.
        let shaper = vallum_core::Shaper::new(vec![machines[6].clone()]);
        assert_eq!(shaper.wake_after(), Some(1000));
        let mut shaper = shaper;
        assert_eq!(
            shaper.handle(vallum_core::Event::NormalSent, 0).len(),
            1,
            "a byte window pads every packet"
        );
    }

    #[test]
    fn the_carrier_defaults_to_udp_and_refuses_a_name_it_does_not_know() {
        // Defaulting matters more than parsing here: every config written before
        // the fallback existed must keep meaning UDP, not acquire a transport.
        let base = |carrier: &str| {
            format!(
                "[interface]\nname = \"v0\"\nprivate_key = \"k\"\n{carrier}\n\n\
                 [[peer]]\nname = \"p\"\npublic_key = \"k\"\nallowed_ips = [\"10.0.0.2/32\"]\n"
            )
        };

        let config: Config = toml::from_str(&base("")).expect("parses without a carrier");
        assert_eq!(config.interface.carrier, None);
        assert_eq!(config.interface.carrier.unwrap_or_default(), Carrier::Udp);

        let config: Config = toml::from_str(&base("carrier = \"tcp\"")).expect("parses tcp");
        assert_eq!(config.interface.carrier, Some(Carrier::Tcp));

        let config: Config = toml::from_str(&base("carrier = \"lwo\"")).expect("parses lwo");
        assert_eq!(config.interface.carrier, Some(Carrier::Lwo));

        let config: Config = toml::from_str(&base("carrier = \"auto\"")).expect("parses auto");
        assert_eq!(config.interface.carrier, Some(Carrier::Auto));

        let config: Config = toml::from_str(&base("carrier = \"ss\"")).expect("parses ss");
        assert_eq!(config.interface.carrier, Some(Carrier::Ss));

        let config: Config = toml::from_str(&base("carrier = \"tls\"")).expect("parses tls");
        assert_eq!(config.interface.carrier, Some(Carrier::Tls));
        assert_eq!(Carrier::Tls.protocol(), "tcp");
        assert!(Carrier::Tls.uses_tcp());
        assert!(Carrier::Tls.uses_tls());
        assert!(Carrier::Tls.is_probeable());

        let config: Config = toml::from_str(&base("carrier = \"quic\"")).expect("parses quic");
        assert_eq!(config.interface.carrier, Some(Carrier::Quic));
        assert_eq!(Carrier::Quic.protocol(), "udp");
        assert!(Carrier::Quic.uses_udp());
        assert!(Carrier::Quic.uses_tls());
        assert!(!Carrier::Quic.is_probeable());

        assert!(validate_tls_sni("cdn.example.com").is_ok());
        assert!(validate_tls_sni("").is_err());
        assert!(validate_tls_sni("https://cdn.example.com").is_err());
        assert!(validate_tls_sni("cdn.example.com:443").is_err());

        let via_toml = "[interface]\nname = \"v0\"\nprivate_key = \"k\"\n\n\
                        [quick]\nvia = \"entry.toml\"\n\n\
                        [[peer]]\nname = \"p\"\npublic_key = \"k\"\nallowed_ips = [\"0.0.0.0/0\"]\n";
        let via_cfg: Config = toml::from_str(via_toml).expect("parses via");
        assert_eq!(via_cfg.quick.via.as_deref(), Some(Path::new("entry.toml")));
        assert_eq!(
            resolve_via_path(Path::new("/etc/vallum/exit.toml"), Path::new("entry.toml")),
            PathBuf::from("/etc/vallum/entry.toml")
        );

        // A typo must not silently leave the interface on the protocol it was
        // meant to avoid.
        let error = toml::from_str::<Config>(&base("carrier = \"tcpp\"")).expect_err("refused");
        assert!(
            error.to_string().contains("tcpp"),
            "the error should name the bad value: {error}"
        );
    }

    #[test]
    fn a_floor_without_jitter_still_parses() {
        // The field is defaulted so a config written before noise existed keeps
        // its meaning: a metronome, not a silent upgrade to a noisier shape.
        let text = r#"
[interface]
name = "v0"
private_key = "k"

[[peer]]
name = "p"
public_key = "k"
allowed_ips = ["10.0.0.2/32"]

[[peer.shaping]]
kind = "constant_rate_floor"
interval_ms = 500
size = 1400
"#;
        let config: Config = toml::from_str(text).expect("parses");
        let machine = config.peers[0].shaping[0].machine();
        let shaper = vallum_core::Shaper::new(vec![machine]);
        assert_eq!(shaper.wake_after(), Some(500));
    }

    #[test]
    fn with_outer_mtu_inserts_when_absent() {
        let text = "[interface]\nname = \"v0\"\nprivate_key = \"k\"\n\n[[peer]]\nname = \"p\"\n";
        let with = with_outer_mtu(text, 1400);
        assert!(with.contains("outer_mtu = 1400\n"));
        let parsed: Config = toml::from_str(&with).unwrap();
        assert_eq!(parsed.interface.outer_mtu, Some(1400));
    }

    #[test]
    fn with_outer_mtu_preserves_explicit_value() {
        let text = "[interface]\nname = \"v0\"\nprivate_key = \"k\"\nouter_mtu = 1200\n\n[[peer]]\nname = \"p\"\n";
        let with = with_outer_mtu(text, 1400);
        assert_eq!(with, text);
    }

    #[test]
    fn with_account_token_records_the_desk_credential() {
        let text = "[interface]\nname = \"v0\"\nprivate_key = \"k\"\n\n[[peer]]\nname = \"p\"\n";
        let with = with_account_token(text, "0123456789abcdef0123456789abcdef");
        let parsed: Config = toml::from_str(&with).unwrap();
        assert_eq!(
            parsed.account.token.as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );
    }

    #[test]
    fn with_account_token_is_idempotent_and_absent_by_default() {
        let text = "[interface]\nname = \"v0\"\nprivate_key = \"k\"\n\n[[peer]]\nname = \"p\"\n";
        let parsed: Config = toml::from_str(text).unwrap();
        assert!(parsed.account.token.is_none());
        let once = with_account_token(text, "0123456789abcdef0123456789abcdef");
        let twice = with_account_token(&once, "ffffffffffffffffffffffffffffffff");
        assert_eq!(once, twice);
    }

    /// ADR-0046: the desk origin rides beside the token so `vallum account`
    /// knows which desk to ask. Both halves must survive the text round-trip.
    #[test]
    fn account_token_and_endpoint_round_trip_together() {
        let text = "[interface]\nname = \"v0\"\nprivate_key = \"k\"\n\n[[peer]]\nname = \"p\"\n";
        let with = with_account_token(text, "0123456789abcdef0123456789abcdef");
        let with = with_account_endpoint(&with, "https://desk.example.com:8443");
        let parsed: Config = toml::from_str(&with).unwrap();
        assert_eq!(
            parsed.account.token.as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );
        assert_eq!(
            parsed.account.endpoint.as_deref(),
            Some("https://desk.example.com:8443")
        );
    }

    /// Configs written before the endpoint field existed must still parse:
    /// the field defaults to absent, never to a guess.
    #[test]
    fn a_config_without_an_account_endpoint_still_parses() {
        let text = "[interface]\nname = \"v0\"\nprivate_key = \"k\"\n\n\
                    [account]\ntoken = \"0123456789abcdef0123456789abcdef\"\n\n\
                    [[peer]]\nname = \"p\"\n";
        let parsed: Config = toml::from_str(text).unwrap();
        assert_eq!(
            parsed.account.token.as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );
        assert!(parsed.account.endpoint.is_none());
        // And a config with no [account] at all defaults both halves absent.
        let bare = "[interface]\nname = \"v0\"\nprivate_key = \"k\"\n\n[[peer]]\nname = \"p\"\n";
        let parsed: Config = toml::from_str(bare).unwrap();
        assert!(parsed.account.token.is_none());
        assert!(parsed.account.endpoint.is_none());
    }

    /// Re-join semantics match the token's: the recorded desk is kept, not
    /// overwritten by whatever the next URI happens to carry.
    #[test]
    fn with_account_endpoint_is_idempotent() {
        let text = "[interface]\nname = \"v0\"\nprivate_key = \"k\"\n\n[[peer]]\nname = \"p\"\n";
        let once = with_account_endpoint(text, "https://desk.example.com");
        let twice = with_account_endpoint(&once, "https://other.example.com");
        assert_eq!(once, twice);
        let parsed: Config = toml::from_str(&twice).unwrap();
        assert_eq!(
            parsed.account.endpoint.as_deref(),
            Some("https://desk.example.com")
        );
    }

    /// The endpoint is not a secret — it is the transparency half of
    /// ADR-0046 — so redaction keeps it while still hiding the token.
    #[test]
    fn the_endpoint_survives_redaction_but_the_token_does_not() {
        let text = "[account]\ntoken = \"0123456789abcdef0123456789abcdef\"\n\
                    endpoint = \"https://desk.example.com\"\n";
        let redacted = redact_secrets(text);
        assert!(!redacted.contains("0123456789abcdef"), "{redacted}");
        assert!(
            redacted.contains("endpoint = \"https://desk.example.com\""),
            "{redacted}"
        );
    }

    #[test]
    fn dns_proxy_parses_and_defaults_to_off() {
        // Off by default: enabling it claims loopback port 53, so a config
        // that never mentions it must never turn it on.
        let text = "[interface]\nname = \"v0\"\nprivate_key = \"k\"\n\n[[peer]]\nname = \"p\"\n";
        let config: Config = toml::from_str(text).unwrap();
        assert!(!config.quick.dns_proxy);

        let enabled = "[interface]\nname = \"v0\"\nprivate_key = \"k\"\n\n[quick]\ndns_proxy = true\n\n[[peer]]\nname = \"p\"\n";
        let config: Config = toml::from_str(enabled).unwrap();
        assert!(config.quick.dns_proxy);
    }

    #[test]
    fn content_blockers_encode_and_decode_magic_resolver_ip() {
        use std::net::{IpAddr, Ipv4Addr};

        assert_eq!(content_blocker_resolver_ip::<&str>(&[]), None);
        assert_eq!(
            content_blocker_resolver_ip(&["ads", "trackers", "malware"]),
            Some(Ipv4Addr::new(100, 64, 0, 7))
        );
        assert_eq!(
            content_blocker_resolver_ip(&["adult", "gambling", "social"]),
            Some(Ipv4Addr::new(100, 64, 0, 56))
        );
        assert_eq!(
            decode_content_blocker_ip(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 7))),
            vec!["ads", "trackers", "malware"]
        );
        assert!(decode_content_blocker_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))).is_empty());

        let quick = Quick {
            dns: vec!["1.1.1.1".to_owned()],
            content_blockers: vec![
                "ads".to_owned(),
                "trackers".to_owned(),
                "malware".to_owned(),
            ],
            ..Quick::default()
        };
        assert_eq!(quick.effective_dns_servers(), vec!["100.64.0.7", "1.1.1.1"]);

        let dir = std::env::temp_dir().join(format!("vallum-cfg-cb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bad_path = dir.join("bad.toml");
        std::fs::write(
            &bad_path,
            "[interface]\nname = \"v0\"\nprivate_key = \"k\"\n\n[quick]\ncontent_blockers = [\"unknown_cat\"]\n",
        )
        .unwrap();
        assert!(Config::load(&bad_path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tcp_upgrade_validates_host_and_rejects_control_characters() {
        assert!(validate_tcp_upgrade_host("cdn.example.com").is_ok());
        assert!(validate_tcp_upgrade_host("cdn.example.com:443").is_ok());
        assert!(validate_tcp_upgrade_host("[::1]:8443").is_ok());

        assert!(validate_tcp_upgrade_host("").is_err());
        assert!(validate_tcp_upgrade_host("   ").is_err());
        assert!(validate_tcp_upgrade_host("cdn.example.com\r\nX-Inject: 1").is_err());
        assert!(validate_tcp_upgrade_host("cdn.example.com\n").is_err());
        assert!(validate_tcp_upgrade_host("bad host").is_err());
        assert!(validate_tcp_upgrade_host("https://cdn.example.com").is_err());
        assert!(validate_tcp_upgrade_host("cdn.example.com/path").is_err());

        let dir = std::env::temp_dir().join(format!("vallum-cfg-tcp-upg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let good_path = dir.join("good.toml");
        std::fs::write(
            &good_path,
            "[interface]\nname = \"v0\"\nprivate_key = \"k\"\ncarrier = \"tcp\"\ntcp_upgrade = \"edge.example.com:443\"\n",
        )
        .unwrap();
        let cfg = Config::load(&good_path).unwrap();
        assert_eq!(
            cfg.interface.tcp_upgrade.as_deref(),
            Some("edge.example.com:443")
        );

        let bad_path = dir.join("bad.toml");
        std::fs::write(
            &bad_path,
            "[interface]\nname = \"v0\"\nprivate_key = \"k\"\ntcp_upgrade = \"edge.example.com\\r\\nInjected: yes\"\n",
        )
        .unwrap();
        assert!(Config::load(&bad_path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod name_tests {
    use super::validate_interface_name;

    #[test]
    fn an_ordinary_name_passes() {
        for name in ["vallum0", "alpha5", "wg-0", "a.b_c"] {
            assert!(validate_interface_name(name).is_ok(), "{name}");
        }
    }

    #[test]
    fn a_traversing_name_is_refused() {
        // The name reaches `/run/vallum/<name>.quick-ns.log` before the kernel
        // ever sees it, so `..` has to be refused here (R2-5).
        for name in ["../..", "a/b", "..", "."] {
            assert!(validate_interface_name(name).is_err(), "{name}");
        }
    }

    #[test]
    fn a_name_the_kernel_would_reject_is_refused_here() {
        assert!(validate_interface_name(&"a".repeat(16)).is_err());
        assert!(validate_interface_name("a".repeat(15).as_str()).is_ok());
        assert!(validate_interface_name("-rf").is_err());
        assert!(validate_interface_name("sp ace").is_err());
        assert!(validate_interface_name("").is_err());
    }
}
