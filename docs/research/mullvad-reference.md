# Mullvad as a reference implementation (updated for v1.6.5)

This note compares Vallum against two authoritative references for a Mullvad-class
privacy VPN:

1. **Live Mullvad 2026.5 installation** (`mullvad-daemon`, ELF x86-64, `[live]`,
   `[settings]`, `[strings]`).
2. **Full Mullvad architectural breakdown & `VariantVPN` cockpit specification**
   (`Mullvad Breakdown and Variant.md` and `VariantVPN-Prototype.html` in the
   operator's reference archive), covering `mullvad-daemon` / `talpid-core` /
   `gotatun` / `maybenot` / `tunnel-obfuscation` / nftables / DNS / API access.

Status markers below track Vallum's progress after closing all seven production-readiness
gates in [the roadmap](../roadmap.md): **`[Built in v1.6.5]`**, **`[Partial]`**,
**`[Next]`**, and **`[Later]`**.

---

## Side by side: Mullvad 2026.5 vs Vallum 1.6.5

| Concern | Mullvad 2026.5 (`talpid-core` / `gotatun`) | Vallum 1.6.5 Status |
|---|---|---|
| Tunnel failure policy | Default-deny fail-closed firewall across `Connecting` / `Connected` / `Error` | **`[Built in v1.6.5]`** — `[quick] failure_policy = "block"` (default) installs atomic blackhole routes; `vallum-guard@` drops non-tunnel egress |
| Lockdown & early boot | `mullvad-early-boot-blocking.service` (`Before=network-pre.target`) + `lockdown_mode` | **`[Built in v1.6.5]`** — `policy = "lockdown"`, `vallum policy lockdown` (no DNS required), `vallum-guard@.service` ordered `Before=network-pre.target` |
| CVE-2019-14899 & NDP | Input drop for tunnel IPs + `src_valid_mark=1` + `arp_ignore=2` + ICMPv6 NDP | **`[Built in v1.6.5]`** — priority `-300` input chain, sysctls, and `nd-{router,neighbor}-{solicit,advert}` accept rules |
| DNS leak protection | Firewall blocks `:53` except approved resolvers + local loopback DNS proxy | **`[Built in v1.6.5]`** — port `:53` drop before LAN rules, fail-closed `resolvectl`/`resolvconf`/`/etc/resolv.conf`, and Wave 6 `vallum-quick dns-proxy` (`LoopbackDnsProxy`, RFC1918 LAN split, IPv4-only `AAAA` `NODATA` suppression, `198.51.100.1` captive-portal spoof) |
| Content blockers | Server-side bitmask resolver IP `100.64.0.<mask>` (`ads\|trackers\|malware\|adult\|gambling\|social`) | **`[Built in v1.6.5]`** — `[quick] content_blockers` + `effective_dns_servers()` + 6-chip GUI selector with live `100.64.0.X` preview |
| Path MTU detection | ICMP PMTUD probing + overhead subtraction per obfuscator | **`[Built in v1.6.5]`** — `probe_path_mtu` + closed-loop `vallum doctor --tune-mtu` + GUI **Probe Live Path** advisor (`1280`/`1340`/`1380`/`1420`) + `JA4T` MSS readout |
| Obfuscation (LWO) | `LWO v1`/`v2` in-place XOR + random header padding + randomized timers | **`[Built in v1.6.5]`** — `carrier = "lwo"` SplitMix64 header masking + LWO v2 handshake & `9..=64` B fragment tail padding + Wave 5–6 `KEEPALIVE_JITTER_MS = 2_000` (10–12 s) / `keepalive_offset` / `retransmit_offset` seeded from daemon RNG in `vallum-tunnel` |
| Obfuscation (TCP / Web) | `udp2tcp` (`2B` length framing, `TCP_NODELAY`), Shadowsocks, QUIC/MASQUE | **`[Partial]`** — `[Built]` `carrier = "tcp"` (`2B` framing, `TCP_NODELAY`), server-side `HTTP/1.1 101 Switching Protocols` reverse-proxy upgrade (`/_vallum`), and Wave 5 client-side `[interface] tcp_upgrade` dial emission; **`[Next]`** QUIC `DATAGRAM` + Shadowsocks |
| Multiplexer (`Auto`) | `tunnel-obfuscation` progressive 500 ms fan-out + `HandshakeFilter` (`mac1`) | **`[Partial]`** — `[Built]` `carrier = "auto"` 500 ms LWO-to-TCP race, Wave 6 100-packet initial burst replay, and TLV + `RECEIVER_INDEX` + `mac1` `HandshakeFilter` (`is_authentic_handshake_packet`); **`[Next]`** TLS/QUIC transport fan-out |
| Traffic analysis (DAITA) | `maybenot` machines over `gotatun` userspace WG, pushed by entry relay | **`[Built in v1.6.5]`** — in-crate `ShapingSpec` (`ConstantRateFloor`, `VolumePadding`, `ByteVolumePadding`, `FrontPadding`, `RespondWithPadding`) + GUI cover-vs-payload monitor; **`[Next]`** server-pushed profile negotiation |
| Active leak checker | Post-connect traceroute over non-tunnel interface (`mullvad-leak-checker`) | **`[Built in v1.6.5]`** — `vallum doctor` `route_leak` & `active_leak` + `vallum-quick leak-check` / `watch` periodic TTL=1 non-tunnel probe |
| Split tunneling | Linux cgroups v2 (`socket cgroupv2`) + `nftables` mark + policy routing | **`[Built in v1.6.5]`** — shared member mount+net namespace (`[quick] app_class = true`, avoiding source-IP socket mismatch in `docs/proof/socket-cgroupv2.md`); **`[Later]`** per-app DNS & metrics |
| Relay & Multihop | Constraint selector (`Auto`/`Always`), entry+exit multihop, API over bridge/DoH/fronting | **`[Later]`** — relay-list API, entry+exit multihop selection, and resilient control-plane fronting (`VariantVPN` API Access tab) |
| Post-quantum crypto | `ML-KEM-1024` + `HQC-256` ephemeral peer exchange (`::1337` smoltcp tunnel) | **`[Built in v1.6.5]`** — `0x0003` tri-hybrid (`X25519 + sntrup761 + ML-KEM-768`), explicitly labelled `experimental-pq` |

---

## Subsystem breakdown from Mullvad 2026.5 & VariantVPN reference

### 1. Two-layer daemon architecture & fail-closed state machine (§1, §2, §9.1–§9.2)
- Mullvad splits a privileged system daemon (`mullvad-daemon` + `talpid-core`)
  from unprivileged frontends over local IPC (gRPC over UDS/named pipe). Frontends
  can crash or restart without tearing down firewall rules or routes.
- Vallum mirrors this split via `vallum run` (daemon with seccomp enforce and
  privilege drop), `vallum-guard@` (`nftables` per-interface table), `vallum-quick`
  (routing + DNS host orchestration), and `vallum-gui` (Tauri console over UAPI
  Unix socket with strict allowlist snapshot in `crates/vallum-gui/src/snapshot.rs`).
- **Remaining gap `[Next]`**: unify crash-persistent state on Linux so an
  unexpected power loss restores lockdown policy before `network-pre.target`
  when `[quick] policy = "lockdown"` is enabled.

### 2. WireGuard obfuscation & multiplexer (`tunnel-obfuscation`, §6)
- **UDP2TCP (`§6.3`)**: 2-byte big-endian length framing over TCP with
  `TCP_NODELAY`, `54 B` accounting overhead. Vallum's `TcpTransport` already uses
  2-byte framing with `SO_MARK` bypass (`fwmark`), server-side
  HTTP/1.1 `101 Switching Protocols` reverse-proxy upgrades on `/_vallum`, and
  Wave 5 client-side `[interface] tcp_upgrade` dial emission (`AutoTransport` +
  `TcpTransport`).
- **LWO v1/v2 (`§6.6`)**: in-place header masking + random padding (1–256 B on
  handshakes) + `Verdict::{Lwo, Plain, Invalid}` coexistence on the same port +
  randomized WireGuard timers (`keepalive 8–12s`, `rekey 100–120s`,
  `rekey_timeout 4.75–5.25s`). Vallum has `lwo::pad_and_mask_in_place`,
  `classify_and_unpad`, `KEEPALIVE_JITTER_MS = 2_000` (10–12 s ceiling), and
  Wave 6 per-session daemon RNG seeding of `keepalive_offset` and
  `retransmit_offset` in `vallum_tunnel::device::timer`.
- **Shadowsocks (`§6.4`) & QUIC/MASQUE (`§6.5`)**: needed when censors reset
  non-HTTP TCP or throttle all UDP except HTTP/3. Scheduled in `[Next]` Track A.
- **Multiplexer (`§6.7`) — `[Built in Wave 6]`**: progressive 500 ms spawn
  stagger, replay of up to `AUTO_MAX_INITIAL_PACKETS = 100` initial packets onto
  TCP, and TLV/`RECEIVER_INDEX`/`mac1` `HandshakeFilter`
  (`is_authentic_handshake_packet` + `verify_handshake_mac1`) gating
  `AutoTransport` UDP/TCP arms; extending fan-out to TLS/QUIC tracks Track A.

### 3. DAITA / Traffic shaping (`§5`)
- Mullvad negotiates per-relay `maybenot` machines + `max_padding_frac` /
  `max_blocking_frac` bounds over an ephemeral tunnel (`10.64.0.1:1337`).
- Vallum already implements the full `maybenot`-style `ShapingSpec` suite in
  `vallum-core` and exposes payload-vs-cover byte telemetry in `DataFlow.tsx`,
  while keeping raw machine definitions out of config files to prevent accidental
  floods. Negotiation of relay-suggested profiles sits in `[Later]`.

### 4. DNS & Server-Side Content Blockers (`§8`)
- **`100.64.0.<bitmask>` magic resolver (`§8.2`) — `[Built in v1.6.5]`**:
  six booleans (`ads=1`, `trackers=2`, `malware=4`, `adult=8`, `gambling=16`,
  `social=32`) ORed into `100.64.0.X`, avoiding client-side blocklist maintenance.
- **RFC1918 split + local loopback proxy (`§8.3`–`§8.4`) — `[Built in Wave 6]`**:
  `vallum-quick dns-proxy` (`LoopbackDnsProxy`) runs a bounded-concurrency (`64`)
  forwarding resolver on loopback with RFC1918/ULA LAN vs tunnel resolver split
  (preserving `100.64.0.0/10` in-tunnel), IPv4-only `AAAA` `NODATA` suppression
  (`tunnel_is_ipv4_only`), and `198.51.100.1` captive-portal spoofing for
  `Blocked` / `Lockdown` state.

### 5. Cockpit & Operator Ergonomics (`VariantVPN-Prototype.html`)
- Key UI patterns carried over into `vallum-gui` (`DataFlow.tsx` & `PeerDialogs.tsx`):
  4-stage connection progress ladder, carrier & overhead chips, payload-vs-cover
  traffic split bar, adaptive MTU + `JA4T` MSS advisor with 1-click **Probe Live
  Path**, egress guard mode selector (`auto` / `on` / `lockdown` / `off`), and
  the 6-category Content Blocker chip grid with live `→ resolver 100.64.0.X` readout.
- **Remaining cockpit enhancements `[Next]`–`[Later]`**: multihop entry/exit hop
  visualization and resilient control-plane access rotation drawer (`Direct`,
  `Bridge`, `Encrypted DNS`, `Domain Fronting`).

---

## Original REA binary-analysis notes (Mullvad 2026.5)

- REA caps analysis at 330 seconds (`provider_timeout` on 17 MB `mullvad-daemon`).
- Ghidra auto-analysis Decompiler Parameter ID is the slow pass on Rust
  binaries (4 GB heap, `MemoryMax=11G` transient systemd unit avoids cgroup OOM).
- Chasing `.rodata` string xrefs on Rust binaries lands on `(ptr, len)` slice
  descriptors in `.data.rel.ro` rather than raw string addresses; disabling
  Decompiler Parameter ID / Function ID upfront and querying incrementally works
  around the timeout.
