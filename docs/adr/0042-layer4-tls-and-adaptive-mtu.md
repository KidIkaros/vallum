# ADR-0042: Layer-4 stream conduit, TLS 1.3 outer carrier, JA4T normalization, and adaptive MTU optimization

**Date**: 2026-11-13
**Status**: proposed
**Extends**: ADR-0026 (`carrier = "tcp"`), ADR-0027 (mesh coordination), ADR-0041 (host boundary)
**Deciders**: Vallum maintainers

## Context

All seven pre-Alpha Layer-3 production-readiness gates in `docs/roadmap.md` are now closed and verified (including fail-closed blackholes, DNS leak blocking, passive re-initiation recovery on `wingman-vps`, active Path MTU ceiling probing, and `vallum_client_verdict`).

Post-Alpha field testing and operator feedback surfaced three structural limitations of being strictly a Layer-3 (`/dev/net/tun`) + raw TCP/UDP tunnel:

1. **Reverse-proxy & firewall coexistence (`carrier = "tls"`):**
   - `ADR-0026` added opt-in `carrier = "tcp"` with a 2-byte length prefix (`vallum_tunnel::stream`). While that traverses basic UDP-blocking links, strict corporate firewalls and cloud edge proxies reset raw binary TCP streams lacking a valid TLS handshake on `:443`.
   - Meanwhile, real-world deployments (such as `wingman-vps`) already bind `:80` and `:443` with reverse proxies like Caddy for HTTPS sites. A TLS-capable Vallum server carrier must either bind `:443` directly **or** sit behind Caddy/Nginx via loopback upstream forwarding without fighting for port ownership.

2. **`JA4+` / `JA4T` / `JA4 Signals` VPN fingerprinting:**
   - Modern inspection firewalls combine `JA4` (TLS `ClientHello` with sorted extensions/ciphers), `JA4S` (TLS `ServerHello`), `JA4H` (HTTP headers/HTTP2 framing), `JA4L` (TCP-vs-TLS RTT light distance), and `JA4T` (TCP `SYN` window size, options, window scale, and MSS).
   - **Why Layer 3 TUN leaks to `JA4T`:** Even when outer packets are encrypted, a Layer-3 TUN interface clamps inner TCP `MSS` (typically `1340`–`1380` instead of native `1460`) so encapsulated frames fit the WAN MTU. The destination web server or WAF observes that shrunk TCP `MSS` inside `JA4T` on the exit socket.
   - **Why naive Layer-7 spoofing fails:** Tools like browser `User-Agent` switchers alter only L7 headers while leaving `JA4` (TLS stack) and `JA4H` (HTTP/2 frame behavior) unchanged — immediately tripping `JA4 Signals` mismatch metrics (`uas_rank_1h`).

3. **MTU ceiling vs. optimal MTU (`1280` USB 1GbE vs. `1380` gaming vs. `1420` bulk):**
   - `probe_path_mtu` (`crates/vallum/src/net.rs`) bisects ICMP DF probes to discover the maximum *non-blackholing* ceiling $M_{\max}$.
   - Measured operator hardware demonstrates that $M_{\max}$ is often **suboptimal**:
     - On Linux over a 1 Gbps USB Ethernet adapter, **`1280` MTU** outperforms larger MTUs by aligning encapsulated frames within USB bulk URB boundaries and avoiding tail latency spikes.
     - On Windows 11 for real-time UDP gaming netcode (`~1100–1350 B` snapshots), **`1380` MTU** outperforms `1280` by preventing inner payload fragmentation into two datagrams while preserving overhead headroom.

## Decision

1. **Rootless Layer-4 Stream & Port Conduit (`vallum forward` / `vallum proxy`)**
   - Reuse `vallum-core`'s sans-I/O Suite `0x0003` handshake, epoch rotation (`peer rotate` → `peer finalize`), AEAD sealing, and Maybenot traffic shaping without opening `/dev/net/tun` or modifying host IP routing/`nftables`.
   - Support rootless local port forwarding (`-L listen:target`), reverse service exposure (`-R`), and local SOCKS5/HTTP `CONNECT` multiplexing over an encrypted stream muxer.
   - Eliminates `CAP_NET_ADMIN` / `root` requirements for application-scoped flows and makes Vallum natively portable across macOS, Windows, and unprivileged containers alongside `ADR-0041`.

2. **Standards-Compliant Outer TLS 1.3 Carrier (`carrier = "tls"` & Caddy Upstream Mode)**
   - Implement `TlsTransport` behind `DatagramSocket` in `crates/vallum/src/net.rs` using `rustls` (TLS 1.3, standard ALPN `h2` / `http/1.1` Upgrade / HTTP/2 tunneling) wrapping the existing `vallum_tunnel::stream` framer.
   - Support two deployment topologies:
     - **Standalone TLS:** Daemon terminates real TLS 1.3 directly with valid certificates.
     - **Behind Reverse Proxy (Caddy / Nginx):** Reverse proxy owns `:443` and `:80` (emitting genuine web-server `JA4S` + ACME certificates) and forwards matched ALPN/path upgrades to `vallum` listening on `127.0.0.1:<port>`.
   - Extend `[carrier = "quic"]` (RFC 9221 HTTP/3 `DATAGRAM` frames) as the subsequent step to eliminate TCP head-of-line blocking under packet loss while keeping TLS 1.3 outer framing.

3. **Coherent `JA4+` / `JA4T` Fingerprint Discipline**
   - Reject uncoordinated Layer-7 `User-Agent` / header spoofing inside the tunnel; keep outer transport stacks standards-compliant so `JA4` / `JA4H` / `User-Agent` signals remain mutually consistent (`JA4 Signals` `uas_rank_1h` clean).
   - Eliminate L3 `MSS`-clamping leaks via Layer-4 exit termination: when `vallum proxy` / `vallum forward` dials a destination from the exit host, the OS opens a fresh native TCP socket with native `1500` NIC MTU (`MSS = 1460` in `JA4T`).

4. **Telemetry-Driven Adaptive MTU Optimizer (`vallum doctor --tune-mtu` & Runtime Controller)**
   - Separate **path ceiling discovery** ($M_{\max}$ via `probe_path_mtu`) from **optimal operating MTU selection**.
   - Evaluate candidate MTUs ($\{1280, 1340, 1380, 1400, 1420\} \le M_{\max}$) using active burst micro-sweeps and closed-loop `Snapshot.counters` telemetry (`goodput`, $\text{RTT}_{p99 - p50}$ tail jitter, and `fragments_dropped + reassembled` fragmentation pressure):
     $$\text{Score}(\text{MTU}) = w_1 \cdot \text{Goodput} - w_2 \cdot \text{Jitter}_{p99 - p50} - w_3 \cdot \frac{\Delta\text{fragments\_dropped} + \Delta\text{reassembled}}{\Delta\text{packets\_delivered}}$$
   - Surface hardware/workload recommendations (`1280` low-jitter/USB-NIC, `1380` low-fragmentation gaming, `1420` bulk throughput) cleanly in both CLI (`vallum doctor --tune-mtu`) and `vallum-gui` (`InterfaceFormDialog`).

## Consequences

### Positive
- Enables rootless, cross-platform enterprise and developer adoption (Zero-Trust L4 service tunnels without whole-host routing changes).
- Stops leaking tunnel presence through `JA4T` clamped MSS headers at destination servers.
- Coexists peacefully with production HTTPS services (Caddy/Nginx) on `:443`/`:80`.
- Optimizes per-link performance dynamically instead of assuming the largest non-dropping MTU is fastest.

### Negative / Trade-offs
- Layer-4 forwarding requires TCP/UDP stream multiplexing and congestion backpressure above `vallum-core`'s message layer.
- Running L4 mode does not intercept arbitrary raw ICMP or non-proxy-aware kernel UDP protocols the way L3 TUN does; both L3 and L4 modes must remain supported side by side.
- Outer `carrier = "tls"` over TCP retains head-of-line blocking on lossy links until the follow-up QUIC `DATAGRAM` (`carrier = "quic"`) carrier lands.

## Implemented Foundations (Post-ADR Increments)
- **`carrier = "lwo"` (`crates/vallum-tunnel/src/lwo.rs`, `crates/vallum/src/net.rs`):** Zero-overhead UDP header XOR masking (`SplitMix64` keyed by trailing packet bytes and length, forcing `mask[0] != 0` for unambiguous `UdpTransport` auto-detection) paired with randomized handshake and non-full fragment tail padding (`9..=64` bytes within `1452 B`). Data packets (`0x04`) keep **0 bytes** of wire overhead, and unmodified `carrier = "udp"` servers transparently accept both plain and LWO peers.
- **`carrier = "auto"` (`crates/vallum/src/net.rs`):** Happy-eyeballs carrier racer starting immediately on LWO-UDP, automatically staggering a TCP fallback transmission after `500 ms` if UDP has not answered, and locking active UDP peers for `15 s`.
- **Reverse-Proxy HTTP/1.1 `101 Switching Protocols` Upgrade (`crates/vallum-tunnel/src/stream.rs`, `crates/vallum/src/net.rs`):** `FrameReader` and `TcpTransport` transparently accept an optional HTTP/1.1 `GET /_vallum` (`UPGRADE_PATH`) with `Upgrade: vallum`, respond with `HTTP/1.1 101 Switching Protocols`, and transition directly into 2-byte length-prefixed framing while remaining 0-RTT compatible with raw `carrier = "tcp"` clients. This lets Caddy or Nginx terminate TLS 1.3 on `:443` and forward Vallum traffic to loopback (`reverse_proxy /_vallum 127.0.0.1:51820`) without port collisions.
- **Closed-Loop Adaptive MTU & Active Leak Diagnostics (`crates/vallum/src/policy.rs`, `crates/vallum/src/commands/doctor.rs`, `crates/vallum-gui`):** `vallum::policy` installs a raw-priority (`-300`) `chain input` dropping off-tunnel packets targeting local tunnel IPs, applies `net.ipv4.conf.all.src_valid_mark=1` and `net.ipv4.conf.all.arp_ignore=2`, and `vallum doctor` runs `leak_guard`, `route_leak` (`ip route get` + `/etc/resolv.conf` verification), and closed-loop `--tune-mtu` (combining active ICMP path sweeps with live UAPI fragmentation counters `vallum_fragments_dropped`, `vallum_reassembled`, `vallum_packets_delivered`, also exposed as a 1-click **Probe Live Path** (`tune_mtu`) action in `vallum-gui`).
- **Cockpit Carrier & Connection Stage UI (`vallum-gui`, `vallum tui`, `vallum::uapi`):** Exposes live `vallum_carrier` via UAPI (`get=1`), carrier selection (`udp`, `lwo`, `auto`, `tcp`) with carrier-aware outer wire overhead math, a 4-stage connection progress ladder, and a payload-vs-cover stream monitor.
