# Android APK (`vallum-engine` + `VpnService`) — Specify & Split

**Process:** `/software-delivery-process` Phase 3 (Specify) & Phase 4 (Split)  
**Prerequisite:** [ADR 0043](adr/0043-operator-library-split.md) Step 4 (`vallum-engine`)  
**Date:** `2026-11-15`

---

## 1. Environment Baseline (Observed `2026-11-15`)

- Installed Rust targets: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `aarch64-apple-darwin`.
- Missing locally for Android builds: `aarch64-linux-android`, `armv7-linux-androideabi`, `cargo-ndk`, `ANDROID_HOME` / Android SDK & NDK, `adb`.
- **Android constraint:** Unprivileged Android apps cannot use `/dev/net/tun` (`tun2`), `CAP_NET_ADMIN`, `netlink`, `nftables`, `seccompiler`, `SO_MARK`, or `systemd`. All tunnel I/O must go through `android.net.VpnService`:
  - `VpnService.Builder.establish()` yields a `ParcelFileDescriptor` (`tun_fd`).
  - Every outbound carrier socket (`UDP`, `TCP`, `TLS`, `QUIC`) must call `VpnService.protect(fd)` before connecting/sending so carrier traffic bypasses the VPN route and cannot loop.

---

## 2. Target Architecture Seam

```text
  Kotlin VpnService (Android)               Linux Daemon (crates/vallum)
  ├── VpnService.Builder -> tun_fd          ├── tun2 -> tun_fd
  ├── VpnService.protect(sock_fd)           ├── SO_MARK (fwmark)
  └── Foreground Service + UI               └── systemd + nftables + netlink
                 \                                     /
                  v                                   v
             +---------------------------------------------+
             |         crates/vallum-engine (new)          |
             |  - TunIo trait (read/write IP packets)      |
             |  - SocketProtector trait (protect(RawFd))   |
             |  - Tunnel loop + Session + Carriers         |
             |  - Enrolment / join ticket parser & client  |
             +---------------------------------------------+
                                    |
          +-------------------------+-------------------------+
          v                         v                         v
     vallum-core              vallum-tunnel             vallum-crypto
```

---

## 3. Vertical Tracer-Bullet Slices (Acyclic)

### Slice 1 — `crates/vallum-engine` extraction (Linux-testable)
- **Blockers:** None.
- **Scope:** Extract the platform-neutral tunnel loop, session driver, and carrier bindings (`UDP`, `LWO`, `SS`, `TCP`, `TLS`, `QUIC`) behind `TunIo` and `SocketProtector` traits. Keep `crates/vallum` using `vallum-engine` with its Linux `tun2` + `SO_MARK` implementations.
- **Acceptance criteria:**
  - `cargo tree -p vallum-engine` contains **0** references to `tun2`, `netlink-sys`, `netlink-packet-route`, `seccompiler`, or `ratatui`.
  - `cargo test -p vallum-engine` passes a bidirectional loopback handshake + packet round-trip over an in-memory `TunIo`.
- **PERT Estimate (days):** O = 2, N = 4, P = 7 (E = 4.2d).

### Slice 2 — Android NDK cross-compile & FFI (`vallum-android-ffi`)
- **Blockers:** Slice 1; local/CI Android NDK + `rustup target add aarch64-linux-android armv7-linux-androideabi` + `cargo-ndk`.
- **Scope:** Thin UniFFI (or JNI) crate exposing `start_tunnel(config_toml, tun_fd, protector)`, `stop_tunnel()`, `status_snapshot()`, and `join_ticket(...)`, compiled into `libvallum_engine.so` for `arm64-v8a` and `armeabi-v7a`.
- **Acceptance criteria:**
  - `cargo ndk -t arm64-v8a -t armeabi-v7a build --release` exits 0 and emits both `.so` artifacts.
  - Unit test verifies JNI/FFI lifecycle (`start` → `status` → `stop`) without leaks or panics.
- **PERT Estimate (days):** O = 1.5, N = 3, P = 5 (E = 3.1d).

### Slice 3 — Kotlin `VpnService` App & Live Handshake
- **Blockers:** Slice 2 + Android SDK / emulator or physical device (`adb`).
- **Scope:** Minimal Android app (`VallumVpnService` foreground service, `VpnService.Builder` configuring tunnel IP/routes/DNS/MTU, `VpnService.protect(fd)` callback, paste/QR `vallum1-join:` ticket import, connect/disconnect toggle).
- **Acceptance criteria:**
  - App installs on Android 12+ (API 31+) emulator/device with **0** root privileges.
  - Joins a live `wingman-vps` server via `vallum1-join:` ticket, completes tri-hybrid handshake, and carries IPv4/ICMP + HTTPS traffic with **100%** of carrier sockets protected (zero routing loops).
  - Survives Wi-Fi ↔ cellular / interface toggle without leaking when Android "Block connections without VPN" is enabled.
- **PERT Estimate (days):** O = 3, N = 5, P = 9 (E = 5.3d).

### Slice 4 — Signed Release `.apk` & Clean Install/Uninstall Gate
- **Blockers:** Slice 3.
- **Scope:** Gradle release signing configuration (dedicated Android keystore, separate from SSH release key), reproducible ABI splits or universal `.apk`, and `scripts/accept-android.sh` (`adb install` → smoke launch → `adb uninstall` → verify clean removal).
- **Acceptance criteria:**
  - `apksigner verify` passes on the release `.apk`.
  - `adb install` + `adb uninstall` completes in **≤ 30 seconds** with **0** leftover packages.
- **PERT Estimate (days):** O = 1, N = 2, P = 4 (E = 2.2d).

---

## 4. Next Prerequisite Command (When Ready to Start Android)

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi
cargo install cargo-ndk
# Install Android SDK / NDK + set ANDROID_HOME & ANDROID_NDK_HOME
```
