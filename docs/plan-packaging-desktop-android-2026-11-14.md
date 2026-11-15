# Packaging, Desktop App, Installer/Uninstaller & Android APK — Intake & Frame

**Process:** `/software-delivery-process` Phase 1 (Intake) & Phase 2 (Frame)  
**Status:** Framed for future planning (Specify & Split deferred until scheduled)  
**Date:** `2026-11-14`

---

## 1. Intake — Observed Gaps & Affected Users

1. **Linux Desktop Users (`vallum-gui`):**
   - `crates/vallum-gui` is already a Tauri v2 app (`tauri = "2"`), and `packaging/vallum-gui.desktop` exists, but `crates/vallum-gui/tauri.conf.json` has `"bundle": { "active": false, "targets": [] }`.
   - Desktop users cannot install `vallum-gui` as a standard `.deb`, `.rpm`, or `.AppImage` bundle from the release artifacts.
2. **Linux Operators & End-Users (Installer / Uninstaller):**
   - Installation exists via `scripts/install.sh`, `.deb`, `.rpm`, and release tarballs, plus `packaging/vallum-cleanup` for runtime teardown.
   - There is no first-class, verified **uninstaller** (`scripts/uninstall.sh` / `vallum uninstall` + package `postrm` parity) that cleanly removes units, binaries, desktop entries, and nftables rules on demand without leaving orphaned state.
3. **Android Users (APK):**
   - Mobile users have no Android `.apk` package. Today `crates/vallum` assumes Linux `CAP_NET_ADMIN`, `/dev/net/tun` (`tun2`), `nftables`, `netlink`, and `systemd` — none of which exist for unprivileged Android apps.

---

## 2. Frame — Open Questions, Recommendations & Decisions Needed

### Surface A: Linux Desktop Application (`vallum-gui`)

| Open Question | Options | Recommendation |
|---|---|---|
| **Distribution format** | (a) Tauri bundler `.deb` / `.rpm` / `.AppImage` alongside CLI packages; (b) Include `vallum-gui` binary + `.desktop` + icons inside existing `vallum` `.deb`/`.rpm`/tarball; (c) Both (`.AppImage` standalone + `.deb`/`.rpm` integration). | **Option (c) or (b) + `.AppImage`**: keep CLI server installs headless (no WebKitGTK/GTK deps on servers) by shipping `vallum-gui` as a separate `vallum-desktop` `.deb`/`.rpm` and/or `.AppImage`. |
| **Privilege boundary** | (a) Run GUI as root (unsafe); (b) GUI runs unprivileged as desktop user and talks to `vallum` daemon control socket via group permissions / Polkit (`pkexec` only for `vallum-ops` / service start). | **Option (b)**: never run WebKitGTK as root; preserve the existing control-socket separation in `vallum-gui`. |

### Surface B: Linux Installer & Uninstaller

| Open Question | Options | Recommendation |
|---|---|---|
| **Uninstall entry point** | (a) `scripts/uninstall.sh` + `vallum uninstall` subcommand; (b) rely only on `apt remove` / `dnf remove`. | **Option (a)** backed by shared cleanup logic used by both `scripts/uninstall.sh` and `.deb`/`.rpm` `prerm`/`postrm`. |
| **Config/key retention on uninstall** | (a) Always delete `/etc/vallum`; (b) Keep `/etc/vallum` by default, delete only with `--purge` (matching Debian `remove` vs `purge`). | **Option (b)**: never destroy identity keys silently on an upgrade/reinstall; require `--purge` to wipe `/etc/vallum`. |
| **Clean-uninstall proof** | (a) Manual check; (b) Automated clean-container/VM gate (`install -> start -> stop -> uninstall -> assert zero units, zero nft tables, zero binaries`). | **Option (b)**: extend `accept-install.sh` to cover the full install → uninstall lifecycle. |

### Surface C: Android APK (`VpnService`)

| Open Question | Options | Recommendation |
|---|---|---|
| **GUI + Tunnel runtime architecture** | (a) Tauri v2 Android mobile app + Kotlin `VpnService` plugin + Rust JNI/UniFFI bridge to `vallum-core`/`vallum-tunnel`/`vallum-crypto`; (b) Native Kotlin/Jetpack Compose UI + UniFFI Rust tunnel library. | Evaluate **(a) vs (b)** before Specify: Tauri v2 Mobile reuses `crates/vallum-gui/ui`, while native Kotlin avoids WebView overhead in a background VPN service. Either way, the tunnel engine runs in-process inside `VpnService` (no root). |
| **Socket & TUN boundary on Android** | Android grants a `ParcelFileDescriptor` TUN fd from `VpnService.Builder.establish()` and requires `VpnService.protect(fd)` on every outbound carrier socket (`UDP`, `TCP`, `TLS`, `QUIC`) to prevent routing loops. | Extract a platform-neutral tunnel/carrier runtime crate (or feature-gate Linux `netlink`/`nftables`/`seccomp`/`systemd` out of `vallum` client-engine) so Android links only userspace crypto, framing, carriers, and TUN fd I/O. |
| **Signing & distribution** | Debug APK vs signed release `.apk` / `.aab` (Play / F-Droid reproducible build). | Require deterministic release signing keystore management (separate from SSH release-signing key) and `arm64-v8a` + `armeabi-v7a` ABI targets. |

---

## 3. Implicit Requirements (Numbered)

- **Install / Uninstall speed:** Clean Linux install and clean uninstall each complete in **≤ 60 seconds** with **0** leftover `vallum*` systemd units, **0** leftover `inet vallum` nftables tables, and **0** stray binaries.
- **Headless server footprint:** Server `.deb` / `.rpm` / tarball installs **0** GUI/WebKitGTK runtime dependencies.
- **Android APK:** Targets `arm64-v8a` (and `armeabi-v7a`), requires **0** root privileges, protects **100%** of outbound carrier sockets via `VpnService.protect`, and survives network handoff (Wi-Fi ↔ cellular) without leaking outside the VPN when Android "Always-on VPN / Block connections without VPN" is enabled.

---

## 4. Out of Scope for Now (Deferred to Specify & Split)

- Writing `.deb`/`.rpm`/`.AppImage` build scripts, `scripts/uninstall.sh`, or Tauri bundle target configs.
- Refactoring `crates/vallum` into a Linux-host crate vs. cross-platform client-engine crate.
- Android Gradle/NDK/SDK toolchain setup, Kotlin `VpnService` implementation, and Play/F-Droid metadata.
