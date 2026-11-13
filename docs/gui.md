# `vallum-gui` — the desktop & localhost operations console

`vallum-gui` is Vallum's graphical operations cockpit. It speaks the same `get=1` UAPI control socket protocol as `vallum tui` ([`docs/tui.md`](tui.md)), shares the `0600` socket / `0770` runtime-directory security gates, and ships two transports for the same React UI:

```sh
# 1. Native desktop window (Tauri)
vallum-gui

# 2. Authenticated localhost HTTP console (loopback-only, token -> HttpOnly SameSite=Strict cookie)
vallum-gui --serve 7317
vallum-gui --serve 7317 --ui crates/vallum-gui/ui/dist
```

<p align="center">
  <img src="../assets/vallum-gui-cockpit.png" alt="Vallum GUI Operations Cockpit" width="100%">
</p>

## Layout & Telemetry

The console organizes every answer in a single overview-first hierarchy with no hidden mode tabs:

1. **Header & Action Bar** — Rampart Seal (`Vallum ❯ TUNNEL CONTROL`), interface switcher, systemd unit status badge, service lifecycle (`start` / `stop` / `restart`), invite ticket minting, and diagnostics drawer (`doctor & dx`). Window/tab titles mirror live posture (`◆ <VERDICT> · <iface> — Vallum`).
2. **Protection Verdict & Boundary Schematic** — Derived host egress verdict (`PROTECTED`, `SPLIT`, `DNS LEAK`, `V6 LEAK`, `UNPROTECTED`, or `NO DAEMON`), paired with the Brandkit §02 tunnel boundary diagram and live `▼ DOWNLOAD` / `▲ UPLOAD` rates.
3. **Status — Is Traffic Protected?** — Host health checks (IPv4 egress route, IPv6 leak policy, DNS resolver check, guard/deadman state), shared-peak spline RX/TX throughput chart (powered by Recharts with key-epoch markers), and the Brandkit §08 Suite `0x0003` combiner pipeline (`X25519 + sntrup761 + ML-KEM-768 -> Blake2s/HKDF -> XChaCha20-Poly1305`).
4. **Peers Workbench & System** — Live searchable/sortable peer table, per-peer details (`ping`, `edit`, `rotate`/`finalize` keys, `export bundle` + `VALLUM1` animated QR, `invite`), configuration editor (`interface` & raw `toml`), runtime save, full-tunnel `apply` trial with `cancel`/`revert` + `vallum-panic`, and streaming journald logs.

## Keyboard Shortcuts

Single-letter shortcuts are suppressed whenever a form input or dialog has focus.

| Key | Action |
|---|---|
| `Cmd/Ctrl+K` or `:` | Open command palette (`PeerPalette`) |
| `/` | Focus peer filter box |
| `j` / `k` or `↓` / `↑` | Select next / previous peer |
| `o` | Cycle peer sort order (`Activity`, `Transfer`, `Name`, `Key`) |
| `Tab` or `[` / `]` | Cycle interfaces |
| `r` | Refresh host health, service state, and preflight facts |
| `i` | Open interface settings form |
| `E` | Open TOML configuration editor |
| `W` | Save runtime peers to disk |
| `d` | Open Doctor, `VAL-E*` error catalog, CLI snippets, and JSON bundle export |
| `?` | Toggle keyboard shortcuts overlay |
| `Esc` | Dismiss shortcuts overlay or clear the peer filter |

## `VAL-E*` Diagnostic Error Codes & Exit Contract

`vallum-gui` maps raw socket, permission, OS capability, egress, and cryptographic messages into structured remediation cards inside the **Doctor & DX** modal (`d`):

| Code | Domain | Exit | Summary |
|---|---|---|---|
| `VAL-E101` | Control | `2` | Write gate refused (`socket != 0600` or runtime dir world-writable) |
| `VAL-E102` | Control | `2` | `/run/vallum` unreadable by desktop/web user (missing group access) |
| `VAL-E103` | Control | `2` | Control socket silent (`ENOENT` / `ECONNREFUSED` — daemon stopped) |
| `VAL-E201` | Config & Keys | `2` | Private key permissions too open (`mode != 0600`) |
| `VAL-E202` | Config & Keys | `2` | Config ownership / `CAP_DAC_OVERRIDE` denied (`chown root:root`) |
| `VAL-E203` | Config & Keys | `2` | TOML / `allowed_ips` validation failure |
| `VAL-E301` | Daemon & OS | `1` | Seccomp syscall filter violation (`status=31/SYS`) |
| `VAL-E302` | Daemon & OS | `1` | TUN creation refused (`CAP_NET_ADMIN` / `/dev/net/tun`) |
| `VAL-E303` | Daemon & OS | `1` | Polkit / systemd authorization denied or dismissed |
| `VAL-E401` | Egress & Leaks | `1` | Full-tunnel DNS leak detected |
| `VAL-E402` | Egress & Leaks | `1` | Full-tunnel IPv6 egress leak detected while `vallum-guard` is inactive |
| `VAL-E403` | Egress & Leaks | `1` | Full-tunnel configured (`0.0.0.0/0`), but host is `UNPROTECTED` |
| `VAL-E501` | Crypto | `2` | Cryptographic suite (`0x0003` tri-hybrid) or `vallum1:` line mismatch |
