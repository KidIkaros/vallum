# ADR-0024: A desktop UI for the operations console

**Date**: 2026-11-05
**Status**: proposed
**Deciders**: Vallum maintainers

## Context

ADR-0008 shipped `vallum tui` for the terminal and deferred a GUI on the grounds
that the terminal is where the daemon runs. That is still true of the daemon and
still false of the operator: the palette is 33 commands, and everything — the
peer table, invite tokens, rotation, service control, logs — assumes a terminal
and a keymap. Nothing exists for the person evaluating Vallum from a screenshot,
and nothing exists for an operator who would rather click a rotate button than
remember that `R` is rotate and `F` is finalize.

Three constraints from the existing design shape what a UI can be.

The control plane is a 0600 Unix socket, same-user, and its accept loop is
**serial**: one connection at a time, a 5 s request timeout, a 64 KiB cap, and
every mutation on the thread that owns the device. A UI that polls is fine; a UI
that holds a connection open, or polls from several places at once, becomes an
outage of the plane it is displaying.

The protocol is the WireGuard-style UAPI (`get=1` / `set=1`, key/value lines)
plus Vallum-prefixed fields, parsed by `crate::uapi`, with all mutation funnelled
through `crate::control`. Any second implementation of that parsing is a second
place for hex and prefix handling to be wrong, in a security tool.

The `aarch64` artifacts come from `cargo zigbuild`, which cross-links Rust and
nothing else. A WebView needs the *target's* `libwebkit2gtk` at link time, so an
arm64 GUI cannot be produced by the current release leg without a real arm
builder or an emulated container.

## Decision

Build the UI as a **Tauri v2** application, `vallum-gui`, in its own crate, whose
Rust host reuses `crate::uapi` and `crate::control` rather than reimplementing
the protocol, and whose front-end is static assets with no remote content. The
GUI ships for **x86_64 only**; `aarch64` keeps the TUI and CLI. Scope is parity
with the TUI's command set, delivered in the phases below rather than at once.

### The host's surface

Every screen has one named source; nothing is invented in the front-end.

| Screen | Data | Source |
|---|---|---|
| Device card: interface, address, listen port, suite, fwmark | `vallum_interface`, `vallum_address`, `listen_port`, `vallum_suite`, `fwmark` | `get=1` |
| Peer table: key, endpoint, handshake age, tx/rx | `public_key`, `endpoint`, `last_handshake_time_sec`/`_nsec`, `tx_bytes`, `rx_bytes` | `get=1` |
| Peer health beyond handshake age | liveness/`blocked` vs `LEAKING` | `vallum status`, `vallum metrics` |
| Peer CRUD, rotation window, allow-list | `set=1` transactions | `crate::uapi::Set` |
| Invite / bundle / QR | one-time token, `.vallum-bundle` | `vallum enroll`, `tui/bundle.rs`, `tui/qr.rs` |
| Service state, start/stop | unit name, `systemctl` argv | same-argv spawn as the TUI |
| Logs | `journalctl -u vallum@<stem> -n 200 -o cat` | same-argv spawn |
| Preflight failures | doctor checks | `vallum doctor` |

### Phases

1. **Read-only.** Device card, peer table, handshake ages, doctor results. One
   poll per second while the window is focused, backing off to 10 s unfocused
   and stopping when hidden. No mutations, so the serial accept loop keeps its
   current latency budget.
2. **Peer writes.** Add, invite, edit, rotate, finalize, remove — the same
   `set=1` transactions the TUI sends, with the same confirmations.
3. **Service and logs.** Start/stop via `systemctl`, log pane, ping a peer.
4. **Config editing.** Structured forms for the fields the UAPI can set;
   routes/DNS need a text editor with validation, a diff, and an explicit apply,
   because `$EDITOR` has no web equivalent and a bad `routes` line is an outage.
5. **Packaging.** Tauri's bundler output folded into `scripts/release.sh` beside
   the tarball and the `.deb`/`.rpm`, the `$HOME`-leak preflight extended to the
   GUI binary and bundle, and `docs/` updated.

## Alternatives Considered

### Alternative 1: Electron
- **Pros**: arm64 needs no cross-link — the runtime is a prebuilt download, so
  both architectures package without a compiler; the most mature tooling.
- **Cons**: the protocol is reimplemented in JS or reached by shelling out to
  `vallum`; ~100 MB per architecture against today's 3.4 MB tarball; Node and
  npm in CI and `npm audit` beside `cargo deny`; Chromium CVE response becomes
  this project's job.
- **Why not**: a second parser of the UAPI, in the language least suited to
  getting hex right, is the exact failure this project designs against. The arm
  packaging advantage is real but buys an artifact the TUI already covers.

### Alternative 2: egui / eframe
- **Pros**: pure Rust, no web stack, likely buildable by `cargo zigbuild` for
  both architectures, smallest dependency addition.
- **Cons**: a retained-mode immediate UI means hand-writing layout, text
  wrapping, focus and accessibility that a WebView gives for free; no front-end
  iteration by anyone who is not editing Rust.
- **Why not**: the point of a GUI here is presentation quality and speed of
  iteration, which is where egui is weakest.

### Alternative 3: A browser UI served by a local process
- **Pros**: usable from another machine; no packaging per architecture.
- **Cons**: adds a loopback HTTP surface and a second authentication story to a
  tool whose whole trust model is "the socket is 0600 or it does not exist";
  DNS-rebinding and CSRF become this project's problems.
- **Why not**: it widens the attack surface of a security product to avoid a
  build problem.

## Consequences

### Positive
- One implementation of the protocol and of key handling: the GUI cannot drift
  from the CLI in what a request means.
- `cargo deny` and the advisories job keep covering the whole UI's Rust side.
- The release stays two Rust binaries plus one GUI bundle, and the GUI's
  privilege model is the TUI's: spawn `systemctl`/`journalctl` with argv arrays
  and show the exact command when privilege is missing.

### Negative
- Building the GUI needs `libwebkit2gtk-4.1-dev`, `libgtk-3-dev` and
  `cargo-tauri`, none of which are on the development host or the runner today.
- The GUI artifact is x86_64 only; arm64 remains a terminal experience.
- A second packaging path in `release.sh`, and a second artifact to sign and
  list in `SHA256SUMS`.

### Risks
- **The serial control socket.** A 1 Hz poll is one connection per second; a
  forgotten window or a detail view that polls independently multiplies that and
  can push a mutation behind the timeout. Mitigation: a single polling task in
  the host, focus-aware cadence, and no long-lived socket use until the daemon
  grows a push channel — which is a daemon change, not a UI change.
- **Hostile strings in a WebView.** Peer names and endpoints are
  attacker-influenced. A WebView with IPC access turns an XSS into privilege
  escalation. Mitigation: no inline script, a strict CSP, message passing over a
  typed command list rather than arbitrary evaluation, and the TUI's existing
  hostile-input tests extended to the boundary.
- **Secrets.** The private key and PSK must never cross the IPC boundary. The
  host strips them before serialising, and a test asserts the stripped fields
  are absent rather than merely unrendered.
