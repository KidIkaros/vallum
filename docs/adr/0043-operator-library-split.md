# 0043. Split the operator-facing library from the Linux daemon

Status: steps 1-3 deferred; step 4 is the Android prerequisite (not yet scheduled)

## Context

`vallum-gui` links the whole `vallum` crate (`default-features = false`,
`features = ["qr"]`). Measured on 2026-11-14, the GUI reaches into about 25
distinct `vallum::` paths: `control`, `uapi`, `qr_frames`, `keys`, `bundle`,
`enroll`, `config`, `config_edit`, `guidance`, `entropy`, `form`,
`host::{probes,paths}`, `commands::control`, and one `net` function
(`tune_path_mtu_host_with_counters`).

Only `uapi` and `qr_frames` are pure protocol. The rest is the operator
surface (config, keys, bundle, enroll, control client), which is also not
Linux-kernel specific. What the GUI does not need is the daemon: `run`,
`tun`, `hostnet`, `sandbox`, `privileges`, `policy`, and the carriers in `net`.

An Android `VpnService` build (see `plan-packaging-desktop-android-2026-11-14.md`)
cannot compile the daemon half (`tun2`, `netlink`, `seccompiler`, `nix`
mounts), and a desktop `.deb` pays for it in size and build time.

## Measured dependency graph (2026-11-15)

Crate-internal imports per operator module, measured with `grep crate::`:

| Module | Depends on |
|---|---|
| `entropy`, `bundle` | nothing |
| `form`, `keys` (also `error`, `host`) | `keys` / `error`, `host` |
| `config` | `error`, `keys`, `logging`, **`privileges`, `sandbox`, `tun`** |
| `config_edit`, `guidance` | `keys` / `config` |
| `uapi` | `keys`, `config::Carrier`, **`run::LoopStats`** |
| `control` | `clock`, `config`, `keys`, `uapi`, **`net`, `run`** |
| `enroll` | `config`, `entropy`, `keys`, `host`, **`commands`, `tls_quic`** |

The first draft of this ADR called `uapi` "pure protocol" and proposed
extracting it first. That was wrong: it needs `config::Carrier` and the
daemon's `run::LoopStats`, and `config` itself reaches into `privileges`,
`sandbox` and `tun`. No operator module can leave first; the daemon-only
types they touch have to be untangled before any crate boundary is cut.

## Decision (proposed)

Cut the dependencies, then the crates, each step shippable alone:

1. **Move the shared data types down.** `LoopStats` and `Carrier` (plain
   data, no behaviour) move to `vallum-core` or `vallum-config`; the daemon
   re-exports them. After this `uapi` no longer imports `run`.
2. **Make `config` stop importing the daemon.** Whatever `config` takes from
   `privileges`, `sandbox`, `tun` (validation helpers, constants) moves with
   the data or is injected; `enroll`'s use of `commands` and `tls_quic` gets
   the same treatment.
3. **Then extract `vallum-operator`**: `config`, `config_edit`, `keys`,
   `bundle`, `enroll`, `control` client, `uapi`, `qr_frames`, `guidance`,
   `form`, `entropy`, `host::{probes,paths}`. The daemon keeps `run`, `tun`,
   `hostnet`, `sandbox`, `privileges`, `policy` and the carriers, and
   re-exports the operator crate so existing paths compile during the move.
4. **`vallum-engine`** (Android): carriers and tunnel loop behind a TUN-fd
   and a `protect(socket)` trait, with no netlink/nft/systemd.

`net::mtu` (already extracted) is the GUI's one `net` use and is pure
computation, so it moves with step 3 rather than dragging the carriers along.

## Why steps 1-3 are deferred (2026-11-15)

Measured with `cargo tree -p vallum-gui -e normal`: the GUI has 504 unique
dependencies, 48 of them Tauri/WebKit/GTK. The daemon-only crates it reaches
through `vallum` (`tun2`, `netlink-*`, `seccompiler`, `quinn-proto`, `rcgen`)
are a handful by comparison. Steps 1-3 touch about 147 `uapi`/`qr_frames` use
sites plus `commands/*`, `run` and `control`, for a benefit that is small next
to the Tauri weight.

An Android `VpnService` app does not link the operator layer or `vallum-gui`;
it needs the engine (step 4). Steps 1-3 therefore do not block Android.

**Trigger to revisit steps 1-3:** a measured desktop problem, such as GUI
build time or `.deb` size that a user or CI run actually complains about.
Step 4 is scoped when the Android work starts.

## Gate for each step

`cargo tree -p vallum-gui` shows none of `tun2`, `netlink-*`, `seccompiler`
after step 2 (the number to record in `docs/qa/`), and the existing
`scripts/gui-smoke.sh` and `accept-*` gates pass on `wingman-vps`.
