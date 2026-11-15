# 0043. Split the operator-facing library from the Linux daemon

Status: proposed (not yet implemented)

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

## Decision (proposed)

Split along the seam the GUI already draws, in this order, each step shippable
alone:

1. `vallum-uapi`: `uapi` + `qr_frames` (smallest, no dependency on the rest).
2. `vallum-operator`: `config`, `config_edit`, `keys`, `bundle`, `enroll`,
   `control` (client), `guidance`, `form`, `entropy`, `host::{probes,paths}`.
3. `vallum` keeps the daemon and re-exports both so `crate::` paths in
   commands keep compiling during the move.
4. `vallum-engine` (later, Android): the carriers and tunnel loop behind a
   TUN-fd and a `protect(socket)` trait, with no netlink/nft/systemd.

`net::mtu` (extracted in this change) is the first piece: the GUI's one `net`
use is pure computation, so it moves with step 2 rather than dragging the
carriers along.

## Why not do it now

Step 2 moves modules that `commands/*`, `run`, and `control` import by
crate-relative path, plus their tests. That is a multi-commit change with
a feature-matrix check on `wingman-vps` after each step, not something to
land unreviewed beside a release.

## Gate for each step

`cargo tree -p vallum-gui` shows none of `tun2`, `netlink-*`, `seccompiler`
after step 2 (the number to record in `docs/qa/`), and the existing
