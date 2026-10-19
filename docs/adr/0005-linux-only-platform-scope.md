# ADR-0005: Linux-only platform scope for this release

**Date**: 2026-10-19
**Status**: accepted
**Deciders**: Vallum maintainers

## Context

The daemon uses Linux-specific mechanisms: `tun2` for the TUN device, netlink
for address assignment, `prctl(PR_SET_NO_NEW_PRIVS)`, `SO_MARK`,
`IP_MTU_DISCOVER`, and `IPV6_DONTFRAG`. There is no macOS, Windows, or BSD
binary. Cross-compiling the daemon from Linux fails in the SDK's C dependencies
(`blake3`, `zstd-sys`) because the host `cc` lacks Apple flags; the pure-Rust
crates do check for `x86_64-apple-darwin`.

## Decision

Linux is the supported target for this release. macOS, Windows, and BSD are
staged, not supported: `vallum --version` prints `(linux-only)`, and
`docs/proof/platforms.md` records the per-OS seams and the order (macOS first).
CI has a gating `macos-inner` check for the protocol crates and an experimental
`macos-daemon` check on a macOS runner.

## Alternatives Considered

### Alternative 1: Cross-compile and check the daemon from Linux
- **Pros**: no extra runner.
- **Cons**: the SDK's C dependencies need Apple clang; the result would not be a
  representative build.
- **Why not**: a check that cannot compile the dependencies proves nothing.

### Alternative 2: Port macOS first now
- **Pros**: `tun2` has a macOS backend; the closest target.
- **Cons**: needs per-OS address, privilege, and socket modules, plus a macOS
  runner for runtime tests; unverified here.
- **Why not**: the honest deliverable is the tier and the CI signal, not an
  untested binary.

### Alternative 3: Userspace backend (wireguard-go style)
- **Pros**: portable across platforms.
- **Cons**: a second data plane; loses the kernel TUN semantics and the current
  MTU/segmentation model.
- **Why not**: a rewrite, not a port.

### Alternative 4: Windows or BSD first
- **Pros**: also real targets.
- **Cons**: more OS policy differences than macOS; no runner here.
- **Why not**: macOS is the staged first target.

## Consequences

### Positive
- The support tier is explicit before a user builds.
- The protocol crates are checked on macOS in CI.
- The platform seams are documented with the order of work.

### Negative
- No cross-platform binary this release.
- `SO_MARK` and the Linux socket options are unavailable elsewhere.
- `vallum-quick` remains Unix-shell based.

### Risks
- Linux assumptions could leak into config or docs; `platforms.md` and the
  `macos-daemon` job are the early warning.
