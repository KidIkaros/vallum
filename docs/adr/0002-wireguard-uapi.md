# ADR-0002: WireGuard-style UAPI over a 0600 Unix socket

**Date**: 2026-10-19
**Status**: accepted
**Deciders**: Vallum maintainers

## Context

Vallum was startup-only: a TOML file, no status, no live peer changes. WireGuard
operators expect `wg show`, `set`, `setconf`, and `syncconf`. Vallum's public
keys are suite-sized (2 374 bytes for the tri-hybrid suite), so WireGuard's
fixed 32-byte field cannot be used verbatim.

## Decision

Serve a WireGuard userspace-UAPI key/value protocol (`get=1` / `set=1`) on a
Unix socket configured by `[interface] control`, mode 0600. Keep WireGuard's key
names for the common surface; `public_key` is suite-sized, while `private_key`
(the seed) and `preshared_key` are 32 bytes. Apply every mutation on the loop
thread via `Input::Control`. The CLI is `show`, `setconf`, `addconf`,
`syncconf`, and `showconf`.

## Alternatives Considered

### Alternative 1: Generic netlink (kernel-style UAPI)
- **Pros**: native Linux tooling; kernel-mediated access control.
- **Cons**: requires a kernel component or a netlink protocol; not a userspace
  transport; large implementation.
- **Why not**: the daemon is userspace; a Unix socket is the natural boundary.

### Alternative 2: Status file only
- **Pros**: simplest; no socket permissions to manage.
- **Cons**: read-only, stale, no live peer mutation.
- **Why not**: the gap was live control, not just status.

### Alternative 3: TOML-only with restart
- **Pros**: one source of truth; no new protocol.
- **Cons**: every change drops sessions; no status or counters.
- **Why not**: operational parity requires live changes.

### Alternative 4: WireGuard's 32-byte key fields verbatim
- **Pros**: exact `wg` UAPI compatibility.
- **Cons**: Vallum's KEM public key is 2 374 bytes; truncating or mapping it
  would invent a second identity.
- **Why not**: the key must be the real key; tooling adapts to its length.

## Consequences

### Positive
- Status, live peers, counters, and one local trust boundary.
- Familiar key names and CLI verbs.
- The socket is the same trust boundary as the private key (0600, same user).

### Negative
- No kernel `wg` tooling integration.
- Suite-sized public keys complicate generic UAPI clients.
- `get` returns the private seed to the socket owner; `show` hides it by default.

### Risks
- Socket mode or ownership mistakes; mitigated by 0600 and a permission test.
- Malformed input; mitigated by a fail-closed parser and property tests.
