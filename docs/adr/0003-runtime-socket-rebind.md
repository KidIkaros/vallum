# ADR-0003: Runtime socket rebind with a generation-checked SharedSocket

**Date**: 2026-10-19
**Status**: accepted
**Deciders**: Vallum maintainers

## Context

`listen_port` and `fwmark` were startup-only: a runtime change returned
`EOPNOTSUPP`, and a restart dropped every session. Operators need to move a port
or apply a policy mark without tearing down the tunnel. The UDP reader blocks on
the socket, so replacing it requires waking the reader without a race.

## Decision

`SharedSocket` holds one `Mutex<SocketState { current, generation }>`. The UDP
reader uses a 250 ms read timeout; after each timeout it compares the generation
and re-reads the socket if it changed. A `set` binds the new socket first and
swaps it only on success, updating the control context and the generation. A
failed bind returns `EPERM`, `EADDRINUSE`, or `EADDRNOTAVAIL` and leaves the
running socket untouched. `vallum_can_set_listen_port` and
`vallum_can_set_fwmark` are true.

## Alternatives Considered

### Alternative 1: Restart-only
- **Pros**: simple; no shared state.
- **Cons**: every port or mark change drops all sessions.
- **Why not**: the requirement was live reconfiguration.

### Alternative 2: Privileged helper process
- **Pros**: keeps rebind outside the unprivileged loop.
- **Cons**: new process, IPC, lifecycle, and another trust boundary.
- **Why not**: the daemon already holds the capability at startup; the swap is
  small enough to stay in-process.

### Alternative 3: `SO_REUSEPORT` or multiple sockets
- **Pros**: avoids swapping the reader's socket.
- **Cons**: multiple binds, load balancing, and the old socket remains open;
  not a single logical listen address.
- **Why not**: the control plane needs one authoritative socket.

### Alternative 4: Close the old fd to unblock the reader
- **Pros**: immediate wake-up.
- **Cons**: the reader sees `EBADF` and must distinguish a swap from a failure;
  closing an fd another thread is reading is racy.
- **Why not**: the generation check is deterministic and keeps error handling
  ordinary.

## Consequences

### Positive
- Live port and mark changes; the tunnel survives (peers roam to the new source).
- One owner for the socket and its generation; no torn state.
- Failed rebinds leave the old socket serving.

### Negative
- Up to 250 ms before the reader switches; the reader wakes four times a second.
- A mark change or privileged port needs `CAP_NET_ADMIN`; after a privilege drop
  it fails with `EPERM` unless the service keeps the ambient capability.

### Risks
- A partial swap would lose packets; mitigated by bind-then-swap and the
  tail-retry send path. The e2e rebinds at runtime and pings afterwards.
