# ADR-0006: Batch UDP sends with sendmmsg; defer GSO/GRO

**Date**: 2026-10-19
**Status**: accepted
**Deciders**: Vallum maintainers

## Context

The loop sent one datagram per `send_to`. WireGuard uses batching and GSO/GRO,
and Vallum's crypto is only a few microseconds per packet, so syscalls dominate
at realistic rates. `tun2` exposes `IFF_VNET_HDR` through
`PlatformConfig::vnet_hdr`, but Linux rejects `queues != 1`, and `tun2` has no
`TUNSETOFFLOAD`; GSO also needs virtio-header, checksum, and segmentation
handling in the daemon.

## Decision

Batch UDP sends. `DatagramSocket::send_many` defaults to a loop;
`UdpTransport` uses `sendmmsg` on Linux. The loop collects the datagrams one
event produced, sends them in one call, and retries the unsent tail
individually so the per-destination `EMSGSIZE` warning survives. `show` reports
`vallum_batching=true` on Linux. GSO/GRO is not implemented; `vallum_offload` is
false.

## Alternatives Considered

### Alternative 1: Keep one `send_to` per datagram
- **Pros**: simplest; per-datagram errors are exact.
- **Cons**: one syscall per packet.
- **Why not**: a burst (handshake fragments, several peers) can be one call.

### Alternative 2: `recvmmsg` receive batching
- **Pros**: symmetric with send batching.
- **Cons**: per-message addresses and buffer management; the reader already has
  a timeout/generation loop.
- **Why not**: the send path is the larger, simpler win; receive batching can
  follow.

### Alternative 3: GSO/GRO
- **Pros**: the largest throughput gain; fewer copies and larger writes.
- **Cons**: needs `TUNSETOFFLOAD` plus virtio-header, checksum, and
  segmentation handling; `tun2` does not provide the offload call.
- **Why not**: a data-plane project, not a tuning tweak; recorded as the next
  step in `performance.md`.

### Alternative 4: Multi-queue
- **Pros**: parallel readers.
- **Cons**: Linux `tun2` rejects `queues != 1`; the loop is single-threaded, so
  the crypto would still serialize.
- **Why not**: blocked by the crate and by the loop model.

## Consequences

### Positive
- One send syscall per burst instead of one per datagram.
- Per-destination `EMSGSIZE` is preserved by the tail retry.
- No wire or crypto change.

### Negative
- Batching only helps bursts; a single datagram still costs one syscall.
- No GSO/GRO, so the largest win remains unavailable.
- A partial `sendmmsg` falls back to individual sends for the tail.

### Risks
- Duplicate sends if the tail retry misunderstood the count; `sendmmsg` returns
  the exact number sent, and the e2e's narrow-MTU phase exercises the path.
