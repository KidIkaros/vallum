# ADR-0032: The admission allowance belongs in the socket reader

**Date**: 2026-11-11
**Status**: accepted and implemented
**Deciders**: Vallum maintainers

## Context

ADR-0030 put a per-source allowance in front of reassembly and measured the
result honestly: 26.3 → 19.4 µs of server CPU per replayed 1452-byte fragment, a
factor of 1.36, not the order of magnitude the phrase "rate limited" suggests.
The ADR named the reason — a one-byte datagram refused outright still cost
8.7 µs — and named the successor: the cost is the path, not the parse, so the
refusal has to happen earlier.

The path between the socket and the loop is: `recv_from` into a shared buffer,
`buf[..n].to_vec()` (an allocation per datagram), an `mpsc` send, and a loop
wake-up. A datagram that will be refused pays all four.

## Decision

**Move the allowance into the socket reader thread**, before the allocation and
before the channel hop. The reader owns its own bucket; it needs two things the
loop owns, and both are handled explicitly:

- **The clock**, shared as `Arc<dyn TimeSource>` — the same clock the loop uses,
  so the bucket and the peer ages cannot disagree about what "now" is.
- **The set of peer endpoints**, shared as `Arc<Mutex<HashSet<SocketAddr>>>` and
  refreshed by the loop **on its idle tick** (~100 ms), not per packet. A peer
  that has just roamed may therefore be bucketed for up to one tick. Its burst
  is 64 datagrams, which is more than a roaming peer sends before the tick, so
  the practical effect is nothing; the theoretical one is stated rather than
  hidden.

The refusal is counted in an `AtomicU64` the reader increments directly, so the
counter survives the move without a channel round trip.

## Alternatives Considered

### Alternative 1: keep the allowance in the loop, optimise the loop
- **Pros**: no shared state, no staleness window.
- **Cons**: the allocation and the channel hop happen before the loop sees the
  datagram, so the floor stays at 8.7 µs.
- **Why not**: it optimises the part that is not the cost.

### Alternative 2: kernel-side filtering (XDP / eBPF)
- **Pros**: refuses before the copy to userspace; the only way past the kernel
  receive path.
- **Cons**: a second policy surface, per-interface loading, a capability story,
  and it cannot see the daemon's peer table.
- **Why not**: still the right long-term answer and still the wrong size; this
  ADR takes the cheap step that does not foreclose it.

### Alternative 3: per-peer exemption looked up in the daemon
- **Pros**: exact, no snapshot.
- **Cons**: the reader would need the device behind a lock, which serialises the
  data path with the loop.
- **Why not**: worse than a 100 ms snapshot.

## Consequences

### Positive
- **26.3 → 11.1 µs per replayed fragment** (measured on the production server,
  same 1452-byte capture, same 5 s burst): the attacker's ceiling per core goes
  from ~38k to ~90k pps.
- A one-byte flood refused in the reader costs **6.5 µs** — that is the floor
  now, and it is the kernel's receive path plus per-datagram bookkeeping, not
  anything this daemon parses.

### Negative
- The reader holds a `Mutex` on the endpoint set per datagram. Uncontended, it
  is cheap; under a flood it is the second-largest cost after the syscall.
- A roaming peer can be bucketed for one tick. Sized so that cannot matter.

### Risks
- **The snapshot goes stale in a way that matters** → the burst is 64 and the
  tick is 100 ms; if a peer is ever observed being bucketed after a roam, the
  fix is to refresh on peer-table change rather than on the tick.
- **`socket.current()` per packet is now a visible share of the floor** → the
  next measurement should attribute it; caching the socket for the reader's hot
  loop is a candidate, and it is a smaller change than this one.
- **The floor is the kernel** → further progress requires Alternative 2, and
  that is a different decision.
