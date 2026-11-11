# ADR-0030: Admission control on the fragment path

**Date**: 2026-11-11
**Status**: proposed
**Deciders**: Vallum maintainers

## Context

An initiation is `~5-9 KB` of hybrid post-quantum material, so it is fragmented,
so the fragment layer must parse and buffer a datagram **before** anything about
it can be authenticated. That ordering is unavoidable: `mac1` lives in the
message the fragments belong to.

The consequence, measured in `docs/security-redteam.md` (H1): one captured
1452-byte fragment, replayed forever, costs the responder **26 µs** per packet.
At 31k pps — one laptop with a Python socket — the daemon burned 75% of its only
loop thread, which is also the thread carrying user traffic. No token, no key, no
account, and the bytes never expire.

The enroll service already answers this class: `RATE_PER_SECOND` and
`RATE_LIMIT_SOURCES` run a per-source limiter **before** its cookie gate, sized
so a spoofed source is cheap to refuse. The tunnel path has nothing between the
socket read and reassembly.

Constraints that shape the decision:

- The socket is shared by inits, data and junk; whatever we add is on the data
  path too, so it must be O(1) and allocation-free in the common case.
- A source **IP** is the only stable key. Source port changes across NAT rebinds
  and daemon restarts, and an attacker chooses their port freely.
- A real peer bursts: a restart re-sends every fragment of an initiation, and a
  bulk transfer sends up to `MAX_OUTER_DATAGRAM`-sized fragments back to back.
  A bucket that a legitimate peer trips is worse than no bucket.
- Silent drops are the house style for unauthenticated traffic (no oracle), so
  the drop must be counted or the finding just becomes L6 again.

## Decision

1. **A per-source token bucket runs before reassembly**, keyed on source IP,
   with a bucket large enough to carry one full initiation plus a burst of data
   (~20 packets) and a refill rate of ~50/s per source. Over-rate datagrams are
   dropped and counted as `vallum_fragments_rate_limited`; they are not queued.
2. **The map is bounded** (`RATE_LIMIT_SOURCES`-style, 4,096 sources) and evicts
   the least-recently-seen, so rotating source IPs cannot grow it without bound.
3. **The bucket is not a policy gate.** It never refuses an authenticated
   session's data on the basis of the bucket alone if the source has a peer:
   the peer's own `allowed_ips` and session state remain the authority. The
   bucket only decides whether a datagram is worth parsing now.

## Alternatives Considered

### Alternative 1: Cookie gate before reassembly
- **Pros**: cheapest possible refusal, and the mechanism already exists.
- **Cons**: cookies are answered per *message*, and a message is many fragments —
  so a cookie would have to be requested on a fragment, which no peer knows how
  to answer mid-initiation. It also adds a round trip to every cold start.
- **Why not**: it changes the protocol for a defence the bucket gives for free.

### Alternative 2: Nothing; accept it and document the exposure
- **Pros**: no new state, no new failure mode.
- **Cons**: the attacker's cost is one captured packet and a Python loop; ours is
  the only thread we have. The ceiling is low enough to reach from one host.
- **Why not**: 26 µs per attacker byte is a bad exchange rate for a product whose
  own capacity claim is a few thousand peers.

### Alternative 3: Kernel-side filtering (BPF / XDP)
- **Pros**: refuses before the copy to userspace; orders of magnitude cheaper.
- **Cons**: a second policy surface outside the daemon, per-interface loading,
  and a capability story of its own. It also cannot see state the daemon holds.
- **Why not**: right answer eventually, wrong size for a pre-alpha. Recorded as
  the successor if the bucket proves insufficient.

## Consequences

### Positive
- A replay flood costs the attacker more than it costs us, so the ceiling stops
  being "one laptop".
- The drop is visible: an operator can tell a flood from a quiet night (fixes L6
  for the fragment path).
- The bucket is the first place any future admission policy lands, including the
  kernel one in Alternative 3.

### Negative
- A peer behind a CGNAT shares its bucket with strangers; the bucket must be
  generous enough that a busy NAT does not starve a quiet peer.
- New state on the data path: one hash lookup per datagram.

### Risks
- **A legitimate burst trips it** → size for one initiation plus `MAX_INJECTION_BURST`
  and prove it with a test that runs a bulk transfer at line rate.
- **Eviction under churn drops a live peer's allowance** → evict least-recently
  seen, and treat a peer with a session as sticky.
- **The bucket hides a real problem** (a peer that genuinely needs more) → expose
  the counter in `doctor` next to the handshake drops, so it reads as a symptom
  and not a background hum.
