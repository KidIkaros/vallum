# ADR-0036: A session's rekey is spread, so a fleet does not rekey in lockstep

**Date:** 2026-11-12
**Status:** proposed
**Deciders:** the maintainer
**Relates to:** ADR-0031 (stale timestamp scope), ADR-0026 (censorship resistance), ADR-0032 (reader-thread admission)

## Context

The premortem's read-only investigators were asked what breaks first at scale.
The answer was not CPU and not memory. It was this:

> The rekey trigger is exactly `established_at + 120 s` with no spread
> (`crates/vallum-core/src/timer.rs:249`). `REKEY_JITTER_MS` is applied to the
> *retransmit* delay, not to the trigger. Peers enrolled or rebooted together
> therefore rekey in the same instant, forever, every 120 s.

A peer with no jitter is not a bug in one peer's timing; it is a fleet-wide
event. A thousand clients that booted together send a thousand initiations to
the server in the same second, and:

- the server's reassembly table holds **sixteen concurrent handshakes**
  (`crates/vallum-tunnel/src/segment/reassembly.rs:69`, `MAX_REASSEMBLIES`);
- when it is full, the oldest entry is evicted, and the evicted message's
  later fragments open a *second* entry for the same id — so that message is
  split across two entries and never completes;
- a handshake that stalls retransmits every 5 s
  (`crates/vallum-core/src/timer.rs:38`), so the herd becomes a standing
  retransmission storm rather than a two-minute event.

The `vallum-core` module doc already stated the intent — "a responder rekeys
all its peers on the same schedule, so without jitter a fleet synchronises into
bursts" (`crates/vallum-core/src/timer.rs:49`) — but the jitter landed on the
retransmit delay, where it does not spread the trigger at all.

## Decision

**A session's rekey trigger carries a bounded, per-session spread.**

- `REKEY_SPREAD_MS = 20_000`. A session's rekey fires at
  `established_at + 120 s + offset`, where `offset` is drawn once per session
  in `0..=20 s`.
- The spread moves the rekey **later, never earlier**: the key's life is not
  shortened by it.
- The randomness is the **caller's**, as with the existing
  `REKEY_JITTER_MS`: `vallum-core` has no RNG. The device draws the offset once
  per session (`crates/vallum-tunnel/src/device/timer.rs`), which already owns
  `Randomness` for the retransmit jitter.
- A new session draws a new offset, so a peer that rekeys repeatedly does not
  always rekey at the same offset.

### The margin survives it

The numbers above interact deliberately, and the margin is the point
(`crates/vallum-core/src/timer.rs:26`): the rekey starts at 120 s, the key is
spent at 180 s, and the handshake has **60 s — twelve 5 s retransmit
intervals** — to complete. "Running out of key must be the peer's fault, not a
scheduling coincidence."

With the spread, the rekey starts no later than 140 s, so the margin is **at
least 40 s — eight retransmit intervals**. A handshake costs ~80 ms, so eight
intervals is ample; the margin is asserted by a test rather than by comment.

## What this does not do

**It does not raise the reassembly table.** Sixteen concurrent handshakes is a
deliberate memory-versus-DoS bound — the module calls it "a hard bound on the
hostile one", and the whole table is 256 KiB at the ceiling. Raising it to 256
would be 4 MiB, and it is a decision about what an unauthenticated peer can
make the device allocate. That is a separate argument, and it is not made
here.

**It does not make the 2,000-peer target reachable.** The spread reduces the
probability of a herd; it does not change the two ceilings that actually bind
a mass re-establishment — sixteen concurrent inbound initiations, and roughly
18 handshakes/s of loop-thread CPU. `docs/requirements.md` now says so in those
terms.

## Alternatives considered

### Spread the rekey *earlier* rather than later
- **Pros:** the margin would grow rather than shrink.
- **Cons:** it shortens the key's life, which is the thing the 120 s figure
  exists to bound.
- **Rejected:** the margin is worth more than a slightly larger spread.

### Spread across a much wider window (60 s and up)
- **Pros:** a flatter curve.
- **Cons:** it would consume the entire margin, leaving no retransmit
  intervals — the rekey could not complete at all under load.
- **Rejected:** the margin is not available for spreading.

### Draw the offset from the peer's identity instead of the RNG
- **Pros:** no RNG plumbing, and the spread is stable per peer.
- **Cons:** the rekey time becomes predictable to anyone who knows the peer's
  key — a small but real reduction in the secrecy of key rotation.
- **Rejected:** the device already owns randomness for exactly this purpose.

## Consequences

- A fleet's rekeys spread over 20 s instead of landing on one instant. The
  number of *simultaneous* initiations at a server drops by roughly the ratio
  of the fleet size to the spread.
- One extra `draw_u64` per session, in the device's timer tick.
- The rekey window for a single peer is unchanged (120 s) unless the offset is
  drawn, and the key's life is unchanged at 180 s.

## Tests

Four tests in `crates/vallum-core/src/timer.rs`:

- `a_rekey_spread_moves_the_trigger_later_not_earlier`
- `a_rekey_spread_never_eats_the_margin` (asserts eight retransmit intervals
  remain)
- `a_rekey_spread_is_bounded_by_the_caller`
- `a_new_session_draws_a_new_spread`
