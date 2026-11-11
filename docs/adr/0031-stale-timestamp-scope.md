# ADR-0031: A stale initiation is refused only while a session exists

**Date**: 2026-11-11
**Status**: accepted and implemented
**Deciders**: Vallum maintainers

## Context

The responder keeps a per-peer high-water mark of initiation timestamps and
refuses any initiation that is not strictly newer. It is the defence against
replaying a captured initiation to tear down or displace a session.

The refusal is silent, by design — an unauthenticated datagram gets no oracle —
and it was unconditional. A peer whose clock stepped **backwards** therefore
could not re-establish at all: the laptop that resumed from suspend, the machine
whose NTP corrected by a few seconds, the client restarted with a stale RTC. Its
retries carried timestamps the guard had already seen, every one was dropped
without a reply, and the tunnel stayed down until the clock caught up — an
unbounded outage with no signal at either end (security-redteam.md M3).

Measured, before the change: a client restarted with a frozen clock retries every
five seconds and the link never goes quiet; the same client with the clock moved
on re-establishes in one round trip.

## Decision

**Refuse a stale timestamp only when the peer still has a live session.** With
no session there is nothing for a replay to displace: the initiation can only
create the session its holder could have created anyway, and `mac1` already
gates the work. The lockout becomes bounded by the session's own lifetime
(`REJECT_AFTER_TIME`, 180 s) instead of unbounded.

The refusal stays silent and is still counted (`vallum_handshake_dropped_stale`),
so the policy change does not cost the observability added in `ad493ef`.

## Alternatives Considered

### Alternative 1: accept any timestamp, always
- **Pros**: no lockout ever, one less state variable.
- **Cons**: removes the replay defence entirely — a captured initiation can
  displace a live session at will.
- **Why not**: that is the property the guard exists for, and a session under
  attack is a worse failure than one that needs 180 s to come back.

### Alternative 2: widen the window instead (accept timestamps within N seconds)
- **Pros**: no dependency on session state.
- **Cons**: N must exceed the worst clock skew anyone will ever have, which is
  unbounded; and any N large enough to help is large enough to make replays of
  that age valid.
- **Why not**: it trades a bounded lockout for a widened replay window and still
  fails the pathological case.

### Alternative 3: keep the guard and fix the clock
- **Pros**: no code change; the invariant stays simple.
- **Cons**: the daemon cannot fix a clock it does not own, and the user sees a
  tunnel that silently stops working after a resume.
- **Why not**: "recovers without a human" is roadmap condition 3.

## Consequences

### Positive
- A clock step costs one session lifetime, not an indefinite outage.
- The failure is now diagnosable in one line: `doctor` names the stale refusals
  and their count.

### Negative
- An attacker can force KEM work against a peer with no session by replaying an
  old initiation. `mac1` gates it, and ADR-0030's bucket applies to sources that
  are not a peer — but this is a real, if small, widening of the DoS surface.

### Risks
- **A peer with no session becomes a free KEM target** → the bucket and the
  cookie path are the mitigations; measure before and after if it is ever seen
  in the wild.
- **Silent acceptance hides a genuinely replayed initiation** → the counter
  stays, and the acceptance path is only reachable when no session exists.
