# ADR-0010: Keep the tri-hybrid default and document a fast profile

**Date**: 2026-10-19
**Status**: accepted
**Deciders**: Vallum maintainers

## Context

The tri-hybrid suite (`0x0003`, X25519+sntrup761+ML-KEM-768) is the default and
the strongest diversity choice, but the SDK's sntrup761 costs ~9.4 ms per
decapsulation: a full handshake is ~54 ms and ~9 KB. Suite `0x0002`
(X25519+ML-KEM-768) completes in ~1.81 ms, still hybrid and post-quantum, at the
cost of one fewer independent PQ leg.

## Decision

Keep `0x0003` as the default. Document and test `0x0002` as a **fast profile**:
generate a key with `vallum keygen --suite 2`, the TUI surfaces the suite and
offers the choice, and `vallum bench --suite 2` reports the baseline. No config
field, wire change, or default change.

## Alternatives Considered

### Alternative 1: Make `0x0002` the default
- **Pros**: ~30× faster handshake, smaller messages.
- **Cons**: loses the independent sntrup761 leg; changes the security posture
  for every deployment.
- **Why not**: the project's differentiator is the tri-hybrid; speed is a
  profile, not the default.

### Alternative 2: No profile, tri-hybrid only
- **Pros**: one choice, no documentation burden.
- **Cons**: operators with latency-sensitive deployments have no supported path
  short of editing the key file themselves.
- **Why not**: the suite is already a property of the key; documenting it is
  cheap and honest.

## Consequences

### Positive
- The default keeps the strongest KEM diversity.
- A documented, tested fast path exists.
- The size/performance difference is measured rather than implied.

### Negative
- Two profiles to explain and test.
- The fast profile is not a single-packet handshake either (ML-KEM ciphertexts
  still exceed 1232 B).

### Risks
- An operator may choose the fast profile without understanding the diversity
  loss; the README and TUI label it explicitly.
