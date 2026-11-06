# ADR-0011: macOS is out of scope for v0.1

**Date**: 2026-10-19
**Status**: accepted
**Deciders**: Vallum maintainers

## Context

ADR-0005 staged macOS as the first non-Linux target and added a gating
`macos-inner` check plus an experimental daemon check. The v0.1 product is
Linux-only, the macOS daemon does not compile without platform work, and the
macOS CI jobs consume runner time without protecting a supported target.

## Decision

Remove the macOS CI jobs for v0.1. macOS, Windows, and BSD remain documented
future targets, but no macOS binary is built, tested, or claimed. The platform
seams in `docs/proof/platforms.md` stay as design notes.

## Alternatives Considered

### Keep the gating protocol-crate check
- **Pros**: catches accidental `cfg` regressions in portable crates.
- **Cons**: it is not a supported target; it gives a green signal for code no
  user can run.
- **Why not**: the Linux gate covers the shipped target.

### Keep the experimental daemon job
- **Pros**: tracks progress.
- **Cons**: it fails for known reasons and adds noise/cost to every run.
- **Why not**: the failure is not actionable in v0.1.

## Consequences

### Positive
- CI is green and focused on the supported target.
- No macOS runner cost.
- The platform roadmap is explicit, not implied by a failing job.

### Negative
- A future macOS port starts without a CI signal; it must add the runner and
  the platform modules together.

### Risks
- Portable crates could regress on non-Linux `cfg`s unnoticed; the code is
  still written against the platform traits and the roadmap names the seams.
