# ADR-0040: One facts-driven guidance engine, rendered by both consoles

**Date**: 2026-11-13
**Status**: agent default — pending operator ratification
**Deciders**: Devin (recorded under the operator's identity without operator sign-off)

> **Correction (2026-11-21).** Same session as ADR-0039, same false
> attribution: this recorded "operator + Devin" for a decision a Devin
> session made and committed alone. The design stands on its merits —
> the operator may ratify or revisit it.

## Context

The alpha's operator-facing goal is a console with a learning curve: the
machine should say what it needs next rather than waiting for the operator to
know the command. Two surfaces must tell the same story — `vallum tui` and
the GUI — and their facts come from different places (the TUI reads the
control socket and systemd directly; the GUI reads its snapshot, hostfacts,
and the same units). Two independent "what now?" implementations would drift:
the day one surface learns a rule the other silently disagrees is the day the
guidance becomes untrustworthy.

The rules themselves have a failure mode worth designing around: a wrong
suggestion is worse than no suggestion. A console that says "join a network"
on a configured, running machine — which the TUI did, live, because it only
counted a config file as configured and socket-discovered interfaces have no
path — trains the operator to ignore the strip entirely.

## Decision

A pure engine in the shared crate — `guidance::suggest(&Facts) -> Vec<Suggestion>`
— owns every rule. Both consoles collect `Facts` from their own vantage
points (config presence, daemon liveness, service/enabled state, peer count,
handshake ages, staged rotations, open enrolment, checkout staleness), call
`suggest`, and render what comes back: the TUI as a footer strip with
key/palette hints, the GUI as the NextSteps card with buttons.

Two properties are load-bearing:

- **Facts are conservative.** `Option` fields carry "unknown"; a rule that
  cannot observe its precondition does not fire. A live control-socket
  answer counts as configured regardless of whether the config file is
  readable.
- **Suggestions carry an action ID, not a command string.** Each surface
  maps the ID to its own affordance (palette verb, dialog trigger, bridge
  call) — the engine never guesses what a UI can do.

## Alternatives Considered

### Alternative 1: Per-surface heuristics
- **Pros**: no shared module; each UI tunes its own wording.
- **Cons**: the rule sets drift immediately; a bug fixed in one surface
  lives on in the other (the config_path assumption proved this — it was
  wrong in both facts-collectors for the same reason).
- **Why not**: the guidance is the product claim — "the machine says what it
  needs next" — and a claim that differs per surface is a defect, not a
  feature.

### Alternative 2: Server-side suggestions in the UAPI
- **Pros**: one source of truth at the daemon; consoles become dumb.
- **Cons**: the daemon cannot see what the consoles see — systemd unit
  state, SSH config, checkout staleness, GUI-side preflight — and hoisting
  those into the daemon widens its read surface for a presentation concern.
- **Why not**: facts live in the consoles; the engine should be where the
  facts are, not where the tunnel is.

## Consequences

### Positive
- A rule lands once and both surfaces inherit it — the next lifecycle stage
  (e.g. "peer identity changed — investigate") is one engine edit.
- The engine is unit-testable without a socket, a TTY or a browser:
  12 tests cover every rule's fire/suppress boundary.
- The suggestion cap and Act/Warn/Info ordering give both UIs the same
  escalation vocabulary.

### Negative
- Facts collection is still per-surface code — the engine cannot stop a
  surface from assembling facts wrongly (the config_present bug was exactly
  that). Tests pin the mapping at the boundaries that mattered.
- `Action` is a shared enum both sides must understand; adding a variant
  means two renderers to update before the suggestion is clickable.

### Risks
- Guidance is only as good as the facts — a stale sync-check cache or a
  silently-wrong unit query produces confident nonsense. Mitigation:
  facts that fail to resolve stay `None` and suppress their rule.
