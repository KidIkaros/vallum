# ADR-0025: Take MOOR's techniques, not its code

**Date**: 2026-11-06
**Status**: proposed
**Deciders**: Vallum maintainers

## Context

MOOR (`codeberg.org/sickkk/MOOR_PQ`, MIT, read at `98bb70c`) is a three-hop
onion router in C, and its author has given permission to use it. It has
real implementations of front padding, a constant-rate floor, volume padding,
EWMA/SKIPS scheduling, Vegas congestion control, Conflux multi-path and six
pluggable transports — areas where Vallum has either nothing or an unpopulated
framework.

The read in `docs/research/moor-reference.md` also found that its test suite
cannot run (31 declared test binaries, one present, zero assertions), that it
has no CI, and that its `LICENSE` names no copyright holder. Its cryptography is
weaker than Vallum's (X25519 + ML-KEM-768 against Vallum's tri-hybrid KEM, and
Falcon-512 against Falcon-1024).

Vallum's shaper is a Maybenot-modelled action framework with per-state cost
bounds and padding inside the AEAD (ADR-0022); MOOR's `wfpad.c` is a table of
defences of the kind that framework exists to express, and Vallum ships none of
them.

## Decision

Adopt specific MOOR **techniques** as new bounded shapes in Vallum's existing
shaping framework, and import no MOOR code. The first shapes to add are a
constant-rate floor, then front padding, then volume padding; per-machine
parameter noise follows. All are expressible as named `ShapingSpec` variants
with bounded parameters, never as a raw state-machine description. Censorship
resistance (transports) is deferred to its own ADR because it is a product
decision, not a shaping change.

**First shape taken.** The constant-rate floor is implemented as
`ShapingSpec::ConstantRateFloor { interval_ms, size }`, off by default, with the
interval clamped at 100 ms so the configuration cannot describe a flood. It
measures 5.82 kbit/s at 2 000 ms and 116.48 kbit/s at the clamp, per tunnel,
with the table and the daemon-level test recorded in
`docs/proof/traffic-shaping.md`.

**Second shape taken.** Front padding is implemented as
`ShapingSpec::FrontPadding { count, interval_ms, size }`, with the count clamped
at 60 packets and the interval at 1 000 ms. It is a count rather than a rate: 60
packets at a 1 400-byte target cost 85 KiB once, against 100 MiB for a 100 ms
floor over the same two hours.

**Third and fourth shapes taken.** Volume padding is
`ShapingSpec::VolumePadding { window_ms, max_packets, size }`: a window closes on
a pause or on a full run of packets, and closing injects until the count is a
power of two. Parameter noise did not become a fifth shape; it became a field on
the floor — `jitter_ms` — because the thing worth randomising is the interval the
floor emits, and a per-firing draw is stronger than the per-circuit draw MOOR
makes: a value chosen once per peer is stable for the life of the daemon, which
is the same window an observer measures in. All four techniques in the research
note's order are now implemented.

## Alternatives Considered

### Alternative 1: Vendor its code

- **Pros**: working implementations exist for all six transports and the padding
  machines; no design work.
- **Cons**: 50k lines of C with a test suite that does not run, no CI, and an
  audit surface Vallum cannot review; FFI and `unsafe` in a daemon whose trust
  story is one audited adapter crate.
- **Why not**: the techniques are small and the code is not verifiable here.
  Copying would trade a design task for an audit debt that is far larger.

### Alternative 2: Adopt nothing

- **Pros**: zero risk and zero work; Vallum's framework already supports a
  deployment that wants padding.
- **Cons**: a framework with no defence configured protects nothing, and the
  idle-tunnel signal that a constant-rate floor addresses is the one Vallum's
  traffic profile leaks most.
- **Why not**: the cheapest of the four techniques is a spec variant and its
  cost is a stated number.

### Alternative 3: Build the anonymity network as a second product

- **Pros**: MOOR's architecture is a complete design for it.
- **Cons**: a different threat model, a different operational burden (directory
  authorities, consensus, hidden services), and a different user.
- **Why not**: out of scope for a point-to-point VPN, and too large to smuggle
  in through a research note. If it is wanted, it gets its own ADR.

## Consequences

### Positive
- Vallum can close the idle-tunnel and front-load leakage without a new parser,
  protocol change or dependency.
- The shaping framework is exercised the way it was designed to be: a defence is
  a table, not a release.
- No C is introduced, and `cargo deny` keeps covering everything that ships.

### Negative
- A constant-rate floor costs bandwidth continuously, including when nobody is
  using the tunnel; the default must stay off.
- Front and volume padding add latency and packet count that the proof document
  will have to measure before they can claim anything.
- The designs are reimplemented, so MOOR's bugs are not inherited but neither is
  its testing — such as it is.

### Risks
- **A floor that is too high becomes a bandwidth bug** (1 cell/s ≈ 4.1 kbit/s;
  10 cells/s ≈ 41 kbit/s per tunnel). Mitigation: bounded, named parameters and
  a measured cost table beside the existing `docs/proof/traffic-shaping.md`.
- **A defence with a fixed signature is itself a fingerprint.** Mitigation:
  parameter noise per session, and no default shape that is identical across
  deployments.
- **Scope creep toward the anonymity stack.** Mitigation: transports and
  multi-hop routing require their own ADR and threat model before any code.
