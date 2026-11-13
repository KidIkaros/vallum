# ADR-0038: A runtime rotation's replaced identity expires after 15 minutes

**Date:** 2026-11-12
**Status:** proposed
**Deciders:** the maintainer
**Relates to:** ADR-0019 (passive side re-initiates), ADR-0036 (rekey spread)

## Context

A peer's identity can be replaced without downtime: `peer rotate` opens a
window in which the replaced key keeps answering handshakes while the device
adopts its new one, and `peer finalize` retires the window. The design intent
is that the window is an overlap — for handshakes in flight and for devices
that have not caught up.

The enforcement machinery for expiry already exists and runs on every
handshake: an identity that asserts a validity document is refused once the
wall clock passes its `not_after`
(`crates/vallum-tunnel/src/device/routing.rs`, `validity_refusal`, called from
the handshake path in `device/handshake.rs`). A rotation driven by a signed
identity document carries that window and so expires by itself.

A rotation driven from the control plane — the `peer rotate` verb — does not.
It builds the new identity from a bare KEM key, which asserts no validity at
all, and `PeerConfig::rotate_identity` stored the replaced identity with
`validity: self.validity` — `None` for such a key. The result: **the replaced
key stayed accepted indefinitely.** The only thing that ever retired it was
an operator running `peer finalize`, and nothing prompted, logged, or
expired it. A replaced key on a lost or wiped-out device remained a valid
handshake identity on the server for as long as the server ran.

The red team's finding was "the rotation window never expires". The report
understates it: the window was not a window. It was a second, permanent
identity.

## Decision

`Device::rotate_identity` bounds the replaced identity's window at
`ROTATION_WINDOW_SECS` — 15 minutes, the same "one sitting" bound an invite
carries — whenever the replaced identity asserts no validity of its own. A
document-asserted window is kept as it is: the signed document is the
authority on its own lifetime.

Past the window, the replaced key is refused at the next handshake by the
existing `validity_refusal` check. No new enforcement path, timer, or
background sweep was added; the expiry rides on machinery that already ran
on every handshake and simply had nothing to say about these keys.

## Alternatives Considered

### Alternative 1: A background sweep that finalizes expired windows

- **Pros**: The peer row is *cleaned* — the replaced identity is removed from
  the table rather than merely refused.
- **Cons**: A sweep mutates device state from a timer, which the rest of the
  device deliberately does not do; the refusal check already gives the same
  security outcome. It also adds a second place where rotation state changes,
  with its own races against an operator's explicit `finalize`.
- **Why not**: Refusing at admission is the security property; tidiness of the
  row does not need a timer.

### Alternative 2: Require an explicit window on every `peer rotate`

- **Pros**: No implicit bound; the operator states the overlap.
- **Cons**: Every rotation then depends on the operator remembering to think
  about expiry — which is exactly the failure mode being fixed. A default that
  fails closed, overridable by a document, is safer than an absence that
  fails open.
- **Why not**: The safe default must be the one that happens when nobody
  thinks about it.

### Alternative 3: Expiry counted from the last handshake on the replaced key

- **Pros**: The window adapts to a device that is still actively using the
  old key.
- **Cons**: "Last use" means a compromised key that keeps talking extends its
  own acceptance indefinitely — the window stops bounding anything.
- **Why not**: An expiry that the key's own traffic can defer is not an
  expiry.

## Consequences

### Positive
- A replaced key stops answering by itself: rotation no longer depends on an
  unprompted manual `finalize`.
- Compromise of a replaced key is bounded at the window, not at forever.
- Document-driven rotations keep their signed windows; nothing existing
  changes behaviour.

### Negative
- A device that takes longer than 15 minutes to adopt its new key loses the
  overlap and must re-enrol or rotate again. The window is bounded at one
  sitting for exactly this reason, and `peer finalize` still exists for
  operators who want the replaced key retired sooner.
- The 15-minute bound is a judgement call, not a measured requirement; it
  matches the invite TTL, which is the closest analogue in the product.

### Risks
- **A client mid-rotation across the boundary drops.** Mitigated by the window
  being generous relative to the 120 s rekey cycle, and by the failure being
  visible: the client's handshakes are refused, rather than silently
  accepted on a key the operator believed retired.
