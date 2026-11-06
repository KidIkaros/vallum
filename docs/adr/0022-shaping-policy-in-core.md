# 22. Traffic shaping is a passive policy machine in `vallum-core`; the `Device` is its single driver

**Status:** accepted · **Date:** 2026-10-23 · **Found by:** the package-design audit, re-examined with the code in front of us

## Context

The package audit flagged `vallum-tunnel` as a watch item: "key exchange and the
traffic-shaping machinery are arguably two change axes sharing a crate." A crate
carrying two axes is where the audit expects either a split or a stated reason
for keeping them together.

Before acting, the item was checked against the actual shape of the code, and
the check changed the item. The shaping *machine* does not live in
`vallum-tunnel` at all. It lives in `vallum-core::shaping`
([`Machine`](../../crates/vallum-core/src/shaping.rs),
[`Shaper`]) as a passive, deliberately engine-free function of
`(state, event, draw)`: no clock, no sockets, no keys, no I/O. The padding it
chooses is applied *inside* the AEAD by `data::Sender::seal_padded`, so the
on-wire length is a chosen quantity rather than a payload leak, and the defense
is measured in `docs/proof/traffic-shaping.md`.

What `vallum-tunnel` holds is the *integration*, and it is thin:

* a per-peer `Shaper` in `device/state.rs`, constructed from config;
* effects applied in `device/data.rs` (queue holds, `seal_padded` padding);
* one event feed — `ShapingEvent::Timeout` — in `device/timer.rs`.

Everything else in the crate is handshake, cookie-gate, epoch and transport
driving. The split the watch item feared has already been made, exactly where
it belongs: the policy axis went down into the stable core (the pure-function
contract is what lets the machine be tested exhaustively in isolation), and
the crate the audit worried about kept exactly one axis — the event loop that
drives everything.

## Decision

Keep the boundary where it is and close the watch item as recorded:

1. **Traffic shaping is a passive policy machine in `vallum-core`.** It may gain
   states, transitions, draws and effects there without a wire change and
   without touching the transport.
2. **`vallum-tunnel`'s `Device` is the shaping machine's single driver.** The
   integration contract is: feed events in, apply effects out — hold a queue,
   pad a sealed packet. The driver owns no shaping policy of its own.
3. **The watch item is re-scoped, not retired.** What remains worth watching is
   named by the tripwire below, not by the original "two change axes" framing.

## Alternatives Considered

* **A dedicated `vallum-shaping` crate.** The pure machine is certainly
  releasable alone (it takes an event stream and a draw), but it has exactly
  one consumer, it already sits in the crate whose instability is anchored by
  protocol conformance, and splitting would move the integration seams — the
  pre-image invariants `seal_padded` enforces — underneath the message that
  carries them. A new component buys nothing until the consequences of the two
  axes actually diverge. Rejected.
* **Move the machine into `vallum-tunnel`.** This is the split the original
  wording imagined, inverted. It would put the only stateless-pure machine in
  the codebase inside the transport driver, couple the policy to the driver's
  concrete event types, and take away the exhaustive isolation testing that in
  turn keeps the machine honest about being engine-free. Rejected.
* **Keep the watch item verbatim.** Recording a fear the code no longer has
  makes the log noise the next audit must spend time explaining. Re-scoped
  rather than deleted so the reasoning survives.

## Consequences

### Positive

* The audit record and the code now agree: the shaping split exists, is one
  step below the transport, and is evidenced by the machine's own contract
  rather than by confidence.
* The re-scope is cheap to hold: three concrete integration points are the
  whole coupling surface today, and any growth of that surface is visible in
  one glance at `device/`.

### Negative

* The machine's invariants (pre-image targets, one `Pad` at a time) are only
  as real as `seal_padded`'s refusals. The guard against a machine bug asking
  for an impossible target lives in `vallum-core::error`, which is correct
  placement — and means the two axes must keep talking through that boundary,
  so neither may drift past it.

### Risks — the tripwire that re-opens the watch

Re-open the question (a split, or a true refactor) if **shaping accumulates
driver-side state**: cross-peer scheduling, queue profiles, or per-session
shaping *history* held anywhere in the device rather than fed as events and
applied as effects. That is the coupling growing a second center of gravity,
and it would mean the driver has stopped being a single axis. Two smaller
signals are worth a glance when they appear — a second transport driver that
needs shapers without `vallum-tunnel`, or effect plumbing spreading across
more of the device — but neither is the tripwire; sizeable growth in
integration calls with no growth in coupling depth is not a sign of anything.
