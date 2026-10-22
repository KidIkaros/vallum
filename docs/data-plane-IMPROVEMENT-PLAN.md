# Data plane — improvement plan

Sequenced from `data-plane-DESIGN-ANALYSIS.md`. Ordered by leverage, not by
difficulty: information flows first, because every loop downstream consumes them.

Nothing here is a rewrite. The session machinery, the timers and the guard are all
correct in what they regulate; what is missing is what they are fed.

## Phase 1 — Give the system a delivery signal (F1)

The one change that unblocks the rest. Define a per-peer delivery ratio from
counters that already exist:

```
delivered / (delivered + rejected)      over a rolling window
```

Both numbers are already maintained in `device/data.rs`. What is missing is:

- a windowed rate rather than a monotonic total, so a stale session cannot look
  healthy because of bytes counted hours ago;
- exposure in uapi (`vallum_delivery_ratio`) and the metrics exporter;
- a documented threshold at which the tunnel is "not carrying".

Do **not** build a new probe. An end-to-end probe is a second mechanism for a
signal the data plane already produces on its own traffic.

Acceptance: a harness case that establishes a session, then drops packets at the
far side, and reads a delivery ratio that falls below threshold — with the
handshake age still fresh.

## Phase 2 — Point the watchdog at the signal (F2)

`DEAD_AFTER` currently regulates handshake age. It should regulate carrying.

Keep the handshake-age rule as a floor (a peer that never handshakes is still
dead), and add: routes are withdrawn when delivery is below threshold for longer
than the rekey interval. That closes the case the live failure exposed — perfect
handshakes, no traffic.

Acceptance: the Phase 1 harness case withdraws routes without waiting for a
handshake to go stale, and restores them when delivery recovers.

## Phase 3 — Make `status` unable to lie (F3)

`vallum status` reads the host rather than the process, which is right. It reads
the wrong host property.

Add a verdict between `up` and `leaking`: **`degraded`** — the guard is installed,
the daemon is alive, and delivery is below threshold. Exit code 0, because it is
not a leak, but it must not print `up`.

This is the highest value-per-line change in the plan: it converts a command that
ends investigations into one that starts them.

Acceptance: the Phase 1 harness case reports `degraded`, not `up`.

## Phase 4 — Move route ownership (F4)

The routes are created by `vallum-quick attach` and destroyed by `vallum-quick
detach`. Their correct lifetime is the session's.

Assign the owner to something that outlives every dependant: the daemon already
knows exactly when a session becomes usable and exactly when it dies. The wrapper
should stop being the owner of a resource the daemon's lifecycle governs.

This is the riskiest item and belongs last. It changes who writes the kernel
routing table on a path that currently works well enough to dogfood.

Acceptance: kill the daemon with routes installed and confirm they are removed;
start it again and confirm they return, without the wrapper running.

## Phase 5 — Define "carrying" (F5)

One paragraph in `docs/requirements.md`: what delivery ratio, over what window,
constitutes a working tunnel. Until that exists, Phase 2's threshold is a guess
and F5 stays open.

Cheap, and it is the goal-level statement the whole plan is measured against.

## Explicitly not doing

- **Not tuning `DEAD_AFTER`, keepalive cadence or attempt counts again.** That rung
  was tried twice and produced no behavioural change. F7 stays open deliberately.
- **Not building a passive-side handshake initiator yet.** ADR-0019 proposed it; the
  audit shows the server cannot attribute an unknown-session packet to a peer
  without guessing from the source address, so it is an amplifier risk for a
  benefit Phase 1–3 make unnecessary.
- **Not adding an end-to-end probe.** The data plane already measures delivery; a
  probe is a parallel mechanism for a signal that exists.

## Sequencing note

Phases 1–3 are one coherent change: measure delivery, feed the loop that acts on
it, and surface it. They should ship together or not at all, because a delivery
signal that no loop consumes is F1 restated.

Phase 4 is independent and riskier. Phase 5 is a paragraph.
