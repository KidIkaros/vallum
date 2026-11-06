# Data plane — systems design analysis

A Meadows leverage-point audit of the session lifecycle: the path from "a packet
enters the tunnel" to "the far side receives it". Written after a live failure in
which the tunnel reported itself healthy while carrying almost nothing.

Scope: `crates/vallum-tunnel` (device, session, timers), the wrapper's routing
(`vallum-quick`), the watchdog, `vallum status`, and the metrics exporter. Not the
crypto primitives, not the TUI.

## What happened, as the audit's evidence base

A full-tunnel client whose server restarted could not reach the internet. Measured
on the deployment:

| Observation | Value |
|---|---|
| Client datagrams sent | 14 626 |
| Client packets delivered | 186 (1.3 %) |
| Handshakes during the outage | every 120 s, all successful |
| Server packets delivered | 227 — the server was receiving and forwarding |
| `vallum status` at that moment | `up` |

So the tunnel was carrying about one packet in a hundred, and every indicator the
system has said it was fine.

## The system, mapped

**Stocks.** The session table (per peer: current session, previous session, epoch,
own index, remote index), the index→peer map, the peer endpoint, the rekey timers,
the tx/rx/delivered/rejected counters, the kernel routing table, the nft ruleset.

**Flows.** Handshake (init/response/conf), seal-and-send, open-and-deliver, rekey,
keepalive, expiry, route installation, packet forwarding on the server.

**Feedback loops.**

| Loop | Regulates | Restores |
|---|---|---|
| Rekey timer (120 s) | key age | yes — new session |
| Retransmit (5 s, max 2) | handshake delivery | yes |
| Reactive keepalive (10 s) | NAT binding | partially |
| Expiry (180 s) | key validity | yes — tears down |
| Watchdog (`DEAD_AFTER`) | handshake age | yes — withdraws routes |
| Guard (ADR-0018) | egress destination | yes — blocks |

**Information flows — the decisive part.** Every loop above regulates a *proxy*:
key age, handshake age, NAT binding. Not one of them is fed by the thing they all
exist to protect — **packets actually arriving at the far side**.

## Findings

| # | Leverage point | Finding | Severity | Effort |
|---|---|---|---|---|
| F1 | #5 Information flows | **No component measures whether data flows.** `delivered`, `rejected` and `rx_bytes` are computed per peer and exported to uapi and Prometheus, then read by no decision. The system has telemetry and no feedback. | Critical | M |
| F2 | #7 Balancing loops | **The watchdog regulates the proxy.** It withdraws routes on handshake age, so a tunnel that handshakes perfectly every 120 s and delivers 1 % of packets is held up indefinitely. The one restorative loop cannot see the failure it exists for. | Critical | M |
| F3 | #5 Information flows | **`vallum status` reports health from the same proxy.** It reads `last_handshake_time_sec` and guard state. During the measured outage it would have said `up`. A status command that is confidently wrong is worse than none — it ends the investigation. | High | S |
| F4 | #10 Stock-and-flow | **Route lifetime is owned by the wrapper, not the session.** The daemon refuses to install routes and only warns (`allowed_ips 0.0.0.0/0 is outside the interface's …; a route to it is needed`). `vallum-quick attach` creates them and `detach` destroys them, so the routes outlive any session that dies without a wrapper noticing. This is a resource whose lifetime is bound to an arbitrary participant. | High | M |
| F5 | #2 Goals | **"Carrying" is never defined.** The stated rule is "a family the tunnel does not carry must not escape", and ADR-0018 enforces it on *destination*. Nothing defines what counts as carrying, so a tunnel delivering 1 % satisfies the letter. A goal that admits a 1 %-working system is under-specified. | High | S |
| F6 | #9 Delays | **Re-establishment is timer-driven only.** The single trigger for a new handshake is `REKEY_AFTER_TIME_MS`; the only liveness signal is a handshake already declared valid for 180 s. Recovery latency is therefore bounded below by the rekey interval, regardless of how fast the network is. | High | M |
| F7 | #11 Parameters | `DEAD_AFTER`, keepalive cadence, attempt counts. | Low | S |

## F7 is the rung I already wasted effort on

I changed `DEAD_AFTER` from 90 s to 210 s and then implemented an
unanswered-keepalive counter, both gate-green, and the live failure was unchanged.
The ladder predicts this: parameters are the lowest-leverage rung, and 99 % of
attention goes there for the least effect. The counter also failed for a reason
worth recording — the client receives a *few* packets during an outage (186), and
each one resets a "we heard nothing" counter. A rule built on silence cannot see a
path that is mostly, but not entirely, dead. That is a **sampling** problem, which
is an information-flow problem (F1), not a parameter problem.

## The shape of the fault

The system has one question it can ask — *when did we last handshake?* — and it
asks it everywhere. Every loop, the status command and the operator's mental model
are all fed by that one number. The data plane's actual output is measured,
exported, and discarded.

That is why the failure was invisible rather than merely bad: not a missing check
in one place, but a missing **information flow** that six loops would all have
consumed had it existed.

## What the audit does not conclude

- It does not claim the 1.3 % delivery figure is the steady state; it is one
  outage window with two server restarts inside it.
- It does not identify why delivery collapsed — that is a separate question, and
  F1 is the reason it could not be answered from the running system.
- It does not propose removing any loop. All six are correct in what they
  regulate; the gap is what they are *fed*.

See `data-plane-IMPROVEMENT-PLAN.md` for sequencing.
