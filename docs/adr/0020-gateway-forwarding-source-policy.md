# 20. A gateway relays sources it does not own; a host claims only its own

**Status:** implemented (`forward = true` in `[interface]`, written by `vallum server init`) · **Date:** 2026-10-23 · **Found by:** `scripts/verify-remote.sh` against `wingman-vps` — the first egress a real client sent through the server's NAT never came back

## Context

The remote gate failed at the first routed packet: handshake over the real network, tunnel ping, and then `1.1.1.1` at 100 % loss while the server's FORWARD counters showed both directions accepted and the masquerade rule sitting exactly where the setup left it. The forwarding plane was innocent. The daemon had rejected the reply itself:

```
vallum[warn] dropping outbound packet from 1.1.1.1: this interface does not own that address, so the peer would reject it
```

The reply's path explains the shape. The server forwards a client packet to the internet, conntrack returns the reply, and the *same* routing decision sends it back into `vallumrc0` — so the daemon reads it on the egress path with `src = 1.1.1.1, dst = 10.99.90.2`, and the egress source filter (the one that catches a socket bound before the tunnel came up leaking a physical address) refuses everything whose source is not an interface address.

That filter was built for a real incident and it is right for a regular host: the peer's `allowed_ips` receives-check silently discards non-allowed sources (no counter, no ICMP, no log), so refusing locally is how a leak becomes a named cause instead of a mystery. The same check placed on a *gateway* eats legitimate relay traffic: egress source ownership is a **host's** claim — "I am speaking" — while a relayed reply is a **flow's** passage through the host, and no packet-content rule can tell the two apart. A forged packet (`src = 192.0.2.99, dst = <peer's /32>`, the case the e2e suite's A3 assertion deliberately exercises) and a conntrack reply (`src = 1.1.1.1, dst = <peer's /32>`) are byte-for-byte the same shape.

## Decision

The distinction is the host's declared role, not the packet's contents. `[interface]` gains:

```toml
forward = true   # this node relays flows for others
```

- `forward = false` (the default): the egress source check is unchanged for every existing config — a source outside the interface's addresses is refused locally and named, which is what A3 asserts and what the leak incidents need.
- `forward = true`: a source the interface does not own is **relayed** rather than refused. Far-side policy still governs — the receiving peer's `allowed_ips` decides whether to accept the source, so this does not license address-claiming; it moves the refusal from "(looks like a claim)" to "(the peer whose address is claimed"). The receive path and everything it checks is untouched.
- **Link-local sources are refused in both roles.** A link-local source means nothing across a link boundary — the same rule that refuses neighbour-discovery traffic in the gate suite; allowing it on a gateway would not make it meaningful.
- `vallum server init` writes `forward = true`: its whole reason is the gateway role, and its host steps already install the forwarding rules and NAT that make relays happen. A config whose operator never writes the flag behaves exactly as before, so the change is opt-in by construction.

The relay is announced once per source (`info`), not per packet: an operator whose gateway starts relaying a source they did not expect can see it, and a busy flow does not spam the log.

## Consequences

- Forwarded TCP and UDP through a Vallum server live. ICMP already worked, which is the trap the gate's DNS note documents ("ping works, nothing else" — this is the daemon-side half of that family).
- The daemon-side interpreter of the "ping works, nothing else" symptom gains an exact log line naming the dropped source and, now, the fix (`set forward = true` in `[interface]`).
- A3 (the foreign-source refusal, `docs/qa/browsing-impact-suite.md`) is unchanged on every host that does not set the flag; on a gateway the e2e suite's refusal assertion could not run, because the forwarding role is precisely the case where a foreign source is legitimate.
- Known residual: with `forward = true`, a socket bound to another local interface (the original leak class) is relayed as well. The far end still refuses it, silently. If dogfooding ever shows this on a real gateway, the fix is excluding sources that belong to *any* local interface, not re-tightening the flag.
- `docs/adr/0016` records that Vallum does not do NAT traversal; this is not traversal — the relay still rides the configured peer endpoint. It is the forwarding half the direct-dial design already needs.

## Verification

- Unit tests in `crates/vallum/src/run.rs` pin the rule table: owned ≷, forwarding on/off, link-local refused in both roles, unparseable refused, the v4/v6 link-local blocks itself.
- `scripts/verify-remote.sh`: with the flag live (written by `server init --no-host` on the remote), the previously-failing egress ping must return answers; the run that found the bug had refused `src=1.1.1.1` at the daemon — the same run with the fix is the regression test.
- Live deployment stamps:

```
── transport: bundle ... 1.1.1.1 unanswered (pre-fix)
   ok    laptop-bundle: handshake, tunnel, egress (post-fix)
```
