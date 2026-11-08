# ADR-0016: NAT traversal and relay — what we will and will not do

**Status:** superseded by [ADR-0027](0027-mesh-topology-and-control-plane.md) (2026-11-07) · **Date:** 2026-10-21

> **Superseded.** The constraints in this record were correct and are adopted
> unchanged by ADR-0027; what changed is the decision *not* to build traversal
> and relay in the current series. ADR-0027 makes them in scope, because the
> goal moved from "a better WireGuard" to "a mesh VPN with Vallum's
> cryptography." Read this record for the constraints; read 0027 for the
> decision.

## Context

Vallum is peer-to-peer over UDP with a configured endpoint. That works when at
least one side has a reachable address — a VPS, a port-forward, a public host.
It does not work when *both* peers are behind NAT, which is the common case for
"my laptop and my home server", and it is the single largest functional gap
against what Tailscale-style tools provide.

WireGuard has the same gap and answers it the same way: port forwarding, or a
third party. What people actually use is a rendezvous/relay service, and that
service is where the interesting decisions are.

## Decision

**Vallum will not gain a relay or hole-punching in the current series.** The
constraints below are recorded now so that when it is built, it is built to
them rather than retrofitted.

### What a relay must not do

1. **It must not terminate the tunnel.** Relay datagrams are the same sealed
   datagrams the peers already exchange; the relay forwards opaque bytes and
   cannot decrypt, re-key, or impersonate. This is the property that makes a
   relay acceptable to run on someone else's machine.
2. **It must be opt-in per server** (`[relay] enabled = false` by default), for
   the same reason enrolment is.
3. **It must be authenticated in both directions**: a peer proves it may use
   the relay (token or its own key), and the relay's identity is pinned by
   fingerprint, as `--expect` does for enrolment.
4. **It must be visible**: `doctor` says whether the path is direct or relayed,
   and metrics count relayed bytes separately. A tunnel that silently degrades
   to a relay is a lie about its own topology.

### What discovery must not do

Hole punching needs each peer to learn the other's observed address, which
means a rendezvous point that sees both. That is metadata the current design
does not emit anywhere. If it is added:

- the rendezvous learns *who talks to whom*, never keys or content;
- it must be runnable by the operator, not only by us;
- a direct path, once established, must not keep reporting to it.

## Options considered

| Option | Verdict |
|---|---|
| Port forwarding only (today) | Keeps working; documented as the answer. No code. |
| STUN-style hole punching with a rendezvous | Works for cone NATs, fails for symmetric; needs the metadata service above. Worth doing *with* a relay as the fallback, not alone. |
| Relay as an opaque forwarder | The right shape. Needs framing, authorization, and a bandwidth policy. |
| An external control plane that also relays (Headscale-shaped) | Rejected for the data plane in ADR-0014 — it would replace Vallum's PQ handshake with WireGuard's. Acceptable only as a rendezvous that speaks Vallum's bundle/JSON contract. |
| TCP/443 fallback for hostile networks | Separate problem, separately decided; it changes the outer transport, not the topology. |

## Consequences

- "Two hosts behind NAT" remains unsupported, and the documentation must say so
  plainly rather than implying a VPN that works anywhere.
- A relay is a bandwidth commitment. Whoever runs one pays for other people's
  traffic, so the first version should be operator-run (a VPS you already have),
  not a public service.
- The rendezvous metadata question is a product decision before it is an
  engineering one: a service that knows who connects to whom is a different
  privacy posture from one that knows nothing.

## Open questions

1. Should a relay be the same binary and port as a server (`[relay]`), or a
   separate mode? Same binary is simpler; a separate mode is easier to audit.
2. Does a relayed path need its own keepalive and MTU budget? Yes — the outer
   path gains a hop, so `outer_mtu` must be discovered or declared per path.
3. What is the failure story when the relay disappears mid-session? Reconnect to
   a direct path if one exists, otherwise re-rendezvous; the handshake is
   already cheap to redo.
