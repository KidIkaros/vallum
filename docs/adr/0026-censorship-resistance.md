# ADR-0026: Censorship resistance is a separate surface from traffic shaping

**Date**: 2026-11-06
**Status**: accepted, amended (see "Implementation status")
**Deciders**: Vallum maintainers

## Context

Vallum's obfuscation today is *shape*: ADR-0022's machine framework and
ADR-0025's constant-rate floor make a tunnel's traffic harder to classify. None
of it helps when the censor does not need to classify — a network that drops UDP
on every port, or blocks every address it has not seen before, blocks Vallum
whatever its packets look like. The read in `docs/research/moor-reference.md`
found MOOR ships six transports, and this is the one area where it is clearly
ahead of us.

The gap is real and it is a product gap, not a module: a transport changes what
the daemon's socket is, what the peer's endpoint means, what happens to a lost
packet, and what a user is promised when the tunnel comes up. It also changes
what we can test. Every claim in this repository is measured against a real
implementation, and the two axes that make a transport worth having — *does the
censor block it today* and *does the censor block it next month* — are neither
local nor measurable here.

## Decision

1. **v0.1 claims no censorship resistance.** The tunnel is UDP and nothing else.
   The property we document is that traffic shape carries little information
   (ADR-0022, ADR-0025), not that the tunnel is reachable where UDP is blocked.
   Saying so plainly is part of the decision: a user who believes the second
   claim and gets blocked has been misled by us.
2. **The next transport, if one is built, is UDP-over-TCP with the same PQ
   handshake inside.** Not a protocol emulation: the tunnel's own framing, sent
   over a TCP connection to the same endpoint, so a censor that blocks UDP but
   permits TCP to the port gets a working — slower, more fragile — tunnel. It
   costs head-of-line blocking, an MSS-limited MTU, and a stream-level signature
   of its own, and those costs are to be measured before it is offered as
   anything.

3. **Protocol emulation is rejected.** MOOR's `transport_*` files emulate
   specific protocols; so do uTLS-style fingerprint forgeries. Two reasons: the
   emulation is only as good as the version of the protocol it copied, and it is
   unverifiable code of the kind §"What not to take" in the research note already
   refuses. A censor that fingerprints the *inauthenticity* of an emulation has a
   cheaper test than one that fingerprints Vallum.
4. **Anything carrying traffic for a third party — relays, bridges, fronting,
   WebRTC-style volunteer proxies — needs its own ADR and threat model.** It is
   a different product with a different user, a different operational burden, and
   an abuse surface Vallum has no story for today. ADR-0016 covers the narrower
   NAT-traversal relay question and stands.

## Implementation status (amendment)

Decision 2's carrier now exists, as `[interface] carrier = "tcp"`. It is opt-in
on both ends — there is no detection and no automatic switching, because a
fallback that engages silently is a fallback the operator never chose — and it
carries exactly the same sealed packets as UDP:

- **Framing.** `vallum_tunnel::stream` is a two-byte length prefix and nothing
  else: no I/O, no connection state, a 32 KiB ceiling below the prefix's own
  range so a bogus length is refused before its body is buffered. Measured over a
  real TCP connection with real sealed packets (`tests/carrier.rs`): 1 458 bytes
  on the wire for a 1 456-byte packet, byte-identical on arrival.
- **One connection per peer.** `TcpTransport` implements the daemon's
  `DatagramSocket`, so the device, the handshake, the loop and the shaping
  machines above it are unchanged. A dial is marked with `SO_MARK` *before* the
  connect, so a full tunnel does not capture its own attempt to establish.
- **What it costs.** Two bytes of frame per packet and the header difference
  (TCP+IP 40 against UDP+IP 28): about 1 % on a full-size packet. What it adds
  is one order: a lost segment holds everything behind it, and a peer cannot
  roam, because the connection is the endpoint.
- **Verified end to end** by
  `two_daemons_carry_traffic_over_the_tcp_carrier` in `tests/gate.rs`: two real
daemons, two real configs, a real handshake and traffic both ways over loopback
  TCP.

The retransmission cost on a *lossy* path is measured now, not argued: 32 MiB in
23 014 frames takes 0.04–0.18 s on a clean 1 ms round trip, 13.2–17.9 s at 5 % loss
on that path, and 26–48 s at 2 % loss over a 40 ms round trip, with every frame
delivered on all five paths. At 2 % loss on a 1 ms path the same run takes anywhere
from 0.04 to 2.5 s depending on whether the repairs fit inside the window or the
window collapses — both measured, and neither is the cost on a real path. The cost
is round trips, not bytes: 11–14 ms per repair at 5 % loss, 46–116 ms at 40 ms.
And the same qdisc that costs the stream 14–18 s at 5 % costs paced datagrams 5 %
of their arrivals in two seconds, which is the comparison the fallback exists for
(`docs/proof/transport.md` §2.8–2.9). The claim therefore stands at "reachable
where UDP is blocked", never "fast there".

## Alternatives Considered

### Alternative 1: Emulate a common protocol (MOOR's approach)

- **Pros**: works today against a censor that pattern-matches Vallum's UDP
  fingerprint; six implementations to take designs from.
- **Cons**: each emulation is a partial, version-dependent copy of somebody
  else's protocol; the code is the most security-sensitive in the tree and the
  least verifiable; and the emulation is a fixed target.
- **Why not**: we would be shipping code we cannot test against the thing it
  must defeat, and whose failure mode is silence rather than an error.

### Alternative 2: Build the anonymity stack (relays, bridges, fronting)

- **Pros**: MOOR's architecture is a complete design; it is what actually resists
  a determined censor.
- **Cons**: directory consensus, bridge distribution, volunteer infrastructure,
  abuse handling, and a threat model in which the operator is an adversary — none
  of which exists here, and none of which is a point-to-point VPN's job.
- **Why not**: too large to adopt as a technique, and it would make every other
  claim in this repository conditional on infrastructure we do not run.

### Alternative 3: Do nothing, and say nothing

- **Pros**: zero work; the shaping work already makes traffic analysis harder.
- **Cons**: leaves users believing a VPN resists blocking, which today it does
  not; and leaves the socket boundary as the thing that would have to be
  rebuilt if a transport is ever wanted.
- **Why not**: the honest statement costs nothing, and the component boundaries
  below are cheap to keep while the daemon is small.

## Consequences

### Positive
- The claim boundary is explicit: shaping resists *analysis*, a transport resists
  *blocking*, and the second is a manual, opt-in fallback.
- `Device` already emits `Action::Send { destination, bytes }`, so the carrier is
  a policy around a byte slice rather than an assumption inside the protocol. A
  TCP carrier is an addition there, not a rewrite of the handshake or the data
  plane.
- Rejecting emulation keeps the audit surface to Rust we wrote and dependencies
  `cargo deny` covers.

### Negative
- A user behind a UDP-blocking network has one answer, and it is manual: name
  `carrier = "tcp"` on both ends. Nothing detects the block for them, and the
  documentation says so where it is most inconvenient — in the install and
  troubleshooting paths, not only in an ADR.
- UDP-over-TCP is a fallback, not resistance: it is exactly the shape a censor
  learns to block second, and it degrades badly on a lossy path.

### Risks
- **A fallback that becomes the default would make every tunnel slower.** The
  mitigation is that the UDP path stays primary and a fallback is opt-in per
  peer, with its cost stated in the config reference.
- **A transport that leaks its own identity is worse than UDP.** A TCP carrier
  with fixed framing and fixed timing is a beacon; it must be shaped by the same
  machines, and measured on the same idle-hour trace ADR-0025 added.
- **Scope creep into the anonymity stack.** Relay, bridge and fronting
  proposals get refused by this ADR until a threat model exists that names the
  operator as an adversary.
