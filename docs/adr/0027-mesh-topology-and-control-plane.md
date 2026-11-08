# ADR-0027: Mesh topology as an external agent — vallum-core stays a tunnel

**Date**: 2026-11-07
**Status**: proposed
**Supersedes**: ADR-0016 (NAT traversal and relay). Amends ADR-0013 (server provisioning is a CLI).
**Deciders**: the maintainer

## Context

Vallum today is a **hub-and-spoke** tunnel: one server, N clients, peers described
by `allowed_ips` prefixes. The goal has changed from "a better WireGuard" to "a
mesh VPN with Vallum's cryptography," and ADR-0016's decision to defer traversal
and relay no longer holds.

The obvious response is to change the project into a mesh: new topology mode in
`vallum-config`, peer-set distribution in core, traversal in the datapath, a relay
mode in the daemon. This record rejects that, because a reading of the existing
code shows the datapath **already has every primitive a mesh needs**, and has had
them since before the mesh was a goal.

### What the datapath already does

Four properties, read from the tree, not inferred:

1. **A peer with no endpoint roams.** `PeerConfig::new` sets `endpoint: None`,
   documented as *"roaming from the peer's own handshakes: the address is learned
   from the first authenticated message and then tracked"*
   (`crates/vallum-tunnel/src/peer.rs:122`). `endpoint_allowed` in
   `device/routing.rs:73` implements it: *"An unpinned peer roams: any
   authenticated source becomes its address."*

2. **The endpoint is settable at runtime, and clearable.** `uapi::Peer.endpoint`
   is `Option<Option<SocketAddr>>` — `Some(None)` clears it to roam,
   `Some(Some(a))` sets it (`crates/vallum/src/uapi.rs:200`). It is accepted over
   the WireGuard-style UAPI `set=1` socket, and `apply_peer` applies it live.

3. **The keepalive timer drives the dial.** `TimerAction::StartHandshake` calls
   `start_handshake(index, None, ...)` (`device/timer.rs:91`), so a peer with a
   configured endpoint and a `persistent_keepalive_interval` is dialled on the
   timer without any traffic. `persistent_keepalive_interval` is also a UAPI
   field.

4. **`allowed_ips` is per-peer and settable live**, with `replace_allowed_ips` for
   the full-set case (`uapi.rs:158`).

Together: an external process that writes `public_key`, `allowed_ip`,
`endpoint`, and `persistent_keepalive_interval` for each peer, over the existing
control socket, produces a full mesh. Every node holds every other node's key,
every node can dial every other node, and the daemon's own roaming handles the
address changes. **No datapath change is required.**

### Why the relay also needs no datapath change

The one piece that looks like it must live in core is the relay, because a
relayed datagram arrives from the relay's address rather than the peer's. But
Vallum's sealed datagrams are opaque and the relay can be fully transparent:

- The relay allocates a distinct UDP port per (peer, peer) pair.
- Node A is configured with `endpoint = relay:port_A_to_B`.
- A's datagrams arrive at the relay from `A:portA`, which the relay maps to
  `B:portB` and forwards from `relay:port_B_to_A`.
- B has `endpoint = relay:port_B_to_A` configured for A, so the source check
  passes and the datagram authenticates normally.

The relay never parses, decrypts, or re-keys anything. It is a port-allocating
UDP forwarder with a registration step. No header, no MTU change (it adds no
bytes), no protocol version bump.

The cost is that the relay must hold N² port mappings in the worst case, and the
coordination plane must distribute them. That is a resource cost on the relay
operator, not a change to the tunnel.

### What this reframes

The gap was never "vallum is not a mesh." It was "nothing distributes the peer
set, and nothing discovers addresses." Those are coordination problems, and a
coordination problem belongs in a coordinator — not in a datapath that is already
correct.

## Decision

**The mesh is an external agent (`vallum-mesh`) that drives the existing daemon
over the existing UAPI. `vallum-core` and `vallum-tunnel` are not modified to
become a mesh.**

The agent is a separate process, not a library loaded into the daemon. It does
four things:

1. **Registers with a coordination plane** and receives a signed peer set: every
   node's public key, its `allowed_ips` allocation, and its candidate endpoints.
2. **Applies the peer set to the local daemon** over the UAPI `set=1` socket —
   `public_key`, `allowed_ip`, `endpoint`, `persistent_keepalive_interval` — with
   `replace_allowed_ips` where the set is authoritative. The daemon's existing
   live-apply path does the rest.
3. **Runs traversal**: STUN discovery, candidate exchange through the plane, and
   hole punching. On success it writes the punched endpoint; on failure it writes
   the relay endpoint. The daemon does not know or care which it got.
4. **Reports topology**: direct vs relayed per peer, relayed-byte counters, and
   the reason a path fell back. This is the agent's knowledge, exposed by the
   agent, satisfying ADR-0016's "a tunnel that silently degrades to a relay is a
   lie about its own topology" without teaching the daemon about relays.

### What stays in core, and what does not

| Concern | Owner | Why |
|---|---|---|
| Sealing, handshake, epochs, PCS | `vallum-core` | unchanged |
| Roaming, endpoint tracking | `vallum-tunnel` | already exists, correct |
| Live peer apply | `vallum` (UAPI) | already exists, correct |
| Peer-set distribution | `vallum-mesh` | coordination, not datapath |
| STUN / hole punching | `vallum-mesh` | coordination, not datapath |
| Relay (port-allocating forwarder) | `vallum-mesh` (separate binary) | transparent to the tunnel |
| Identity document issuance | coordination plane | already built in core, needs a service |
| ACL policy | coordination plane + agent | evaluated centrally, applied as `allowed_ips` |
| MagicDNS | `vallum-mesh` | names → `allowed_ips` + resolver config |

Note that ACLs reduce to `allowed_ips` at the data plane, which is the mechanism
Vallum already enforces. A policy that compiles to per-peer prefixes is enforced
by the tunnel itself; a policy that needs more than that is a data-plane change
and should be argued separately rather than smuggled in.

### The coordination plane

A `vallum-coord` service that:

- **Issues identity documents**, reusing `IdentityDocument::issue` with its signed
  `Validity` window (`vallum-core/src/identity.rs:411`, the struct at 365).
  Already built.
- **Distributes signed peer sets** with a monotonic version, so a node detects a
  stale or rolled-back view.
- **Holds ACL policy** and compiles it to per-peer `allowed_ips`.
- **Never holds a private key.** It signs documents and distributes public
  material. Compromise must not yield traffic keys.

ADR-0013's "no control plane in core" survives this decision intact. The plane is
a separate service that speaks the machine interface ADR-0013 deliberately built:
`--json`, a versioned bundle schema, documented exit codes. That ADR anticipated
exactly this — *"A third party can build the enrolment service; it calls the same
commands a person does, and Vallum does not have to grow an API to support it."*
The mesh agent is that third party.

### Default suite for mesh deployments: `0x0002`

Amends ADR-0010. The reasoning is audit surface, not performance.

Tracing what `vallum-crypto-sdk` imports and what runs per handshake, the custom
unaudited code in the handshake path is exactly three components:

| Component | SDK module | `AUDIT_PACKAGE.md` rating |
|---|---|---|
| NTRU Prime (sntrup761) encapsulate/decapsulate | `pqc::ntru_prime` | Medium — 100/100 KAT vectors byte-exact |
| ChaCha20-DRBG (deterministic encapsulation RNG) | `drbg::ChaCha20Rng` | Medium |
| Hybrid signing (Ed25519 + Falcon-1024) | `signing::hybrid` | **High** — novel composition |

Everything else in the handshake is external and audited: `x25519-dalek`,
`ml-kem` (RustCrypto, FIPS 203), `falcon-rs` (FIPS 206), `chacha20poly1305`,
`sha3`.

Neither document is in this tree: both are in the SDK repository that the workspace
pins as a git dependency (`origin-crypto-sdk`, OriginSDK `v0.7.4`). The ratings are
a property of that pinned version — an audit of a later one is a different
question, and the pin is what makes this citation checkable.

Suite `0x0002` (X25519 + ML-KEM-768) removes the custom NTRU leg from the
handshake entirely while remaining hybrid and post-quantum. ADR-0010 measured the
alternative: sntrup761 is ~9.4 ms per decapsulation, a full handshake ~54 ms and
~9 KB, against ~1.81 ms for `0x0002`.

**Decision**: the mesh agent's generated configuration defaults to suite `0x0002`.
Suite `0x0003` remains available and documented as the choice for deployments that
specifically want the independent non-NIST PQ leg, with the audit-surface
trade-off stated next to it. This is a default for the mesh agent's output, not a
change to the daemon's default: hub deployments — the daemon with no agent running,
which is all of them today — keep ADR-0010's tri-hybrid, where handshake volume is
bounded by client count rather than by peer-pair count.

What this does not solve: hybrid signing stays on the hot path, because identity
documents are signed and verified per peer relationship. That remains the single
highest-value audit target, and it is one component with a small surface — a
targeted review, not a whole-SDK audit.

## Alternatives Considered

### Alternative 1: Change core into a native mesh mode
- **Pros**: one binary, one config, no external process, first-class `topology = "mesh"`.
- **Cons**: touches the datapath that is currently correct and tested; adds a
  topology concept to a protocol that is deliberately topology-free; puts
  coordination (a service concern) inside a daemon that has no service concerns;
  and duplicates roaming, which already works.
- **Why not**: the primitives already exist. Rebuilding them in core is work that
  produces no new capability, in the one part of the project that is hardest to
  get right and most expensive to re-verify.

### Alternative 2: A library crate loaded into the daemon (a true plugin)
- **Pros**: no IPC, no separate process, direct access to peer state.
- **Cons**: a dynamic-loading surface in a security daemon; a plugin ABI to
  version and audit; the daemon's sandbox and privilege model would have to admit
  third-party code.
- **Why not**: "plugin" should mean *a separate process driving a documented
  interface*, not *foreign code inside the trusted process*. The UAPI is already
  the interface, and it is already the trust boundary.

### Alternative 3: Adopt Headscale as the coordination plane
- **Pros**: exists today, proven, Tailscale-client compatible.
- **Cons**: speaks WireGuard's wire contract, which means WireGuard's handshake.
- **Why not**: it would replace Vallum's cryptographic differentiator with the
  thing Vallum exists to improve on. ADR-0016 rejected this for the data plane and
  the reasoning holds.

### Alternative 4: Merge `origin-network` wholesale
- **Pros**: 8 552 lines of traversal and relay already written and tested.
- **Cons**: brings a second handshake (Noise IK), a second identity model, and a
  TCP-framed relay into a UDP-datagram stack.
- **Why not**: two handshakes on one connection is not a merge, it is a rewrite of
  whichever loses. Take the topology, leave the session layer.

### Alternative 5: Keep hub-and-spoke, document the limitation
- **Pros**: zero new code, zero new operational surface, honest.
- **Cons**: the common case ("my laptop and my home server, both behind NAT")
  stays unsupported.
- **Why not**: it forecloses the product. ADR-0016 chose this for a release; it is
  not a viable permanent position for a mesh VPN.

### Alternative 6: Peer-to-peer only, no coordination plane
- **Pros**: no service to run, no metadata concentration.
- **Cons**: suite-sized keys make the peer set large (2 374 bytes per peer for the
  tri-hybrid, per ADR-0002), hand-maintained, and there is nowhere to hold policy
  or issue documents.
- **Why not**: it does not scale past a handful of nodes, and it pushes the
  configuration burden onto exactly the operator a mesh is supposed to help.

## Consequences

### Positive

- **`vallum-core` and `vallum-tunnel` are untouched.** The part of the project
  that is hardest to verify and most expensive to change stays as it is, and its
  existing test suite keeps meaning what it meant.
- The mesh can ship, be rewritten, or be abandoned without a protocol version
  bump or a datapath regression.
- The relay is transparent — no header, no MTU change, no wire format change.
- ADR-0013's "no control plane in core" is preserved rather than reversed. The
  plane is a separate service speaking the machine interface that ADR already
  built for exactly this purpose.
- The mesh agent defaults to `0x0002`, shrinking the unaudited handshake surface
  to hybrid signing alone — a defensible audit scope.
- Hub-and-spoke is not a "mode" to maintain. It is what the daemon does when no
  agent is running.

### Negative

- **Two processes to deploy and supervise** instead of one. The agent needs its
  own unit, its own failure story, and its own restart semantics.
- **The agent is a new trust boundary.** It writes peer configuration, so it can
  add peers. It must not be able to read private keys, and it must authenticate to
  the UAPI socket like any other operator (same-user, 0600).
- **The relay holds N² port mappings** in the worst case, and the plane must
  distribute them. That is a real resource cost on the relay operator.
- **Topology visibility is split.** `vallum doctor` will not know a path is
  relayed; the agent must report it. Two places to look instead of one.
- **The agent is a single point of failure for configuration**, though not for
  traffic: a running daemon keeps its peer set if the agent dies.

### Risks

- **The UAPI becomes a de facto public API.** It was an operator interface; the
  agent makes it a programmatic one. Mitigation: document it as the mesh
  integration surface, version it deliberately, and treat its field semantics as
  a compatibility commitment.
- **The relay's port-allocation scheme does not scale to large meshes.** N²
  mappings is fine for tens of nodes and not for thousands. Mitigation: measure
  the direct-path success rate before building relay capacity, and treat
  large-mesh relay as a separate problem with a different design.
- **The coordination plane is a metadata concentration.** It knows which node
  talks to which. That is a different privacy posture from a hub-and-spoke server
  and must be documented, not buried. Mitigation: operator-runnable; the relay
  learns topology only.
- **The unaudited SDK is load-bearing for more users.** Mitigation: the `0x0002`
  default, plus the audit sequencing below.
- **Scope creep into a policy engine.** Mitigation: ACLs compile to `allowed_ips`
  and nothing else; anything more is a separate argument.

## Implementation sequence

Each phase is independently shippable and independently useful.

1. **`vallum-mesh` applies a static peer set.** No plane, no traversal: read a
   peer list from a file, write it to the daemon over UAPI, verify with
   `vallum show`. This proves the integration surface against a topology that
   already works, and it is the phase that would expose any UAPI gap.
2. **`vallum-coord` issues documents and serves signed peer sets.** The agent
   fetches instead of reading a file. Version monotonicity and rollback detection
   land here.
3. **STUN and hole punching.** Candidate exchange through the plane; the agent
   writes the punched endpoint on success. Measure the direct-path success rate
   before building any relay capacity, because that number sizes the relay.
4. **Relay as a port-allocating UDP forwarder.** Per-peer port allocation,
   registration, and the plane distributing the mappings. Opaque forwarding,
   opt-in, pinned fingerprint, visible in the agent's status.
5. **MagicDNS.** Names from the node registry, compiled to `allowed_ips` and
   resolver configuration.
6. **ACLs.** Minimal policy, compiled to `allowed_ips` at the plane.

Audit sequencing, in parallel and not optional for a security product:

- **Before phase 2**: mutation testing at real scale on the three handshake-path
  components. `QUALITY_REPORT.md` reports 100% on 25 mutants; 25 is too small a
  sample to be evidence for a crypto crate, and this is free to fix.
- **Before phase 4**: targeted review of `signing::hybrid`. One component, small
  surface, rated High by the project's own package. This is the review that
  matters, and it is a targeted engagement, not an SDK audit.
- **Before any public relay**: the `0x0002` path is external-and-audited except
  for hybrid signing, so a review of that one component covers the relay's
  exposure.

## Open questions

1. **Does the agent own `allowed_ips` or does the operator?** If the agent applies
   `replace_allowed_ips`, it will clobber hand-written prefixes. Leaning: the
   agent owns a dedicated interface and the operator's edits go elsewhere.
2. **What is the failure story when the plane is unreachable at boot?** A node
   with a cached, unexpired peer set should start. A node with nothing should not
   silently come up with an empty mesh.
3. **Does the relay need per-path MTU discovery?** It adds no bytes, so probably
   not — but the outer path gains a hop and the assumption should be measured, not
   asserted.
4. **How does the agent authenticate to the UAPI socket?** Same-user and 0600 is
   the current model. Whether the agent should have a distinct credential is
   unresolved.
5. **Is `vallum-mesh` one binary or three?** Agent, relay, and coordination plane
   share a crate but have very different deployment shapes and privilege needs.
