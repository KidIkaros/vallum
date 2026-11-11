# MOOR as the north star (2026-11-11)

Direction doc. MOOR_PQ (a friend's project, used by permission) is the
reference architecture Vallum grows toward. This records what it does, what
Vallum already took, and the order in which the rest gets adopted — as
designs, never as code (separate licence, different language, different
threat model; the earlier consult already ruled out importing it).

## What MOOR is, verified from the repo (160 commits, C)

A **3-hop onion overlay**: client → guard → middle → exit, each relay peeling
one layer, none knowing both ends. Hybrid post-quantum on every layer
(X25519 + ML-KEM-768, Ed25519 + ML-DSA-65/Falcon-512, no downgrade path).
Multi-DA consensus with dual signatures. Hidden services (`.moor` addresses
committing the PQ keys). Six pluggable transports for censored networks —
the one that matches "minecraft networking" is **Nether**: cover traffic that
is a real Minecraft 1.21.4 handshake and login on the wire.

Operator-facing pieces worth naming: per-fingerprint relay lookup, a
reachability tester, build-ID fleet gates (mixed-commit fleets cannot form),
a mandatory exit notice, seccomp-bpf sandbox, mlockall, Argon2id PoW for relay
admission.

## What Vallum already took from it

- **EPERM instead of SIGSYS** for off-list syscalls — a missing filter entry
  costs one operation, not the tunnel (`sandbox.rs`).
- **Operator visibility as a first-class concern** — the console's verdicts,
  drift checks and preflight exist because MOOR treats operator trust as part
  of the protocol.
- **seccomp-bpf allow-list discipline**, and the deferred `PR_SET_DUMPABLE(0)`
  (deferred precisely because it blocks the diagnostic that just closed
  Phase 2).

## The four gaps, in adoption order

### 1. A carrier abstraction (prerequisite for everything below)

Vallum's datagrams leave through one UDP socket hard-wired in the tunnel
loop. MOOR's transports work because the cell layer knows nothing about the
carrier. **First step:** introduce a carrier boundary in `vallum-tunnel` —
one trait with `send(datagram)` / `recv()` — with the current UDP socket as
the only implementation. No behaviour change; it is the seam the next three
items need. Small, testable, reversible.

### 2. Nether-style transport (the "minecraft networking")

A bridge mode: client speaks a Minecraft-1.21.4-shaped TCP stream (VarInt
framing, status/handshake, login sequence) carrying Vallum datagrams; the
bridge converts to real UDP toward the server. The server stays untouched.
Why this one first: it is the user's stated interest, it needs no consensus,
and it exercises the carrier seam with a real second implementation. The
cover only needs to survive DPI heuristics, not to be a playable server.

### 3. A signed relay list (the "many hosts" foundation)

Today a client trusts one endpoint string. The multi-host model starts as a
**static, signed relay file**: entries of `{name, endpoint, fingerprint, role}`
signed by a key the client pins — MOOR's consensus without the protocol.
Clients learn relays from it; the console shows the list and lets the operator
pin one. Multi-DA signing is a later step, triggered by the second independent
operator.

### 4. Multi-hop circuits (the actual onion)

Guard → middle → exit with per-hop keys, fixed-size cells, and path selection
from the relay list. This is the big one and the reason for the order above:
it needs carriers (1), relays to choose from (3), and a threat model that
names what it protects (Vallum's current promise is "the server does not see
your traffic's content"; multi-hop changes the promise to "no single host
sees both ends").

## Deliberately NOT adopted (with the trigger that would change it)

| MOOR capability | Why not now | Trigger |
|---|---|---|
| 55k-line Tor-compatible core | Vallum is an L3 VPN with its own identity; cloning Tor is a different product | never — borrow designs, not the architecture |
| Consensus protocol / DAs | one operator, one server; a signed file is enough | a second independent operator joins |
| PIR descriptor storage | no hidden-service directory exists yet | hidden services ship |
| Conflux multi-path, EWMA scheduling, WTF-PAD | traffic-analysis defence for an anonymity network; Vallum's current threat model is a hostile network, not a global observer | the threat model widens |
| Enclaves | single fleet today | a partner wants an independent network |
| Argon2id relay PoW | nobody is flooding relay admission | public relay list exists |
| Build-ID fleet gate | already have the effect via `vallum-ops sync` drift checks | fleet grows past one operator |

## What the north star changes about today's roadmap

The alpha stays an L3 VPN with one server; nothing above lands before the
current phases close. But the ordering matters: **carrier seam first**, because
it is the only step that is cheap now and expensive to retrofit later — every
transport, relay hop and mimicry mode depends on the tunnel loop not knowing
what a socket is.
