# Plan: what origin-tools can and cannot give Vallum

**Date:** 2026-11-12 · **Status:** scouting complete, premortem in flight · **Author:** Claude

## The premise, stated and checked

> "origin-tools shares the same core, same dependency of the sdk. We could
> literally port any code we need from it to satisfy this."

Three parts. Two check out; one does not.

| Claim | Verdict | Evidence |
|---|---|---|
| Same crypto dependency | **true** | Vallum: `origin-crypto-sdk` at git tag `v0.7.4` (`Cargo.toml:46`). origin-tools: the same crate at `=0.7.2` (`origin-tools/Cargo.toml:43`) — **two versions behind** |
| Porting is mechanically feasible | **true for the crypto-facing crates** | A copy of origin-tools repointed at `v0.7.4` builds `origin-channel` and `origin-network` **unchanged** (`BUILD=0`). The whole workspace fails to resolve: the SDK's `zstd` feature pulls `zstd-safe 8.2.0 → zstd-sys`, and origin-tools' committed `Cargo.lock` conflicts (`origin-canary` is what pulls the feature) |
| "Literally port any code" | **false for the protocol** | origin-channel's handshake is an ephemeral-static Noise-shaped exchange with a running transcript hash (`origin-channel/src/handshake.rs:9-17,42-43`). Vallum's is its own hybrid X25519 + sntrup761 + ML-KEM-768 protocol with its own framing, admission gate, cookie and rekey (`crates/vallum-tunnel/src/device/handshake.rs`). Both are built on the same primitives — that is not the same protocol |

## What the two trees actually are

Complementary, not overlapping. Sharing a crypto library is not sharing a product.

**origin-tools** (`~/Coding/Gold/origin-tools`, 23 crates, ~90k lines, Apache-2.0 ✓) has
the *primitives and protocols*: `origin-channel` (ratcheted session, Noise-shaped
handshake), `origin-network` (STUN + hole punching, relay, QUIC, UDP),
`origin-seal` (data-ops CLI), `origin-provenance`, `origin-secrets` (K-of-N),
`origin-vcs` (encrypted bundles), `origin-wallet`, `origin-payments`.

**Vallum** has the *product around them*: the installer and its packaging, the
systemd units, the console and the TUI, the seccomp sandbox, the acceptance
gates, the signed release path. origin-tools has **no packaging, no units, no
installer, no console** (checked: no `*.service`, `*.deb`, `*.rpm`, `install.sh`
anywhere in it) ✓ and a **thinner release path** — its `release.yml` builds,
packages and uploads, with no signing, no SHA256SUMS and no attestation steps,
while Vallum's `release.sh` signs, stamps and refuses an unsigned release.

So: origin-tools is where **protocols and primitives** live. Vallum is where
**the shippable thing** lives. A port moves protocols *into* the product; it
does not move the product *out*.

## The candidates, mapped to Vallum's actual gaps

Vallum's remaining gaps, in the order they block a stranger:

1. **The repository is private** — no stranger can install what the gates prove.
2. **The release is stale** — `v1.6.4` (2026-11-05) against a tree at `def8170`;
   `scripts/release.sh --dry-run` refuses on the tag rule.
3. **Enrolment needs a human** — the server writes `laptop.toml`, an operator
   copies it and `laptop.key` to the laptop, the client installs it with
   `vallum setup --client-config`.
4. **No NAT traversal** for real clients behind NAT.
5. **No relay** for censored networks (ADR-0026's fallback is `carrier = "tcp"`
   on both ends).

| Candidate | Source | Gap it would touch | Measured cost |
|---|---|---|---|
| STUN + hole punching | `origin-network/src/nat.rs` (666 lines; the file's own header says it was adapted from `signet-channel/src/transport/{stun,p2p}.rs`) | 4 | small, **but it discloses the client's public IP to a third party** — `DEFAULT_STUN_SERVER = "stun.l.google.com:19302"` (`nat.rs:39`) — against a project whose stated posture is that DNS does not leak (`docs/requirements.md`) |
| Relay | `origin-network/src/relay.rs` (859 lines), `relay_server.rs` | 5, 4 | needs a publicly reachable server with bandwidth, state, eviction and abuse handling — a **deployment**, not a crate |
| Ratcheted session for enrolment | `origin-channel/src/handshake.rs` (337), `session.rs` (370), `ratchet.rs` (154) | 3 | **a second protocol** (see the premise table) — and a ratchet needs an authenticated peer key, which is the thing the human copy carries today |
| QUIC carrier | `origin-network/src/quic.rs` | 5 | a new carrier end to end: config, carrier dispatch, both ends, gates, docs |
| Release attestation | `origin-tools/RELEASE_ATTESTATION_DESIGN.md` + implementation | 2 | **thin** — Vallum's release path already signs and stamps; origin-tools treats its own as "a reference implementation, not a product dependency" (its HEAD commit) |
| Data-ops CLI (`origin-seal`) | `origin-seal/src` | — | nothing in Vallum needs it; Vallum's `bundle.rs` already does the encrypted-bundle job |

## The gap the port does not touch

Gaps 1 and 2 — the private repository and the stale release — need **no line of
ported code**. They need a version decision, a signed tag, and a visibility
switch. Meanwhile the port opens a programme (a second protocol, a relay, a
QUIC carrier, a STUN dependency) that would displace the two hours of work
which would actually let a stranger install the product.

## Decision

**Port nothing yet.** The premise is half right, and the half that is right
does not point at the blockers.

What the scouting *did* establish, and what is worth acting on:

- The **SDK skew is a real trap**: origin-tools pins `=0.7.2` while Vallum
  tracks the git tag. Accepting origin-tools' code wholesale would pull
  Vallum's crypto dependency backwards, or into two copies. Any port must go
  through Vallum's `vallum-crypto-sdk` adapter (the only crate that names SDK
  types) and `vallum-crypto-contract` (the provider-agnostic contract whose
  `run_contract()` fails CI loudly on a provider swap).
- **STUN is a privacy contradiction**, not a feature: a VPN that discloses the
  client's public address to Google on every connect, in a project that
  advertises that DNS does not leak, is a contradiction a user will find.
- The **enrolment gap is a trust-bootstrap gap**: origin-channel's handshake
  requires a peer static key, and the human copy is exactly how that key
  reaches the client today. Porting the transport does not remove the human.
- **`origin-network`'s NAT code is itself a port** (from `signet-channel`), so
  porting is an established practice in this ecosystem — which means the
  *discipline* of porting (carry the tests, re-verify against the contract)
  is also available and should be written down before any port happens.

## Open questions, for the premortem

Running six read-only investigators against the plan above. Their findings
decide one thing: **is there any port candidate worth making at all, or is
the right answer "the port is the wrong programme"?**

## If a port is ever approved, the rules it must obey

1. **Port the tests with the code.** A ported module arrives without the
   evidence that made it trustworthy; Vallum's own rule is that code which
   builds is not thereby proven.
2. **No second protocol.** A port that cannot speak Vallum's deployed wire
   format is a new product, and it must be argued for as one.
3. **Nothing behind the adapter.** Ported code reaches `origin-crypto-sdk`
   only through `vallum-crypto-sdk`; the contract crate must pass unchanged.
4. **No dependency skew.** The SDK stays at the git tag; origin-tools' `=0.7.2`
   pin never becomes Vallum's.
5. **The gate is the deliverable.** A port that no gate in Vallum can observe
   is a port that is not finished.
