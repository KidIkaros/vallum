# Plan: what origin-tools can and cannot give Vallum

**Date:** 2026-11-12 · **Status:** premortem done, one defect fixed, one gate added · **Author:** Claude

## The premise, stated and checked

> "origin-tools shares the same core, same dependency of the sdk. We could
> literally port any code we need from it to satisfy this."

Three parts. Two check out; one does not.

| Claim | Verdict | Evidence |
|---|---|---|
| Same crypto dependency | **true** | Vallum: `origin-crypto-sdk` at git tag `v0.7.4` (`Cargo.toml:46`). origin-tools: the same crate at `=0.7.2` (`origin-tools/Cargo.toml:43`) — **two versions behind** |
| Porting is mechanically feasible | **true for the crypto-facing crates** | A copy of origin-tools repointed at `v0.7.4` builds `origin-channel` and `origin-network` **unchanged** (`BUILD=0`). The whole workspace fails to resolve: the SDK's `zstd` feature pulls `zstd-safe 8.2.0 → zstd-sys`, and origin-tools' committed `Cargo.lock` conflicts (`origin-canary` is what pulls the feature) |
| The two trees can converge on one SDK | **false, and it is a one-way door** | The registry holds **only 0.7.2** (`~/.cargo/registry/cache`: `origin-crypto-sdk-0.7.2.crate`); 0.7.3 and 0.7.4 exist **only as git tags**. So moving either tree means a *source* swap, not a version bump. And Vallum **cannot** move backwards: `crates/vallum-crypto-sdk/src/lib.rs:270` calls `MlKem768Kem::encapsulate_deterministic`, which is **absent from v0.7.2** (`git show v0.7.2:src/pqc/ml_kem.rs` → no match) — the adapter would not compile. Worse, `deny.toml:67` is `multiple-versions = "warn"`, so cargo-deny would **not** stop two SDK copies linking side by side |
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
| STUN + hole punching | `origin-network/src/nat.rs` (666 lines; the file's own header says it was adapted from `signet-channel/src/transport/{stun,p2p}.rs`) | 4 | small, **but it discloses the client's public IP to a third party** — `DEFAULT_STUN_SERVER = "stun.l.google.com:19302"` (`nat.rs:39`) — against a project whose stated posture is that DNS does not leak (`docs/requirements.md`). Worse, **Vallum's own guard would drop the packet**: the egress table's terminal rule is `drop` (`crates/vallum/src/policy.rs:240`) with accepts only for the tunnel's endpoint and DHCP (`:197-207`), so a STUN query to Google never leaves — ADR-0018's whole rule is "a packet may leave this host only through the tunnel, or to the endpoint that carries the tunnel" |
| Relay | `origin-network/src/relay.rs` (859 lines), `relay_server.rs` | 5, 4 | needs a publicly reachable server with bandwidth, state, eviction and abuse handling — a **deployment**, not a crate |
| Ratcheted session for enrolment | `origin-channel/src/handshake.rs` (337), `session.rs` (370), `ratchet.rs` (154) | 3 | **a second protocol** (see the premise table) — and a ratchet needs an authenticated peer key, which is the thing the human copy carries today. Two of its ingredients are already *refused in writing* here: Vallum's crypto contract exposes **no DH operation** (so origin-channel's `DH(s_i, s_r)` cannot be expressed at all), and `crates/vallum-core/src/session.rs:14-30` rejects the symmetric chain origin-channel's ratchet implements, with the Babbage–Golić reason |
| QUIC carrier | `origin-network/src/quic.rs` | 5 | a new carrier end to end: config, carrier dispatch, both ends, gates, docs |
| Release attestation | `origin-tools/RELEASE_ATTESTATION_DESIGN.md` + implementation | 2 | **thin** — Vallum's release path already signs and stamps; origin-tools treats its own as "a reference implementation, not a product dependency" (its HEAD commit) |
| Data-ops CLI (`origin-seal`) | `origin-seal/src` | — | nothing in Vallum needs it; Vallum's `bundle.rs` already does the encrypted-bundle job |

## The gap the port does not touch

Gaps 1 and 2 — the private repository and the stale release — need **no line of
ported code**. They need a version decision, a signed tag, and a visibility
switch. Meanwhile the port opens a programme (a second protocol, a relay, a
QUIC carrier, a STUN dependency) that would displace the two hours of work
which would actually let a stranger install the product.

## What the premortem found, and the one thing it changed

Six investigators went deep on the plan. Their findings were checked against
the trees before any of it was believed, and three claims died on contact:

- *"crates.io has no 0.7.3 or 0.7.4"* — the registry cache holds only
  `origin-crypto-sdk-0.7.2.crate` ✓, and the local SDK checkout's tags stop at
  `v0.7.3` ✓. **Confirmed**, and it is worse than a version skew: the two
  trees cannot converge without a *source* swap, and Vallum cannot move
  backwards at all (`encapsulate_deterministic` is absent from v0.7.2).
- *"cargo-deny would stop two SDK copies"* — **false**: `deny.toml:67` is
  `multiple-versions = "warn"`, so the supply-chain gate would go green with
  two SDKs linked.
- *"a STUN client would work"* — **false**: Vallum's own egress guard drops
  the packet before it leaves the host.

Two findings **confirmed a decision already taken in writing**:

- `docs/adr/0015-enrolment-v2.md:75-77` already refused this port's premise:
  *"The client has no static key before enrolment; a static leg would require
  provisioning the very thing enrolment exists to provision."* The ratchet
  port re-introduces the static leg that ADR-0015 removed.
- `crates/vallum-core/src/session.rs:14-30` already refuses the ratchet
  origin-channel implements, with the reason (Babbage–Golić time/memory
  tradeoff attacks), and `crates/vallum-crypto/src/suite.rs` exposes **no DH
  operation** — so origin-channel's `DH(s_i, s_r)` cannot be expressed through
  Vallum's contract at all.

### And one finding that was a defect in this repository, now fixed

The file path — the *primary* path, the one ADR-0034 calls a method rather
than a ritual — installed whatever key the config named, with **no way to
check it**: `--expect` carried `requires = "join"`, so the token path could
verify the server's fingerprint and the file path could not. A config that
travelled over email, USB or a chat could be anything, and the operator's
copy was the only thing binding the client to that server.

Now `vallum setup --client-config <file> --expect-server <fingerprint>`
refuses a config naming a different server, **before anything is written**,
with the decision in a pure function (`check_server_fingerprint`) and its own
tests.

## Revised plan

What the premortem changed, in the order it is worth doing:

1. **Do not port anything for the enrolment.** ADR-0015 already refused the
   premise — a static leg would require provisioning the very thing enrolment
   exists to provision — and the file path's real gap is trust establishment,
   not transport. That gap is now partly closed: `setup --client-config
   <file> --expect-server <fingerprint>` refuses a config naming another
   server, before anything is written.
2. **Keep the SDK at the git tag, always — and enforce it.** cargo-deny cannot
   express "deny a duplicate of this one crate" (its `multiple-versions` is
   global, and the workspace legitimately carries duplicates), so the guard is a
   lockfile check instead: `scripts/check-sdk-pin.sh` asserts the lockfile
   names `origin-crypto-sdk` **once** and from the pinned git source. It runs
   in the supply-chain CI job and in `scripts/ci-local.sh`, and its failure
   prints both copies — because "the pinning policy" is not the same thing as
   the pinning policy being enforced.
3. **If STUN is ever wanted, it cannot use a third-party default.** It would
   disclose the client's public address to Google on every connect, and
   Vallum's own fail-closed guard would drop the packet anyway
   (`crates/vallum/src/policy.rs:240`). A self-hosted STUN server, or the
   peer-exchange design in `docs/research/pi-hole-in-vallum.md`.
4. **Write the porting discipline down before any port** — carry the tests
   with the code, no second protocol, nothing behind the adapter but
   `vallum-crypto-sdk`, no dependency skew, and **the gate is the
   deliverable**: a port that no gate in Vallum can observe is a port that is
   not finished.

## Decision

**Port nothing yet.** The premise is half right, and the half that is right
does not point at the blockers. Two of the port's ingredients are already
refused in this repository's own ADRs and code comments, and the third — the
enrolment — is a trust-bootstrap problem that a transport cannot solve.

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
