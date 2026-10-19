# ADR-0012: Defer a code-based KEM and prefer HQC or a provisioned McEliece profile later

**Date**: 2026-10-19
**Status**: accepted
**Deciders**: Vallum maintainers

## Context

Vallum's default suite (`0x0003`) combines X25519, sntrup761, and ML-KEM-768.
This provides a classical leg plus two post-quantum legs, but sntrup761 and
ML-KEM-768 are both broadly lattice-family. A code-based KEM would add a
different cryptanalytic assumption, not a capability that is missing from the
current SDK.

The research literature supports hybrid deployment and use-case-specific KEM
selection. NIST selected HQC for standardization in March 2025 as a
non-lattice backup to ML-KEM; FIPS 207 is still in draft/finalization. BIKE was
not selected, and its IND-CCA security depends on a probabilistic decoder's
failure rate: weak-key and m-gathering analyses can push static-key security
below target unless the decoder, key binding, and key filtering are fixed.
SIDH/SIKE was broken by a practical key-recovery attack.

Classic McEliece is the conservative code-based candidate, but its very large
public key only fits Vallum if that key is provisioned or cached out of band.

## Decision

Keep the current SDK-backed suites and default unchanged. Defer code-based KEM
support to a future suite/profile implemented through `origin-crypto-sdk` and
exposed only through Vallum's `CryptoSuite` abstraction.

If a code-based suite is pursued, evaluate only:

1. **HQC**, after FIPS 207 is stable enough to implement against and the
   implementation is mature and auditable;
2. **Classic McEliece**, only as a provisioned/static profile where its public
   key can be distributed outside the normal handshake/public-line path.

Do not use BIKE or SIDH. Do not claim that a code-based leg makes the existing
tri-hybrid handshake single-packet.

## Alternatives Considered

### Alternative 1: Keep only the current lattice hybrid
- **Pros**: no SDK or protocol work; the current suites already provide classical
  plus two PQ legs.
- **Cons**: no protection against a future cryptanalytic advance that affects
  the shared broad lattice family.
- **Why not**: diversity is valuable enough to keep on the roadmap.

### Alternative 2: Add a code-based KEM now
- **Pros**: immediate family diversity.
- **Cons**: the SDK has no code-based primitive; adding one requires a new
  implementation, vectors, benchmarks, side-channel review, protocol analysis,
  and provisioning design.
- **Why not**: this is a v0.2 project, not a safe patch.

### Alternative 3: Use HQC immediately
- **Pros**: NIST-selected non-lattice KEM; the clearest path to a standardized
  code-based backup.
- **Cons**: FIPS 207 is not final; parameter and formatting changes are still
  possible; no audited SDK implementation exists yet.
- **Why not**: wait for a stable standard and a reviewable implementation.

### Alternative 4: Use BIKE
- **Pros**: code-based; competitive bandwidth in some settings; a fresh
  ephemeral key can rely on IND-CPA rather than IND-CCA.
- **Cons**: NIST selected HQC instead in IR 8545. BIKE's IND-CCA security for
  long-term static keys depends on the decoder's low failure rate; weak-key and
  m-gathering analyses can exceed the allowed contribution, and the BIKE team's
  2024 material still lists weak-key/error-floor open questions. A 2026
  deep-learning attack against the latest unprotected BGF reference
  implementation recovered a private-key-dependent 16-bit sequence with 95.68%
  perfect sequence recovery; it is not a full key recovery, but it demonstrates
  continued implementation-leakage risk. Vallum's code-based leg would be a
  long-term static KEM, so the ephemeral/IND-CPA shortcut does not fit.
- **Why not**: not safe for Vallum's static-key model, not the selected
  standard, and would require decoder, key-binding, weak-key-filtering, DFR,
  and side-channel proof work before it could be reconsidered.

### Alternative 5: Use Classic McEliece in the normal public line
- **Pros**: the most conservative code-based candidate.
- **Cons**: its public key is far too large for the current key line, QR/bundle,
  UAPI, and peer-identity assumptions.
- **Why not**: it is only viable when provisioned/cached out of band.

### Alternative 6: Use an isogeny-based KEM such as SIDH/SIKE
- **Pros**: small keys were historically attractive.
- **Cons**: the SIDH/SIKE family suffered a practical break.
- **Why not**: rejected as a Vallum candidate.

## Consequences

### Positive
- The current release remains aligned with the SDK and already-tested suites.
- Code-based diversity remains a documented roadmap objective.
- The eventual design can choose between HQC and a conservative provisioned
  McEliece profile.
- Public-key size is treated as an operational design constraint, not just a
  KEM parameter.
- BIKE and SIDH are explicitly excluded rather than left as vague options.
- BIKE's weak-key/decoder-failure constraint is recorded as a static-key
  mismatch, not merely as a NIST selection result.
- BIKE's implementation-level leakage evidence is recorded without overstating
  it as an algorithmic break.

### Negative
- Vallum still has no non-lattice post-quantum leg.
- HQC cannot be adopted until FIPS 207 and an audited implementation are ready.
- Classic McEliece requires a different provisioning model from today's public
  key line and QR/bundle flow.

### Risks
- HQC parameters may still change before FIPS 207 is final. Mitigation: track the
  draft, pin a final parameter set, and require vectors and audit before
  enabling it.
- BIKE weak-key and side-channel analyses may evolve. Mitigation: BIKE may only
  be reconsidered if a standardized implementation demonstrates a decoder with
  an adequately bounded failure rate, binds the public key into the ciphertext,
  filters weak keys, and passes side-channel review; it remains excluded now.
- Any code-based implementation, including HQC, may leak through power or
  timing behavior. Mitigation: require constant-time properties, independent
  side-channel review, and attack-surface documentation before SDK integration.
- A future code-based primitive may receive damaging cryptanalysis. Mitigation:
  keep it optional, keep the current tri-hybrid default, and require vectors,
  benchmarks, audit, and Tamarin review before enabling it by default.
