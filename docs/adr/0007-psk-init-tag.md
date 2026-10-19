# ADR-0007: Authenticate `InitHello` with a configured-PSK admission tag

**Date**: 2026-10-19
**Status**: accepted
**Deciders**: Vallum maintainers

## Context

PQ-WireGuard mixes the configured PSK into the timestamp-encryption key, so the
responder can reject a forged `InitHello` after op A and before the expensive
ops B/C. Vallum's configured PSK was only in the final schedule: a forged
`InitHello` with a valid sealed hint could still force both responder
encapsulations. The paper's Tamarin `dos_mitigation` lemma depends on this
early check.

## Decision

Add an optional 32-byte `PSK_TAG` to `InitHello` when a PSK is configured. It is
`KDF(salt = PSK, ikm = InitHello minus PSK_TAG and MAC1/MAC2,
info = "vallum/init-psk-tag/v1")`. The responder checks it after op A and the
hint check, before op B. Wrong, missing, or unexpected tags return
`HandshakeError::PskTag` with no reply. `None` adds no field and keeps every
default vector byte-identical; the tag is admission-only and not folded into
`TR`.

## Alternatives Considered

### Alternative 1: Keep the PSK in the final schedule only
- **Pros**: no wire change.
- **Cons**: no early rejection; a forged `InitHello` forces ops B/C; the paper's
  DoS property is not met.
- **Why not**: this is the gap the paper exposed.

### Alternative 2: Encrypt the timestamp under a PSK-keyed key (the paper's form)
- **Pros**: closest to PQ-WireGuard.
- **Cons**: changes the timestamp field/key schedule and the PSK vectors; the
  timestamp is already public and replay-guarded.
- **Why not**: a separate tag gives the same admission property with less churn.

### Alternative 3: Fold the tag into `TR`
- **Pros**: one transcript covers admission.
- **Cons**: couples an admission check to the session transcript, changes PSK
  vectors, and makes the tag's failure look like a transcript failure.
- **Why not**: admission should be checked and reported before the session
  derivation.

## Consequences

### Positive
- A forged initiation costs the responder one op-A decapsulation, not ops B/C.
- Default vectors unchanged; only PSK-configured handshakes add 36 B.
- The tag is constant-time and draws no reply, so it is not a PSK oracle.

### Negative
- A new wire field on the PSK path; PSK KATs must be regenerated.
- The tag covers `InitHello` minus the cookie MACs; the exclusion is deliberate
  because the tag is computed before the MACs are attached.

### Risks
- A future field added to `InitHello` must be included in the tag input; the
  builder/parser share `psk_tag_input`, so the omission is a code change, not a
  configuration choice.
- Tamarin must model the tag; if a lemma fails, the code fix stays but the claim
  is downgraded and recorded.
