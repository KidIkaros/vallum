# ADR-0001: Mix a configured PSK after the UKS psk, and keep it out of the identity

**Date**: 2026-10-19
**Status**: accepted
**Deciders**: Vallum maintainers

## Context

WireGuard's `Noise_IKpsk2` accepts a per-peer preshared key; Vallum's only PSK
was derived from both static public keys for UKS mitigation, so an operator
could not add a real shared secret. The default path must stay byte-identical to
the frozen vectors. An earlier implementation stored the PSK on `PeerIdentity`,
which made identity equality include a secret and let two peers with the same
KEM key and different PSKs both pass duplicate detection.

## Decision

An optional 32-byte PSK lives on `PeerConfig`, not `PeerIdentity`. The key
schedule mixes it after the UKS psk as
`key = KDF(key, psk, "vallum/config-psk/v1")`; `None` skips the step. The
handshake exposes `initiator_hello_with_psk`, `responder_accept_with_psk`, and
`responder_process_init_with_psk`; the original functions pass `None`.

## Alternatives Considered

### Alternative 1: Noise IKpsk2-style mix at a fixed step
- **Pros**: WireGuard parity; well-studied placement.
- **Cons**: Vallum's schedule is a hybrid combiner plus UKS mix, not Noise's
  chaining; a fixed step would move the transcript and frozen vectors.
- **Why not**: the post-UKS KDF gives the same property with no wire change.

### Alternative 2: Put the PSK in the transcript
- **Pros**: binds configuration into the handshake.
- **Cons**: changes every vector; turns a mismatch into a transcript failure.
- **Why not**: the confirmation already detects a mismatch.

### Alternative 3: Keep the PSK on `PeerIdentity`
- **Pros**: no call-site churn.
- **Cons**: equality includes a secret; duplicate detection accepted the same
  KEM key with different PSKs; the type no longer means "public identity".
- **Why not**: it caused a real duplicate-peer bug. Moved to `PeerConfig`; the
  `*_with_psk` variants avoid touching 79 call sites.

## Consequences

### Positive
- Defence in depth without a wire change; default vectors byte-identical.
- Identity equality and public-key encoding are public-only.
- A mismatch or one-sided PSK fails as an ordinary confirmation failure.

### Negative
- One extra KDF per handshake when configured.
- The API has parallel `*_with_psk` functions.

### Risks
- The PSK file is a secret-management surface; the 0600 policy and redacted
  `Debug` mitigate it.
