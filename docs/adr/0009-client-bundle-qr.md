# ADR-0009: A versioned client bundle and animated multi-frame QR

**Date**: 2026-10-19
**Status**: accepted
**Deciders**: Vallum maintainers

## Context

A tri-hybrid public line is ~4.7 KB of hex; a full client config is larger. A
single QR code holds at most ~2.9 KB at version 40-L, so a literal full-config
QR is impossible. A client config also needs a private key, which the config
schema represents as a file path, not an inline value.

## Decision

Export a versioned JSON bundle containing the client config TOML and the key-file
TOML. The key stays a separate 0600 document inside the bundle; no inline seed is
added to the config schema. The bundle is split into up to 16 frames:

`VALLUM1:<seq>/<total>:<sha256-prefix>:<chunk>`

and animated in the TUI at ~700 ms/frame. The SHA-256 prefix is checked by the
importer; the file fallback is `<key>.vallum-bundle`, written 0600 and ignored by
`.gitignore`. Import is from a file; there is no camera scanner in the terminal.

## Alternatives Considered

### Alternative 1: Inline `private_key_seed` in TOML
- **Pros**: one human-readable config; a single artifact.
- **Cons**: a secret in a config file, a schema change, and a permission policy
  for the config itself.
- **Why not**: the bundle keeps the key as a 0600 file and the config schema
  unchanged.

### Alternative 2: A single QR, best effort
- **Pros**: simplest.
- **Cons**: impossible for the tri-hybrid; a capacity error for the default suite.
- **Why not**: the user asked for a full config; multi-frame is the honest way.

### Alternative 3: A peer invite QR only
- **Pros**: small; no private key.
- **Cons**: not a full config; the receiver still has to generate a key and edit.
- **Why not**: full config was the chosen scope.

## Consequences

### Positive
- A full client can be exported without a schema change or a secret in TOML.
- The bundle is integrity-checked and file-fallback-safe.
- The QR is explicit about being a secret-bearing view.

### Negative
- A receiver needs a multi-frame-aware importer (the TUI imports the file).
- The QR modal contains the private key; it must be closed/cleared and never
  logged.
- A 16-frame bound may reject very large configs; the file fallback remains.

### Risks
- Chunking must not split a UTF-8 character; the splitter respects char
  boundaries and the tests cover a multi-byte payload.
- A future field added to the config does not change the bundle format; the
  version field is the compatibility gate.
