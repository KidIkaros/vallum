# ADR-0004: Extract the TOML schema into vallum-config

**Date**: 2026-10-19
**Status**: accepted
**Deciders**: Vallum maintainers

## Context

`vallum-quick` depended on the `vallum` daemon crate for `Config`, which pulled
the TUN backend, UDP socket, privilege code, and the crypto SDK into an admin
tool that only reads a TOML file. The package audit flagged this as an SDP/CRP
violation: the most volatile crate was reused for a small, stable slice.

## Decision

Create `vallum-config` with the TOML schema only: `Config`, `Interface`,
`PeerEntry`, `Quick`, `ShapingSpec`, `Log`, `Config::load`, and `ConfigError`.
Resolution stays in the daemon as the `ResolveConfig` trait (`suite_id`,
`resolve`, `resolve_with`), because it needs the crypto suite, the key file, and
the OS privilege policy. `vallum` re-exports the schema types; `vallum-quick`
depends on `vallum-config` instead of `vallum`.

## Alternatives Considered

### Alternative 1: Feature-gate the daemon crate
- **Pros**: no new crate; one package.
- **Cons**: the admin tool still compiles the daemon's OS layer and dependencies;
  the feature matrix grows and is easy to get wrong.
- **Why not**: a separate crate makes the dependency boundary explicit.

### Alternative 2: Duplicate the schema in `vallum-quick`
- **Pros**: simplest split; no new crate.
- **Cons**: two definitions drift; a field added to the daemon is silently
  unknown to the admin tool.
- **Why not**: one schema is the point.

### Alternative 3: Move keys, privileges, and the error type too
- **Pros**: more reuse; one config-and-key library.
- **Cons**: the config crate becomes Linux/OS-coupled through `nix` and `prctl`,
  and the daemon's error type grows into it.
- **Why not**: resolution is daemon policy; the schema is the stable slice.

## Consequences

### Positive
- `vallum-quick` depends only on clap, ipnet, `vallum-config`, and
  `vallum-tunnel`; no daemon, `tun2`, `origin-crypto-sdk`, or `nix`.
- The TOML schema has one definition.
- The daemon's resolution stays with the code that owns the suite and OS policy.

### Negative
- One more crate.
- Callers of `suite_id`/`resolve` must import the `ResolveConfig` trait.
- `Config::load` returns `ConfigError`; the daemon converts it to `Error`.

### Risks
- The schema/resolution split could hide a validation rule; the daemon's tests
  and the e2e exercise the combined path.
