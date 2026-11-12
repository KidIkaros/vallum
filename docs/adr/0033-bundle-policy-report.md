# ADR-0033: An imported bundle states its policy, and a weak one is refused

**Date**: 2026-11-11
**Status**: proposed
**Deciders**: Vallum maintainers
**Answers**: `security-redteam-round2.md` R2-2

## Context

A bundle is a file a stranger's server hands to a root-running daemon. `import`
validates it syntactically — `toml::from_str`, then `Config::load` — and writes
it. Every one of these is a legal, accepted config:

- `seccomp = "off"` — the sandbox is gone, and nothing says so;
- no `user` — the daemon runs as root and never drops privileges;
- `control = "/tmp/vallum.sock"` — a control socket in a world-writable
  directory, reachable by every local user and pre-creatable by any of them;
- its own `[quick] dns` — every name the client resolves goes where the server
  chooses.

The client's operator believes they imported an address and a key. In fact they
imported a **local security policy they never saw**. The bundle format has a
`version` (checked) and a name (sanitised), and nothing that describes what the
resulting daemon will look like.

There is prior art in this repo's ecosystem: `origin-tools/origin-provenance`
carries a signed `ReleaseManifest` with `product`, `channel`, a monotonic
`sequence` used as rollback defence (T2), and `--artifact` narrowing so an
installer verifies only the members it installs. Its `verify.rs` refuses before
use. That is the same shape this problem needs.

## Decision

**Two halves, the first cheap and the second the real one.**

1. **`import` prints an effective-policy block before writing anything**, and
   `--strict` refuses a bundle that is weaker than the *local defaults* — not a
   hardcoded list, because the local defaults are what the operator already had.
   The block names: sandbox mode, whether privileges drop and to whom, the
   control path and its directory's mode, and the DNS servers. A control path
   outside a root-only directory warns **even without `--strict`**, because it is
   the setting that admits other local users.
2. **A bundle carries a signed manifest** — member list, monotonic sequence,
   signer — in the shape `origin-provenance` already uses, so an import can
   verify before use, name the signer, and refuse a rollback.

Half 1 is judgement about a config. Half 2 is authentication of the file, and
they are separate because half 1 is provable today and half 2 needs a format
version and a key distribution answer.

## Alternatives Considered

### Alternative 1: refuse anything not matching the defaults, no report
- **Pros**: one rule, no output to read, no policy vocabulary in the import path.
- **Cons**: a legitimate bundle that pins `dns` to the server's resolver is
  refused with no explanation, and the operator learns to pass `--strict` off.
- **Why not**: the report *is* the feature; the refusal is the option.

### Alternative 2: hash-pin the config only
- **Pros**: cheap, catches a modified file.
- **Cons**: says nothing about *weaker*, only *different*; and a hash the same
  channel delivered is no defence against the server.
- **Why not**: orthogonal — good with half 2, useless alone.

### Alternative 3: trust the server, it administers the tunnel anyway
- **Pros**: zero work; the server can already do a lot.
- **Cons**: the server cannot turn off the client's sandbox or move its control
  socket — those are strictly local settings it is currently allowed to
  overwrite blind.
- **Why not**: true and insufficient.

## Prior art in `origin-tools`, and what to take

**Take the shape, not the dependency.** `origin-provenance` is a separate tree
with its own harness; vendoring it would couple Vallum to an unrelated crate for
one manifest type.

Directly reusable as design:

- **`ReleaseManifest`** (`origin-provenance/src/release.rs:68`) — signed
  `product` / `channel` / `sequence`, artifacts in canonical order.
- **`sequence` as rollback defence** — a bundle signed with sequence *n* loses to
  a stored *n-1*, which is the "server serves you the old, sandbox-off config"
  attack. This is the half that makes the report more than a courtesy.
- **`--artifact` narrowing** (`commands.rs:630`) — verify only the members the
  importer will install, so a large manifest does not become an import cost.
- **Verify-before-use in `verify.rs`** — the refusal happens before anything is
  written, which is the ordering `import` must adopt.
- **`origin-attest`'s revocation journal** — if a signer key is ever retired, the
  answer already exists there; it also gives a trust-graph vocabulary for "who is
  allowed to sign a bundle for this relay" instead of inventing one.

Not reusable: the types (different crate, different serde and error shapes), the
C2PA/watermark surface (image provenance), and the CLI (`clap` structures tied to
its own commands).

## Consequences

### Positive
- The operator sees the policy they are about to adopt, before adopting it.
- A rollback to a weaker config becomes detectable rather than invisible.
- `--strict` gives the paranoid path without making the default hostile.

### Negative
- Import output grows by a screen, on a path that is currently one line of
  silence.
- Half 2 adds a bundle format version bump; v1 bundles keep working unsigned
  (the report still applies), so it is a soft migration.

### Risks
- **The report becomes noise** → it must be short, ordered by severity, and
  silent when every setting matches the local default. A block that always prints
  the same eight lines gets skipped.
- **`--strict` becomes the default by drift** → keep the flag additive; the
  default must stay "import and tell me", or every bundle from a slightly
  different generator fails.
- **Signing without key distribution is theatre** → half 2 is only worth doing
  with an answer to "who signs, and how does the client learn that key". Until
  then the report's `signer` line reads `unsigned`, and that is honest.
- **A bundle can still carry a hostile `[quick]` table** → out of scope here; the
  quick path runs as root and rewrites `resolv.conf`, and deserves its own look
  (already listed as unattacked in round two).

## Implementation order

1. `import` gathers the effective settings, compares against defaults, prints.
   No format change, no new dependency.
2. Directory-mode and world-writable checks on `control`, warning without
   `--strict`.
3. `--strict` refusal set, defined as exactly the settings half 1 reports.
4. Bundle `version = 2` with optional `manifest`; v1 stays valid and unsigned.
