# ADR-0033: An imported bundle states its policy, and a weak one is refused

**Date**: 2026-11-11
**Status**: half 1 accepted and implemented; half 2 proposed
**Deciders**: Vallum maintainers
**Answers**: `security-redteam-round2.md` R2-2

## Context

A bundle is a file a stranger's server hands to a root-running daemon. `import`
validates it syntactically — `toml::from_str`, then `Config::load` — and writes
it. Every one of these is a legal, accepted config:

- `seccomp = "log"` — the filter is installed but only reports; **correction:
  there is no `"off"`.** `Seccomp` has exactly two variants, `Log` and
  `Enforce` (ADR-0028), so a bundle cannot disable the sandbox at all. The red
  team's first bullet was wrong, and the enum is why;
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

**Half 1 is implemented** (`bundle::policy_report`, `inspect_policy`,
`import_with_policy`, `--strict`). It reports log-only seccomp, a control socket
in a world-writable directory, and a bundle-supplied DNS resolver — the three
settings a server can actually choose for the client. Verified against a crafted
bundle: two warnings and a successful import, then the same bundle refused under
`--strict` with the reasons and the way out.

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

### Deviation: hooks are refused, not reported

R2-4 (found while auditing `[quick]`) showed the same file can carry
`pre_up`/`post_up`/`post_down`, which `vallum-quick` runs with `sh -c` as root.
For that one finding the decision is **refuse by default** with an
`--allow-hooks` escape, not "report and let `--strict` decide": a warning beside
a root shell command is not a control. Every other finding keeps the
report-plus-`--strict` shape.

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

**The author of those crates has given permission to copy or depend.**

*Correction (same day).* An earlier draft of this section declined the
dependency on the grounds that Vallum "carries its own PQ crypto" and should not
acquire a provenance stack. **That was wrong.** Vallum's `vallum-crypto-sdk` is an
adapter over `origin-crypto-sdk` — the same crate, the same git tag — so the
cryptographic dependency `origin-provenance` would add is one Vallum already
carries. Checked, not assumed: `Cargo.toml:48` pins
`origin-crypto-sdk = { git = "…/OriginSDK", tag = "v0.7.4" }`, and
`crates/vallum-crypto-sdk` exists to be the only crate that names SDK types.

What actually blocks the dependency is **publication status**, verified against
crates.io rather than inferred:

| crate | crates.io |
|---|---|
| `origin-crypto-sdk` | published (200) |
| `origin-common`, `origin-proof`, `origin-attest`, `origin-provenance` | not published (404) |

A path or git dependency on unpublished crates makes Vallum unbuildable anywhere
but this laptop, and breaks the CI that is already the weakest link in the
release gate. The `fuzz` and `origin-cross-tests` crates set `publish = false`;
these four do not — they are simply not published yet.

So the decision is conditional rather than closed:

- **Preferred**: publish the four crates (the author owns them), then depend on
  `origin-provenance` directly. The signed manifest, the monotonic `sequence`
  rollback defence, `--artifact` narrowing and verify-before-use are already
  written and tested; re-deriving them here would be strictly worse than
  depending, and the crypto is already shared.
- **Fallback if publishing is not wanted now**: vendor the specific module with
  attribution, which is what half 2 would do anyway.
- **What is not acceptable**: a path dependency that only resolves on this host.

What was **mirrored regardless, and is in the code today**: the
`Err` / `Ok(non-Valid)` split from `ReleaseVerdict`. `Err` means not authentic —
hard fail. `Ok` with findings means authentic but refused by policy — refuse and
report, never treat as corruption. That distinction is in `PolicyFinding` and
`import_with_policy` now.

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
