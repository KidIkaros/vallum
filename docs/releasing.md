# Releasing

A release is a claim that a tree is deployable. Everything below exists to make
that claim checkable rather than remembered.

## One release per batch, not per commit

A batch is a coherent piece of work with its own gates: a feature, its tests,
its docs, and the verification that exercises it. Cut a tag when the batch is
done — not because `main` has moved.

Cutting 1.5.0 and then 1.6.0 within a day was the wrong shape: 1.6.0 shipped
before the two-host gate had ever run and before the new parser had a fuzzer,
and it took two corrections (a tag on a tree with the previous version, and a
tarball missing a unit) to get the artifact right.

## The gate

`scripts/release.sh` refuses to build unless all of this holds:

| Check | Why it is here |
|---|---|
| working tree is clean | a release is built from a commit, not from a directory |
| the tag, if present, is at HEAD; `Cargo.toml` version matches it | a tag whose tree says a different version installs the wrong code |
| `CHANGELOG.md` has a `## <version>` section | a release nobody can read |
| `scripts/verify-remote.sh` recorded a pass **for this commit** | one host is not the product; two hosts are |
| `E2E=1 ./scripts/verify.sh` passes | the namespace gate of record |
| the SSH signing key matches `packaging/vallum-release.pub` | releases are only as trustworthy as what `install.sh` verifies |
| the packaged shell completions were generated from this binary and are not empty | stale completions once shipped a `teardown` nobody could tab-complete; they are build artifacts now, so the remaining failure is an empty file |

After building, the tarballs are inspected for both binaries, all units and
the man pages before anything is uploaded.

`--dry-run` runs the cheap checks and prints the rest. `--skip-remote "reason"`
releases without the two-host pass, and `--skip-arm "reason"` releases without
the aarch64 artifact; each reason is printed, and it should be a sentence
someone would be willing to read later.

## CI on a tag

Pushing `v*` runs `.github/workflows/release.yml`, and it does not publish. It
checks the cheap half of "this tree is releasable" — the tag names the
`Cargo.toml` version, the tagged commit is HEAD, `CHANGELOG.md` documents the
version — by running `release.sh --dry-run`, so the tag is judged by the same
preflight as the publish rather than by a second copy of it. The signing key and
the two-host stamp are the publisher's own checks, below.

Publishing stays local because the two things it needs are not CI's to hold: the
signing key would make the repository's trust anchor depend on a repository
secret, and the two-host stamp is written by a machine that ran
`verify-remote.sh`. That is not a gap to close later — `install.sh` only *warns*
on an unsigned release, so a tag built by a runner would install with a warning
and look official. The preflight is what makes that impossible.

## The artifacts

Every release ships, per architecture (`x86_64`, `aarch64`):

- `vallum-<tag>-<arch>-linux.tar.gz` — both binaries, all units, man pages,
  completions, sample alert rules;
- `vallum-<tag>-x86_64-linux.deb` and `.rpm`;
- `SHA256SUMS` + `SHA256SUMS.sig` + `allowed_signers` — the signature file
  `install.sh` verifies before trusting any checksum;
- `vallum-<tag>-sbom.spdx.json` — SPDX 2.3 SBOM of the crates.io graph (the
  SDK is a git dependency and appears as such).

The aarch64 artifact is cross-built with `cargo zigbuild`; the E2E gate runs
on x86_64 only — say so in the release notes if it ever matters.

## Signing

Releases sign `SHA256SUMS` with an SSH key (`ssh-keygen -Y sign`, OpenSSH
>= 8.0 — present on every supported target). The private key lives at
`~/.config/vallum/release-signing-key` or `$VALLUM_RELEASE_KEY`; the public
half is committed at `packaging/vallum-release.pub`, which makes the
repository the trust anchor: a forged release page cannot forge the repo's
pinned key. `scripts/release.sh` refuses to sign with a key that does not
match the committed public half.

Key custody is one person + offline storage; the fingerprint is printed in
every release's notes. Losing the key means generating a new one, committing
the new public half, and telling users — the same trust model WireGuard's
minisign releases use.

## The two-host stamp

`scripts/verify-remote.sh` writes
`${XDG_STATE_HOME:-~/.local/state}/vallum/remote-verified` containing the commit
it proved. The stamp lives outside the repository so it cannot be committed by
accident, and it is bound to a commit so a pass from last month cannot stand in
for this tree.

## Cutting a release

```sh
# 1. bump the version and write the changelog section, then commit
$EDITOR Cargo.toml CHANGELOG.md && git commit -am "release: X.Y.Z"

# 2. prove it on two hosts (writes the stamp)
sudo ./scripts/verify-remote.sh <ssh-host>

# 3. tag and publish (the gate runs the local E2E itself)
./scripts/release.sh
```

If the gate refuses, fix the tree. Do not move a tag that has already been
published unless the release is minutes old and demonstrably broken; a moved
tag is a lie to everyone who fetched it.
