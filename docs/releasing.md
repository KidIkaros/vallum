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
| packaged shell completions diff-clean against this binary | stale completions once shipped a `teardown` nobody could tab-complete |

After building, the tarballs are inspected for both binaries, all units and
the man pages before anything is uploaded.

`--dry-run` runs the cheap checks and prints the rest. `--skip-remote "reason"`
releases without the two-host pass, and `--skip-arm "reason"` releases without
the aarch64 artifact; each reason is printed, and it should be a sentence
someone would be willing to read later.

## The artifacts

Every release ships, per architecture (`x86_64`, `aarch64`):

- `vallum-<tag>-<arch>-linux.tar.gz` — both binaries, all units, man pages,
  completions, sample alert rules;
- `vallum-<tag>-x86_64-linux.deb` and `.rpm`;
- `SHA256SUMS` + `SHA256SUMS.sig` + `allowed_signers` — the signature file
  `install.sh` verifies before trusting any checksum;
- `release.json` — a hybrid Ed25519+Falcon-1024 attestation over the artifact
  set, product, channel and release sequence (see below); it is itself listed
  in `SHA256SUMS`, so the SSH signature covers it too;
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

## The post-quantum attestation

The SSH signature proves *who* built a release. It says nothing about *when*,
which is why a replayed older release — signature intact, checksums intact —
would install cleanly. Two things close that:

- **`release.json`** is signed by `origin-provenance release-create` with a
  hybrid Ed25519+Falcon-1024 key over the artifact digests, `product=vallum`,
  `channel=stable`, a monotonic `sequence` derived from the version
  (`1.6.2 → 1006002`) and an optional expiry. The seed lives at
  `~/.config/vallum/release-attest.seed` (32 raw bytes, `$VALLUM_ATTEST_SEED`
  to override). Its public fingerprint belongs in
  `packaging/vallum-release-attest.fp`; until that file exists the release run
  prints the fingerprint to commit and continues — after it exists, a
  mismatched key is a refusal.
- **`install.sh` refuses a downgrade.** It compares the target tag against
  `/usr/bin/vallum --version` and stops if the target is older. The installed
  binary *is* the floor: there is no state file to forget, corrupt, or point at
  the wrong directory, and nothing an attacker could rewrite without already
  owning the host. `--allow-downgrade` is the deliberate rollback switch.

`install.sh` verifies `release.json` when `origin-provenance` is on `PATH`
(`release-verify --artifact <the file being installed>`); without the tool it
warns and relies on `SHA256SUMS.sig`, which still covers every byte.

Verify a download by hand:

```sh
origin-provenance release-verify release.json --artifact-dir . \
  --product vallum --channel stable
```

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
