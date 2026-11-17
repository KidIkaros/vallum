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
| neither release binary names the builder's `$HOME` | panic and assertion messages carry `file!()` literals, which `strip = "symbols"` does not remove: `v1.6.3` shipped 288 `/home/…` strings in `vallum` and 43 in `vallum-quick`, so `strings` told every downloader the maintainer's username and layout |

After building, the tarballs are inspected for both binaries, all units and
the man pages before anything is uploaded.

Builds export `--remap-path-prefix=$HOME=/build --remap-path-prefix=$CARGO_HOME=/cargo`,
so those paths read `/build/…` and `/cargo/…` instead: anonymous, and the same on
two machines, which is what makes the string tables comparable between builds.
Rebuilding a cached `target/` does not re-apply it, which is why the check greps
the built binaries rather than trusting the environment.

`--dry-run` runs the cheap checks and prints the rest.

## A skip is written down

Five escape hatches exist — `--skip-remote`, `--skip-stale`, `--skip-arm`,
`--skip-fuzz`, `--skip-desktop` — and each takes a reason. Until 2026-11-17 the
reason was printed to stdout and nothing else happened, so a release that
shipped without the two-host gate left exactly the same state on disk as one
that ran it: the stamp still named an older commit, no record said otherwise,
and the gate chain looked green.

Now a skip writes two records:

- a **signed, commit-bound verdict** with `"status": "skipped"` and the reason
  in `"note"` (`.vallum-verdicts/<gate>.json`), so a release log says
  `N gate(s) unproven for this commit` and names them;
- a **row in `docs/qa/gate-skips.md`**, a tracked file, because verdicts are
  gitignored and regenerated per run and the history of what shipped unproven
  has to live somewhere git keeps. `release.sh` prints a reminder to commit it.

The reason should be a sentence someone would be willing to read later. It is
signed into the record, so it cannot be edited afterwards — which is the point:
the artefact says what the release did and did not prove.

## CI on a tag

Pushing `v*` runs `.github/workflows/release.yml`, and it does not publish. It
checks the cheap half of "this tree is releasable" — the tag names the
`Cargo.toml` version, the tagged commit is HEAD, `CHANGELOG.md` documents the
version — by running `release.sh --dry-run`, so the tag is judged by the same
preflight as the publish rather than by a second copy of it. The signing key and
the two-host stamp are the publisher's own checks, below.

The runner is chosen by repository visibility, in all three workflows:
private gets `self-hosted, linux, x64` — this account's machine (`wingman-vps`,
service `actions.runner.KidIkaros-vallum.wingman-vps`) — and public gets
`ubuntu-latest`. Self-hosting is not a preference: hosted minutes are refused on
this account before a runner is ever assigned ("the job was not started because
recent account payments have failed or your spending limit needs to be
increased"), so a hard-coded `ubuntu-latest` would queue every push until the
repository is public, where minutes are free.

The rule is the fork guard. A private repository has no forks, so there is no
untrusted `pull_request` to execute on a persistent machine. A public one does,
which is why self-hosting is only selected while the repository is private: the
expression in each workflow's `runs-on:` makes that a property of the
configuration instead of a thing to remember. Three consequences worth knowing:
while CI is on that machine, a push during its downtime *queues* instead of
failing, so a tag's check can sit there quietly; the e2e gate needs a
host where unprivileged user namespaces are allowed, or passwordless `sudo` for
the runner user, and `ci.yml` says which; and the visibility expression appears
in five places (three jobs in `ci.yml`, one in `fuzz.yml`, one in `release.yml`),
so changing the rule is the same edit in three files.

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
every release's notes.

## Break glass: the signing key

The anchor is one *set* of keys held in three places, kept identical by
`scripts/check-trust-anchor.sh` (a gate: `verify.sh`, CI, `ci-local.sh`):

| File | Holds | Read by |
|---|---|---|
| `scripts/install.sh` — `RELEASE_SIGNING_PUBKEY` | the keys, embedded | every user's installer, as its `allowed_signers` |
| `packaging/vallum-release.pub` | the keys, one line each | `release.sh`'s key check, the docs |
| `packaging/allowed_signers` | the keys, as signer lines | `release.sh` verifying verdict signatures and `SHA256SUMS` |

**Why the installer carries its own copy.** It is written from the pinned key
and never downloads one: an `allowed_signers` fetched beside the signature
could be swapped for an attacker's. The cost is that the anchor must be edited
in a file that is *not* covered by `release.sh`'s key check — which is exactly
the gap this gate exists for.

**A rotation that replaces the pin outright breaks every install.** `install.sh`
is fetched from `main`, so the moment a new key lands there the installer pins
the new key — while the current release is still signed with the old one, and a
failed verification is a **hard refusal**, not a warning. Verified, not assumed:
with both keys listed, a signature by either is accepted; with only the new key
listed, the old signature is refused.

So a rotation is two changes, one release apart:

1. **Add.** Generate the new key (`ssh-keygen -t ed25519 -f
   ~/.config/vallum/release-signing-key-<year> -C vallum-release`), put **both**
   keys in all three files (`check-trust-anchor.sh` prints the commands and
   accepts a two-key set), and sign that release with the **old** key. Users'
   installers now trust both.
2. **Drop.** Once that release has shipped, sign the next release with the new
   key and delete the old key's lines from all three files. Dropping the old key
   before a new-signed release is out leaves a window where installs of the
   current release fail.

**If the private key is lost** (no copy on offline storage): it cannot be
re-derived, so this is a rotation with no outgoing signature — do step 1 keeping
the old *public* half listed (still committed, so still trusted) and sign with
the new key immediately. Users on the current release are unaffected; the next
release verifies under the new key, and the old public half is dropped the
release after.

**If the private key is compromised** — the case that cannot be soft-pedalled:

- Rotate immediately with step 1 and **sign the next release with the new key**,
  so a stolen key cannot produce a release that verifies.
- Publish the old key's **revocation** in the release notes and the CHANGELOG:
  the fingerprint, the date, and "releases signed by this key after <date> are
  not ours". `install.sh` cannot express revocation — it only knows which keys
  verify — so the announcement is the only channel. That is a real limitation of
  an SSH-key trust model, not a gap in this repository.
- Assume the attacker could sign anything the old key could: `SHA256SUMS`,
  verdicts in `.vallum-verdicts/`, and release notes. The two-host stamp lives
  outside the signed set, so a forged `verify-remote` verdict is caught by
  re-running `verify-remote.sh` against a host — say so in the advisory.
- Check the release history for anything signed with the old key after the
  compromise date before publishing.

**Making it not be one person.** The key is why the gates can be trusted and why
none of them can run without the maintainer. Two things fix that, and neither
changes the trust model:

- a **second signer**: another `vallum-release` line in `allowed_signers` and a
  second maintainer who can sign, so a release can ship while one person is
  unavailable. Two signers means either can sign; a threshold would need a
  different mechanism, which SSH signatures do not express.
- a **break-glass copy**: the key's location and passphrase recorded with a
  lawyer or in a sealed envelope with a second person — the argument that a
  single-point credential needs a documented custody path, not a second live
  copy on the same disk.

The gate catches the mechanical failure (two of three files updated). It cannot
catch a compromised host or a forgotten passphrase, which is why the custody
line above stays short and honest: one person, offline storage, and now a
written procedure.

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
