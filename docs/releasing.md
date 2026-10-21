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

After building, the tarball is inspected for both binaries, all three units and
the man pages before anything is uploaded.

`--dry-run` runs the cheap checks and prints the rest. `--skip-remote "reason"`
releases without the two-host pass; the reason is printed, and it should be a
sentence someone would be willing to read later.

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
