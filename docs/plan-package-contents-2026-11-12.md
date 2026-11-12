# Plan: make every install channel ship what the units actually exec

**Date:** 2026-11-12 · **Origin:** the red team (`/tmp/rt/report.md`, RT-01 and RT-02) · **Status:** in progress

## The finding

The three install channels disagree about what ships, and the disagreement is
invisible because the parity check only compares *packaging file names*.

- `crates/vallum/Cargo.toml`'s deb and rpm asset tables ship the units and the
  tmpfiles rule, but **no `/usr/local/sbin` executables** — verified:
  `grep -c '/usr/local' crates/vallum/Cargo.toml` → `0`.
- `packaging/vallum@.service:19` runs
  `ExecStartPre=+/usr/local/sbin/vallum-heal-runtime-dir`, and
  `vallum-cleanup.service` and `vallum-deadman@.service` exec two more
  (`vallum-cleanup`, `vallum-guard-deadman`). `ExecStartPre` failure is fatal,
  so **every packaged tunnel start fails with 127**.
- `scripts/release.sh`'s tarball omits the same executables *and* the guard
  unit, the cleanup unit, the dead-man pair and the tmpfiles rule.
- `scripts/check-package-manifest.sh:21`'s regex only matches names ending
  `.service|.timer|.conf|<digit>`, so extensionless files (`vallum-ops`,
  `vallum-panic`, `vallum-cleanup`, `vallum-heal-runtime-dir`,
  `vallum-guard-deadman`) are invisible to it — the check that exists to catch
  this drift cannot see it.

The installer channel (`scripts/install.sh`) is correct: it installs all five
executables and renders the sudoers rule. The defect is that the other two
channels are not equivalent to it.

## What "equivalent" means here

The units are the authority. Every path a shipped unit references must exist
in the shipped tree, or the unit fails at the worst possible moment.

The five executables all three channels must ship:

| file | who needs it |
|---|---|
| `vallum-heal-runtime-dir` | `vallum@.service`'s `ExecStartPre` — the tunnel cannot start without it |
| `vallum-cleanup` | `vallum-cleanup.service` |
| `vallum-guard-deadman` | `vallum-deadman@.service` |
| `vallum-panic` | the console's kill switch (`/api/panic`) |
| `vallum-ops` | the console's privileged path (`/api/apply`, `/api/service`) |

The sudoers rule is the one file that cannot be shipped as a package asset:
`packaging/vallum-ops-sudoers` carries an `@USER@` placeholder, and a package
cannot know which user to substitute. The installer renders it; the packages
will print the exact one-line grant at install time instead, and the parity
check will say so rather than pretend.

## The work

1. **The five executables into both asset tables** (`crates/vallum/Cargo.toml`),
   with the modes `install.sh` uses (0755).
2. **The missing units and the tmpfiles rule into the tarball**
   (`scripts/release.sh`), and the tarball assembly into a script both the
   release and the gate call, so the list cannot drift.
3. **The parity check** (`scripts/check-package-manifest.sh`) must see
   extensionless files, and must compare what *ships* rather than what is
   listed.
4. **The gate** (`scripts/accept-package-contents.sh`): build the real deb with
   `cargo-deb`, assemble the tarball tree, and assert that every path the
   shipped units reference exists in both, with the right mode. This is the
   gate that would have caught RT-01 and RT-02, and it must fail when the
   defect is present — proven by forcing it.

## Acceptance

- [ ] `cargo deb` produces a package whose contents include every path the
      units reference.
- [ ] The tarball tree includes the same.
- [ ] The parity check compares the three channels including extensionless
      files, and says which file each channel legitimately differs on.
- [ ] The gate fails when a required file is removed from the asset table —
      forced, not asserted.
- [ ] `accept-install-layout.sh` still passes, and the workspace suite, fmt and
      clippy are green.
