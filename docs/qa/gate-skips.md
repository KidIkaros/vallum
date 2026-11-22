# Gate skips

One row per gate a release shipped without. Written by `scripts/release.sh`
when an escape hatch is used (`--skip-remote`, `--skip-stale`, `--skip-arm`,
`--skip-fuzz`, `--skip-desktop`). A row here is the honest record that the
artefact went out without that gate; the matching signed verdict lives in
`.vallum-verdicts/`, which is gitignored and regenerated per run.

`release.sh` appends a row and refuses nothing, so this file is the *record*,
not the *gate*. Read it as: every row is a release whose evidence was smaller
than its changelog claims.

| date | commit | gate | reason |
|---|---|---|---|
| 2026-11-19 | aff6a37 | desktop-bundle | the console does not ship in the alpha (ADR-0039); desktop bundle + GUI version bump deferred to beta |
| 2026-11-19 | 54a2da4 | accept-verdicts | accept-desktop + desktop-bundle verdicts are beta-desktop scope (#33); all alpha-surface gates re-run at HEAD |
| 2026-11-19 | 54a2da4 | desktop-bundle | beta desktop bundle, #33 tauri version mismatch; GUI excluded from alpha by ADR-0039 |
| 2026-11-20 | ab92136 | accept-verdicts | accept-desktop/desktop-bundle/accept-verdicts are beta-desktop scope (ADR-0039, #33); all alpha-surface gates fresh at HEAD (pair 88, isolation 15, agent-enrol 25, install 4, ops 10, desk-restore 8, deployment-backup 12, many 2, verify-remote 42) |
| 2026-11-20 | ab92136 | desktop-bundle | GUI console ships at beta (ADR-0039); version tracking fixed in #33 |
| 2026-11-22 | b5eb053 | accept-verdicts | accept-verdicts and desktop-bundle are release-internal records from the prior cut; this run re-verifies every signed verdict and rebuilds the desktop bundle itself |
| 2026-11-22 | e1f6b40 | accept-verdicts | accept-verdicts and desktop-bundle are release-internal records from the prior cut; this run re-verifies every signed verdict and rebuilds the desktop bundle itself |
| 2026-11-22 | ad97048 | accept-verdicts | accept-verdicts and desktop-bundle are release-internal records from the prior cut; this run re-verifies every signed verdict and rebuilds the desktop bundle itself |
| 2026-11-22 | 9e3b808 | accept-verdicts | accept-verdicts and desktop-bundle are release-internal records from the prior cut; this run re-verifies every signed verdict and rebuilds the desktop bundle itself |
