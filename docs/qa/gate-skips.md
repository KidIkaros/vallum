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
