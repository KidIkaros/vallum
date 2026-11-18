# Premortem — the alpha failed (`2026-11-17`)

**Frame:** it is May 2027. The alpha failed. Six investigators worked backwards from one failure mode
each; every claim below was checked against the tree before it was kept, and two that did not survive
the check are recorded at the end rather than quietly dropped.

**Most likely failure** — the desk loses the accounts. The account number is the only credential the
service mints and cannot re-issue; the database was outside the backup contract until 2026-11-17 and
there is still **no timer that takes a copy**, so the first real loss is one `rm -rf` away and the
desk starts happily on the empty file it creates.

**Most dangerous failure** — the gate that proves the product is the gate that deletes it.
`scripts/verify-remote.sh` refuses a host already running Vallum and `--clean-remote` runs
`sudo rm -rf /etc/vallum` plus the binaries (scripts/verify-remote.sh:358-379); it backs up nftables
and nothing else. The restore is a hand-made tarball described in prose
(docs/alpha-readiness-2026-11-12.md:36-40) that does not include `/var/lib/vallum`. So the most
dangerous failure is the most likely one, on a schedule, every release.

**Hidden assumption** — *that a written record is a mechanism.* Six investigations, one shape: the
backup exists as a document, the skip exists as a printed line, the throwaway host exists as "the
standing improvement", the restore exists as a tarball in a paragraph. Each artefact faithfully
records an intent, and no actor performs it.

## Failure modes

1. **One host is everything** *(most likely)* — runner, live server, desk host and the only gate
   target are one machine, so proving the product costs the deployment. · *Watch for:* the restore
   step living only in prose; any run whose stamp says `"namespaced": true`.
2. **The gate destroys what it validates** *(most dangerous)* — `--clean-remote` deletes
   `/etc/vallum`; nothing in the script restores it and nothing backs up `/var/lib/vallum`. ·
   *Watch for:* a release whose stamp commit and whose deployment's peer list disagree.
3. **Reproducibility was true only for the author** — the claim needs a disposable root Linux host,
   Ubuntu 24.04+, `unshare`/`nsenter`, and a clone; gate 1's own status line still reads "running"
   (docs/alpha-readiness-2026-11-12.md:25) while four downstream gates read PASS. · *Watch for:*
   distinct `remote_host` values across every stamp ever produced — it is 1.
4. **The desk lost the accounts** — `desk.sqlite` at /var/lib/vallum, `token_hex(16)` per account
   (service/vallum-desk:340), no backup timer, no desk alert, and `open_database` recreates an empty
   schema on a missing file (:102-123). · *Watch for:* `SELECT count(*) FROM accounts` returning to
   0; no `desk-*.sqlite` copy anywhere on disk.
5. **Bus factor one locked the tree** — the key at ~/.config/vallum/release-signing-key, the stamp in
   `$HOME/.local/state`, verdicts gitignored (.gitignore:37) and CI deliberately excluded
   (docs/releasing.md:76): gates that refuse unsigned evidence refuse *all* evidence when the single
   signer is away. · *Watch for:* `unsigned: no verdict key` in any run; zero non-maintainer commits.
6. **The most important gate is the one most often skipped** — `--skip-remote` prints a reason to
   stdout and proceeds (scripts/release.sh:138-139); nothing writes it down, and the stamp keeps the
   *previous* commit's pass, so a skipped day is indistinguishable on disk from a gated one. ·
   *Watch for:* the ratio of tags whose stamp names that tag's commit — any value below 100%.

## Revised plan

1. ~~Make `verify-remote.sh --clean-remote` take and verify its own backup.~~ **Done 2026-11-17**:
   `scripts/backup-deployment.sh` copies `/etc/vallum`, `/var/lib/vallum` and the units, verifies the
   archive (every config present, the desk database still starting with the SQLite header), writes
   `0600`, and prints the restore command. `--clean-remote` runs it on the host before touching
   anything, refuses the run if it fails, and records the archive path in both the stamp and the
   signed verdict. `scripts/accept-deployment-backup.sh` is the gate (12 assertions, signed verdict,
   including the failure paths).
2. ~~Add a `vallum-desk-backup` timer and a restore drill.~~ **Done 2026-11-17**:
   `vallum-desk-backup` + `.timer` ship with the desk, the installer and both packages enable the
   timer, and the service is conditioned on the database existing so it is inert where there is no
   desk. Each copy is reopened and compared against the source before it counts.
   `scripts/accept-desk-restore.sh` runs the copy-and-restore path as a gate (8 assertions, signed
   verdict) in `verify.sh`, `ci-local.sh` and CI. Off-host remains the operator's `--dest`; a copy on
   the same disk is not disaster recovery and the docs say so.
3. ~~Make a skip an artefact.~~ **Done 2026-11-17** (`efab8cc`): every escape hatch
   (`--skip-remote`, `--skip-stale`, `--skip-arm`, `--skip-fuzz`, `--skip-desktop`) writes a signed,
   commit-bound verdict with `status: skipped` and the reason in `note`, plus a row in the tracked
   `docs/qa/gate-skips.md`. The release log prints `N gate(s) unproven for this commit`, and a
   recorded skip is no longer misread as a failed gate.
4. ~~Provision the throwaway second VPS.~~ **Superseded 2026-11-17 — the second host was never
   needed.** The refusal that made this look like an infrastructure problem was the script's own
   teardown: scratch mode installed nothing into `/etc/vallum`, `/run/vallum`, `/usr/bin` or table
   `inet vallum`, yet cleanup deleted all of them on the way out, so the script had to refuse any host
   that already ran Vallum. Cleanup now removes only what the run created, a port/subnet collision is
   checked up front, a host's own `/usr/bin/vallum{,-quick}` is set aside and restored, and the run
   asserts at the end that `/etc/vallum` and `inet vallum` survived (revoking the stamp if not).
   Verified by running it: `verify-remote.sh wingman-vps` **PASSED with 42 assertions beside the live
   deployment**, and the host's config, key and NAT table checksums were identical before and after.
   `--host-direct` remains the only true two-machine pass, and that is a laptop run, not a VPS.
5. Put a second owner on `CODEOWNERS` and a second key in `packaging/allowed_signers`, or write the
   break-glass procedure for the key — the strictness is right; single custody is what is missing.

## Before you commit

- [ ] `--clean-remote` refuses without a backup it took itself.
- [ ] A desk backup exists off-host and one restore drill is recorded as a signed verdict.
- [ ] `--skip-remote` produces a signed `skipped` record.
- [x] `GET /healthz` on the desk returns 503 when the database or the daemon socket is unusable — **done 2026-11-18**: the route reads the database and asks the daemon (`vallum show --json`), answers `200` only when both do, and names the failed dependency in the body. It also closed the gap the endpoint exposed: the account page and the sweep had read the daemon's counters unguarded, so a down daemon was a 500 on the page and an aborted enforcement pass.
- [ ] A second key and a second owner exist in the trust anchor.

## Corrections to the investigations

- **`wingman-vps` is no longer the CI runner.** `ci.yml:67` selects `ubuntu-latest` whenever the
  repository is public, and it is public since 2026-11-16. The host remains the live server, the desk
  host and the only gate target, so failure mode 1 stands with that one leg removed.
- **`namespaced` lives in the stamp, not the verdict JSON.** `verify-remote.sh:1610-1620` writes
  `commit`/`remote_host`/`namespaced`/`assertions` to `~/.local/state/vallum/remote-verified`;
  `.vallum-verdicts/verify-remote.json` carries gate/status/commit/assertions/target and no
  `namespaced` field. The substance — a namespaced run is not two hosts — is unaffected, and
  `release.sh:147` reads only `remote_host`.
