# Production-readiness verification — 2026-11-19

**Verdict: READY for alpha operation** (CLI + TUI + UTCP + desk, the ADR-0039 surface).
Every leg of the battery passed with signed evidence. This is a verified readiness
statement, not a claim of perfection — the honest residuals are listed at the end.

## The battery (all measured today, commit `006c105`)

| Leg | Result | Evidence |
|---|---|---|
| Local gate `verify.sh` | **PASS** | fmt, clippy `-D warnings`, 457 lib + workspace suites, supply chain (`advisories ok`), standalone build, TUI snapshot, signature round trip |
| E2E leg `E2E=1 verify.sh` | **PASS** | netns e2e both binaries; **isolation 15 assertions**; **headless agent enrolment 25 assertions (FAIL=0)**; seccomp allow-list 79 entries; desk copy/restore 8; deployment backup 12 |
| Two-host gate `verify-remote.sh wingman-vps` | **PASS — 42 assertions, signed**, stamp commit-bound at `006c105` | outage: 741 datagrams into a dead tunnel, none answered, route held — **no leak**; recovery: carried again **8 s** after the server returned, client untouched; verdict scrapes (blocked/LEAKING states); enrolment transports; rotation; live deployment restored intact |
| Stranger install `accept-install.sh` | **PASS — 4 assertions, signed** | clean systemd container installs from the **published v1.9.0 release media**, receives a real ticket minted on the production server, joins (handshake `1795105515`, endpoint `74.101.134.101:33055`), tunnel carries, `uninstall --purge` leaves 0 binaries / 0 config / 0 units |
| Desk suite | **271 tests OK** | CI's exact discover command |

## Sensitive-information audit — CLEAN
- **Repo text**: no token/ticket values quoted in tracked docs/reports; the only 32-hex
  strings are synthetic test fixtures (`0123456789abcdef…`).
- **Git history**: no `.key` / `.env` / secret / credential file was **ever** committed.
- **Screenshots**: the 19 tracked dogfood frames are GUI/TUI renders; the four
  highest-risk ones (token-landing, config-dialog, no-token-403, devices) were
  vision-audited individually — **no credentials visible**. The product cannot render
  private key material by construction (GUI IPC allowlist, ADR-0024).
- **Live desk**: served pages carry no secret material; credential answers are
  `Cache-Control: no-store`; tokens ride POST bodies, never URLs (410 + guidance otherwise).
- **Private keys**: generated and kept on devices (ADR-0013); the pinned-enrol gate
  proves a wrong key is refused with no config written and no server peer created.

## Reproducibility
- A stranger installs from the published release on a clean machine and joins the real
  server — proven, not asserted (`accept-install`, signed).
- The two-host stamp is **commit-bound** (`006c105`): re-running at a different commit
  refuses the stale stamp.
- Release artifacts: SHA256SUMS + ED25519 signature + SBOM + allowed_signers published;
  signature verified stranger-style earlier today.

## Honest residuals (named, not hidden)
1. **Two desynced peers on the alpha server** (`laptop`, `lab8`): config keys ≠ daemon
   session keys, residue of the enrolment experiment; neither has ever handshaked.
   `vallum doctor` now warns on both (the #34 fix, deployed). Remediation is an operator
   decision (re-apply or delete-and-re-enrol); it does not affect new enrolments.
2. **GUI is beta** (ADR-0039 excludes it from the alpha): #35 (privilege read path —
   the console can't see a root-owned daemon as a normal user) and #36 (status/legend/
   contrast) are tracked. The alpha ships CLI/TUI/UTCP, all verified above.
3. **Dependabot**: `glib` (medium, unsoundness in a GTK iterator) is a **GUI-only**
   dependency, not in the daemon path; `atty` (low) is a legacy transitive dep. The
   gate's `cargo audit` passes. Both are beta/dev-scope, tracked upstream.
4. **Main is ahead of the published release**: tonight's fixes (honest snapshots,
   name-keyed metrics, doctor peer-sync, account/device desk) are **deployed and verified
   on the server** but ship to strangers in the next tagged release. The published 1.9.0
   install path is proven working as-is.
5. **ADR-0047 ratification pending** — architecture direction for beta (isolation
   refinement, agent devices, token lifecycle); does not block alpha operation.

## Bottom line
The tunnel carries, the guard holds under outage, nothing leaks, a stranger can install
and join from published media, an agent can enrol headless, strangers on a shared server
can be isolated, and the secrets audit is clean. **Production-ready for the alpha's
stated scope.** The residuals above are tracked, scoped, and none of them is a leak or a
data-path bug.
