# Production-readiness verification — 2026-11-19

**Verdict: READY for alpha operation on the OPERATOR's environment** (CLI + TUI + UTCP +
desk, the ADR-0039 surface) — **scoped by the premortem below**. Every leg of the battery
passed with signed evidence, but the battery proves the *local build* on a *controlled
host*, not the published-release stranger path.

> **Correction (2026-11-19, premortem).** Three claims in the original verdict were
> falsified and are corrected in place: (1) `accept-install` installs the **local main
> build** (`install.sh --local`), never the published release — the stranger
> download+signature path is exercised by **no gate**; (2) the `laptop`/`lab8` drift was
> not "experiment residue" but a **live write-without-apply bug** in TUI/GUI rotate/finalize,
> now fixed (`32f181d`); (3) "the published 1.9.0 install path is proven working" was never
> tested. Full analysis: `docs/qa/premortem-alpha-verification.md`.

## The battery (all measured today, commit `006c105`)

| Leg | Result | Evidence |
|---|---|---|
| Local gate `verify.sh` | **PASS** | fmt, clippy `-D warnings`, 457 lib + workspace suites, supply chain (`advisories ok`), standalone build, TUI snapshot, signature round trip |
| E2E leg `E2E=1 verify.sh` | **PASS** | netns e2e both binaries; **isolation 15 assertions**; **headless agent enrolment 25 assertions (FAIL=0)**; seccomp allow-list 79 entries; desk copy/restore 8; deployment backup 12 |
| Two-host gate `verify-remote.sh wingman-vps` | **PASS — 42 assertions, signed**, stamp commit-bound at `006c105` | outage: 741 datagrams into a dead tunnel, none answered, route held — **no leak**; recovery: carried again **8 s** after the server returned, client untouched; verdict scrapes (blocked/LEAKING states); enrolment transports; rotation; live deployment restored intact |
| Stranger install `accept-install.sh` | **PASS — 4 assertions, signed** | clean privileged Ubuntu 24.04 systemd container installs the **local main build** (`install.sh --local`, `accept-install.sh:67` — **not** the published release), receives a real ticket minted on the production server, joins (handshake `1795105515`), tunnel carries, `uninstall --purge` leaves 0 residue. **Does not exercise the release download/signature path.** |
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
- A clean-machine install of the **local build** joins the real server — proven
  (`accept-install`, signed). The **published-release** download+verify path a stranger
  actually uses is **not** exercised by any gate (`accept-install` runs `--local`); see
  the premortem correction.
- The two-host stamp is **commit-bound** (`006c105`): re-running at a different commit
  refuses the stale stamp.
- Release artifacts: SHA256SUMS + ED25519 signature + SBOM + allowed_signers published;
  signature verified stranger-style earlier today.

## Honest residuals (named, not hidden)
1. **Two desynced peers on the alpha server** (`laptop`, `lab8`): config keys ≠ daemon
   session keys. The premortem found the **root cause** — TUI/GUI rotate/finalize discarded
   the daemon apply outcome (`let _ = syncconf_running`) and reported success regardless;
   fixed in `32f181d` (the apply outcome is now surfaced). `vallum doctor` warns on both
   (detection, deployed). The two stale peers still need an operator re-apply or
   delete-and-re-enrol; new rotations no longer drift silently.
2. **GUI is beta** (ADR-0039 excludes it from the alpha): #35 (privilege read path —
   the console can't see a root-owned daemon as a normal user) and #36 (status/legend/
   contrast) are tracked. The alpha ships CLI/TUI/UTCP, all verified above.
3. **Dependabot**: `glib` (medium, unsoundness in a GTK iterator) is a **GUI-only**
   dependency, not in the daemon path; `atty` (low) is a legacy transitive dep. The
   gate's `cargo audit` passes. Both are beta/dev-scope, tracked upstream.
4. **Main is 49 commits ahead of the published release** (`v1.9.0`): tonight's fixes
   (honest snapshots, name-keyed metrics, doctor peer-sync, account/device desk, reset-token,
   the drift fix) are **deployed and verified on the server**, but a stranger installing
   `--from-release` still gets `v1.9.0` — pre-fix, including the fabricated TUI traffic.
   No gate forces release parity, and the published install path is **untested** (corrected
   by the premortem). Cut a release before the cohort installs.
5. **ADR-0047 ratification pending** — architecture direction for beta (isolation
   refinement, agent devices, token lifecycle); does not block alpha operation.

## Bottom line
The tunnel carries, the guard holds under outage, nothing leaks, an agent can enrol
headless, strangers on a shared server can be isolated, and the secrets audit is clean.
**Ready for alpha operation on the operator's environment** — but the premortem scoped
this: the published-release stranger path is untested, the conversion funnel cannot see
the install drop-off, and the drift bug (now fixed) was a real data-path bug. The
revisions in `docs/qa/premortem-alpha-verification.md` are the path to a stranger-facing
"ready".
