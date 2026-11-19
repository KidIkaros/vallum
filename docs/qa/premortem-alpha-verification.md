# Premortem: the Vallum alpha launch and the verification system that declared it ready

**Date:** 2026-11-19 · **Target:** the alpha launch (M1: ≥50% of join tickets reaching a
handshake by 2026-12-03; baseline 0/14) **and the gate battery that pronounced it
"production-ready."** A premortem on the checks finds the defects that let product defects
through — the ones the author, who wrote both sides, is least likely to see.

**Frame:** it is May 2027. The alpha failed. The cohort never converted, or trust leaked.
Working backward.

**Method:** nine failure reasons, one investigator each (five completed with `file:line`
citations; four hit the API rate limit and were investigated inline by the parent). Every
citation below was re-checked against the freshest code; two accusations were *corrected*
where the code contradicted them, and one published report was falsified and fixed in place.

## Synthesis

**Most likely failure — the stranger installs stale, untested code and dies invisibly.**
`main` is 49 commits ahead of `v1.9.0`; `install.sh --from-release` resolves `releases/latest`
= `v1.9.0`, so a stranger gets pre-fix code (including the *fabricated* TUI traffic). No gate
forces release parity, and `accept-install.sh:67` runs `install.sh --local` — the published
download+signature path is exercised by **no gate**. The funnel cannot see the install
drop-off, so M1 stays near zero while every dashboard is green.

**Most dangerous failure — the gate destroys the only production host and stamps it verified.**
`verify-remote.sh` swaps `/usr/bin/vallum{,-quick}` on the live single host; the binary restore
is an unchecked `mv -f` with discarded output and an unconditional "restored" note
(`:495-499`), the post-check asserts only that `/etc/vallum` and the nft table *exist*
(`:520-528`), and the `.pre-verify-remote` aside-copy overwrites each run (`:908-911`) — so a
killed run poisons the next backup. A hard crash mid-run (which `trap EXIT` cannot catch)
leaves production running the gate's binary or broken, stamped PASS. Recurs every release.

**Hidden assumption — *a recorded success is a performed success.*** Across all nine modes
the same shape: the artefact records the intent and no actor performs it. A PASS verdict, a
"rotated" message, a "restored" note, a runbook, a `pager_path_ok=1` gauge, a capacity target
— each is trusted as the reality it names. The purest instance was **live**: the TUI/GUI said
"rotated/finalized" while the daemon apply was discarded (`let _ = syncconf_running`). The
system trusts its own records over performed, verified reality for the real user.

## Failure modes

1. **Gates prove the operator's environment, not the stranger's** *(most likely cluster)* —
   `accept-install.sh:43-46` is a *privileged Ubuntu 24.04 systemd* container; `install.sh:99-107`
   needs root, `:169-172` rejects non-x86_64, `:72` assumes systemd; `accept-agent-enrol.sh:33`
   needs `unshare` caps. A stranger on a filtered network, sleeping laptop, non-systemd distro,
   ARM, or no-root diverges down a path no gate exercises. *Assumption:* the rig's environment
   is the user's environment. *Watch for:* a stranger's `vallum --version`/distro differing from
   the gate's; join failures with no corresponding gate signal.
2. **The published release is stale and untested** *(most likely)* — `git rev-list --count
   v1.9.0..HEAD` = 49; `Cargo.toml` still `1.9.0`; `accept-install.sh:67` `--local`, never
   `--from-release`; `release.sh:162-169` checks tag==HEAD only when manually invoked.
   *Assumption:* "verified on main + deployed to our server" == "what a stranger downloads."
   *Watch for:* commit-count-since-tag > 0 while version equals the tag; the gate's own install
   line reads `--local`.
3. **The instrument mutates the single host; restore is not verified** *(most dangerous)* —
   binary restore unchecked (`verify-remote.sh:495-499`), existence-only post-check (`:520-528`),
   `.pre-verify-remote` overwritten each run (`:908-911`); `backup-deployment.sh:64-71` omits
   `/usr/bin/vallum*`. *Correction:* the NAT restore **is** verified (`restore_nat`, `:390-400`)
   and a prior premortem (2026-11-12) already hardened the teardown — the residual is the
   *binary* restore + hard-crash window, not "restore is a doc paragraph." *Assumption:* copying
   files back is restoring a service. *Watch for:* post-gate `/usr/bin/vallum --version` reports
   the tree build, or `vallum@` inactive despite the "restored" log line.
4. **The dead-man's switch's dead-man is absent** — `contrib/ops/vallum-watchdog.*` is installed
   by **nothing** (no second host exists); the direct-page fallback fires only when Alertmanager
   itself is down (`push.sh:112-123`), so with AM up `pager_path_ok=1` while pages die at ntfy.sh
   or the phone; cooldown state is written *before* curl with output discarded (`:126-132`), so
   failed pages are swallowed and suppressed 300s. *Assumption:* a watcher/router/relay/receiver
   sharing one host and one unverified delivery path is independent. *Watch for:* no
   `vallum-watchdog.timer` on any host; a test page fails to land while `pager_path_ok` stays 1.
5. **The funnel sees the absence, not the drop-off step** — `funnel_exposition`
   (`service/vallum-desk:1657-1699`) emits only terminal-state gauges; no install/join-attempt/
   refusal-reason counters exist. A stranger dying at **install** never reaches `add_device`, so
   `devices_total` stays 0 and `VallumNoDeviceEverConnected`'s `total>0` guard
   (`packaging/vallum-alerts.yml:363-365`) means it **never fires at all**; `for: 24h` lets a day
   of failure read as idle. *Assumption:* terminal counts locate where conversion dies.
   *Watch for:* `accounts{status="active"}` rising while `devices_total` stays 0.
6. **Bus factor documented, not mitigated** — `incident-response.md:137,147` secondary is an empty
   `OPERATOR:` placeholder; escalation is explicitly manual (`:155-159`); alertmanager has a
   single `ntfy` receiver (`alertmanager.yml.example:13,18-19`). *Assumption:* a runbook is a
   responder. *Watch for:* the placeholder still unfilled; no second SSH key/receiver provisioned.
7. **Credential recovery has no ownership proof** — `_account_for_body` (`service/vallum-desk:524`)
   addresses by peer or token; a device-less lost-number account can't be reset-token'd, but
   `_list_peers` exposes every token via `accounts --json`. *Correction:* not a true dead-end (the
   admin list is a handle) — the real gap is **no PII to verify the requester owns the account**,
   so recovery is churn-or-impersonation. *Assumption:* no-PII purity is free. *Watch for:*
   recovery requests the operator cannot attribute; tokens handed over on a claimed label alone.
   **FIXED:** signup shows a recovery code once (sha256-hashed, schema v5); `reset-token
   --recovery-code[-file]` verifies ownership before re-issuing a number. Residual: a peer name is
   not proof; a device-less account with neither number nor code is rebuilt from a minted code.
8. **Config↔daemon drift: a live write-without-apply bug** — **FOUND AND FIXED (`32f181d`).**
   TUI `tui/actions.rs:267,282` and GUI `vallum-gui/src/actions.rs:564,584` did
   `let _ = syncconf_running(...)` then reported unconditional success; `control.rs:692-705`
   returns `Ok(NoControlSocket/NoControlDeclared)` or `Err`, all discarded. This generated the
   live `laptop`/`lab8` drift (config≠session, no window). Now all four sites propagate the error
   and append `ApplyOutcome::describe()`. *Assumption:* a successful config save *is* the rotation.
   *Watch for:* a "rotated/finalized" message while `show` still answers the old fingerprint.
9. **Capacity unmeasured under load** — `docs/requirements.md:22-25` "Derived, not measured…
   never observed under load"; `:33` 2,000 peers is a "Stated target"; memory measured at 1,000
   (`:59`) but throughput/concurrency never; `accept-isolation.sh:176` creates **two** clients
   (`devb devc`); benches are micro-benchmarks. *Assumption:* "server-size bound" is known without
   a load test. *Watch for:* conntrack/NAT table growth, handshake CPU, or fd limits at the first
   real cohort — none exercised by a gate. **PARTIAL:** `accept-many 12` on v1.10.0 enrolled and
   carried 12/12 with the server tracking all 12 (signed verdict); memory/restart/address ceilings
   already measured. End-to-end throughput and a sustained hundreds-of-peers rekey-herd run remain
   unmeasured — do not quote a throughput number until one exists.

## Revised plan (each maps to a mode; doable this week)

1. **[DONE `32f181d`]** Surface the daemon apply outcome on TUI/GUI rotate/finalize (mode 8).
   TDD red→green; 458 lib + GUI tests, clippy clean. The drift no longer generates silently.
2. **[DONE — v1.10.0 published]** Cut a release and gate the published artifact (modes 2, 1):
   bumped to 1.10.0, tagged, `release.sh` published all eight signed assets; `accept-install.sh`
   gained `--from-release` and **passed against the published v1.10.0** (download → signature
   verify → install → join → carry → purge). `verify.sh` now warns when HEAD ≠ latest tag.
   The gate immediately caught a real stranger prerequisite the `--local` path never could:
   a minimal machine lacks `openssh-client`, so `install.sh` fail-closed refuses the signature
   check — the gate now provisions it (mode 1 made concrete).
3. **[DONE]** Verify the binary restore (mode 3): the `mv -f` must succeed AND the restored
   `/usr/bin/vallum --version` must run; on a live deployment the daemon is restarted onto the
   restored binary and asserted active. Any failure sets `BINARY_RESTORE_FAILED`, which revokes
   the stamp and fails the run (the same revoke-on-failure pattern as the NAT guard). The
   aside-copy now **refuses** when a `.pre-verify-remote` already exists, so an interrupted run
   cannot launder the gate's binary into the "production" backup. Tested both ways: a normal run
   asserts "the restored binary runs" + "the daemon is active on the restored binary"; a planted
   leftover backup makes the gate refuse at the ssh transport with the host left intact.
4. **[DONE — activation pending operator]** Make the dead-man's switch independent (mode 4):
   the watchdog now runs on the operator's **desktop** as a user systemd timer with linger
   enabled (a second host on a second network, runs while logged out) — independence achieved
   without a second VPS. The pusher also carries an **external dead-man's-switch ping**
   (healthchecks.io-style, reads `/etc/vallum/healthchecks-url`; no-op until the operator creates
   a free check and drops the URL) and the alertmanager example carries a commented **email
   second channel** (fill SMTP to enable). The cooldown is now written *after* a successful page,
   so a failed page retries instead of being suppressed. Watchdog paging proven: a bogus-host run
   fired a direct "host unreachable" page. The healthchecks.io check is now **wired and pinging**
   (URL on the VPS, pusher confirmed `OK`); the operator should tighten its period to ~1 min / grace
   ~5 min (it was created at 1 day / 1 hour, far too slow). Remaining operator steps: fill SMTP for
   the email channel; a human secondary responder if one exists (else bus factor is honestly 1, named).
5. **[DONE]** Instrument the journey, not just the outcome (mode 5): the desk funnel now
   persists per-step counters (`funnel_events`, schema v4) — `vallum_alpha_signup_total`,
   `vallum_alpha_add_device_total`, and `*_refused_total{reason}` (bad_request / forbidden /
   unknown / conflict / limited / daemon / capacity), every series emitted even at zero.
   New alert `VallumSignupNoDevice` (`sum(accounts{active}) > 0 and devices_total == 0`, 6h)
   catches the signup→install drop-off the ticket-vs-handshake alert structurally cannot see.
   Deployed live: v3→v4 migration faithful (17 accounts intact), counters emitted, alert loaded
   (vmalert dry-run validated the expr). The join-step refusal *reasons* are daemon-side (the
   enrol responder); the client already surfaces them via the no-answer diagnostic — labelling
   them as a daemon metric is the remaining sub-item.
6. **Provision a real secondary** (mode 6): fill the contact, add a second SSH key, wire a second
   alertmanager receiver with escalation; until then the bus factor is 1, named.
7. **Add ownership proof to recovery** (mode 7) — **DONE.** Signup shows a recovery code once
   (sha256-hashed, schema v5); `reset-token --recovery-code[-file]` verifies ownership before
   re-issuing a lost number. 7 new tests green; deployed live (v4→v5 migration faithful, 17 dead
   dogfood accounts cleared to one). Docs name the residual: a peer name is not proof.
8. **Load-test before the cohort** (mode 9) — **PARTIAL.** `accept-many 12` on v1.10.0: 12/12
   enrolled and carried, distinct addresses, server tracked all 12 (signed). Memory at 0/1000/2000
   and restart latency already measured in `requirements.md`. Still unmeasured: end-to-end
   pps/throughput and a sustained hundreds-of-peers rekey-herd run.

## Before you commit (pre-launch checklist)

- [x] A release is cut; a clean-container gate installs `--from-release` and a stranger's
      `vallum --version` carries the fixes (mode 2). **Done: v1.10.0, `accept-install --from-release` PASS.**
- [x] `verify-remote` verifies the restored binary runs and the daemon carries; the aside-copy
      cannot be poisoned by a killed run (mode 3). **Done: verified restore + refuse-on-leftover, tested both ways.**
- [x] The watchdog runs on a second host; its paging path is proven (mode 4). **Done: desktop
      watchdog live (linger), bogus-host test fired a direct page; healthchecks.io + email prepped
      pending operator activation.**
- [x] Per-step funnel counters exist and the signup→install drop-off alert is wired (mode 5).
      **Done: signup/add_device counters + VallumSignupNoDevice, deployed live, expr vmalert-validated.**
- [ ] A secondary responder is provisioned (contact + SSH key + receiver), not a placeholder
      (mode 6).
- [x] Recovery proves ownership (mode 7). **Done: recovery code shown once at signup, hashed;
      `reset-token --recovery-code` verifies it; deployed live, migration faithful.**
- [x] Concurrent enrolment validated on the released build (mode 9, partial). **Done: accept-many 12
      PASS on v1.10.0; throughput + sustained rekey-herd load remain unmeasured and named.**

## Verification note

Citations re-checked against the freshest code: mode 8's four `let _ = syncconf_running` sites
and `ApplyOutcome` (confirmed, fixed); mode 3's `restore_nat` (confirmed verified — the raw
accusation over-reached, corrected), binary restore `:495-499` and aside-copy `:908-911`
(confirmed unchecked); mode 2's 49-commit gap and `--local` (confirmed); mode 7's `_list_peers`
token exposure (confirmed — the "no handle" claim corrected). The published
`docs/qa/production-readiness-2026-11-19.md` was corrected in place (accept-install claim, drift
root cause, release-parity residual, verdict scope). Modes 1, 6, 7, 9 were investigated inline
after their investigators hit the API rate limit; their citations are the parent's, checked the
same way.
