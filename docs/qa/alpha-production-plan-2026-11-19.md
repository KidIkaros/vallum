# Alpha → production-readiness plan (overnight autonomous loop, 2026-11-19)

**Mission.** The operator is asleep and asked for autonomous work to get the Vallum
alpha to a *workable, production-readying* standard. This file is the loop's single
source of truth. A cron job (`vallum-alpha-loop`) reads it each tick, picks the next
unfinished workstream, implements it test-first, gates it, commits it, and updates the
status table + state log below. **Honest scope:** a VPN is not "perfected" in one night.
The goal is verified, gated progress on the prioritized architectural gaps — not a claim
of production perfection.

## Safety boundaries (HARD — never cross while the operator sleeps)
1. **Never break the live alpha.** `desk.wingman.gold` + `vallum@vallum0` on wingman-vps
   are serving a colleague cohort. Existing accounts/devices MUST keep working.
2. **Gate before commit.** Every slice: `python3 -m unittest service/test_vallum_desk.py`
   (desk) and/or `bash scripts/verify.sh` (Rust) green BEFORE commit. TDD: failing test first.
3. **Backup before any live deploy.** `sudo bash scripts/backup-deployment.sh --dest
   /var/backups --label before-<change>` on wingman-vps. Keep rollback ready.
4. **Deploy policy (OVERNIGHT = HOLD ALL).** While the operator sleeps, develop+gate+commit
   only; **do NOT deploy anything to the live desk/daemon overnight.** Mark every live change
   `DEPLOY-HOLD`. The operator reviews and deploys when awake (gate+backup+rollback then).
   This keeps the live alpha safe for the cohort. Rationale: an unsupervised bad deploy could
   break the running alpha; verified committed progress is the deliverable tonight.
5. **No irreversible architecture calls unilaterally.** Record hard-to-reverse decisions as
   ADRs (proposed) for operator review. The personal-vs-service tenancy spine is decided in
   ADR-0047; its *open questions* stay open until the operator ratifies.
6. **No GPU quota, no H200.** Not relevant here, but the standing rule holds.
7. **vallum-fox budget is law.** Dogfooding the agent lane: never raise the per-domain
   budget, never retry a BUDGET_EXHAUSTED domain in a loop, fail-closed (no host fallback).
8. **Commit per slice on main** (house convention), tree releasable throughout. Parallel
   subagents work in their OWN worktree/branch; never merge/push/ssh from a child — the
   parent (loop) verifies the diff and merges.
9. **No secrets in commits/logs.** Leave `.env`, keys, tokens, the pager topic alone.

## The decided spine (ADR-0047 — read it)
- **Daemon is the source of truth** for peer existence + server capacity. The desk owns
  account *policy* and reconciles its device count against `vallum show --json`.
- **Two limits, two layers:** server capacity (daemon/resource, hardware-bound, scales with
  the box; address pool `/20`=4094, handshake CPU ~2000 peers, single-thread data plane) vs
  account device cap (desk/policy, a plan attribute, optional for paid tiers). The physical
  ceiling is daemon-enforced race-free at allocation; the policy ceiling is desk-enforced.
- **Account ≠ device.** Web signup creates an account only (code → token, no device name).
  Devices enrol client-driven, on demand, free up to capacity: client keygens → presents
  public line + label + token to `POST /api/devices` → desk counts/reserves → mints a
  **pinned** single-use invite (`peer invite --public-key`, already exists) → client joins.
  Each device gets its OWN pinned invite (preserves single-use; no reusable account ticket).
- **Rotation preserves the slot:** `peer rotate <name> --public-key` (client-generated key,
  custody preserved) under the stable name; `finalize` retires previous. Never `add_device`
  for rotation (burns a slot). The desk needs a rotation endpoint (currently none).
- **Personal vs service tenancy mode:** personal = flat (devices reach each other, a feature);
  service = per-account isolated (strangers must not reach each other). Isolation is opt-in.

## Workstreams (vertical slices; status: TODO / DOING / DONE / DEPLOY-HOLD / BLOCKED)
Acceptance criteria are numbers with runnable checks (software-delivery-process §3).

| # | Workstream | Acceptance (runnable) | Status |
|---|---|---|---|
| WS1 | ADR-0047 spine + open questions | ADR exists, cited, open questions marked | DONE (13e8a78) |
| WS2 | White-label operator-config: install source + repo links + brand from config/env, no hardcoded KidIkaros | desk tests: operator install_source renders; default unchanged; 0 hardcoded KidIkaros in served pages when configured | DONE — merged e0d6711 (f282050,f816eab); 165 tests OK; follow-up DONE in 450c322: service/README config table +2 flags |
| WS3 | Multi-tenant isolation (opt-in service mode): `[interface] client_isolation` drops tunnel→tunnel forward; personal flat default | new gate: with isolation on, two peers cannot ping each other but both reach internet; default off = flat (accept-pair stays green). Per-account refinement (same-account talks, cross-account blocked) is ADR-0047 open Q1 — DEFER, do not decide unilaterally | DONE (5cae2fc) — accept-isolation 15 assertions; accept-pair 88; verify.sh PASS; DEPLOY-HOLD |
| WS4 | Account/device enrolment redesign (account-only signup + client-driven pinned enrolment + rotation endpoint + cap reconciliation + migration) | desk tests: signup creates account w/o device; add_device mints PINNED invite; rotation preserves count; cap race-free; legacy accounts migrate; count reconciles vs daemon | DONE — slice (a) DONE (450c322 + review 9d70fd3): account-only signup + v3 migration + device-less readers/admin + docs; slice (b) DONE (821087b + review 6eb03da): add_device mints PINNED invite via --public-key (canonicalized, validated pre-reservation) + `vallum join --key` redemption + place_config idempotent key + UTCP/README/glossary; desk 236 OK, verify.sh PASS, real-binary two-netns probe 22 checks FAIL=0 (handshake + ping 3/3 + wrong-key refusal). Slices c (rotation) DONE (c1dc595 + review 7981a40; real-desk two-netns rotation probe 22 checks FAIL=0 — rotate at cap, key swap re-handshake, retired key refused+counted), d (reconciliation) DONE (a12f425, full CI 261 OK, verify.sh PASS). DEPLOY-HOLD for live signup flip |
| WS5 | Web re-skin: Vallum brandkit (obsidian + signal cyan + ◆, "every boundary under watch"); account-first journey | site/index.html uses brand tokens; no wingman-gold; renders; links valid (desk embedded pages re-skinned in WS4) | DONE — merged e0d6711 (bcaf3fd,037ff1c,f9032bb); signal cyan #39c5cf, Nu-valid; follow-up DONE in 450c322: journey step1 + agent API block re-worded for account-only signup (live journey re-proof rides WS6's headless gate) |
| WS6 | Agent dogfood + headless enrolment gate: enrol a device headless via API (signup→devices→join), exercise vallum-fox lane | new gate: headless agent enrols + handshakes in ≤3 API calls + join; fox egress separated:yes | DONE — accept-agent-enrol (533fc44, parent-built, 25 assertions PASS: account-only signup→pinned devices→join --key→handshake+ping, wrong-key refused). Fox-lane egress part HELD: no fox peer enrolled on the VPS; setup needs operator polkit + is a live change |
| WS7 | Numeric acceptance + gates wired into verify.sh; requirements.md capacity number stated | new gates run in verify.sh; capacity ceiling stated with source | DONE — accept-isolation (e47dc8a) + accept-agent-enrol (7cc3158) wired into E2E; both PASS standalone (15 + 25 assertions); capacity ALREADY stated+sourced in requirements.md |

## Loop procedure (each cron tick)
1. Read this file + ADR-0047 + `git log --oneline -5` + the state log.
2. Pick the lowest-numbered TODO workstream whose blockers are DONE. Mark DOING.
3. Implement test-first (failing test → simplest pass → refactor). Keep the slice vertical
   and demoable. Use the relevant skills (tdd, implement, philosophy-of-software-design,
   devops-topologies, software-delivery-process, premortem, vallum-operations, vallum-fox).
4. Gate: desk unittest + `bash scripts/verify.sh` (or the slice's scoped gate). Green required.
5. Commit per slice on main (or merge a verified child worktree). Update the status table.
6. Append a state-log entry: timestamp, workstream, what changed, gate result, commit, deploy
   status. If BLOCKED, write why + what the operator must decide; move to the next TODO.
7. Deploy only per the deploy policy (backward-compatible + gate + backup). Breaking = HOLD.
8. Stop ticking when all workstreams are DONE/BLOCKED/DEPLOY-HOLD (pause the cron via
   cronjob_manage, write the morning report). Do not invent new scope beyond the gap list.

## Morning report
Write `docs/qa/alpha-overnight-report-2026-11-19.md`: what changed (commits), what's gated
green, what's DEPLOY-HOLD awaiting review, what's BLOCKED needing a decision, the honest
remaining gaps. Lead with findings in words, numbers as backup.

## State log (append-only)
- 2026-11-19 00:07 EST — plan created; main@37c0cbc; desk tests green; WS1 (ADR-0047) in progress.
- 2026-11-19 00:1x EST — WS1 DONE (13e8a78: ADR-0047 + plan). WS2 (white-label) + WS5 (brand site)
  dispatched to background children in worktrees vallum-ws2 / vallum-ws5. Overnight deploy policy
  set to HOLD ALL live deploys for operator review. Cron loop `vallum-alpha-loop` to continue
  WS4/WS3/WS6/WS7 and merge verified child worktrees.
- 2026-11-19 00:1x EST — DOGFOOD (clientele): the vallum-fox agent lane on the operator host is
  DOWN (daemon+quick inactive, egress unreachable, fail-closed). It is an on-demand member
  namespace (vallum-quick app), not a persistent unit; local sudo needs a password so /etc/vallum
  is inspectable only via the VPS (passwordless). WS6 must verify the fox setup + headless agent
  enrolment (signup→devices→join) and the lane's start path. Finding recorded, not fixed tonight.
- 2026-11-19 00:1x EST — Foundation complete: plan + ADR-0047 committed (13e8a78 + plan commit);
  WS2/WS5 children running; cron loop 45dc5f86ee11 scheduled (first tick 00:57). Parent turn ends;
  the loop carries WS3/WS4/WS6/WS7 and merges verified worktrees through the night.
- 2026-11-19 00:4x EST — WS2 + WS5 VERIFIED by parent (re-ran gates: desk 165 OK + siblings 25 OK;
  site brand tokens present, old theme 0 hits, Nu-valid, write-sets respected) and MERGED into
  main e0d6711 (--no-ff). Worktrees removed, branches deleted. WS3 refined to implementable opt-in
  client_isolation (per-account refinement deferred to ADR-0047 Q1). Next: WS3 then WS4 (sliced).
  Follow-ups booked: service/README config table +2 flags (WS2); landing human-journey step1 re-check
  after account-only signup flip (WS4/WS5).
- 2026-11-19 06:1x EST — OPERATOR STATUS CHECK. Parent grounded the loop's reports against the
  real tree: WS3/WS4a/WS4b committed as claimed, BUT found WS4c (rotation) written + green yet
  UNCOMMITTED (the 05:21 tick ran out before commit; "tree clean" claim was stale). Parent verified
  the WIP (full CI desk suite 255 OK; reviewed rotate_device + DaemonCli.rotate: custody preserved,
  slot preserved at cap, ownership + NULL-trap guarded, honest finalize reporting) and committed it
  c1dc595. Tree clean. WS4 a/b/c done; d (cap reconciliation) + WS6 + WS7 remain. Live alpha untouched.
  Loop hygiene note: a tick may leave green WIP uncommitted if it exhausts its budget mid-slice — the
  next tick (or parent) must check `git status` and finish/commit pending WIP before starting new work.
- 2026-11-19 06:3x EST — OPERATOR: "work now instead of later." Cron paused (parent synchronous).
  WS4d DONE (a12f425): cap reconciles against daemon liveness (source of truth), ghost reservations
  released past reservation_ttl (1200s), pending kept, redeemed kept regardless of age, unreachable
  daemon fail-closed; sweep clears ghosts on active accounts. TDD 6 red->green; full CI 261 OK;
  verify.sh PASS. WS4 a-d all DONE. Next: WS6 (agent dogfood + headless enrolment gate), WS7.
- 2026-11-19 06:4x EST — WS7 partial (e47dc8a): accept-isolation wired into verify.sh E2E leg +
  syntax check; ran it standalone PASS 15 assertions (signed). requirements.md Capacity already
  states the measured ceilings with sources — no new number needed. accept-agent-enrol wiring waits
  on WS6 (child sa-0, worktree vallum-ws6, building the headless gate). CLIENTELE dogfood: the VPS
  vallum0 peer table has only `laptop` + `lab8` — NO fox peer enrolled, so the vallum-fox agent lane
  was never set up on this deployment. Fix = `agent/vallum-fox setup wingman-vps` (enrols the peer +
  writes the app_class config + a local polkit/sudoers prompt). Needs the operator's local sudo
  password AND is a live change -> HELD for operator. The headless enrolment gate (WS6) is the
  agent-on-demand proof that does not depend on the fox lane being pre-provisioned.
- 2026-11-19 07:0x EST — OPERATOR: "take the wheel." Parent stopped the WS6 child (no committed
  output) and built accept-agent-enrol.sh directly from the cron's pin-probe topology + desk API.
  First run failed: unshare -Urn has no mount ns, so tmpfs over /etc/vallum + /run was denied;
  fixed with -m (unshare -Urnm). PASS 25 assertions. Merged 533fc44; wired into verify.sh E2E
  (7cc3158). WS6 + WS7 DONE. ALL workstreams WS1-WS7 complete. Morning report written; cron paused.
- 2026-11-19 12:2x EST — OPERATOR "go": DEPLOYED + PUSHED + desk UI re-skinned. Re-skinned the desk
  embedded pages to the brandkit (b14fdb7, 271 tests OK, verify.sh PASS); pushed origin 5d85727..b14fdb7;
  deployed to wingman-vps (backup tarball + binary rollback + DB copy staged). LIVE verified:
  https://desk.wingman.gold branded (obsidian+cyan+◆), healthz ok (db+daemon), closed mode preserved,
  migration faithful (17 accounts identical to pre-deploy backup: 2 expired + 15 revoked), account-only
  signup live (old code+name shape refused with the new message), bogus code 403. DEPLOY-HOLD lifted for
  the desk. Cron's final tick reviewed WS4c and fixed real bugs (7981a40); live run cancelled after.
  Rollback: install vallum-desk.rollback-brand + restore desk-before-brand.sqlite + restart.
- 2026-11-19 13:0x EST — DOGFOOD fixes (operator: "start" on fix 2). systematic-debugging 4-phase:
  the "unattributed traffic" was NOT real — tui/mod.rs seeded showcase rates (1_420_800/3_891_200 B/s)
  on EVERY --snapshot with a device; ADR-0039 advertises --snapshot as an agent read verb. FIXED
  0a6cb0d: seed gated behind --demo, snapshot renders real data; generate_media.py opts in.
  ad1afb1: metrics peer counters labelled {interface, peer} (fingerprint forks series on rotation);
  fingerprint now vallum_peer_fingerprint_info metadata. 421b193: Starting status says "no peer is
  connected yet" instead of the absolute "no handshake has completed" that contradicted
  handshakes_established_total=1 in the same scrape. 455 lib tests; verify.sh PASS; workspace 48
  suites clean; pushed b088cbe..421b193. VERIFIED LIVE on wingman-vps with the rebuilt binary:
  plain snapshot honest (0.0 B/s flat), --demo showcase intact, metrics name-keyed + info metric.
  NEW finding filed #34: laptop's config fingerprint (7db904af) ≠ daemon session fingerprint
  (abc04277), no rotation window — a config↔daemon desync on the live server; doctor check proposed.
  NOTE: the deployed VPS daemon binary is still 1.9.0 (pre-fix); deploying the new binary is a
  separate live change, staged decision with the operator.
- 2026-11-19 01:37 EST — WS3 DONE (5cae2fc): opt-in `[interface] client_isolation` + `--client-isolation`
  flag; drop chain in the wholesale-replaced `inet vallum` table (converges both ways; teardown already
  removes it); config is source of truth on re-init (flag/config conflict refused); `--no-nat`+isolation
  refused; quick's NAT reconcile made chain-scoped so an attach cannot wipe the isolation chain (found
  during design: quick deleted the whole table). New gate scripts/accept-isolation.sh (server + 2 clients
  + wan netns, no docker): 15 assertions PASS — flat control, refusal path, peers blocked both directions
  (sustained window), wan + server-input preserved, toggle-off convergence, creation flag persist/report.
  Gates: verify.sh PASS (final tree), workspace 1006 tests 0 fail, desk 165 OK, accept-pair 88 assertions
  PASS (flat default intact). Suite-alarm proof: mutant (drop chain disabled) caught by the gate rc=1,
  reverted, gate re-passed. DEPLOY-HOLD — live alpha untouched. Follow-ups booked: doctor isolation check;
  shared NAT-planner dedup (hostnet/quick two writers); WS7 wires accept-isolation into verify.sh;
  kernel proof of quick-reconcile-preserves-chain awaits a NAT-only quick verb. Next: WS4 slice (a).
- 2026-11-19 01:50 EST — WS3 two-axis review (Standards + Spec sub-agents, code-review skill) on
  5cae2fc: no hard violations; spec axes clean (flat default, opt-in, Q1 left open, wan proof genuine).
  Verified-then-fixed: test-helper duplication extracted (nat_script); --force and --no-host semantics
  documented in comments (both consistent by design, not holes); CONTEXT.md gained the Tenancy entry;
  gate script trailing newline. Waived with reason: --force recreates from flags (explicit, like every
  field); --no-host claims no host change (flag applies on next host-applying re-run). Review-fix commit
  follows; verify.sh re-run on the final tree. Skill lesson saved to vallum-operations
  references/client-isolation.md (SKILL.md is over its 100k char limit — split booked as follow-up).
- 2026-11-19 02:36 EST — WS4 slice (a) DONE (450c322): account-only signup per ADR-0047 §3. Signup =
  code → account number (peer NULL, no peers row, NO daemon call — a down daemon cannot stop signup);
  device name at signup refused with guidance (code not burned). Schema v3 rebuilds accounts.peer
  nullable (idempotent, row-preserving; v0→v3 in one start); legacy accounts keep device/enforcement/
  readers. Device-less accounts first-class: account/status/funnel/sweep truthful at zero devices,
  expiry revokes them, admin set-plan/revoke-account accept token, listing carries the number, CLI
  --token. Latent bug fixed: voucher burn wrote used_by=peer (NULL on device-less → code redeems
  twice); one _account_name definition serves burn/revoke/sweep-log. Pages: index without device-name
  field, account-created page (shown-once number, next step), ticket page stays on add-device. Docs in
  the same edit: service README (+WS2's two booked config-table flags), site journey step 1 (WS5
  follow-up), UTCP manual (signup shape, new add_device tool, status token out of the retired URL
  shape). Seams: Desk.signup, open_database, device-less readers, HTTP wire, admin CLI (plan-agreed).
  TDD: migration tests RED→GREEN first, then full contract rewrite (147 red) → implementation → green.
  Gates: desk 217 OK (CI discover command), verify.sh PASS (incl. accept-desk-restore on v3).
  Suite-alarm: NULL-burn mutant caught by 2 tests, reverted, green. DEPLOY-HOLD — live alpha untouched.
  Next: WS4 slice (b) — add_device mints a PINNED invite via --public-key.
- 2026-11-19 03:2x EST — WS4 slice (a) two-axis review on 450c322 (Standards sub-agent + Spec checked
  against ADR-0047 §3). Spec clean (account-only, no device name on web, migration row-preserving, open
  questions untouched, pinned invites stay slice b). Standards: 3 HARD findings, each REPRODUCED live
  before fixing, each regression-tested RED-first: (1) remove_device missing-peer ownership bypass
  (None != None is False on the now-NULL legacy column → daemon.remove(None)); (2) _migrate_v2 rebuild
  non-atomic under autocommit — crash between DROP and RENAME silently loses every account, orphaned
  scratch table wedges reopen → now one BEGIN IMMEDIATE/COMMIT + DROP IF EXISTS, both recovery paths
  proven by probe; (3) account_created_page served the credential without no-store/noindex →
  private=True, headers pinned on the wire. Judgement calls landed: signup writes one transaction
  (failure-injection test), _account_name unified across voucher/set-plan responses, stale comments
  corrected, CLI --token-file + masked human accounts listing (full under --json), UTCP set_plan/
  set_status token addressing (both directions verified live). Review-fix commit 9d70fd3; gates re-run
  on the final tree: desk 224 OK, verify.sh PASS. Lessons saved to vallum-operations
  references/service-layer.md. DEPLOY-HOLD unchanged. Next: WS4 slice (b).
- 2026-11-19 05:19 EST — WS4 slice (b) DONE (821087b + review 6eb03da): pinned device enrolment,
  the full vertical path. Desk add_device accepts the device's public line (public_key),
  canonicalizes it (lowercase hex, 4-digit suite, whitespace stripped — the responder's pin is a
  whole-line byte comparison against encode_public's canonical form), validates structure BEFORE
  the reservation (400 burns no slot, no daemon call; non-string → 400 not 500), and mints via
  `peer invite --public-key` (one argv element, never shell). Response carries `pinned: true|false`;
  absent/empty line = the unchanged web path (single-use, unpinned, key at join time). Client half:
  `vallum join --key <file>` (join_identity helper: mode check before read, global
  --allow-insecure-key-permissions plumbed; custody preserved — placed key byte-identical to the
  device's); place_config skips a byte-identical key already at its destination (a spent invite must
  not strand on an overwrite refusal), different key still refuses. Docs same edit: service README,
  UTCP desk manual (public_key required-with-empty convention, like signup's code — the manual
  discipline test demands required placeholders), UTCP vallum manual (vallum_join_pinned), CONTEXT.md
  Pinned invite entry. TDD throughout (12 desk tests + 7 Rust tests RED→GREEN). Gates: desk 236 OK
  (discover), verify.sh PASS on the final tree (workspace 1013 tests, clippy -D warnings, fmt, lean
  leg, supply chain, copy/restore, TUI, signature). Real-binary proof: two-netns veth probe (host
  /etc+/run hidden behind tmpfs) — keygen→pubkey→pinned invite→join --key→handshake both ends→ping
  3/3 through the tunnel; wrong key refused naming the pin, no config, no server peer; 22 checks
  FAIL=0. Suite-alarm: desk canonicalization mutant + Rust ignore-the-key mutant each caught,
  reverted, green. Two-axis review: Spec faithful (single-use, custody, atomic cap, legacy path,
  open questions untouched); Standards 1 hard (duplicated decision comment → deduped) + non-string
  400 (reproduced, regression-tested) + glossary entry; waived with reason: dry-run/live match blocks
  are different speech acts. Probe topology lesson: a loopback endpoint in one netns is the client's
  own address — the product's self-tunnel refusal is correct, the probe needed two namespaces.
  Lessons saved to vallum-operations references/service-layer.md. DEPLOY-HOLD — live alpha untouched.
  Next: WS4 slice (c) — rotation endpoint calling `peer rotate --public-key`, preserving the device count.
- 2026-11-19 07:09 EST — WS4 slice (c) EVIDENCE + REVIEW complete (the 06:06 tick, in flight while the
  parent session finished d/WS6/WS7 and paused cron 45dc5f86ee11). Rotation endpoint POST /api/devices/rotate
  {token,peer,public_key}: Desk.rotate_device -> DaemonCli.rotate = `peer rotate --public-key --json` +
  `peer finalize` (finalize in the same call: client-driven rotation means the caller holds the new key,
  so the grace window protects nothing; a failed finalize is reported finalized:false + warning, retry
  converges). No reservation/cap/ticket — slot preserved. Real-binary proof (REAL desk + REAL binaries,
  two netns, --device-cap 1 so the account is AT its cap): signup→pinned add_device→join --key→handshake+ping
  (key A)→rotate over the wire (200, finalized+applied, no ticket; config holds key B only, 1 peer; desk DB
  slot preserved)→device swaps its key file, config untouched→re-handshake+ping (key B)→retired key A
  refused and counted (unknown_peer 0→1), no data plane. 22 checks FAIL=0. Suite-alarm: skip-finalize +
  skip-canonicalization mutants each caught, reverted, green. Gates: desk 255 OK on c1dc595 in an isolated
  worktree; UTCP manual tests 9 OK; Rust tree byte-identical to e6873d0 (verify.sh PASS 05:19), so the
  Python-only slice did not re-run the full Rust gate. Two-axis review: Spec faithful to ADR-0047 §4
  (stable name, custody, slot at cap, old key retired, single-use untouched, open questions untouched);
  Standards (sub-agent, every finding reproduced in an isolated checkout): 1 HARD — non-string peer/token
  crashed behind a 500 (sqlite bind) or read 404; 2 SOFT — rotate/mint JSON of wrong shape -> AttributeError
  behind a 500, FakeDaemon.rotate more permissive than the real CLI (ignored missing_peers); 2 JUDGEMENT —
  duplicated decision comments, README example omitted `applied`. ALL fixed RED-first in 7981a40: shared
  _device_target intake helper (typing + lookup + ownership; NULL-guard comment once; also closes the
  pre-existing remove_device gap), loud shape guards on rotate/mint JSON, faithful fake + missing-peer
  negative test, comment dedup, README. Desk 269 OK after fixes; intake-guard mutant caught, reverted.
  Probe-rig lessons (rig, not product): join's 35s proof is fed by the RUNNING client's 25s keepalive —
  start the client before waiting for join; a retired key fails the peer-HINT lookup -> unknown_peer,
  not unidentifiable. FOLLOW-UP finding (recorded, not in the plan gap list, not fixed): CLI `show --json`
  (uapi::response_json) omits the handshake_dropped_* counters — they ride `vallum metrics` and the raw
  get=1 response; a diagnostic reading show --json cannot see refusal reasons. Concurrency: the parent
  committed this tick's green WIP mid-flight (c1dc595, believing it a prior tick's leftover); the tick
  verified its committed slice in an isolated worktree and applied review fixes on main after the tree
  went clean — never touching the concurrent slice-d WIP. DEPLOY-HOLD unchanged; live alpha untouched.
