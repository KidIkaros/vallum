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
| WS2 | White-label operator-config: install source + repo links + brand from config/env, no hardcoded KidIkaros | desk tests: operator install_source renders; default unchanged; 0 hardcoded KidIkaros in served pages when configured | DOING (child sa-0, worktree vallum-ws2, branch ws2-white-label) |
| WS3 | Multi-tenant isolation (opt-in service mode): nft drops tunnel→tunnel across accounts; personal flat default | new gate: 2 peers different accounts cannot ping; same account can; default off = flat (accept-pair still green) | TODO |
| WS4 | Account/device enrolment redesign (account-only signup + client-driven pinned enrolment + rotation endpoint + cap reconciliation + migration) | desk tests: signup creates account w/o device; add_device mints PINNED invite; rotation preserves count; cap race-free; legacy accounts migrate; count reconciles vs daemon | TODO (DEPLOY-HOLD for live signup flip) |
| WS5 | Web re-skin: Vallum brandkit (obsidian + signal cyan + ◆, "every boundary under watch"); account-first journey | site/index.html uses brand tokens; no wingman-gold; renders; links valid (desk embedded pages re-skinned in WS4) | DOING (child sa-1, worktree vallum-ws5, branch ws5-brand-site; site/* only) |
| WS6 | Agent dogfood + headless enrolment gate: enrol a device headless via API (signup→devices→join), exercise vallum-fox lane | new gate: headless agent enrols + handshakes in ≤3 API calls + join; fox egress separated:yes | TODO |
| WS7 | Numeric acceptance + gates wired into verify.sh; requirements.md capacity number stated | new gates run in verify.sh; capacity ceiling stated with source | TODO |

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
