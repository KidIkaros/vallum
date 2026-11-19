# Alpha overnight report — 2026-11-19

**The finding, in words:** the alpha's account/device architecture is now *built and gated*.
Signup creates an account (not a device); devices enrol on demand from the client, each with a
key-pinned ticket; rotation preserves the device slot; the device cap reconciles against the
daemon's actual peers; strangers on a shared server can be isolated; an agent can enrol headless;
and the desk + landing page carry the Vallum brand and can be re-branded by another operator.
**31 commits, all test-first and gated. Nothing is deployed** — the live alpha is exactly as you
left it, and the breaking signup flip waits for your review. This is *production-readying*, not a
claim that a VPN is perfected in one night.

## What changed (workstreams → commits)
| WS | Change | Key commits |
|---|---|---|
| 1 | **ADR-0047** — account≠device; daemon owns physical truth; two-layer cap; tenancy mode | `13e8a78` |
| 2 | **White-label desk** — operator `--install-source`/`--repo-url`/brand; no hardcoded upstream when configured; defaults byte-identical | `f282050`,`f816eab` |
| 3 | **Opt-in tenant isolation** — `[interface] client_isolation` drops tunnel→tunnel; flat personal default preserved; fixed a latent NAT-table-wipe bug in vallum-quick | `5cae2fc`,`95f88ac` |
| 4 | **Account/device enrolment** — (a) account-only signup + v3 migration; (b) pinned enrolment + `join --key`; (c) rotation endpoint; (d) cap reconciliation vs daemon + ghost-reservation release | `450c322`,`821087b`,`c1dc595`,`a12f425` (+reviews `9d70fd3`,`6eb03da`) |
| 5 | **Vallum brand landing page** — obsidian + signal cyan `#39c5cf` + ◆, account-first, honest claims | `bcaf3fd`,`037ff1c`,`f9032bb` |
| 6 | **Headless agent enrolment gate** — `accept-agent-enrol.sh`, real binaries end to end | `533fc44` |
| 7 | **Gates wired + capacity stated** — both netns gates in `verify.sh` E2E; capacity already in `requirements.md` | `e47dc8a`,`7cc3158` |

## Evidence (measured, not asserted)
- **Desk suite: 261 tests OK** (CI's exact `discover -s service -p 'test_*.py'`).
- **`verify.sh` PASS** on the final tree (fmt, clippy `-D warnings`, workspace + lean tests, supply
  chain, desk copy/restore on the new schema, standalone build, TUI snapshot, signature round trip).
- **`accept-isolation`: 15 assertions PASS** (signed) — flat default, isolation blocks peer↔peer,
  internet + server preserved, toggle converges both ways. `accept-pair` still 88 (flat intact).
- **`accept-agent-enrol`: 25 assertions PASS** (signed) — account-only signup → device keygen →
  pinned ticket → `join --key` → handshake + ping 3/3; wrong key refused (names the pin, no config,
  no server peer).
- **Suite-alarm proofs**: mutants caught then reverted (NULL-burn, skip-canonicalization,
  ignore-named-key, isolation-drop-disabled). TDD red→green throughout.
- The two-axis reviews caught **real bugs**, each reproduced before fixing: an ownership bypass
  (`None != None` on the NULL legacy column), a non-atomic migration (crash loses accounts), a
  cacheable credential page, a non-string `public_key` 500.

## DEPLOY-HOLD — awaits your review (nothing live was touched)
1. **The account-only signup flip is breaking.** Existing accounts/devices migrate (v3,
   row-preserving, idempotent, crash-recovery proven), but the live desk still runs the old flow.
   Deploy = gate + `backup-deployment.sh` + swap the desk binary + restart, with rollback ready.
2. **Client isolation** is opt-in (default off) — enabling it on the live server is a tenancy
   decision (see open Q1).
3. **White-label branding** of the live desk + landing page is a deploy choice.

## Open questions — ADR-0047, need your ratification (NOT decided unilaterally)
1. **Isolation mechanism**: full client isolation (built) vs per-account subnets/nft (same-account
   devices talk, cross-account blocked). The latter needs the daemon to learn account membership
   or per-account subnets — a real design call.
2. **Agent device class**: ephemeral/auto-expiring slots vs a separate agent quota (the durable
   device model strands reservations when short-lived agents die).
3. **Account-token lifecycle**: rotation/recovery vs the PII-free no-recovery stance (ADR-0045).
4. **Web→client token handoff**: shown-once vs a `vallum://account` URI.
5. **Wire-versioning rule** for adding enrolment fields without breaking enrolled clients.

## Clientele findings (I am a user too)
- **The `vallum-fox` agent lane is not provisioned on this deployment**: the VPS `vallum0` peer
  table has only `laptop` + `lab8`, no fox peer. Fix = `agent/vallum-fox setup wingman-vps` (enrols
  the peer + writes the app_class config + a local polkit/sudoers prompt). Needs your local sudo
  password and is a live change → held. The headless gate proves agent-on-demand enrolment without
  depending on that lane.

## Honest remaining gaps (not done tonight)
- **Per-account isolation** (open Q1) — only full client isolation is built.
- **Agent device lifecycle** (open Q2) — ghosts are released by TTL, but there is no agent class.
- **Account-token rotation/recovery** (open Q3).
- **Horizontal scaling** — the data plane is single-threaded; capacity is vertical-only. Stated,
  not solved.
- **The live deploy itself** — held for you.
- A loop-hygiene lesson recorded: a cron tick can leave green WIP uncommitted if it exhausts its
  budget mid-slice; the next tick/parent must check `git status` first (this happened with WS4c).

## How to take it from here
1. Read ADR-0047 + ratify (or redirect) the five open questions.
2. Review the diff: `git log --oneline 37c0cbc..HEAD` (31 commits) and `git diff 37c0cbc..HEAD`.
3. Run the gate yourself: `bash scripts/verify.sh` (and `E2E=1 bash scripts/verify.sh` for the
   netns gates).
4. Deploy when satisfied: backup → swap desk binary → restart → verify `/healthz` + a live enrol.
5. Resume or remove the paused cron `vallum-alpha-loop` (job `45dc5f86ee11`) — its work is done.
