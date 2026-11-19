# REPORT — issue #29 (ticket-03)

Worktree: /home/ikaaros/Coding/Gold/vallum-ticket-03 · branch ticket-03 · base 1e7a66e
Gate env: CARGO_TARGET_DIR=/home/ikaaros/Coding/Gold/vallum/target

## Baseline (before any change)
- `cargo test -p vallum`: **525 passed, 0 failed** (423 lib unit + 102 integration; see scratch/baseline-tests.txt).
- Governing docs read: ADR-0046, ADR-0039, CONTEXT.md (console's reader; carrying/degraded/stale/blocked/leaking).

## Plan (vertical TDD slices, commit each when green)
1. Seam: expose `read_report` from commands/account.rs (minimal visibility) + seam test from the TUI module.
2. TUI Account panel: Trial view becomes the Account panel (desk read cached off the render path, periodic refresh), snapshot tests.
3. doctor/status account-aware failure hints (both directions pinned).
4. TUI join form: optional account token (+ desk endpoint) into the privileged join; test.

## Design notes / disagreements (follow-up tickets, NOT changed here)
- **Trial feature preserved.** The view at ui.rs:1459 is the *full-tunnel trial* (arm `a` / panic `p`, palette-only, pinned by 3 existing tests). "Becomes an Account panel" is implemented as: the view is renamed Account and leads with the desk account section; the full-tunnel trial plan stays below it with its keys unchanged. Deleting the trial would break pinned tests and remove a shipped feature.
- **Desk endpoint across sudo.** `vallum-ops join` (packaging/vallum-ops, outside write set) reads stdin line 1 = ticket, line 2 = token → VALLUM_ACCOUNT. It has **no channel for VALLUM_DESK_ENDPOINT**, and the sudoers rule has no SETENV/env_keep, so env dies at sudo. The TUI passes the endpoint as env on the spawned process: it reaches `vallum join` on the direct (root) path; on the sudo path it is stripped. Follow-up ticket: dispatcher stdin line 3 → VALLUM_DESK_ENDPOINT (packaging change). Until then a sudo-path manual join records the token without the endpoint; `vallum account` already renders that state honestly ("token but no endpoint — re-join from the desk's connect link").
- **status hint scope.** Account hint attaches to `stale` and `starting` (the handshake-failure verdicts). `degraded` has fresh handshakes (not a handshake failure); daemon-gone verdicts are local problems. doctor: hint on reachable=Some(true) and None (both currently advise `peer add`); Some(false) (path down) unchanged — an account cannot cause a dead path.

## Log
- (init) baseline captured; docs read; code surveyed.