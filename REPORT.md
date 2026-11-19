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
- **Slice 1 — seam** `bf55026`: `read_report` → `pub(crate)` (Report fields already pub); seam test `the_tui_reuses_the_desk_read_seam` in tui::tests. RED: E0603 private. 526 green.
- **Slice 2 — TUI account panel** `a9b2769`: new `tui/account.rs` (AccountState + lines), App cache fields, `View::Trial`→`View::Account`, `draw_trial`→`draw_account` (account section leads, trial plan below, a/p keys unchanged), `actions::poll_account` (worker thread + mpsc, polled each event-loop tick; refresh on open / 30 s / interface change), palette command "read desk account…" (Action::AccountPanel, palette-only). Report boxed in AccountState (clippy large_enum_variant).
  - New tests: `account_panel_renders_the_desk_read` (snapshot), `an_unreachable_desk_renders_unknown_with_the_raw_line`, `a_config_without_a_desk_account_says_so_plainly`, `the_account_read_runs_off_the_render_path` (real config + closed-port desk; first poll returns with pending, answer lands cached), `the_palette_offers_the_desk_account_read`. Each watched RED first.
  - Hand-verified render (TestBackend 100x16, full desk answer):
    ```
    ╭◆ Vallum ❯ ACCOUNT [line 1/10] (a arm trial, p panic, r refresh, Esc)─╮
    │desk       https://desk.wingman.gold                                  │
    │account    u0001 — laptop                                             │
    │plan       trial                                                      │
    │status     active                                                     │
    │expires    2026-12-02                                                 │
    │bytes      1.00 / 5.0 GiB used (shared across devices)                │
    │devices    2 on this account                                          │
    │connected  1 of 2 devices have connected                              │
    │                                                                      │
    │FULL-TUNNEL TRIAL — route all host traffic through the tunnel.        │
    ╰──────────────────────────────────────────────────────────────────────╯
    ```
  - Gates: 531 passed / 0 failed; fmt OK; clippy -D warnings clean.
- **Slice 3 — doctor/status account hints** `c82e083`: `doctor::desk_account_hint` (pub(crate), shared wording), `handshake_verdict`/`check_tunnel` take `Option<&Account>`; doctor reads `[account]` from the file (Resolved carries no account — the daemon is account-ignorant). Hint replaces the `peer add` advice on reachable=Some(true) and None when a token is recorded; Some(false) (dead path) and token-less configs unchanged. `status::account_hint` attaches to Stale/Starting only; printed as an `account` row and emitted as `account_hint` in --json (null otherwise).
  - New tests: doctor `a_refused_client_with_a_desk_account_is_pointed_at_the_desk`, `a_refused_client_without_an_account_keeps_the_existing_advice`, `an_account_without_an_endpoint_gets_the_hint_without_a_url`, `the_unprobed_and_dead_path_branches_stay_honest_about_the_account`; status `a_handshake_failure_with_a_desk_account_is_pointed_at_the_desk`, `a_handshake_failure_without_an_account_keeps_the_existing_advice`, `only_handshake_failure_verdicts_get_the_account_hint`. All watched RED first.
  - Hand-verified with the real binary against a fake control socket (scratch/hint-check):
    - `vallum status` (starting, with account): `account    this config carries a desk account - it may have expired or hit its byte cap; run `vallum account` or open https://desk.wingman.gold/account`; without account: no account row; --json carries `account_hint`.
    - `vallum doctor` (client, never handshook, with account): `FAIL tunnel … the likely causes, in the order to check them: this config carries a desk account - it may have expired or hit its byte cap; run `vallum account` or open https://desk.wingman.gold/account; the server no longer has this client's key …`; without account: `… re-enrol with `vallum peer add` …` unchanged. Exit 1 both.
  - Gates: 538 passed / 0 failed; fmt OK; clippy -D warnings clean.
- **Slice 4 — join form account token** `bd326f2`: `Form::join_network` gains "account token (optional)" (masked) and "desk endpoint (optional)"; `actions::join_request` (pub(crate) seam) validates and builds the privileged invocation's channels — ticket stdin line 1, token line 2 (dispatcher re-exports VALLUM_ACCOUNT), desk origin as VALLUM_DESK_ENDPOINT env via `run_privileged_with_env`. Token must be 32 hex; endpoint must parse as a desk origin (reuses `parse_desk_endpoint`); endpoint-without-token and token-with-SSH-target are refused with field errors. Nothing secret in argv.
  - New tests: `the_join_form_carries_the_account_token_into_the_privileged_join`, `the_join_form_without_an_account_keeps_the_ticket_only_payload`, `the_join_form_refuses_a_malformed_account_token`, `the_join_form_refuses_a_bad_desk_endpoint`, `the_ssh_join_path_carries_no_desk_account`. All watched RED first.
  - Hand-verified: the dispatcher's join case (extracted verbatim from packaging/vallum-ops, /usr/bin/vallum stubbed) fed the exact join_request payload → `args:join - ticket:vallum1-join:… account:0123456789abcdef0123456789abcdef desk:https://desk.wingman.gold`; token-less payload → `account: desk:` empty. Form render shows both fields, token masked (`account token (optional) ************`).
  - Gates: 543 passed / 0 failed; fmt OK; clippy -D warnings clean.

## Final tally
- Baseline 525 → **543 passed, 0 failed** (+18 tests: 1 seam, 5 panel, 4 doctor, 3 status, 5 join).
- Write set respected: only tui/, doctor.rs, status.rs, account.rs (seam only: `pub(crate) fn read_report` + doc). No service/, vallum-config/, setup.rs, main.rs, gui, packaging changes.
- Commits on ticket-03: bf55026 (seam) → a9b2769 (panel) → c82e083 (hints) → bd326f2 (join).
- Follow-up tickets (see Design notes): dispatcher stdin line 3 for VALLUM_DESK_ENDPOINT across sudo; optional `--snapshot-view account` for a TTY-free agent view.