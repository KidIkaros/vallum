# Agent notes

## Agent skills

### Issue tracker

Issues and specs are tracked as GitHub issues on this repository (`gh` CLI). See `docs/agents/issue-tracker.md`.

### Triage labels

Default five-role vocabulary (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` at the repo root is the glossary; `docs/adr/` holds decisions. See `docs/agents/domain.md`.

## Gates

`scripts/verify.sh` is the gate of record ("green" = its PASS). `scripts/verify-remote.sh <host>` is the two-host release gate; its stamp is commit-bound. Desk tests: `python3 -m unittest service/test_vallum_desk.py -v` (no daemon needed — the `Desk` tests against a fake `Daemon` port).
