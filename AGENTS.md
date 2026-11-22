# Agent notes

## Agent skills

### Issue tracker

Issues and specs are tracked as GitHub issues on this repository (`gh` CLI). See `docs/agents/issue-tracker.md`.

### Triage labels

Default five-role vocabulary (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` at the repo root is the glossary; `docs/adr/` holds decisions. See `docs/agents/domain.md`.

### ADR authority

An ADR names the operator as decider only when the operator made the decision
in-session. Agent-proposed decisions that ship unreviewed record
`Status: agent default — pending operator ratification`, with the agent as
decider. Recording shared authorship that did not happen is a record
integrity bug, not a style choice (see the ADR-0039 correction).

## Gates

`scripts/verify.sh` is the gate of record ("green" = its PASS). `scripts/verify-remote.sh <host>` is the two-host release gate; its stamp is commit-bound. Desk tests: `python3 -m unittest service/test_vallum_desk.py -v` (no daemon needed — the `Desk` tests against a fake `Daemon` port).
