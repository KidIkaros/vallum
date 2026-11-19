# Incident YYYY-MM-DD-short-slug

Copy this file to `YYYY-MM-DD-short-slug.md` in this directory when a page
fires. Fill it in as the incident happens, not after. See
[../incident-response.md](../incident-response.md) for the runbook and
[README.md](README.md) for the rules of the log.

| Field | Value |
|---|---|
| Id | `YYYY-MM-DD-short-slug` (same as the filename) |
| Date opened | YYYY-MM-DD HH:MM UTC |
| Severity | SEV1 / SEV2 / SEV3 — and why, if it differs from the alert's label |
| Status | open / contained / resolved |
| Detector | which alert fired (`Vallum…`), which probe, or "operator noticed" — the last is a finding about the monitoring |
| Commander | who is driving (primary / secondary / other) |
| Ack at | HH:MM UTC — when the first human acked the page |
| Escalated | no / to whom, at HH:MM UTC |

## Summary

One or two sentences: what broke, what it cost, what fixed it. Written last,
read first.

## Timeline

UTC, one line per event, appended as it happens. Include the pages, the acks,
every command that changed state, and the moment the detector went quiet.

| Time (UTC) | Event |
|---|---|
| HH:MM | alert fired: `Vallum…` on `…` |
| HH:MM | acked by … |
| HH:MM | ran `…` — output: … |
| HH:MM | contained: … |
| HH:MM | resolved: … |
| HH:MM | alert cleared / drill-verified |

## Impact

Count what was affected, in the two units the system actually has — peers
(devices) and accounts ([ADR-0047](../../adr/0047-the-account-is-not-the-device.md):
the account is not the device).

- Peers affected: which names, for how long, and in which state — carrying /
  blocked / stale / **leaking**. A leaking window is a breach window; state
  its start and end explicitly, or say "unknown" and treat it as SEV1.
- Accounts affected: enrolments failed, tickets burned, desk unreachable —
  `vallum-desk-admin accounts` / `devices` and the alpha funnel series
  (`vallum_alpha_devices{state}`) are the sources, not memory.
- Data at risk: was anything in the clear, was any key exposed, was the desk
  database touched? If yes or unknown → [../compromise.md](../compromise.md).

## Root cause

What actually broke, at the level a fix can attach to. "The path dropped UDP"
is a cause; "it was broken" is not. If the cause is unknown, say so and name
what evidence would settle it — an unresolved cause is a follow-up, not a
blank to fill with a guess.

## Resolution

What was done, and **the proof it worked** — paste or name the output:

- `sudo vallum doctor --config /etc/vallum/vallum0.toml` — PASS
- `vallum status --config …` — verdict `up` (or `blocked`, if containment was
  the resolution)
- `vallum show` — fresh handshake on the affected peers
- the gate's verdict, if the fix touched anything the gate asserts
  (`scripts/verify.sh`, or the two-host stamp for a release)
- restored state verified per [../backup.md](../backup.md) — row counts and
  `PRAGMA user_version`, never "the desk started"

## Follow-ups

Each becomes a GitHub issue (`docs/agents/issue-tracker.md`) with a triage
label (`docs/agents/triage-labels.md`). Link the issue here; an unlinked
follow-up is a forgotten one.

- [ ] #… — what, and why it would have caught or prevented this
- [ ] #… — monitoring gap this incident exposed (a detector that stayed
      green, a silence nobody noticed)

## Postmortem

SEV1: required within a week — link it here. SEV2/SEV3: this file is the
postmortem; write the root cause and follow-ups well enough that it can stand
alone.

- Postmortem: `link or "this file"`
