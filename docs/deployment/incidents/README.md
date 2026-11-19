# Incident log

One file per incident. This directory is the deployment's memory: what broke,
what it cost, what fixed it, and what the monitoring missed. The runbook that
drives it is [../incident-response.md](../incident-response.md).

## Rules

- **Copy [TEMPLATE.md](TEMPLATE.md)** to `YYYY-MM-DD-short-slug.md` — the date
  the incident opened (UTC), a slug a stranger can read (`tunnel-down`,
  `pusher-silent`, `cert-renewal`). The filename is the incident's id.
- **One file per incident.** Two alerts from one cause are one incident with
  two detectors in the timeline; one alert recurring after a "fix" is a new
  incident that links the old one.
- **Never delete, never rewrite.** Corrections are appended with a timestamp.
  A log that can be tidied is a log that can hide the 30-hour failure.
- **False alarms get a file too.** A detector that cries wolf is a finding
  about the detector; log it, tune the rule, link the change.
- **Write the timeline as it happens**, in UTC. Fill the summary last.
- Open a file for every page, including the ones resolved in two minutes —
  the two-minute ones are how you learn which alerts are noise.

## What belongs in the file

The template asks for it all; the load-bearing fields are the detector (which
alert or probe — "operator noticed" is a monitoring gap, record it as one),
the impact in peers and accounts, and the resolution **with proof** (command
output, not "it looks fine"). Follow-ups become GitHub issues with triage
labels and are linked back here.

## Related

- [../incident-response.md](../incident-response.md) — severity ladder,
  pager verification, escalation, the silent-monitoring case
- [../monitoring.md](../monitoring.md) — what each alert means
- [../troubleshooting.md](../troubleshooting.md) — diagnosis
- [../compromise.md](../compromise.md) — when the keys stop being trusted
- [../backup.md](../backup.md) — restore, and proving a restore
