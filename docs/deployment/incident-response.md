# Incident response and escalation

The alpha runs on one operator and one host. The pager reaches one person, and
for 30 hours three failed units sat under 19 green alert rules because every
rule read Vallum's own metrics — a unit that is not running emits none. This
runbook exists for both failures: the tunnel breaking, and the watching
breaking. It is written to be executable by someone who did not build the
system.

Companions: [monitoring.md](monitoring.md) (what is watched),
[troubleshooting.md](troubleshooting.md) (how to diagnose),
[compromise.md](compromise.md) (when to stop trusting the keys),
[backup.md](backup.md) (how to restore).

## Severity ladder

Severity is about **safety first, carrying second**. A blocked client is an
outage; a leaking client is a breach. The alpha has no uptime SLA — the
requirement is failure behavior, not uptime (`docs/requirements.md`).

| Sev | Meaning | Examples | Respond |
|---|---|---|---|
| SEV1 | traffic in the clear, or the tunnel is down with guard state unknown | `LEAKING` verdict; `VallumTunnelDown`; `VallumUnitFailed` on a `vallum@`/`vallum-quick@` unit; suspected key compromise | now — contain first, diagnose second |
| SEV2 | degraded but safe: the guard holds, or one peer is sick while the rest carry | `blocked`, `stale`, `degraded` verdicts; a failing probe with `vallum_up 1`; the desk's `/healthz` answering 503; the gate failing | this waking day |
| SEV3 | cosmetic or task-shaped: nothing is leaking and nothing is down | certificate expiring in under 21 days; gate weakening; a failed unit that is not Vallum's | next working session |

The alert's `severity` label is the starting point, not the verdict:

| Alert | Label | Sev | First move |
|---|---|---|---|
| `VallumClientLeaking` | critical | SEV1 | block first — below |
| `VallumTunnelDown` | critical | SEV1 | the server cannot see a client's guard; treat as leaking until `vallum status` on the client says `blocked` |
| `VallumControlPlaneUnreachable` | critical | SEV1 | the tunnel may carry but nothing can administer it; fix `/run/vallum` group, restart the unit (the alert's annotation has the command) |
| `VallumUnitFailed` | critical | SEV1/SEV3 | `vallum_unit_failed{unit}` names the unit; a Vallum unit is SEV1, anything else is SEV3 |
| `VallumProbeFailing` | critical | SEV2 | run the probe by hand (the annotation has the `curl`); with `vallum_up 1` the fault is in front of the daemon |
| `VallumTwoHostGateFailing` | critical | SEV2 | the proof failed, not necessarily the tunnel; read `journalctl -u vallum-verify-scheduled` |
| `VallumClientBlocked` / `VallumClientStale` / `VallumClientDegraded` | warning | SEV2 | [troubleshooting.md](troubleshooting.md), in that order |
| `VallumHandshakeStale` / `Refused` / `FragmentsDropped` / `PeerDeliveryLow` / `PeerAllowedIpsRejected` / `LoopDroppedUnknownIndex` / `ClientReconnectLoop` | warning | SEV2 | one peer or one path; the rest carry |
| `VallumDeskCannotSeeDaemon` / `VallumNoDeviceEverConnected` | warning | SEV2 | the account layer's view is broken; the tunnel is a separate question |
| `VallumTwoHostGateHarnessError` / `Stale` / `Weakening` | warning | SEV2/SEV3 | the rig, not the product — never page it as a tunnel failure |
| `VallumDeskCertificateExpiring` / `VallumAtCapacity` | warning | SEV3 | a task with a deadline, not an incident |

### SEV1 containment

**A leaking client** — traffic is leaving in the clear right now:

```sh
sudo vallum policy on --config /etc/vallum/vallum0.toml   # block first
sudo systemctl start vallum-guard@vallum0                 # then make it stick
sudo systemctl start vallum@vallum0                       # then the tunnel
```

If `policy on` refuses because the endpoint does not resolve, fix DNS or the
endpoint first — a block with no permitted destination blocks the handshake
too ([ADR-0018](../adr/0018-fail-closed-egress.md)). To take the machine off
the network entirely instead: `sudo ip link set <uplink> down`.

**A down server** — `journalctl -u vallum@vallum0 -n 50` and
`sudo vallum doctor --config /etc/vallum/vallum0.toml` first
([troubleshooting.md](troubleshooting.md)). If the host itself is lost, restore
`/etc/vallum` per [backup.md](backup.md): the server identity is derived from
`server.key`, so clients do not re-enrol.

**Suspected compromise** — a key you cannot account for, an endpoint answering
in the server's place, a config changed by no one: stop troubleshooting and
follow [compromise.md](compromise.md). A restored key that must be treated as
compromised is not a restore; it is a re-enrolment of every client.

Two rules that hold under pressure:

- **Remove the block before removing the daemon** (`docs/operations.md`).
  Stopping `vallum@` leaves the guard standing — correct during a failure,
  a lockout during a rollback.
- A blocked client that needs its internet back has one command:
  `sudo vallum-panic` (`docs/if-it-breaks.md`). It is reversible; nothing
  Vallum installs is not.

## The pager path, and proving it fires

```
vallum metrics ─▶ vallum-telemetry.timer (~15 s) ─push─▶ VictoriaMetrics :8428
blackbox.service ─scrape─▶ VictoriaMetrics ◀─ vmalert :8880 ─┘
                               vmalert ─▶ Alertmanager 127.0.0.1:9093 ─▶ ntfy topic ─▶ phone
```

| Hop | Where | What breaks it |
|---|---|---|
| pusher | `/usr/local/bin/vallum-telemetry-push.sh`, `vallum-telemetry.timer` | a dead timer means no series — including the failed-units series |
| store | VictoriaMetrics, `127.0.0.1:8428` | running with zero series in it looks exactly like healthy |
| evaluator | vmalert, `127.0.0.1:8880`, rules `/etc/vallum/vallum-alerts.yml` | rules not loaded; `-notifier.blackhole` still in place |
| router | Alertmanager, `127.0.0.1:9093` | the notifier drop-in missing (`contrib/ops/vmalert-notifier.conf`) |
| delivery | `https://ntfy.sh/<topic>/alertmanager` | topic typo, phone unsubscribed, ntfy.sh unreachable |

**Passive checks** — the four commands in `contrib/monitoring/README.md` prove
the pipeline is collecting, not merely running:

```sh
curl -s 'http://127.0.0.1:8428/api/v1/query?query=vallum_up'        # a series, value 1
curl -s http://127.0.0.1:8880/api/v1/rules | jq '.data.groups | length'   # 3 groups
curl -s http://127.0.0.1:8880/api/v1/alerts | jq '.data.alerts | length'  # 0 when healthy
sudo journalctl -u vallum-alert-journal -n 5                          # silent when healthy
```

**End-to-end drill** — do this after any change to the chain, and monthly.
A green unit is not evidence; a notification on the phone is.

1. Append a drill rule to `/etc/vallum/vallum-alerts.yml`, inside the last
   group's `rules:` list, at the same indentation as the existing items:

   ```yaml
         - alert: VallumPagerDrill
           expr: vector(1)
           labels:
             severity: warning
           annotations:
             summary: "Pager drill — delete this rule"
   ```

2. `sudo systemctl restart vmalert` — the rule fires within one evaluation
   interval (30 s) plus `group_wait` (30 s).
3. Confirm the notification arrives on the phone's ntfy topic.
4. **Delete the drill rule and restart vmalert again.** A drill rule left in
   place is a permanent false page, and `repeat_interval: 3h` means it repeats.

The drill proves delivery, not subscription: a phone on silent, a dead battery
or an unsubscribed app receives nothing and the chain still looks green. Check
the last hop on its own too — `curl -d 'pager drill' https://ntfy.sh/<topic>`
must appear on the phone. The topic is unguessable and never committed
(`contrib/monitoring/alertmanager.yml.example`); anyone who knows it can read
or publish alerts.

## Who gets paged

**Primary: the owner** (Ikaaros) — the operator of record for the alpha host.
Every page lands on the primary's ntfy topic first.

**Secondary: `OPERATOR: set secondary ntfy topic / contact here`.**

That slot is deliberately empty, and the empty slot is the risk: one operator
means the pager, the host access and the knowledge all have the same bus
factor. Fill it before the alpha takes strangers, and fill it with a *separate*
ntfy topic — a shared topic is a shared pager, not a second person.

| Role | Contact | Ack window (SEV1) |
|---|---|---|
| Primary | the owner; ntfy topic in `/etc/prometheus/alertmanager.yml` | 15 min |
| Secondary | `OPERATOR: set secondary ntfy topic / contact here` | 30 min after escalation |

Ack means a reply on the ntfy thread **and** an incident file opened (below).
SEV2 acks within the waking day; SEV3 needs no ack, only a log entry.

### Escalation ladder

1. Page fires → primary. Primary acks within 15 min (SEV1) and opens the log.
2. No ack in 15 min → escalate to the secondary contact. Alertmanager repeats
   every 3 h (`repeat_interval`); the repeat is not an escalation — a human
   (or the drill-checked secondary subscription) must make the second contact
   happen. `OPERATOR: wire automatic escalation here if a second receiver is
   ever added; today it is manual.`
3. Secondary unreachable too → **containment-only fallback**: anyone with host
   access runs the SEV1 containment commands above. They are written to be
   safe without diagnosis — block first, restore from backup, never re-key
   silently. A blocked host is recoverable; a leaking one is already breached.
4. Containment done, diagnosis waits for whoever is reachable. Log everything;
   an unlogged containment is a mystery for the next operator.

For the secondary to be usable at all, three things must be pre-positioned —
they are the bus-factor mitigation, not optional extras:

- **Off-host backups** of `/etc/vallum` and the desk database
  ([backup.md](backup.md)); a copy on the same disk is not disaster recovery.
- **This runbook** plus [troubleshooting.md](troubleshooting.md) and
  [backup.md](backup.md), reachable without the primary (they are in the repo).
- **Host access** — an SSH key the secondary can use, and the ntfy topic above.

## When the monitoring itself is silent

The dead-man's-switch case. The pusher is the only thing that reports unit
health, so if the pusher dies, `VallumUnitFailed` — the rule that exists to
catch dead units — dies with it. Every rule reads series; **absence does not
fire `== 0` rules**. A store with stale data and a green rules page is the
exact state this deployment was in for three days before the wiring existed.

**Detect it by freshness, not by absence of alerts:**

```sh
# Age of the last push. The timer runs every ~15 s; over 120 s means the
# pipeline is silent, whatever the rules page says.
curl -s 'http://127.0.0.1:8428/api/v1/query?query=time()-timestamp(vallum_failed_units_total)'
curl -s 'http://127.0.0.1:8428/api/v1/query?query=time()-timestamp(vallum_up)'
```

Run both after any host reboot, any upgrade, and whenever a page *should* have
arrived and did not. An empty result is worse than a large number: the series
is gone entirely.

**When silent:**

1. Treat it as SEV2 and check the tunnel by hand — the monitoring's word is
   not available: `vallum status --config …` on the clients,
   `sudo vallum doctor --config /etc/vallum/vallum0.toml` on the server.
2. Walk the chain backwards: store (`systemctl status victoria-metrics`) →
   pusher (`systemctl status vallum-telemetry.timer`,
   `journalctl -u vallum-telemetry.service`) → vmalert → Alertmanager.
   `systemctl --failed` names the broken hop in one command.
3. Restart the failed hop, then re-run the freshness check until the age is
   under 15 s again. The pusher exits nonzero when a scrape produces nothing,
   so its own unit state says so — that is what `VallumUnitFailed` reads once
   the push is back.
4. Log it. Silent monitoring is an incident even when the tunnel was fine the
   whole time — the 30-hour failure was exactly this, with the tunnel down.

**Independent witnesses.** Three things do not depend on the pusher and have
their own staleness alerts: the nightly gate
(`VallumTwoHostGateStale`, 48 h), the desk backup timer
(`systemctl list-timers vallum-desk-backup.timer`), and the blackbox probes
(scraped, not pushed). All three quiet at once points at the store, not at
three coincidences.

**Now automated:** `VallumMonitoringSilent` fires when
`time() - vallum_monitoring_heartbeat_seconds > 180` — the pusher emits that
heartbeat every run, so its silence pages instead of reading as green.
`VallumPagerPathBroken` fires when Alertmanager is unreachable, and the pusher
pages ntfy **directly** in that case (it is a separate timer, so it survives the
router's death). For a witness independent of the watched host entirely,
`contrib/ops/vallum-watchdog.sh` runs on a second always-on host and pages over
ssh if the heartbeat is stale, Alertmanager is down, or the host is unreachable.
The manual freshness check above stays the post-reboot / post-upgrade habit; the
alerts are the backstop. See
[monitoring.md](monitoring.md#the-monitoring-watches-itself).

## Incident-log discipline

Every page gets a file. The log is the evidence that the watching worked —
and the only way the next operator (or the secondary) inherits what happened.

- One file per incident in [incidents/](incidents/README.md), copied from
  [incidents/TEMPLATE.md](incidents/TEMPLATE.md), named
  `YYYY-MM-DD-short-slug.md`.
- Write the timeline **as it happens**, in UTC. A timeline reconstructed from
  memory after resolution is a story, not a record.
- Record the detector (which alert or probe fired, or "operator noticed" —
  that answer is a finding about the monitoring), the impact in peers and
  accounts, the root cause, and the resolution **with the command output that
  proves it** (`doctor` PASS, a fresh handshake in `vallum show`, the gate's
  verdict).
- `sudo vallum support-bundle` collects the diagnostics in one redacted
  archive — attach it or name its path in the log. It carries no keys, tickets
  or account numbers (`docs/if-it-breaks.md`).
- Follow-ups become GitHub issues with the triage labels
  (`docs/agents/triage-labels.md`); link them from the log. A SEV1 gets a
  postmortem within a week, linked from the log.
- Never delete or rewrite an incident file. Corrections are appended, dated.
  False alarms get a file too — a detector that cries wolf is a SEV3 finding,
  not a non-event.
