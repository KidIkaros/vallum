# Monitoring a Vallum deployment

`vallum metrics` is a one-shot text exporter: it renders the daemon's counters
in Prometheus format and exits. Nothing collects them, and until this directory
existed nothing on the reference deployment did — the store was running with
**zero series in it**, and thirteen alert rules sat in a package nobody had
loaded. That is worse than no monitoring, because a running store with nothing
feeding it looks like monitoring.

This is the wiring. It is deliberately three files and no framework: an operator
copies what they need and nothing is a product dependency.

```
vallum metrics ──┐
                 ├─▶ vallum-metrics.timer   /run/vallum/metrics.prom
                 │        └─▶ vallum-telemetry.timer ──push──▶ VictoriaMetrics
scripts/verify-scheduled.sh ──▶ verify.prom ──push──▶ VictoriaMetrics
                                                              │
blackbox_exporter ──scrape──▶ VictoriaMetrics ◀── vmalert ────┘
                                    │                 │
                                    └──▶ Grafana      └──▶ vallum-alert-journal ──▶ journald
```

| File | Role |
|---|---|
| `vmalert.service` | evaluates `packaging/vallum-alerts.yml` against the store |
| `vallum-alert-journal` + units | turns firing alerts into journal lines, once each |
| `blackbox.yml` + `blackbox.service` | ICMP, DNS, desk-TLS and desk-`/healthz` probes |
| `scrape.yml` | what the store scrapes (blackbox); everything else is pushed |
| `vallum-verify-scheduled.{service,timer}` | nightly two-host gate, recorded |
| `grafana/` | datasource + dashboard as files, so a rebuild is a copy |

## Why push, not scrape

`vallum metrics` is a command, not an endpoint. Exposing it would mean a new
listener on every host that runs a tunnel, which is a worse trade than a 15 s
timer that writes a textfile and a `curl` that posts it. The store stays on
loopback; the push rides the same trust path the operator already uses.

## The three layers, and what each one catches

1. **The daemon's own counters** — handshakes, delivery ratio, fragment drops,
   the client verdict. Catches the tunnel failing.
2. **The gate's result** — `vallum_verify_passed`, `vallum_verify_assertions`,
   `vallum_verify_last_success_timestamp_seconds`. Catches the *proof* failing,
   or quietly stopping, or asserting less than it used to.
3. **Outside-in probes** — `probe_success`, `probe_ssl_earliest_cert_expiry`.
   Catches the path, the resolver and the certificate, none of which the daemon
   can see — plus the desk's own `/healthz`, which answers `503` when the
   account database or the daemon behind it is unusable.

A failing probe with `vallum_up 1` is the interesting case: the process is
healthy and something in front of it is not.

## What is deliberately absent

- **Alertmanager.** One operator, one host. `-notifier.blackhole` plus a journal
  bridge does the routing, and adding a second daemon to notify the same person
  is a config file that can only break. Add `-notifier.url` on the day there is
  somewhere else to send them.
- **A UDP probe of the tunnel port.** Blackbox has no UDP prober, and a TCP
  connect to a UDP port can only ever fail — the trap recorded in
  `docs/alpha-readiness-2026-11-12.md`. The two-host gate measures that path
  instead.
- **An off-host prober.** Every probe here runs *on* the server, so ICMP to its
  own public address proves the interface and the local firewall accept, not the
  internet path. A real outside-in check needs a prober somewhere else; the
  nightly gate is the closest thing this deployment has.

## Install

```sh
sudo install -m0755 vmalert-prod /usr/local/bin/           # from the VictoriaMetrics release
sudo install -m0755 blackbox_exporter /usr/local/bin/      # from the Prometheus release
sudo install -m0644 blackbox.yml scrape.yml /etc/vallum/
sudo install -m0644 vmalert.service blackbox.service \\
    vallum-alert-journal.service vallum-alert-journal.timer /etc/systemd/system/
sudo install -m0755 vallum-alert-journal /usr/local/lib/vallum/
sudo install -m0644 ../telemetry/vallum-telemetry-push.sh /usr/local/bin/
sudo useradd --system --no-create-home --shell /usr/sbin/nologin vmalert
sudo useradd --system --no-create-home --shell /usr/sbin/nologin blackbox

# VictoriaMetrics needs the scrape config
sudo systemctl edit victoria-metrics   # add: -promscrape.config=/etc/vallum/scrape.yml

sudo systemctl daemon-reload
sudo systemctl enable --now vallum-metrics.timer vallum-telemetry.timer \\
    vmalert blackbox vallum-alert-journal.timer
```

Grafana: copy `grafana/datasource.yml` and `grafana/dashboards.yml` into
`/etc/grafana/provisioning/{datasources,dashboards}/`, the dashboard JSON into
`/etc/vallum/grafana-dashboards/`, and restart. It binds `127.0.0.1:3000` — reach
it over an SSH tunnel, not by opening the port.

## The gate's exit codes, and why there are three

`verify-remote.sh` and `verify-scheduled.sh` distinguish a product failure from a
harness failure, because they are unrelated and one of them must never page as
the other:

| Exit | Meaning | Alert |
|---|---|---|
| 0 | every assertion passed | — |
| 1 | an assertion failed — **Vallum** failed a claim | `VallumTwoHostGateFailing` (critical) |
| 2 | the harness could not run — SSH, host down, moved checkout | `VallumTwoHostGateHarnessError` (warning) |
| 3 | the gate passed but asserted less than last week | `VallumTwoHostGateWeakening` |

A harness error is recorded as `vallum_verify_outcome{kind="harness_error"} 1`
and its `assertions` is **0**, not the previous run's count — the verdict file
survives between runs, and reading it undated was how an unreachable host once
reported 42 assertions it never made.

## Check it is actually working

A green unit is not evidence. These four commands are:

```sh
curl -s 'http://127.0.0.1:8428/api/v1/query?query=vallum_up'        # a series, value 1
curl -s http://127.0.0.1:8880/api/v1/rules | jq '.data.groups | length'   # 2 groups
curl -s http://127.0.0.1:8880/api/v1/alerts | jq '.data.alerts | length'  # 0 when healthy
sudo journalctl -u vallum-alert-journal -n 5                          # silent when healthy
```

If `vallum_up` returns an empty result, the pipeline is broken no matter what
`systemctl is-active` says. That is the exact state this deployment was in for
three days.
