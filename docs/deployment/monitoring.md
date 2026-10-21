# Monitoring Vallum

Vallum deliberately has no metrics listener: `vallum metrics` prints a
Prometheus text exposition and exits. Two supported ways to get it into a
scraper — the shipped systemd timer for `node_exporter`, or run the command
from whatever collector you already have.

## What you can see

Every scrape carries `vallum_up` (did the control socket answer) and
`vallum_interface_info{interface,suite,version}` — the build version rides in
the labels so a fleet dashboard can show which hosts run which release.

Interface counters (absent on daemons older than the telemetry work — absent
means unknown, never a false zero):

| Metric | Meaning |
|---|---|
| `vallum_loop_datagrams_sent_total` / `_failed_total` | datagrams handed to / refused by the socket |
| `vallum_loop_packets_delivered_total` / `_failed_total` | packets written to / failed on the TUN |
| `vallum_loop_handshakes_established_total` / `_refused_total` | completed handshakes vs policy refusals (expired identity, pinned endpoint) |
| `vallum_loop_reassembled_total` / `vallum_loop_fragments_dropped_total` | segmentation-layer successes vs refused/abandoned fragments |
| `vallum_peers_total`, `vallum_peer_handshaked`, `vallum_peer_handshake_age_seconds`, `vallum_peer_epoch` | configured peers and per-peer liveness |

## node_exporter textfile (shipped)

`install.sh` drops `vallum-metrics.service` + `vallum-metrics.timer` into
`/etc/systemd/system`. The timer is enabled automatically **only** when
`/var/lib/node_exporter/textfile_collector` exists — otherwise the units sit
installed but inert, and you enable them yourself:

```sh
sudo systemctl enable --now vallum-metrics.timer
```

The service runs `vallum metrics --config /etc/vallum/vallum0.toml --output
/var/lib/node_exporter/textfile_collector/vallum.prom`, writing atomically
(temp file + rename) so the collector never reads a torn file. When the
daemon is down the service still writes `vallum_up 0` and exits nonzero —
staleness should mean "down", never "quietly old data". For a different
interface name, override `ExecStart` with a drop-in.

## Direct scrape

Any collector that can exec a command can scrape directly — the command is
idempotent and read-only:

```sh
vallum metrics --config /etc/vallum/vallum0.toml        # full exposition
vallum metrics --control /run/vallum/vallum0.sock       # socket directly
vallum metrics --prefix site_a                         # rename every family
```

## Alert rules

`packaging/vallum-alerts.yml` ships starting-point rules: `VallumDown`
(`vallum_up == 0`), `VallumPeerHandshakeStale` (peer past two rekey
intervals), `VallumHandshakesRefused`, `VallumFragmentsDropped`, and
`VallumSendFailures`. Load it via `rule_files` and tune `for:` before paging.

## Operational tooling

- `vallum doctor --config …` — host-level health (forwarding, firewall,
  service state, config mode, path MTU with `--probe-mtu`, clock sync).
- `vallum show --control …` / `vallum tui` — live peer state, traffic, loop
  counters, invite/rotation actions.
- The units are `Type=notify` with `WatchdogSec=30s`: a wedged run loop is
  restarted by systemd rather than hanging silently.
