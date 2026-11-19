# Monitoring Vallum

Vallum deliberately has no metrics listener: `vallum metrics` prints a
Prometheus text exposition and exits. Two supported ways to get it into a
scraper — the shipped systemd timer for `node_exporter`, or run the command
from whatever collector you already have.

## What you can see

Every scrape carries `vallum_up` (did the control socket answer) and
`vallum_interface_info{interface,suite,version}` — the build version rides in
the labels so a fleet dashboard can show which hosts run which release.

A scrape started with `--config` also carries `vallum_client_verdict` — the
verdict `vallum status` reports for that host (`up`, `degraded`, `stale`,
`starting`, `blocked`, `LEAKING`, `down`), computed by the same code path, every
scrape:

| Metric | Meaning |
|---|---|
| `vallum_client_verdict{interface,verdict}` | one series naming the host's current state |

This is the client-side signal: a client whose tunnel is dead but whose guard
holds is invisible on the server's counters, and only this metric — or an
operator running `vallum status` by hand — distinguishes carrying, blocked and
leaking. The shipped timer (below) runs with `--config`, so scrapes on both
servers and clients carry it; a `--control`-only scrape deliberately omits it,
because guard state and policy mode are properties of the host + config, not of
a bare socket.

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

## Watching the gate, and watching from outside

Two things the daemon's counters cannot see, both wired on the reference
deployment and both reproducible from `contrib/monitoring/`:

- **Whether the proof still passes.** `scripts/verify-scheduled.sh` runs the
  two-host gate nightly and publishes `vallum_verify_passed`,
  `vallum_verify_assertions` and `vallum_verify_last_success_timestamp_seconds`.
  Three alerts read them: the gate failing, the gate going stale for 48 h, and
  the gate asserting less than it did a week ago — a gate that stops checking
  something still reports PASS, which is why the count is tracked.
- **Whether the deployment is reachable from outside the process.**
  `blackbox_exporter` probes ICMP, the resolver and the desk's TLS certificate
  (`probe_success`, `probe_ssl_earliest_cert_expiry`). A failing probe with
  `vallum_up 1` means the daemon is healthy and something in front of it is not.

`contrib/monitoring/README.md` has the wiring, and the four commands that prove
it is actually collecting rather than merely running — the state a store with no
series in it convincingly imitates.

## Alert rules

`packaging/vallum-alerts.yml` ships starting-point rules in three groups. The
`vallum` group is server-side: `VallumDown` (`vallum_up == 0`),
`VallumPeerHandshakeStale` (peer past two rekey intervals),
`VallumHandshakesRefused`, `VallumFragmentsDropped`, `VallumPeerDeliveryLow`,
`VallumPeerAllowedIpsRejected`, `VallumLoopDroppedUnknownIndex`. The
`vallum-client` group is where a *client* failure is seen — from its own
scrape, since a fail-closed client whose tunnel is dead reports a perfectly
healthy peer on the server:

- `VallumClientLeaking` (`verdict="LEAKING"`, no grace) — traffic is leaving
  the host in the clear.
- `VallumClientBlocked` (`verdict="blocked"`, 15 min) — the guard holds, DNS
  included, and it has outlasted any self-recovery window.
- `VallumClientDegraded` (`verdict="degraded"`, 10 min) — attached, handshaked,
  carrying nothing: the browser-dead state that a fresh handshake does not show.
- `VallumClientStale` (`verdict="stale"`, 150 s) — the daemon answers and the
  session is dead: no handshake inside the 180 s reject window. An idle host has
  no delivery sample for `VallumClientDegraded` to fire on, which is why this
  state needed its own verdict rather than being reported as `up`. The grace is
  the recovery budget the real-link gate allows (`scripts/verify-remote.sh`,
  `RECOVERY_BUDGET`) — the same number in both files, so the pager never fires
  on a recovery the suite still considers on time. With the reject window in
  front of it, it pages about 5.5 minutes after the last handshake.
- `VallumClientReconnectLoop` (handshake rate > 0.1/s for 10 min) — recovery
  is looping rather than converging; steady state rekey is ~0.008/s per peer.

Load it via `rule_files` and tune `for:` before paging. DNS failing is not a
separate alert on purpose: the policy drops `:53` egress outside the tunnel and
the resolver install is fail-closed, so "DNS broke" manifests as one of the
four verdict states above — the same states the browsing suite asserts.

## Operational tooling

- `vallum doctor --config …` — host-level health (carrier, forwarding,
  firewall, service state, config mode, path MTU with `--probe-mtu`, clock
  sync). `--probe-path` adds the one check that dials: it opens a TCP connection
  to each peer's endpoint, which is how a closed or filtered port is told apart
  from a wrong key.
- `vallum show --control …` / `vallum tui` — live peer state, traffic, loop
  counters, invite/rotation actions.
- The units are `Type=notify` with `WatchdogSec=30s`: a wedged run loop is
  restarted by systemd rather than hanging silently.

## The monitoring watches itself

Every rule above depends on two things staying alive: the telemetry pusher
(`vallum-telemetry.timer`, ~15 s) that moves metrics into VictoriaMetrics, and
Alertmanager, which routes firing alerts to the ntfy pager. If either dies, the
rules go silent — and silence reads as green. That is the same absence that let
three failed units hide for thirty hours with every rule green, one layer up.
Three guards close it (the `vallum-monitoring` rule group):

- **Heartbeat.** Each push emits `vallum_monitoring_heartbeat_seconds` (unix
  time). `VallumMonitoringSilent` fires when `time() - heartbeat > 180` for a
  minute: the pusher stopped, or the store stopped accepting pushes. Treat every
  other alert's silence as *unknown*, not green, while this fires.
- **Pager-path self-check.** Each push also probes Alertmanager
  (`/api/v2/status`) and emits `vallum_pager_path_ok`. When Alertmanager is
  unreachable the pusher pages ntfy **directly**, bypassing the broken router —
  the pusher is a separate timer, so it survives Alertmanager's death.
  `VallumPagerPathBroken` records the state for the dashboard; the direct page is
  the live notice (that alert cannot route through the very router that is down).
  The direct page needs the topic URL in `/etc/vallum/pager-url` (0600, the same
  unguessable topic Alertmanager uses, never committed); a five-minute cooldown
  stops a sustained outage from flooding the topic.
- **Independent watchdog.** `contrib/ops/vallum-watchdog.sh` runs on a *second*
  always-on host, not the one it watches. Over ssh it checks the watched host's
  heartbeat freshness and Alertmanager health, and pages ntfy directly if either
  is bad — or if the host does not answer at all. A dead-man's switch that shares
  the failure it watches is not one; this is the layer that survives the watched
  host dying completely. Install `vallum-watchdog.{service,timer}` there with
  `VALLUM_WATCH_HOST` and `VALLUM_PAGER_URL` in `/etc/default/vallum-watchdog`.

**No second VPS? Two ways to get independence anyway.** The watchdog only needs a
second *vantage point*, not a second server:

- **The operator's own desktop.** Install the watchdog as a *user* systemd timer
  (`~/.config/systemd/user/vallum-watchdog.{service,timer}`, `EnvironmentFile`
  pointing at a 0600 `~/.config/vallum-watchdog.env`), then
  `systemctl --user enable --now vallum-watchdog.timer` and `loginctl enable-linger`
  so it runs while logged out. It is a separate host on a separate network; the
  only limit is the desktop must be powered on.
- **An external dead-man's switch (always-on, recommended).** The pusher pings a
  healthchecks.io-style check each cycle; if the host or pusher dies the pings stop
  and the service alerts independently of everything on the host. Create a free
  check, then `sudo sh -c 'umask 077; echo https://hc-ping.com/<uuid> >
  /etc/vallum/healthchecks-url'`. Absent that file the ping is a no-op, so the
  wiring ships before the check exists.

**A second alert channel.** A single ntfy topic is one delivery path; an ntfy.sh
outage or a silenced phone blinds it. Uncomment the `email_configs` block in
`contrib/monitoring/alertmanager.yml.example` (fill the SMTP placeholders, keep the
file 0600) so the same alerts reach email too. The *secondary responder* is a
person, not a host — a trusted contact with the ntfy topic, an SSH key and this
runbook; with none, the bus factor is honestly 1, mitigated by off-host backups,
this runbook, and the independent watchdog above.

**Prove the pager fires.** A pager path that has never delivered a page is a
guess. After installing or changing it, send a test alert through the whole
chain and confirm it lands on the phone:

```sh
curl -sS -X POST http://127.0.0.1:9093/api/v2/alerts \
  -H 'Content-Type: application/json' -d '[{
    "labels": {"alertname":"VallumPagerTest","severity":"warning","instance":"manual-test"},
    "annotations": {"summary":"Vallum pager test — confirm you received this"},
    "startsAt":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"
  }]'
```

If it does not arrive, walk the chain backwards: ntfy topic reachable?
Alertmanager routing (`/api/v2/status`)? vmalert notifying (`-notifier.url`)?
The pusher pushing (`journalctl -u vallum-telemetry -n 50`)?
