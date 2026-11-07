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

## Alert rules

`packaging/vallum-alerts.yml` ships starting-point rules in two groups. The
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
