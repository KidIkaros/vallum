# Traffic telemetry

Persist what `vallum metrics` reports, so per-peer traffic survives a daemon
restart and can be queried over time.

Not shipped in the package: this is an operator choice, not a product
dependency. Copy the files where you want them.

## What it does

`vallum metrics` is a one-shot text exporter — it renders the daemon's counters
in Prometheus format and exits. Nothing collects them, and the counters are
cumulative since the daemon started, so a restart resets every byte count to
zero.

The pipeline is three pieces:

| File | Role |
|---|---|
| `vallum-telemetry-push.sh` | one scrape → `POST /api/v1/import/prometheus` |
| `vallum-telemetry.service` | runs the push once (oneshot) |
| `vallum-telemetry.timer` | every 15 s |

It pushes rather than exposes, so there is no exporter to run and nothing new
listening on a port.

## Install

```sh
# a store; single binary, ~100 MB resident
curl -sSL -o /tmp/vm.tar.gz \
  https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/v1.154.1/victoria-metrics-linux-amd64-v1.154.1.tar.gz
tar xzf /tmp/vm.tar.gz -C /tmp
sudo install -m0755 /tmp/victoria-metrics-prod /usr/local/bin/
sudo useradd --system --no-create-home --shell /usr/sbin/nologin victoriametrics
sudo mkdir -p /var/lib/victoria-metrics
sudo chown -R victoriametrics:victoriametrics /var/lib/victoria-metrics

# ... its unit: see the deployment notes below, or run it by hand first

sudo install -m0755 vallum-telemetry-push.sh /usr/local/bin/
sudo install -m0644 vallum-telemetry.service vallum-telemetry.timer /etc/systemd/system/
sudo install -m0755 vallum-usage /usr/local/bin/
sudo systemctl daemon-reload
sudo systemctl enable --now vallum-telemetry.timer
```

## Use

```sh
$ vallum-usage
Vallum traffic through this server
  down    32.1 MiB
  up      12.6 MiB
  total   44.7 MiB
  now     down 64.6 KiB/s, up 10.3 KiB/s

  peer                       down         up  last handshake
  laptop                  32.1 MiB   12.6 MiB  88s ago
```

Raw PromQL against the store on `127.0.0.1:8428`:

```promql
sum(vallum_peer_rx_bytes_total)                          # since daemon start
sum(increase(vallum_peer_rx_bytes_total[1h]))            # across restarts
sum by (peer) (rate(vallum_peer_tx_bytes_total[5m]))     # per-peer live rate
```

`increase()` over a window is the one to use for a real total: it handles the
counter reset a daemon restart causes, which a raw counter cannot.

## Notes

- The store listens on `127.0.0.1` only. Expose it deliberately or not at all.
- `-retentionPeriod=90d` in the unit; 15 s scrapes of ~18 series is a few MB a
  month, so retention is not the constraint.
- Per-peer labels carry the peer's config `name`, which the daemon only knows
  because `peer_lines` sends `vallum_name` in the `set=1` body. Without that the
  label is `peer-<key prefix>` and cannot be mapped to a device.
