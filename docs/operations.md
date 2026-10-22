# Operations

How to install, upgrade, roll back, and — the case that matters — what to do
when `vallum status` says `LEAKING`.

---

## The one command to know

```sh
vallum status --config /etc/vallum/vallum0.toml
```

It answers the question no other command answers: **is traffic in the tunnel,
blocked, or leaving in the clear?** It works when the daemon is dead, which is
exactly when you need it.

| Verdict | Meaning | Exit |
|---|---|---|
| `up` | tunnel carrying traffic | 0 |
| `starting` | daemon running, no handshake yet | 0 |
| `blocked` | **daemon dead, guard holds — nothing leaks** | 0 |
| `down` | daemon dead, split tunnel, nothing to block | 0 |
| `LEAKING` | **daemon dead and nothing blocks** | **1** |
| `unknown` | cannot read the guard (not root) | 0 |

`blocked` and `leaking` both mean the tunnel is down. Only one of them is safe.
The distinction is the reason this command exists, and `unknown` is deliberately
not `LEAKING` — not being able to look is not evidence that nothing is there.

---

## Ordering rule

**Remove the block before removing the daemon.**

The guard is deliberately not `PartOf=` the tunnel, so stopping or removing
`vallum@` leaves the block standing. That is correct during a failure and
inconvenient during a rollback: remove the daemon first and the host is blocked
with no tunnel to carry anything.

```sh
# right
sudo vallum policy off --config /etc/vallum/vallum0.toml
sudo systemctl disable --now vallum@vallum0 vallum-guard@vallum0

# wrong — leaves the host blocked
sudo systemctl disable --now vallum@vallum0
```

---

## Install

```sh
sudo apt install ./vallum_<version>_amd64.deb
sudo vallum server init --config /etc/vallum/vallum0.toml
sudo systemctl enable --now vallum@vallum0 vallum-guard@vallum0
```

`server init` provisions both address families by default:
`10.7.0.1/24` and `fd00:7::1/64`.

**Platform floor: glibc 2.39** — Ubuntu 24.04 or newer. Not Debian 12, not
Ubuntu 22.04. This is a `cargo-deb` artifact of the build host, not a choice.

## Upgrade

```sh
sudo vallum policy off --config /etc/vallum/vallum0.toml   # only if the guard is on
sudo apt install ./vallum_<new>_amd64.deb
sudo systemctl restart vallum@vallum0 vallum-guard@vallum0
vallum status --config /etc/vallum/vallum0.toml
```

Every config write leaves a `.bak` beside the file. `peer add`, `setconf` and
the TUI all write one, so the previous state is always recoverable by hand.

## Roll back

```sh
sudo vallum policy off --config /etc/vallum/vallum0.toml
sudo systemctl disable --now vallum@vallum0 vallum-guard@vallum0
sudo dpkg -i vallum_<previous>_amd64.deb
sudo systemctl enable --now vallum@vallum0
```

There is no repository yet, so a rollback means keeping the previous `.deb`.
Keep it.

---

## Alert thresholds

`docs/operations/vallum-alerts.yml` carries one threshold per alert, each
derived from a daemon timer rather than chosen for looking round:

| Alert | Threshold | Basis |
|---|---|---|
| `VallumTunnelDown` | `vallum_up == 0` for 3m | 180 s reject window |
| `VallumHandshakeStale` | handshake age > 180 s for 1m | 120 s rekey, one missed rekey |
| `VallumHandshakeRefused` | rate > 0.1/s for 5m | well above retry noise |
| `VallumFragmentsDropped` | rate > 1/s for 5m | past what reassembly absorbs |
| `VallumAtCapacity` | `vallum_peers_total > 2000` | stated target, ceiling 2,211 |

**Not covered by metrics: whether a client is leaking.** Guard state is a
property of the client host, not of the daemon, so poll it:

```sh
vallum status --config <path> --json   # exits 1 when verdict is LEAKING
```

That gap is worth naming: the server can tell you its own health and cannot tell
you a client's safety. A future exporter on the client side would close it.

---

## When `vallum status` says `LEAKING`

Traffic is leaving outside the tunnel right now.

```sh
sudo vallum policy on --config /etc/vallum/vallum0.toml   # block first
sudo systemctl start vallum-guard@vallum0                 # then make it stick
sudo systemctl start vallum@vallum0                       # then the tunnel
```

If `policy on` refuses because the endpoint does not resolve, that is the guard
protecting you from a worse outcome: a block with no permitted destination
blocks the handshake too. Fix DNS or the endpoint first.

To take the machine off the network entirely instead:

```sh
sudo ip link set <uplink> down
```

---

## Restart behaviour

## Restarting a server disconnects every client

A client only re-establishes when its own rekey timer expires, because the server
never initiates a handshake — it is always the responder (ADR-0019). Measured on
a live deployment: a client whose server restarted recovered only at its next
rekey, **120 s later**, and a 45 s observation window after the restart saw no
successful traffic at all.

So a server restart is a 120-second outage for every attached client, and a
full-tunnel client is blackholed for all of it. Plan it: detach clients first, or
restart during a window and tell people. `persistent_keepalive = 25` does not
help — a keepalive is a data packet on an existing session, not a probe that can
discover the session is gone.

`vallum@` carries `StartLimitBurst=3` in `StartLimitIntervalSec=60`, so a config
that cannot start fails after three attempts instead of the 259 restarts a
missing `/run/vallum` used to produce. If a unit is in `failed`:

```sh
systemctl status vallum@vallum0
sudo systemctl reset-failed vallum@vallum0
```

`reset-failed` is required before `start` will try again — the limit counts
across restarts by design.

---

## What is not built

Stated here so it is not discovered during an incident:

- **No client-side exporter.** A client's guard state is only visible by running
  `vallum status` on it.
- **No package repository.** Upgrades and rollbacks are manual `.deb` handling.
- **No independent crypto audit.** Recorded in the README.
- **No HA.** One daemon owns one interface. There is no failover, and two
  daemons on one host would fight for the same TUN.
