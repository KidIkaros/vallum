# Live traffic audit — 2026-11-09

A real deployment, exercised: client unit on `SkyGyard` (this machine), server
unit on `wingman-vps`, browser traffic through Camoufox, a sampler reading the
control socket every 2 s, and bulk transfers through the tunnel.

Everything below is measured. Where a claim is a hypothesis it says so.

## What works

| Property | Measurement |
|---|---|
| Bulk throughput | 20 MB in 1.38 s — **14.5 MB/s** (~116 Mbit/s) through the tunnel |
| Integrity | md5 of the transfer equals the source, byte for byte |
| Loss under burst | 200 packets at 5 ms intervals: **0 % loss**, RTT 62–68 ms |
| MTU | 1380, exact: DF payload 1352 passes, 1372 fails (1380 − 28) |
| Rekeying | epochs 0→5 over five minutes of traffic, **0 refusals**, 0 fragment drops |
| Counters | control-plane counters match the bytes actually moved (15 033 packets in a 2 s sample during the burst) |
| Recovery | after a kill, systemd restarts and the peer re-establishes in ~2 s |
| Lifecycle | START/STOP from the console with no password (narrow sudoers rule) |

## Anomalies

### 1. The daemon is killed by its own syscall filter under sustained load

Twice in ten minutes, during transfers:

```
kernel: audit: type=1326 ... comm="vallum" sig=31 syscall=257 ...
systemd: vallum@vallum0.service: Main process exited, code=killed, status=31/SYS
```

Syscall 257 is `openat`. The filter's default action was `KillProcess`, so the
first file the daemon opened at runtime ended the tunnel. systemd restarted it
automatically, so the console showed `UP` again within seconds — the outage is
invisible unless the journal is read.

Not reproducible in a privileged container with the same binary and config,
which is itself a finding: the trigger is environmental (systemd's unit context
and/or the post-drop user), not the data path.

**Fix applied:** `Mode::Enforce` now returns `EPERM` instead of killing, so a
missing entry costs the operation, not the tunnel — the same choice MOOR makes
(`src/sandbox.c`, Tor-aligned but `EPERM` for everything off the list). The
caller's error now names the file, which is how the missing entry gets found.

**After the fix**, three consecutive 20 MB transfers and a five-transfer burst
(100 MB): **0 SIGSYS kills**, unit `active` throughout, 7.1–13.9 MB/s. The
openat no longer recurs in the journal, so the failing call is still unnamed —
the filter no longer turns it into an outage, but the missing entry is still
missing and belongs on the list.

### 2. Web traffic does not traverse the tunnel

```
$ ip route get 1.1.1.1
1.1.1.1 via 192.168.1.1 dev wlp0s20f3        ← the Wi-Fi, not vallum0
```

Browsing through Camoufox during the test:

| Check | Result |
|---|---|
| `ipinfo.io` | `198.51.100.7` — Verizon FiOS, New York (the home ISP) |
| `cloudflare.com/cdn-cgi/trace` | `ip=2600:4041:542b:7800:…` — native IPv6 |
| `dnsleaktest.com` | `Hello 198.51.100.7 from Brooklyn` — ISP resolver |

The peer's `allowed_ips` is `10.7.0.1/32`: the tunnel is a point-to-point link
and nothing else. The console's `UP` is true — the link is up — but this config
is not a VPN for browsing, and the interface says nothing about that.

### 3. IPv6 leaks

`ifconfig.me` and the Cloudflare trace both returned the host's native IPv6
address while the tunnel was up. `vallum0` carries a link-local v6 address
only, so v6 cannot be tunnelled in this deployment. ADR-0018 documents exactly
this: claiming `::/0` does not create a v6 route, and the packet half of the
fix is not implemented.

### 4. No kill switch is installed

`vallum policy` exists in the binary; no `vallum-guard@` unit is installed and
no `inet vallum_policy` table is active. ADR-0018's rule — *a packet leaves only
through the tunnel, or to the endpoint* — is unimplemented on this host, so a
dead tunnel is a silent revert to the physical interface. Combined with
anomaly 1, that is the worst pair in this report: the daemon dies, and the
traffic keeps flowing outside the tunnel.

### 5. Throughput fell apart after a kill

First transfer after a clean start: 14.5 MB/s. A later 20 MB transfer with no
console attached: 505 KB/s, 39.6 s — while a privileged container on the same
host, same binary, same tunnel and same `--limit-rate 1M` cap achieved
1.0 MB/s. **Explained by anomaly 1**: the daemon was being killed mid-transfer
and restarted. After the EPERM fix the host sustains 7.1–13.9 MB/s with no
deaths.

### 6. START could not clear a tripped start limit

After three quick failures systemd refuses to start the unit until
`reset-failed`. The console's START did not do that and reported a failure it
had caused. Fixed: `service_action` now clears the counter before `start`, and
the sudoers rule allows `reset-failed`.

## Minor

- Seven `dropping outbound packet from ::` warnings in 40 minutes. Cosmetic, but
  it means the daemon is seeing packets from the IPv6 unspecified address.
- The console's `control Ns` reads `0s` in every snapshot; the age is not
  advancing as it should.

## What MOOR contributes

- **`EPERM`, not `SIGSYS`** (`src/sandbox.c`): the difference between a failed
  operation and a dead tunnel. Adopted.
- **`PR_SET_DUMPABLE(0)` and an `RLIMIT_FSIZE`**: hardening Vallum's sandbox
  does not yet do — a core dump of the daemon is a core dump of the keys.
- **Operator visibility** (their "Relay verification + log clarity" commit):
  always-print status banners and a `--check-relay` reachability test. The
  equivalent here is a restart counter and last death reason in the console,
  because right now a SIGSYS kill and a healthy tunnel look identical.
