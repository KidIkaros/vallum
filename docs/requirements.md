# Requirements

Functional requirements live in `docs/roadmap.md` as seven checkable
conditions. This page is the **non-functional** half, which did not exist until
now — the system-design audit scored it as the root cause of four other failures,
because a system that does not state what it guarantees cannot be verified
against anything.

Every number here is either measured (with the source) or explicitly marked
**unmeasured**. A target that has never been measured is a wish, and this page
exists to stop wishes being quoted as facts.

---

## Capacity

**Measured.** Handshake cost, `docs/proof/performance.md`:
tri-hybrid `0x0003` **54.27 ms**, fast profile `0x0002` **1.81 ms**.
Rekey interval 120 s, so steady-state handshake rate is `peers / 120`.

| Suite | Handshakes/s per core | Peers per core |
|---|---|---|
| `0x0003` tri-hybrid (default) | 18.4 | **2,211** |
| `0x0002` X25519+ML-KEM-768 | 552.5 | **66,298** |

**Stated target:** 2,000 peers per daemon on the default suite, 50,000 on
`0x0002`. The gap between target and ceiling is headroom for the data plane,
which shares the core.

**This is a product decision, not an accident.** The default suite makes Vallum
a team-scale VPN. Anyone who needs more runs `0x0002` or more cores. It must be
said in the README, because a customer discovering it during rollout is a
support incident.

**The first ceiling is not on that table: it is the address plan (measured).**
Until this release `vallum server init` wrote `10.7.0.1/24`, and `vallum peer add` allocates each
device's inner address from that prefix. Enrolling peers one at a time into a
running daemon succeeds **253 times** and then stops with "the tunnel has no free
address left", having handed out 10.7.0.2 through 10.7.0.254. A default install
therefore capped at 253 devices — eight times below the target above — and no
amount of handshake headroom changes it. The fix is one line: a wider prefix
(`/20`, 4,094 devices, is the default from this release).

**Memory per peer (measured).** 6.9 MB resident with no peers, 15.7 MB at 1,000,
24.8 MB at 2,000 → **8.9 KB per peer**, ~0.25 ms of startup each. Worst case is
the per-peer queue bound (256 packets ≈ 384 KB), which puts a 3.9 GB host at
~10,000 congested peers. Memory is not binding below that.

**A restart is a two-minute event (measured, then derived).** One handshake
costs the same whatever the peer table holds — 79.6 ms at 1 peer, 79.9 at 100,
80.1 at 1,000, 77.1 at 2,000 (5 samples each, both sides in one process) — so
recovery is `N × one handshake` with no cliff. At the 18.4 handshakes/s above,
2,000 peers re-establish in **~109 s**, and for that window the single-threaded
loop is spending its core on handshakes rather than on traffic. Size the restart
window from this number, not from the handshake latency.

**Peers are devices, not people.** At two to four devices per person the
2,000-peer target is roughly 500–1,000 people. Quote it as devices.

**Unmeasured:** packets per second and throughput. The queue bounds are known
(`MAX_QUEUED_PACKETS` 256, `MAX_QUEUED_BYTES` 4 MiB per peer), and per-packet
crypto is measured (`vallum bench`: 8.3 µs seal, 5.2 µs open on the reference
server — about 0.82 Gbps of crypto per core), but no load test has produced an
end-to-end pps or bitrate figure. **Do not quote a throughput number until one
exists**: the crypto figure is not one, because it excludes syscalls, the
interface and the loop.

---

## Latency

| Path | Budget | Basis |
|---|---|---|
| Handshake, default suite | **< 100 ms** | measured 54.27 ms; 2× headroom for a slow core |
| Handshake, `0x0002` | **< 10 ms** | measured 1.81 ms |
| Data plane added latency | **< 1 ms** | userspace seal/segment, no queueing under normal load |

Handshake latency is dominated by sntrup761 in the SDK. A handshake is ~9 KB, so
at a 1400-byte MTU it is **7 fragments**; at 5% loss the chance all seven arrive
is **0.698**, which is why recovery windows are measured in tens of seconds
rather than seconds. See `docs/research/fault-lab.md`.

---

## Availability

**Statement, not aspiration:** a `vallum run` daemon is a **single point of
failure** for the interface it owns. There is no failover, no replication, and
none is planned — a client host runs one daemon per tunnel, and two daemons
would fight for the same TUN.

**Therefore the requirement is not uptime, it is failure behaviour:**

| Requirement | State |
|---|---|
| A dead tunnel must not leak traffic | **Met** — fail-closed egress via `vallum policy` / `vallum-guard@` (ADR-0018) |
| A dead tunnel must be visible to the operator | Met — `vallum status`, and it works with the daemon dead |
| The daemon must restart without human action | Met — `RestartSec`, watchdog, `StartLimitBurst=3` |
| Recovery must complete without intervention | Met — proven in the fault lab under loss, MTU narrowing, reorder, delay |

No uptime percentage is claimed. Claiming 99.9% for a single process with no
failover would be a fabrication.

---

## Recovery

| Property | Value | Why |
|---|---|---|
| **RPO** | 0 for configuration | The TOML file on disk *is* the state; there is no second copy to lose |
| **RPO** | 15 minutes for enrolment invites | `INVITE_TTL_SECS`; a reboot voids a live token by design |
| **RTO** | < 5 s | process restart + handshake; measured in the fault lab |
| **Session state** | none persisted | keys and epochs are rebuilt from the handshake |

Losing a daemon loses no data. That is a genuine strength of the stateless
design and it should be stated rather than left implicit.

---

## Platform

Linux only (ADR-0005). Kernel 5.6+ for the TUN and nftables features used.
Package floor: **glibc 2.39** — Ubuntu 24.04+, not Debian 12 or Ubuntu 22.04.
This is a cargo-deb artifact of the build host, and it must be in the release
notes until the build moves to an older base.

---

## Security posture

| Property | State |
|---|---|
| Crypto | tri-hybrid X25519 + sntrup761 + ML-KEM-768, handshake fragmentation managed |
| Crypto dependency | `origin-crypto-sdk` (`EXPERIMENTAL — NOT FOR PRODUCTION USE`); classical X25519 mitigates single-point PQ failure |
| Addressing | dual-stack by default — `10.7.0.1/20` (4,094 peer addresses) and `fd00:7::1/64`; a peer gets one address per family |
| Independent audit | **None.** Stated plainly in the README |
| Fail-closed | **Implemented** — `vallum-guard@` blocks egress outside the tunnel, endpoint excepted (ADR-0018) |
| Privilege | control socket `0600 root`; daemon drops to the configured user where possible |
| Secret storage | keys `0600`; invites `0600` in tmpfs with a 15-minute TTL |

---

## Delivery & Carrying (Data Plane)

A tunnel is **carrying** if traffic transmitted across it is being acknowledged or returned by the remote peer:

- **Window:** rolling 60-second window of transmitted and received packets per peer (`vallum_window_sent`, `vallum_window_received`).
- **Delivery ratio:** `vallum_peer_delivery_ratio = window_received / window_sent`. An idle peer (0 sent) reports `1.0`.
- **Degraded threshold:** ratio < `0.1` after at least 100 datagrams sent in the window. A ratio below 0.1 indicates the tunnel is sending into a void (e.g. far-side dropped sessions, routing blackhole, or anti-spoofing rejection).
- **Verdict mapping in `vallum status`:**
  - `up`: Daemon alive, guard installed (if active), latest handshake fresh (< 180s), delivery ratio >= 0.1 (or idle).
  - `degraded`: Daemon alive, guard installed, handshake fresh, but delivery ratio < 0.1 across >= 100 packets.
  - `stale`: Daemon alive, but the oldest peer's handshake is >= 180s old — past `REJECT_AFTER_TIME`, so the daemon has stopped using the key and the session is dead. Judged before the delivery ratio, because an idle tunnel never sends enough datagrams for that rule to say anything. Not a leak: outbound packets still enter the tunnel and are dropped there.
  - `blocked`: Guard installed, daemon stopped. Egress is safely blocked.
  - `leaking`: Daemon dead, guard NOT installed. Egress is escaping via gateway.

  Every state that is not `up` requires a reason a daemon can be asked for. A
  live process is not a live session: handshake *presence* was once taken as
  proof of liveness, and a host whose server died overnight reported `up` until
  the delivery ratio had a sample to judge — which an idle host never has.

---

## What this page changes

Four of the audit's failures were "the system does not say". Two of them are now
answered with measured numbers (capacity, latency), one with an explicit
statement (availability: no HA, failure behaviour instead), and one with a
correction to the claim itself (recovery: RPO is zero because there is nothing to
lose).

Fail-closed egress is implemented via `vallum-guard@.service` and `vallum policy`,
and delivery ratio provides operational visibility into carrying versus degraded
state.
