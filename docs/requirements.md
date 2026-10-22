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

**Unmeasured:** packets per second, memory per peer, and throughput. The queue
bounds are known (`MAX_QUEUED_PACKETS` 256, `MAX_QUEUED_BYTES` 4 MiB per peer),
but no load test has produced a pps figure. **Do not quote a throughput number
until one exists.**

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
| A dead tunnel must not leak traffic | **Not met** — fails open. ADR-0018 |
| A dead tunnel must be visible to the operator | **Not met** on the client |
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
| Independent audit | **None.** Stated plainly in the README |
| Fail-closed | **Implemented** — `vallum-guard@` blocks egress outside the tunnel, endpoint excepted (ADR-0018) |
| Privilege | control socket `0600 root`; daemon drops to the configured user where possible |
| Secret storage | keys `0600`; invites `0600` in tmpfs with a 15-minute TTL |

---

## What this page changes

Four of the audit's failures were "the system does not say". Two of them are now
answered with measured numbers (capacity, latency), one with an explicit
statement (availability: no HA, failure behaviour instead), and one with a
correction to the claim itself (recovery: RPO is zero because there is nothing to
lose).

The remaining honest gap is the one that matters most: **fail-closed is not
built.** Everything on this page describes a system that is well-specified when
it is working, and silent when it is not.
