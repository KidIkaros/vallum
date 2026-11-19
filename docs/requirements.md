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

**Measured:** the handshake cost of one exchange, `docs/proof/performance.md`:
tri-hybrid `0x0003` **54.27 ms**, fast profile `0x0002` **1.81 ms**. That is a
Criterion median of *both sides in one process* - single-threaded, no network,
no fragmentation, no daemon.

**Derived, not measured:** everything in the next table. "Handshakes/s per
core" is `1 / latency`, which assumes one handshake per core at a time with
nothing else running; "peers per core" is that number times the 120 s rekey
interval. Neither has been observed under load, and the second column's
meaning depends on the first being true.

| Suite | Derived handshakes/s per core | Derived peers per core |
|---|---|---|
| `0x0003` tri-hybrid (default) | 18.4 | 2,211 |
| `0x0002` X25519+ML-KEM-768 | 552.5 | 66,298 |

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
amount of handshake headroom changes it. The fix is a wider prefix: `/20`
(4,094 devices) is the default in `vallum server init`
(`crates/vallum/src/commands/server.rs:429`).

**This page previously claimed the /20 was "the default from this release".
It was not, on the documented path.** `vallum setup --server` carried its own
`10.7.0.1/24` (`crates/vallum/src/commands/setup.rs:101`) and passed it
explicitly, so the /20 default in `server.rs` was never reached and the
documented install produced 253 devices — eight times below the target this
page claims. Both now use the /20.

**Memory per peer (measured).** 6.9 MB resident with no peers, 15.7 MB at 1,000,
24.8 MB at 2,000 → **8.9 KB per peer**, ~0.25 ms of startup each. Worst case is
the per-peer queue bound (256 packets ≈ 384 KB), which puts a 3.9 GB host at
~10,000 congested peers. Memory is not binding below that.

**A restart is a two-minute event (measured, then derived — and the two
figures disagree).** One handshake costs the same whatever the peer table holds
— 79.6 ms at 1 peer, 79.9 at 100, 80.1 at 1,000, 77.1 at 2,000 (5 samples each,
both sides in one process) — so recovery is `N × one handshake` with no cliff.

Those four measured latencies give **2,000 peers in ~159 s** (2,000 × 79.6 ms).
The **~109 s** figure published earlier came from the *other* measurement on
this page — 18.4 handshakes/s, i.e. 54.27 ms — so the two published numbers
describe different instruments and the smaller one was the one quoted. The
honest statement is a range: **roughly 110–160 s**, from a per-handshake
latency measured with both sides in one process and no network. Quote the range
or neither; do not quote 109 s as if it were the outcome of the other
measurement.

For that window the single-threaded loop is spending its core on handshakes
rather than on traffic. Size the restart window from this number, not from the
handshake latency.

**But a mass simultaneous rekey is not bounded by that number, and this is the
exposure the page previously did not name.** Three structural limits, none of
them CPU:

1. **The reassembly table is 16 entries for the whole device**
   (`crates/vallum-tunnel/src/segment/reassembly.rs:69`). One instance serves
   a whole device, and an entry is one *message* - a handshake's fragments
   accumulate into a single entry, so the bound is on **concurrent handshakes**,
   not on fragments. Sixteen concurrent initiations fit; the seventeenth
   evicts the entry that has waited longest, and the evicted message's later
   fragments then open a *second* entry for the same id - so that message is
   split across two entries and never completes. 16 is a deliberate bound:
   the module docs call it "a hard bound on the hostile one", and the whole
   table is 256 KiB at the ceiling. Raising it is a memory-versus-DoS decision
   (256 entries would be 4 MiB), not a free fix, and it is not raised here.
2. **A stalled handshake retransmits every 5 s**
   (`crates/vallum-core/src/timer.rs:38,243`), so a herd that cannot get
   through becomes a standing retransmission storm rather than a 2-minute
   event.
3. **The rekey trigger has no jitter.** `REKEY_JITTER_MS` applies to the
   *retransmit* delay (`crates/vallum-core/src/timer.rs:271`), not to the
   rekey trigger itself, which is exactly `established_at + 120 s`
   (`crates/vallum-core/src/timer.rs:249`). Peers enrolled or rebooted together
   rekey in the same instant, every 120 s.

There is also less room than the number suggests: the protocol's own budget is
60 s between the rekey trigger (120 s) and key death (180 s)
(`crates/vallum-core/src/timer.rs:26,44`), which is **shorter** than the
recovery time quoted above.

**So the honest statement of the 2,000-peer target is: 2,000 peers fit in the
address plan and in roughly 25 MB of RAM, and the handshake path cannot carry
2,000 of them at once.** Two ceilings, neither of them the one the old number
implied:

- **at most 16 concurrent inbound initiations** (the reassembly table), and
- **~18 handshakes/s sustained** (the loop thread's CPU, which is what the
  18.4 figure above actually measures).

A server absorbing a *fleet* re-establishing at once is outside both. What
that means in practice, for an operator: size the restart window for the
peers that will re-establish together, and stagger them yourself if that
number is large. The daemon does not spread a fleet's rekeys for you — see
point 3.

**Peers are devices, not people.** At two to four devices per person the
2,000-peer target is roughly 500–1,000 people. Quote it as devices.

**Unmeasured:** packets per second and throughput. The queue bounds are known
(`MAX_QUEUED_PACKETS` 256, `MAX_QUEUED_BYTES` 4 MiB per peer), and per-packet
crypto is measured (`vallum bench`: 8.3 µs seal, 5.2 µs open on the reference
server — about 0.82 Gbps of crypto per core), but no load test has produced an
end-to-end pps or bitrate figure. **Do not quote a throughput number until one
exists**: the crypto figure is not one, because it excludes syscalls, the
interface and the loop.

**Concurrent enrolment (measured on the released build).** `accept-many 12`
against v1.10.0: 12/12 clients enrolled and carried, 12 distinct addresses, the
server's peer table tracked all 12 (signed verdict). The RSS delta at this small
N (≈30 kB/peer) is dominated by page granularity and neither confirms nor refutes
the 8.9 kB/peer figure measured at 0/1000/2000. This validates the enrolment path
at concurrency on the shipped artifact; it is **not** a throughput or
sustained-rekey-herd measurement.

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
| DNS | **Does not leak** — UDP and TCP port 53 egress is dropped outside the tunnel by the killswitch filter before any allow rule; `attach` and `up` fail closed when a resolver cannot be installed; the server pushes a resolver into the tunnel with `--dns`. See the boundary below. |
| Privilege | control socket `0600 root`; daemon drops to the configured user where possible |
| Secret storage | keys `0600`; invites `0600` in tmpfs with a 15-minute TTL |
| Verdict | **`vallum doctor` fails when the client is not protected.** A client whose daemon is not running, or that is dialling and has never been answered, exits non-zero and says `NOT protected` — it does not exit 0 over a client sending every byte in the clear. A *server* whose peers are merely offline does not fail: that is ordinary, and failing it would train people to ignore the line. Pinned by `crates/vallum/tests/exit_codes.rs`. |

### What the DNS guarantee is, and is not

**Is:** while the tunnel is attached, DNS queries do not leave it. Port 53
egress outside the tunnel is dropped by the killswitch filter
(`crates/vallum/src/policy.rs`) before any allow rule, so a rogue or
host-local resolver cannot answer; and if a resolver is configured but cannot
be installed, `attach` and `up` fail closed rather than fall back to the
physical link. The server can also push a resolver into the tunnel
(`vallum peer add --dns`, `vallum server init --dns`).

**Is not:** that the resolver is private. The guarantee is about the *path*,
not the *endpoint*: the resolver operator still sees the query names. In a
hub-and-spoke deployment the resolver is usually the server's, so the server
operator sees the client's queries. RFC 8932 puts the same point plainly for
encrypted DNS — the resolver operator still has full visibility of the query
data — and RFC 9076 §6.1.4.1 says encryption does not reduce what the
recursive resolver can see.

That boundary is why the product does not ship a blocklist engine. A
sinkhole on the server would put the operator in the position of seeing every
client's browsing, and its updater would add a third-party list supply chain
to a daemon whose job is to be trusted with keys. Blocking belongs on the
client's side of the resolver, where the trust already is. See
[`research/pi-hole-in-vallum.md`](research/pi-hole-in-vallum.md).

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
