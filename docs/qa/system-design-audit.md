# System design audit — Vallum

**Date:** 2026-10-22 · **Scope:** the system as built, scored against a rubric
that fits a data-plane daemon rather than a web service, before any cutting.

The point of this pass is to separate two different kinds of mess. The ponytail
audit found line-count bloat in the shell. This one asks whether the *system*
holds up: what it guarantees, at what scale, and where it fails. Those answers
decide what is safe to cut, and in what order.

---

## Score: 6/10 — and why the generic rubric said 4

The eight-row diagnostic in the system-design framework is written for
**stateless web services at scale** — URL shorteners, feeds, chat. Vallum is a
**data-plane daemon**: one process owning one TUN, no database, no read path, no
producer/consumer split. Applying the rubric mechanically produced a misleading
number, and that was my error, not the project's.

| Generic row | What it actually asks of a VPN | Verdict |
|---|---|---|
| Database scaling strategy | No database. Config is the source of truth | **N/A** |
| Cache for read-heavy paths | No read path — config is parsed once at start | **N/A** |
| Async paths using queues | No producer/consumer split; control plane is bounded sync | **N/A** |
| Every component redundant | A client VPN must **not** be redundant — two daemons fight for one TUN | **N/A, not a failure** |
| QPS and storage estimate | Capacity matters, but the unit is peers/core, not QPS | Applies |
| Requirements listed | Applies directly | Applies |
| Monitoring and alerting | Applies directly | Applies |
| Deployment strategy | Applies directly | Applies |

Three rows are structurally inapplicable, and a fourth (redundancy) is actively
*wrong* for this system class: redundancy is a defect in a VPN client, not a
virtue. Counting those as failures produced 4/10. Scored on the rows that
describe this kind of system:

| Row | Verdict | Score |
|---|---|---|
| Failure semantics when the tunnel dies | **FAIL** | 0 |
| Data-plane correctness under loss / MTU / reorder | PASS | 1 |
| Crypto posture and provenance | PASS | 1 |
| Capacity model | PARTIAL | 0.5 |
| Non-functional targets (peers, pps, SLO) | **FAIL** | 0 |
| Operability (doctor, bundles, metrics, packages) | PASS | 1 |
| Observability coverage, both ends | PARTIAL | 0.5 |
| Upgrade / rollback path | PARTIAL | 0.5 |

**4.5 / 8 → 6/10.** Two hard failures, both specification rather than
engineering: the system does not say what it guarantees, and it fails open when
the tunnel dies.

The findings below did not change — only the score and the framing. Every item
worth acting on survives: fail-open, the absent non-functional targets, the
unpublished capacity ceiling, server-only alerts, no rollback path.

### The original scoring, kept for the record

Under the generic rubric as written: 3 rows passed (only because inapplicable),
5 failed → 4/10. That number is reproducible and is what the framework literally
returns. It is also the wrong answer to the question "is this system sound",
which is why it is recorded here rather than used.

---

## The system as built

### Components

| Component | Threads | Owns | Lifecycle |
|---|---|---|---|
| `vallum run` | 3 (data, timer, control) | one TUN, one UDP socket, peer table | `vallum@<if>.service` |
| control plane | 1 (serial accept) | UAPI-style request/response over a unix socket | child of the daemon |
| `vallum-quick` | — | routes, DNS, hooks | oneshot `attach`/`detach` |
| `vallum-metrics` | — | textfile for node_exporter | timer |
| `vallum-enroll@` | — | enrolment responder | per-interface unit |

### Data flow

```
app → TUN → daemon: seal → segment → UDP → peer
peer → UDP → daemon: reassemble → verify → TUN → app
```

The device is owned by exactly one thread; every mutation happens there. That
invariant is sound and is why the control plane is serial rather than parallel.

### State tiers — and one mistake

| State | Location | Durability | Correct? |
|---|---|---|---|
| Config | `/etc/vallum/*.toml` | durable | yes |
| Keys | `/etc/vallum/*.key` (0600) | durable | yes |
| Control sockets | `/run/vallum` | tmpfs, per-boot | yes — machine resource (ADR-0017) |
| quick state | `/var/lib/vallum` | durable | yes |
| **Enrolment invites** | **`/run/vallum`** | **tmpfs — 15-minute TTL** | defensible, but undocumented |

**F1 — invites live in the volatile tier, and that is probably right.**

`enroll.rs:266` builds the invite path from `run_dir()`, which resolves to
`/run/vallum`. A reboot inside an enrolment window silently invalidates a live
token, and `peer invite` does not say so.

It is tempting to call this a mis-tiered directory. It is not: `INVITE_TTL_SECS`
is **15 minutes** (`enroll.rs:72`), so what is being lost is a short-lived
secret, and keeping a short-lived secret off durable storage is a security
*positive*, not an oversight. `/var/lib/vallum` exists for state that should
survive, and an enrolment token is deliberately not that.

The real finding is narrower: **the decision is invisible.** A reader sees
`/run`, sees `/var/lib` used elsewhere, and cannot tell whether the split was
chosen or accidental — and an operator mid-enrolment gets no hint that a reboot
will void their token. The fix is a comment at `invite_path` and one sentence in
`peer invite`'s output, not a code change.

**This audit found no outright bug.** That is worth stating plainly: the state
model is correct, including the part that looks wrong at first glance.

---

## The missing capacity model

The measurements exist in `docs/proof/performance.md` and
`docs/proof/pq-wireguard-comparison.md`; nobody derived the ceiling from them.

Handshake cost: **54.27 ms** tri-hybrid (`0x0003`), **1.81 ms** for `0x0002`.
With a 120 s rekey, steady-state handshake rate is `peers / 120`:

| Peers | Handshakes/s | Load on one core (tri-hybrid) |
|---|---|---|
| 100 | 0.83 | 4.5% |
| 500 | 4.17 | 22.6% |
| 1,000 | 8.33 | 45.2% |
| 2,000 | 16.67 | 90.5% |
| 5,000 | 41.67 | **226% — over capacity** |

**Ceiling: ~2,211 peers per core with the default suite**, or **~66,300** with
`0x0002`. That is the single most important number the project does not state,
because it decides the product: the default suite makes Vallum a
**team-scale VPN, not a service-provider VPN**, and that is a legitimate
position — but it must be chosen, not discovered by a customer.

It also explains the fault lab. A 9 KB handshake at a 1400-byte MTU is **7
fragments**; at 5% loss the chance all seven arrive is **0.698**, so a handshake
needs several attempts. The 25 s recovery window was not arbitrary — it was
compensating for a number nobody had written down.

---

## The six areas, applied

**1. Requirements.** Functional is strong (seven roadmap conditions). Non-functional
is absent: no peers target, no pps, no latency budget, no availability statement,
no RPO/RTO. *This is the root cause of the other failures.*

**2. Estimation.** Now done above. The inputs were always there.

**3. Building blocks.** Present and appropriate: unix-socket control plane, UDP
data plane, systemd supervision, textfile metrics. Absent and correctly so: no
load balancer, no CDN, no cache, no queue — a VPN daemon has no read path to
cache and no producer/consumer split to decouple.

**4. Data design.** No database, and none wanted. The finding is tiering (F1),
not scale. Config is the source of truth; runtime state is rebuilt at boot; that
is the right model and it is 95% implemented correctly.

**5. Common designs.** The patterns that apply are already applied well:
rate limiting (cookie gate + `MAX_INJECTION_BURST`), unique IDs (key
fingerprints), and a control plane that is a request/response API rather than an
RPC mesh. Nothing here is missing.

**6. Reliability and operations.** The strongest and weakest area at once.
Metrics and health checks are real (`Type=notify`, watchdog, per-peer handshake
age). Deployment is a package install with no revert story. Failure is silent
and open on the client.

---

## The plan

Ordered. No dates. Each batch closes with `./scripts/verify.sh` green.

**Batch 1 — make the spec exist (docs only, no code).**
Write the non-functional section: peers target, pps target, handshake latency
budget, availability statement, RPO/RTO. Publish the capacity table. State the
2,211-peer ceiling and choose it deliberately, with `0x0002` named as the
high-density profile.

**Batch 2 — make the invite tiering legible.**
Not a code move. A comment at `invite_path` stating why a 15-minute token lives
in tmpfs, and one line in `peer invite`'s output warning that a reboot voids it.
Cheap, and it stops the next reader re-deriving the question this audit just
spent an hour on.

**Batch 3 — fail-closed (ADR-0018).**
The one structural gap that decides whether this can be called a product. Block
egress outside the tunnel, keep the endpoint reachable, drop the family the
tunnel does not carry. Guard unit ordered before the tunnel, not part of it.

**Batch 4 — IPv6 provisioning.**
Per-family address allocation so a peer gets a v6 tunnel address and `::/0`
becomes a claim with a route behind it, instead of the leak.

**Batch 5 — operations.**
Client-side signal, one threshold per alert, and a documented rollback for units
and packages.

**Batch 6 — the cuts.**
Only now: 4,305 generated completion lines, the three style layers, `peer.rs` and
`vallum-quick/main.rs` splits. These are safe at any time, which is exactly why
they go last — they change the shape of the code, not the shape of the system,
and doing them first would have made this audit harder to run.

---

## What this audit changed my mind about

The ponytail audit made the tree look like it had drifted into polish. This pass
shows the opposite: the protocol and transport are in good order, the state model
is right except for one path, and the metrics are better than most products ship.
What is missing is **specification** — numbers, targets, and a stated failure
mode — and one genuinely mis-tiered directory.

Cutting first would have removed lines without answering any of that.
