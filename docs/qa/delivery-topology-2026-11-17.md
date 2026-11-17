# Delivery topology — the operating model, diagnosed (`2026-11-17`)

**Process:** `devops-topologies` — Mode Pass, Maturity Pass, Anti-Type Pass, then one Transition move.
**Trigger:** 1.8.0 shipped a stateful service (the desk) into a delivery model that had only ever
carried a stateless daemon.

This is a diagnosis of *how work reaches production here*, not of the code. It exists because the
mode, the rung and the failure were all implicit: the gates are excellent and nobody had asked what
class of asset they were gating.

---

## 1. Mode Pass — Mode 4 (DevOps bridge team), bridge-shaped

Evidence, not the org chart. The four questions the mode is decided by:

| Question | Answer | Evidence |
|---|---|---|
| Who approves a production release? | The maintainer, locally, by running `scripts/release.sh` | the signing key and the two-host stamp are deliberately not CI's to hold (`docs/releasing.md`) |
| Who is paged at 03:00? | Nobody. The alerts ship, the pager does not: `vallum status` is polled | `packaging/vallum-alerts.yml`, `docs/operations.md` |
| Who provisions an environment? | `scripts/verify-remote.sh` against a disposable root host; `wingman-vps` is the standing one | scratch or `--product`, everything removed on exit |
| Where does work queue between the two groups? | Nowhere — there are not two groups. The queues are the self-hosted runner and one person's attention | `ci.yml` header: a push during runner downtime *queues* |

Bridge, not silo, by the test that matters: **the product team can deploy without asking anyone.**
The three activity groups exist and each has an owner — physical systems (`server init`,
`install.sh`, `wingman-vps`), pipelines (`accept-*` + `verdict.sh` + `verify.sh` + the workflows),
application lifecycle (the product, which releases itself). They are owned by the same person and
the same agents on different days; that is what makes the model workable at this size, and it is
also the coupling that broke in §3.

**Cost being carried:** the bridge needs three competent owners. Here, one. Depth in any single
group is borrowed from documentation rather than from a second person.

## 2. Maturity Pass — rung D, and the number is misleading

| Variable | Score | Observation |
|---|---|---|
| Collaboration frequency | 2 | daily, unprompted, in the same tree |
| Product ownership sharing | 2 | the same party owns the code and the running host |
| Autonomy | 2 | no approval gate exists anywhere in the path |
| Leadership | 2 | one leader, one reporting line |
| Silos | 2 | neither organisational nor cultural — see the caveat below |
| Cross-functionality | 2 | the same hands do kernel work, packaging, ops and docs |

**Total 12 → rung D.** The honest caveat: on a one-person organisation the top rung is a property of
being one person, not an achievement. The variable that will actually bite is not on the ladder —
**bus factor 1**: the release key, the two-host stamp and the reason each gate exists all live with
one human. The ladder cannot see it, so it is recorded here instead.

The one cultural silo that does exist points the other way from the classic one: the belief that a
new component does not need operational work because it is small, stdlib-only, or already tested.
That belief is anti-type C's, and §3 is where it landed.

## 3. Anti-Type Pass — F, on the desk

**Named: anti-type F — Ops embedded in a dev team.** Not as a structural choice but as a mechanism:
operational work that has no owner loses to feature work, and the result is half-finished by
construction.

Evidence:

- `service/vallum-desk` keeps durable state at `/var/lib/vallum/desk.sqlite` — accounts, device
  peers, plans, expiry, byte caps, codes, voucher redemptions.
- `docs/deployment/backup.md` opened with *"All durable Vallum state lives in one directory:
  `/etc/vallum`"*. It named neither the desk database nor `/var/lib/vallum`. An operator following
  the documented DR procedure restores a host and every account is gone — and the desk starts
  happily on the empty database it creates, so the loss is silent.
- The account number is the service's **only** credential, with no reset flow by design (ADR-0045).
  There is nothing to re-derive it from.
- No gate asked the question: `verify.sh`, `release.sh` and the `accept-*` family cover the daemon,
  the dispatcher, the installer, the pair path and the console. The desk's own tests run against a
  fake daemon, which is right for the logic and says nothing about a deployment's state.
- 1.8.0's release commit touched `Cargo.toml`, the changelog, the lock and the Tauri config. The
  operational surface of a new stateful service was in no gate's scope.

**Lookalike tests, answered:**

- *F vs legitimate capability transfer* — is a support engineer dedicated to this team temporarily,
  with capability transfer as the purpose and an end date? **No.** No such role exists; nothing was
  transferred. F, not the twin.
- *C vs Type 2 (fully shared responsibility)* — is there a single product, and do operational skills
  genuinely exist inside the team? **Yes to both.** So the topology is already correct; the fault is
  not structural, it is that one piece of the operational surface was never built.

**The coupling fault, in one sentence:** the batch that adds a durable store and the batch that
maintains the backup contract are the same batch only when someone remembers, so the contract is
maintained by attention and fails silently when attention is on the feature.

## 4. Transition Pass — one move

Suitability test, all four:

1. **How many products?** One product, one service. Direct collaboration is viable; no silo is
   structurally forced.
2. **Technical leadership with a shared goal?** Yes — one leader, and the goal is written down
   (`docs/releasing.md`: a release is a claim that a tree is deployable).
3. **Will Ops change?** There is no separate Ops to change. The operations *function* here is the
   gate chain, which is already the thing that carries operational judgement.
4. **Can anyone lead on operational concerns?** Yes, and that is exactly the failure — capability is
   present, so the work is assumed rather than assigned.

**The move:** *from (Mode 4, rung D, anti-type F on the desk) to (the same topology with the
durable-state question owned by the gate chain rather than by memory) — one rung of ownership, not a
reorganisation.*

Concretely, in this change:

- `docs/deployment/backup.md` now names both roots, what the desk database loses, how to copy it
  safely (`.backup`, or stop-and-copy), how to restore it, and how to prove the restored copy is
  the right one.
- `scripts/check-state-coverage.sh` fails when a durable root appears in shipped code and not in
  that document. It is wired into `scripts/verify.sh`, the `ci` workflow, and `ci-local.sh`.

**Metric:** change fail rate on *operational omissions* — releases requiring a post-release
correction for something no gate covered. Baseline: 1 (1.8.0's desk), against 0 for the tunnel.
Target: 0 across the next two batches. Leading indicator: durable state roots documented ÷ durable
state roots in the tree — 1/2 before, 2/2 after.

**Reversal condition (expiry `2026-12-01`, or the next release cut, whichever is first):** if the
check never fires and the inventory stops matching the tree — a store added under a pattern the scan
misses — replace the grep with a generated inventory. If instead it fires only as noise on paths
that are not state, narrow the pattern. If neither happens, keep it: it costs one grep.

**Deliberately not done** (the double-move anti-pattern): no new team, no renamed role, no tooling
change, no attempt to reach a rung above D — D is the ceiling and the topology is right.
