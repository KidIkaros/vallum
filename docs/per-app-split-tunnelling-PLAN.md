# The per-app split tunnelling plan (ADR-0023 → implementation sketch)

**Status:** plan. No `routes.rs` or verb code below is written yet; this is the
shape that builds on what ADR-0023 decided and what
`docs/proof/socket-cgroupv2.md` measured. It exists so the first PR has a
named target instead of re-deriving the design from the ADR's prose.

## What the measurement already settled

- One rule classifies every member and nothing outside it:
  `socket cgroupv2 level N "<class-path>"`, where N is the *depth of the
  class's cgroup-relative path* and the string must resolve from the cgroup
  root at rule-add time (`nft` validates it; the class directory therefore
  exists before the rule).
- Slash-bearing paths are nameable only through `nft -f` — the argv parser
  rejects them — so every class rule is written as a file.
- `level 0` is a dead end; depth-N prefix compare is the form.
- Delegated `user@uid.service` subtrees are writable by mapped credentials,
  which is how an unprivileged gate machine exercises the mechanism, and is
  the tier a real laptop runs as.

## One amendment this plan contributes back to the ADR

**Steering needs a `route` chain, not the `filter` chain the probe measured.**
Policy routing evaluates `ip rule` marks at the route lookup, which for
locally-generated packets happens before the `filter`-type output hook runs.
nft's `type route hook output` chain runs *before* the routing decision, and
is how a mark set in nft can drive `ip rule` for the marked packet. The
probe/gate cases counted with a `filter` chain — correct for classification
assertions, wrong for the delivery path. Before any `routes.rs` work, the
gate gains the pairthat proves the distinction: one scoped packet counted at `filter` and steered at
`route`.

**Measured 2026-10-23** (scratch probe, Linux 7.0.0-38, nft 1.0.9,
`user@1000.service` tier, inside a probe netns): the claim holds as stated. An
unmarked UDP `sendto` from a class-leaf process died in the steered table
(blackhole → `EINVAL`, the discriminator) with the mark set *only* by a
`type route hook output` chain — at both priorities tried (`filter` and
`mangle`) — and socket-marked (`SO_MARK`) connect and per-packet sendto steer
identically. The kernel's post-hook re-route (`ip_route_me_harder`) is real
on this kernel, which is the whole hinge: connect-time lookups run unmarked,
so steering depends on the packet being re-routed after the output chain —
and it is. The gate still codifies the pair (a scratch ≠ the gate); the verb
counts it as closed.

> Disclosure: the first three probe attempts measured wrongly and said "no
> re-route" — a `local`-route steer target plus a main-table default both via
> `lo` collapsed the two outcomes into one device, and `ping`'s raw-socket
> path answered nothing steering could distinguish. The blackhole matrix
> (consulted ⇒ instant `EINVAL`, not consulted ⇒ emitted and timed out) is
> what settled it. The verb's gate case should use the blackhole form, not
> the `local`-route form the plan's earlier §verb referenced.

## The install (attach side, `vallum-quick`)

New module `crates/vallum-quick/src/class.rs`, called from `attach` after
`apply_routes` succeeds (and before `detach`'s removal path in reverse).

### Config surface

`[quick] app_class = false` in `vallum-config`, honored by `attach` only when
the config is a full tunnel (`allowed_ips` contains a `0.0.0.0/0` or `::/0`)
**and** has `[interface] fwmark` — both of which `policy_for` already
enforces for the policy machinery. A split tunnel with `app_class = true` is
refused at attach: ADR-0023 names exactly one class for v1; riding a
prefix-list tunnel's `[quick] table` re-opens the routing questions that
decision deferred.

### Class directory resolution (deterministic, no new state)

The same tier probe the gate's phase uses:

- **tier 1** (`/sys/fs/cgroup` itself writable — the daemon/root case):
  class = `/sys/fs/cgroup/vallum-apps`, relative path `vallum-apps`;
- **tier 2** (first writable `/sys/fs/cgroup/user.slice/*/user@*.service`):
  class = `<that dir>/vallum-apps`, relative path
  `user.slice/user-<uid>.slice/user@<uid>.service/vallum-apps`;
- neither → attach prints a named note that the machine cannot carry the
  class, and installs everything else as today. The note is not an `ok`.

The class directory is **created once and never removed** — it exists across
detach/reboot so a re-attach's rule-add is valid without ceremony. Only
member leaves (below) come and go. On tier 1 the creation needs CAP; `attach`
already runs privileged for the tunnel it is proving, so this is not a new
escalation.

### What installs

```
table ip vallumapps
chain cls { type route hook output priority filter ; }
rule output socket cgroupv2 level <N> "vallum-apps" meta mark set <CLASS_MARK>

table ip6 vallum6app
chain cls { type route hook output priority filter ; }
rule output socket cgroupv2 level <N> "vallum-apps" meta mark set <CLASS_MARK>
```

Both families, because the tunnel's v6 claim routing is part of the leak
story (`routes.rs` comments on `::/0`). One mark, not per app — ADR-0023's
stated economy; `CLASS_MARK: u32 = 5140`, a named constant in `class.rs` with
a comment on the documented 4660/51820/51820-neighborhood budget, and attach
refuses a config whose `fwmark` equals it (colliding with the tunnel's own
mark would classify the daemon's datagrams into the tunnel it is trying to
escape — the exact bug the `not fwmark` rule exists to prevent).

**No new `ip rule`.** This is the part of the sketch that leans hardest on
the measured machinery: the policy table's lookup rule is
`not fwmark <interface fwmark> table <policy table>`. A packet marked
`CLASS_MARK` (≠ the tunnel's mark) matches *not* — and lands in the same
policy table, whose default routes through `vallum0` and whose
`suppress_prefixlength 0` guard still routes everything nest-and-prefix the
main table's way. Nothing about `RoutePlan`, the record, or the teardown
machinery changes. The member's fail-closed semantics are inherited for
free the same way: when the watchdog blackholes the policy table
(`plan_blackhole_routes`, ADR-0022's route-record seam), class-marked
packets blackhole with the tunnel's. **No guard code change in v1** — the
`failure_policy = "block"` posture is the table's, not a per-app rule.

### The record

`state_path(interface)` gains a sibling, `<iface>.quick-class`, written
*before* the `nft -f` runs (the same write-then-run pattern `apply_routes`
uses): one line per family, `nft ip vallumapps <rel-path>` /
`nft ip6 vallum6app <rel-path>`. `detach` reads it and
`nft -a delete table <fam> <name>` leniently (the record exists so a config
edited between attach and detach cannot strand the tables, exactly the
invariant `teardown_plan` protects for routes). `RoutePlan.parse` stays
unchanged: it does not learn `nft` verbs.

**One interface per machine.** Two configs with `app_class = true` attached
at once would have their rules fight over one mark; `attach` refuses the
second one with a message naming the interface that holds it. This is the
class-is-a-machine-resource fact ADR-0023 records, applied at attach time.

## The verb (`vallum-quick app run`)

Registered as another `Action` in `main.rs`:

```
Up { config, dry_run, allow_insecure_config }        // what exists today
App { config, name, cmd: Vec<OsString> }             // new
```

`main.rs` dispatches to `class.rs`'s `app_run`. Sequence:

1. Read the config for the interface name (the lifecycle is keyed on the
   interface, the way the record is) and for `control`'s daemon check only
   insofar as routes already exist — a run whose policy table is gone would
   launch outside the tunnel. The concrete check: the recorded
   `<iface>.quick` exists AND `ip rule` (queried once, as
   `interface_networks` queries addr today) still contains the policy-rule
   line. Absent → refuse loudly: "the tunnel is not attached — launching
   now would run outside the tunnel", exit 1. This is the leak-guard refusal
   ADR-0023's membership decision depends on: an unknowing direct user
   would look exactly like an exiting user.
2. Validate `name`: `[a-zA-Z0-9_[.-]]` capped at 32 bytes — cgroup name
   legality plus the null-free/`..`-free property. Refuse before the fork
   forks and the cgroup-and-exit never happen.
3. Resolve the class dir the same way `attach` did (deterministic; no state
   read, state is for undoing, not discovering). On tier 1 this verb must be
   running privileged (as a member of the same CAP group) — `app run` on a
   root tier simply inherits the operator's already-privileged attach
   context; the mapped laptop tier needs nothing.
4. Compute the leaf's exact name: `<name>-<child pid>`. The pid is known
   only after `Command::spawn` — so the child itself does the creating:

   ```rust
   Command::new(&cmd[0]).args(&cmd[1..]) ... .pre_exec(move || {
       // Child, pre-exec: same kuid as the parent verb, same tty.
       let leaf = <class>/<name>-<std::process::id()>;
       fs::create_dir(&leaf);
       fs::write(leaf.join("cgroup.procs"), std::process::id());
       // exec(2) happens after this closure runs, so the launched program
       // is born inside its class, kernel-guaranteed.
       Ok(())
   }).spawn()
   ```

   Everything the process spawns from here (!) — every descendant of the
   launched program — is born inside the leaf by cwd... by *cgroup
   inheritance*, the kernel property ADR-0023's membership decision leans
   on. No pid discovery, no lifetime bookkeeping, no re-classify.
5. Parent: wait exactly like the shell does (SIGTERM → child TERM, argc
   preserved; the crate is already Linux-only per ADR-0005). On exit,
   `rmdir` the leaf — succeeds only when the leaf holds no processes, so a
   descendant that outlived the launched program prints a one-line note and
   the leaf survives; the next `attach` (or the next `app run` with the
   same name pattern) sweeps empty leaves under the class dir (`read_dir`,
   `cgroup.events`... just `rmdir`; the kernel refuses anything non-empty
   for free).
6. `--dry-run`: print the would-be leaf name and exec command, nothing more.

Why `pre_exec` and not a wrapper shell: a `/bin/sh -c "echo $$ > leaf; exec
CMD"` re-cooks the operator's argv through a shell the config did not audit.
`pre_exec` runs in the child after fork and before exec — no shell in
between, no quoting layer, exactly ONE process. The verb stays stdlib-only:
no `nix`/`libc` dependency, and the recorded form is
`Command::pre_exec` + `std::process::id()`.

**Amendment, 2026-10-25 (landed)**: the workspace policy is
`unsafe_code = "forbid"`, and `pre_exec` is inherently `unsafe`, so every
invocation the plan sketched is unwritable as stated. The landed form
reaches the same execution point without it: the verb moves **itself** into
the leaf `<name>-<pid>` (its own pid, known immediately — no spawn-ordering
trick needed) and then plain-spawns the command as a child. Everything
counted for is preserved: the child is born into the leaf by cgroup
inheritance (so every descendant joins the class); argv is preserved
exactly — the spawn goes straight to exec, no shell, no quoting layer; the
verb keeps the wait and forwards the child's exit code; the stdlib-only
property holds. The delta is process count (two, verbatim reverting when
the child exits, still no pid discovery) and the leaf's pid being the
verb's. The one-property test lives in the gate's verb-lifecycle case.

**Amendment, 2026-10-25 (the leaf note, observed live)**: the landed form
put the verb itself inside the leaf, so the sketch's exit-time `rmdir`
above was refused on *every* launch — the verb is a resident of the leaf
until after `remove_dir` runs — and the "descendant still inside" note
fired on clean launches that had none. Measured in the live verb watch
(userns+netns, tier-2 class, one counting rule): the honest decision reads
the leaf's `cgroup.procs` and subtracts the verb's own pid. Empty minus
self → the verb steps back into the class root, `rmdir`s its now-empty
leaf immediately, and says nothing. A resident pid remains → the note
fires and names it. The decision is a pure helper
(`leaf_member_pids`) with a unit test; the sweep contract below is
unchanged — a real straggler leaf still waits for the next attach.

## Tests the plan lands with

1. **Gate, pair-assertion (the `route`/`filter` distinction):** in
   `e2e-netns.sh`'s "per-app classification" phase, after the classification
   assertions hold, install the *mark* rule in both chain types and assert
   steering the measured way — a scoped leaf UDP `sendto` at a
   blackhole-steered discriminator (`consulted ⇒ instant EINVAL, missed ⇒
   emitted and lost`, see the addendum's disclosure). No `ip route get`:
   the scratch probes caught it traversing no output chain, so it cannot
   see a `route` chain's mark at all. The assertion stands that no future
   `filter`-chain regression can be silent.
2. **Gate, verb lifecycle:** inside the full-tunnel phase, `QUICK app run
   <config> test-probe -- ping` scoped traffic counted by the class rule,
   `<name>-<pid>` present under the class dir while the ping runs, and the
   leaf gone when the verb exits; a straggler leaf is swept by the next
   attach.
3. **routes.rs unit:** a config with `app_class = true` and a non-full
   tunnel refuses at attach; a config with `fwmark == CLASS_MARK` refuses;
   a second interface's `app_class` attach refuses with the first
   interface's name in the message.
4. **proptest (RoutePlan untouched, class record has its own):** class
   resolution is the same on repeat calls (purity — no state drift between
   attach and verb), and the leaf-name sanitizer's alphabet is closed under
   attempted input.
5. **verify-remote (follow-up):** the browser-impact suite's next case —
   "a launched member's DNS rides the tunnel's resolver" — is the first
   end-user story this feature ships with, and names the class resolution
   on a real host where the gate's scratch dir does not exist.

## What v1 stays out of, and why

- **Per-app DNS, metrics, alerts** — ADR-0023: received, not built; the
  member's resolver path is the tunnel's; per-app observability is v2.
- **Retroactive claim of an already-running process** — the membership
  decision: deliberate launch, never discovery.
- **Riding a split (prefix-list) tunnel** — one class, one table; prefix
  composition is v2.
- **pdeathsig and group-kill guarantees for orphaned members** — the leaf's
  `rmdir`-only-when-empty plus attach-time sweep covers the crash case
  honestly (the member stays where it was launched — inside the class —
  until it exits; the note names it, as the launch made it precise).

## Measured verdict on the verb's pre-flight (the liveness question)

The concrete verb sketch ends on an open question: should `app run` verify
the nft tables are still installed at launch time, or is route+record enough?
Measured 2026-10-23 (same scratch probe series):

- `nft list chain <t> <chain>` **exit 0 does not prove the rule exists**:
  after `delete rule ... handle N` the chain still lists (exit 0), with the
  rule gone from its body. A `flush ruleset` or a partially-degraded
  install is the exact state a laptop can silently land in.
- With the table absent, listing exits 1 with `Error: No such file or
  directory` on stderr — a shape usable as the absence signal, but exit-code
  analysis alone cannot separate `chain exists, rule gone` from `all well`.
- The one cheap, faithful check is a **grep of the listing** for the rule's
  own predicate text (`cgroupv2 level N "<rel-path>"`) alongside exit 0.

Decision, applied to the verb: `app_run`'s pre-flight, after proving the
record and the policy table (see the concrete sketch's `assert_attached`),
runs one `nft list chain ip vallumapps cls` per the record's families and
requires the `cgroupv2` line to be present in the grep'd output. Absent →
refuse with the same posture as the un-attached refusal: launching now would
run *outside the measured machinery* — the packet would ride the policy table
(it would arrive), but the class would claim nothing and count nothing, and
that regression must not be silent. Refusing costs one `nft` round-trip per
launch; a hot wrapper that resents the check is free to shell straight
through its own `Command` after pinning the chain itself — the tool's
contract stays trustworthy by default.

The gate's liveness case (plan §Tests item 1's sibling, at verb-lifecycle
time) drops the chain — `nft delete rule` only — and asserts the verb refuses
with the named message. That is the exact regression the pre-flight exists
to catch.

## The two failure modes this plan explicitly names from the probe

- **The rule's path is validated at add time** — class dir before the
  `nft -f`, always; the gate case carries the ordering regression trap.
- **`run_lenient` is what `detach` uses** — class tables are removed
  leniently the same way, so a partially-failed detach doesn't strand them
  on a state file the next boot cannot understand (and the record lives in
  `/var/lib/vallum`, which survives reboot — deliberate, per the comment at
  `STATE_DIR`).
