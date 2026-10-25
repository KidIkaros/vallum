# ADR-0023: Per-app split tunnelling rides the tunnel's mark tables, with launch-bound membership

**Date**: 2026-10-23
**Status**: accepted
**Deciders**: the maintainer, over a grounded grill session on 2026-10-23

## Context

Split tunnelling has only ever been per-destination: `allowed_ips` prefixes are
read by the route plan and steered by routing table. That cannot express "the
browser rides the tunnel, the terminal rides the physical link" — the traffic is
indistinguishable at routing level, and the person who can describe the intent is
not the packet. `docs/roadmap.md` gates the item on a mechanism decision
(cgroup, netns, or namespace-per-app) before any code, so this record is that
decision.

The forces that shaped it are all in the repo today:

- The full-tunnel attach plan **already is** a mark classifier: it installs
  `fwmark` + `ip rule` + a policy routing table (`vallum-quick/src/routes.rs`),
  with `suppress_prefixlength` keeping the daemon's own datagrams on the real
  gateway. Per-app is that machinery applied to a subset of processes, not a
  second routing model.
- The guard layer (ADR-0018, the fail-closed default of item 2) already installs
  layered `nft` tables. Whatever the classifier is, the leak rule and the blackhole
  semantics must ride the same tables, not invent a parallel one.
- The 15-character interface-name budget is already enforced by provisioning
  (`peer add` refuses collisions and truncates to `vallum-laptop-b`-style names).
  A namespace-per-app design needs one interface name per app; auto-derivation
  from app names walks straight into that ceiling.
- DNS and resolver installation (item 3) are solved per host, not per namespace.
  Namespace designs multiply that story for every container created.

## Decision

1. **Mechanism: a cgroup classifier riding the tunnel's own mark tables.**
   The router chooses the path per packet, not per process: traffic produced
   inside a member app's cgroup is marked, `ip rule` steers the mark to the
   policy routing table the full tunnel already holds, and the guard's
   fail-closed semantics apply to that class exactly as they do to the whole
   tunnel — when the tunnel is down, member traffic is blocked, not reverted.
   The exact `nft` form is measured, not assumed: the rule names the class's
   cgroup-relative path, and the match compares the socket's cgroup path
   against it at the class's depth (`level N "path"`, where N is the depth).
   nft validates the string against the hierarchy at rule-add time — a
   component-only name resolves only for a top-level class, and slashes are
   unnameable through the argv grammar, so deep classes are written through
   `nft -f` — and the class directory must exist before any rule names it.
   `level 0` is effectively unusable: its exact-path compare needs slashes in
   the string. The measure record is `docs/proof/socket-cgroupv2.md`. What
   remains decided here is unchanged: the classifier is a mark in the existing
   tables, and all members share one mark rather than one per app — per-app
   differentiation beyond membership is a decided-against extension for v1.

2. **Membership: launch-bound.** A process becomes a member by being
   *launched* as one — a `vallum app run NAME -- CMD` verb and a `detach`-style
   removal, recorded in the config the way `peer add` records peers, applied by
   the attach plan the way routes are. A cgroup is created per membership and
   the verb `exec`s the program inside it; everything the program spawns stays
   inside by kernel inheritance, which is the property that makes the
   membership statement true without PId-discovery races. An already-running
   process is never retroactively claimed.

## Alternatives Considered

### Selector membership recorded in config (`vallum app add` + PID discovery)

- **Pros**: mirrors the repo's own verb-records-in-TOML pattern (`peer add`,
  enrollment); no launch habit required; works on apps the wrapper never saw.
- **Cons**: matching a process name or binary path to a PID set races the
  classifier — anything spawned between a lookup and a move, or during
  re-attach, escapes the class exactly when the scope is being proved honest;
  and cgroup membership is the kernel's *only* leak-proof statement about a
  process tree, so claiming via `/proc` scanning rebuilds the boundary with a
  best-effort tool.
- **Why not**: the boundary is the product's whole point; a membership model
  that can be defeated by process-start timing is a leak that pages nobody.

### netns per app-set / namespace-per-app

- **Pros**: the kernel boundary is absolute and namespace-local resolvers work
  natively; no nft work at all.
- **Cons**: membership means every launch site learns the namespace
  (`systemd-run`, desktop entries, shells) — the same wrapper burden as the
  chosen design, but paid multiplicatively because *launch* rather than
  *classification* carries it; resolver/`resolv.conf` machinery the attach plan
  already solved must work per container; the guard installs per namespace;
  interface naming runs into the 15-char truncation ceiling; the scratch
  namespaces the CLI already provisions are for tests, and productionizing
  that shape means a `vallum` daemon broker owning foreign lifetimes that
  ADR-0017's runtime-directory rules were written to prevent owning.
- **Why not**: same leak guarantee as cgroups, much larger blast radius for
  everything else the product does (DNS, guard, doctor, attach/detach).

## Consequences

### Positive

- No second routing model: per-app traffic and full-tunnel traffic land in the
  same policy table; a single implementation of per-app follows.
- No second leak model: the guard's fail-closed behavior extends to the
  per-app class with no new rules to write — `failure_policy = "block"`
  blocking member traffic when the tunnel dies is inheritance, not a feature.
- Membership is provable per process lifetime: the scope exists exactly as
  long as the launch that created it, so `doctor` can name member scopes and
  what they are classified as.
- `doctor` and the alerts files inherit honest statements about members:
  a member traffic pattern missing the tunnel is named by the existing
  verdict/alert surface, because the class is in the same tables.

### Negative

- An app that cannot be launched through the verb is *not a member* and is
  documented as such, not magically detected. Membership is a deliberate
  launch decision, by design.
- Per-app DNS is **received, not built**: the member's resolver path is the
  tunnel's own (same table, same guard), so a member cannot have a DNS
  different from the tunnel's push. Fine-grained DNS per app is v2 territory.
- Per-app metrics/alerts beyond the tunnel's existing client verdict is v2
  territory; this ADR names exactly one class, not per-app observability.

### Risks

- `nft` support for `socket cgroupv2` must be asserted on every harness's
  kernel before any `routes.rs` work. Measured 2026-10-23 on both: the remote
  harness (`wingman-vps`, kernel 6.8.0-31, real root, top-level class at
  level 1) and the local harness (kernel 7.0.0-38, delegated `user@uid`
  subtree, deep class at level 4 — the delegated environment with mapped
  credentials the gate's own unprivilege runs in). The e2e-netns gate carries
  the case (`scripts/e2e-netns.sh`, "per-app classification" phase): class
  directory before the rule, unscoped control plus a machinery control, a
  member counted, and a nested member counted by the same single rule. All
  measured PASS in `docs/proof/socket-cgroupv2.md`.
- Marks must not collide with the tunnel's own `fwmark = 4660`/`51820`
  budget; the classifier's mark gets a named constant and a documented space.
- Non-systemd hosts where cgroup v2 delegation fails would break `app run` —
  the verb must fail *loudly* (naming the environment, not pretending to
  attach), consistent with the abort-on-fail DNS posture of item 3.
