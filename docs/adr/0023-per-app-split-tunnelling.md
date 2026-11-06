# ADR-0023: Per-app split tunnelling rides the tunnel's mark tables, with launch-bound membership

**Date**: 2026-10-23
**Status**: implemented (v1 — `crates/vallum-quick/src/member.rs`: a shared member network namespace). The mechanism is not the mark table this record first chose: the 2026-10-28 amendments record why the mark could not split the host, and what replaced it. Launch-bound membership is unchanged — `vallum-quick app CONFIG NAME -- CMD` is still the only way in.
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
   *Superseded (2026-10-28): the mark steers packets but cannot move a socket's
   source address, so it cannot split the host. Replaced by one shared member
   namespace — see the second amendment at the end of this record.*
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

- The host is untouched. `attach` installs no host routes and rewrites no host
  resolver; a process that is not a member keeps exactly the networking it had
  before the tunnel existed.
- The member's source address is the tunnel's by construction, because the
  namespace decides the route before the socket exists. No mark, no `nft`
  rule, no source rewrite, no app cooperation.
- Fail-closed is structural: the member namespace's only default route is the
  tunnel device, so a dead session leaves members with no path rather than the
  physical one.
- Membership is still launch-bound: the verb is the only way in, and a process
  started outside it is not a member.

### Negative

- An app that cannot be launched through the verb is *not a member* and is
  documented as such, not magically detected. Membership is a deliberate
  launch decision, by design.
- Members share one namespace: they share loopback and can reach each other's
  local services, while a helper process left outside cannot talk to a member's
  loopback. One namespace per tunnel, not one per app.
- DNS is a private `resolv.conf` in the namespace naming the tunnel's pushed
  resolvers. A member cannot have a DNS different from that push; fine-grained
  DNS per app is v2 territory.
- Per-app metrics/alerts beyond the tunnel's existing client verdict is v2
  territory; this ADR names exactly one class, not per-app observability.
- The product now depends on `unshare` and `nsenter` (util-linux) for the
  namespace, as it already does on `ip`.

### Risks

- Holder lifecycle. The namespace is held by a process `attach` spawns; if the
  holder dies, the device dies with the namespace and the daemon loses its
  interface. `detach` moves the device back and stops the holder, and `app`
  refuses when the holder is gone rather than launching outside the tunnel.
  Crash recovery for a device left in a dead namespace is not yet exercised.
- A mount namespace is required for the private resolver. `attach` creates it
  with `unshare --mount --propagation private`; on a host where that fails,
  attach refuses rather than leaking the host's resolver.
- Sharing one namespace means a browser's helper processes must live in it. A
  helper launched outside cannot reach the member's loopback by design.

## Amendment, 2026-10-28 (measured: the mark cannot split the host)

Dogfooding the landed v1 on the operator path (`vallum-quick up` →
`vallum-quick app … web -- curl …`) showed that the class discriminates but
changes no packet's path: the full tunnel's `not fwmark <interface mark>` rule
claims every process, so members and non-members both ride the tunnel. The
gate's own full-tunnel assertion with `app_class = true` says the same thing —
an outside lookup resolves into the tunnel.

The obvious repair — replace that rule with `fwmark 5140 table <policy>` and
leave the main table's default in place — was implemented and measured (netns
lab, kernel 7.0.0-38, nft 1.0.9, delegated cgroup subtree). It does **not**
work, for a reason the mark cannot touch:

- The rule installs, and only members are marked (class counter: host fetch 0,
  member fetch 7), so classification is exact.
- The member's datagram enters `vallum0` carrying the **physical** source
  address: `IP 192.0.2.1 > 203.0.113.9: ICMP echo request` on the client's
  tunnel device. The socket chose its route and source at connect time, before
  any output-chain mark exists; `ip_route_me_harder` re-routes the destination
  only.
- The peer drops it on cryptokey routing (source not in its `allowed_ips`):
  100 % loss for ICMP, a TCP connect timeout. A member's ping to the tunnel's
  own address still works — that isolates the cause to source selection, not to
  a broken tunnel.

A NAT-to-tunnel-address hairpin at output would give the packet the tunnel
source, with conntrack restoring the socket's local address on reply. It could
not be measured on this harness (`snat` is `EOPNOTSUPP` in the unprivileged
netns the gate runs in, and there is no root to run it outside); it is recorded
as an open option, not a decision.

**Therefore v1 is a classifier.** `[quick] app_class = true` installs the class
rule, the mark and the launch verb; the tunnel remains host-wide. This ADR's
motivating case — "the browser rides the tunnel, the terminal rides the
physical link" — is **not** delivered by v1, and no wording in this repository
should claim that it is.

### The v2 mechanism decision (decided: mechanism 1, implemented below)

Only two mechanisms give a member's sockets a tunnel-owned source before the
first lookup. Both are larger than a rule change, so the choice was made on a
measurement rather than on paper:

1. **A shared member network namespace** — one namespace, the tunnel interface
   moved into it, one resolver and one guard inside it; `app` launches into it.
   A kernel boundary that covers every app, static binaries included. Reverses
   the namespace-per-app alternative below in its *single shared namespace*
   form, and moves DNS, guard and interface work into that namespace.
   **Chosen.** Prototyped and then landed (`docs/proof/member-netns.md`): with
   the device moved after establishment, a member's fetch carried `10.7.0.2`
   while a host process kept its physical address, DNS resolved through the
   tunnel from a private `resolv.conf`, and the daemon plus its control plane
   survived the move. The implementation is the second amendment below.
2. **Socket marking at creation** — an eBPF `cgroup/connect4` program calling
   `bpf_setsockopt(SO_MARK)`, or an `LD_PRELOAD` shim setting `SO_MARK` in
  `socket()`. The latter silently misses static and uninstrumented binaries
  and is therefore unsuitable as the only mechanism.

## Amendment, 2026-10-28 (second): the shared member namespace, landed

Mechanism 1 above is implemented in `crates/vallum-quick/src/member.rs`. The
cgroup class, its mark, the leaf/sweep machinery and the `nft` tables are gone;
so is the `fwmark` requirement, which only existed to let the daemon escape a
host-wide tunnel the host no longer has.

What `attach` does for `[quick] app_class = true`:

- spawns a holder with `unshare --propagation private --mount --net` and waits
  for a ready token the holder writes only after its setup succeeded;
- when `[quick] dns` is set, writes a private `resolv.conf` naming those
  resolvers and bind-mounts it over `/etc/resolv.conf` *inside* the holder;
- moves the tunnel device into that namespace and gives it its configured
  addresses and a default route per family — and installs nothing on the host:
  no routes, no resolver, no `nft` tables;
- records `pid` and interface in `<state>/<iface>.quick-ns`, written after the
  setup so a failure leaves nothing to honour.

`app CONFIG NAME -- CMD` proves the record, the holder and the device, then
execs `nsenter -t <holder> -n -m -- CMD` and exits with the child's code.
`detach` issues the move home *inside* the holder (`ip` resolves names in its
own namespace), stops the holder, and removes the record; a device that cannot
be moved back is named rather than silently lost. `watch` refuses an
`app_class` config: there are no host routes to hold, and a dead session in the
namespace is already fail-closed.

Measured on the operator path in the lab (`docs/proof/member-netns.md`): a
member's fetch arrived from the tunnel address while a host fetch kept the
physical one, DNS resolved through the tunnel from the private file, `detach`
returned the device with the daemon still running, and a re-attach restored the
member path. The netns gate carries the same shape — host lookup physical,
member lookup and member DNS inside the tunnel, device home on detach, refusal
when detached, re-attach — and the full-tunnel phase's escape assertions now run
on a client without `app_class`, where they are true.

### Crash recovery (measured, landed)

A network namespace destroys the devices it holds, so a holder that dies does
not hand the tunnel back: the daemon is left without an interface, and no
`attach` can fix that because quick cannot create a TUN the daemon owns. Measured
on a real `init_net` and in the lab (`docs/proof/member-netns.md`): the device is
gone, the daemon is alive, and the record still claims an attachment.

Recovery therefore belongs to whoever owns the daemon, and the record must never
outlive the namespace:

- `up` owns the daemon it spawned. With no tunnel device present it stops that
daemon — matched by its command line, so a reused pid is never signalled — waits
for it to exit, starts a fresh one, and attaches around the new device. One
command, no reboot.
- `attach` (the systemd form) owns nothing, so it refuses with the truth instead
of waiting five seconds for an interface that cannot appear: it names the holder
that died, says the namespace took the device, and gives the unit to restart
(`systemctl restart vallum@<stem>`), never guessing a unit when the stem is
unreadable. The stale record is removed first, because a record naming a dead
namespace makes every later `app` fail with advice that cannot work.
- `detach` on a lost device says the daemon must be restarted rather than exiting
silently, and a record now carries the holder's start time so the recovery path
signals the holder and not whatever inherited its pid.

The session gate also had to move: `attach` waits for a handshake before it
routes the *host*, which per-app does not do. Waiting made per-app attach
impossible from a cold daemon (the first handshake comes from the first member,
after the namespace exists) and made crash recovery impossible (the crashed
daemon's handshake has aged out). `app_class` skips the gate; the member
namespace is still fail-closed by structure.

Still open, and named in the proof file: the systemd lifecycle of the holder, and
the sharing semantics of one namespace per tunnel.

