# The socket-cgroupv2 probe (ADR-0023's first implementation task)

ADR-0023 decided per-app split tunnelling rides a cgroup classifier extending
the full tunnel's mark tables, and made any `routes.rs` work conditional on a
probe: nft's `socket cgroupv2` must actually match, on the harnesses' kernels,
before code trusts it. The probe ran on 2026-10-23.

**Environment.** `wingman-vps` (the host `verify-remote.sh` targets), sudo over
SSH BatchMode: kernel `6.8.0-31-generic`, nftables `v1.0.9`, cgroup v2 unified
hierarchy. Scratch table `ip cgprobe`, scratch counters, scratch scope
`/probe.scope`; nothing left behind (`nft list tables` and `/sys/fs/cgroup`
verified empty afterwards). The probe scripts were session scratch in `/tmp`,
not committed: their value is the findings below, and the gate assertion that
will replace them is repo code.

## Findings

1. **nft validates the cgroup path at rule-add time.** Adding a
   `socket cgroupv2 level 0 "/probe.scope"` rule before the directory exists
   fails with `cgroupv2 path fails: No such file or directory` — and two probe
   runs silently reported "ok" while the rule of interest never installed (the
   checks had verified the *table*, not the rule). A counting probe is
   worthless unless both the control and the positive assert. The lesson for
   the implementation: the `app` verb must create the scope before any table
   that names it — and it is also why the probe's own first two runs lied.

2. **`level 0` (exact-path compare) never fired — even correctly installed.**
   With the scope existing before the rule, a scoped ping left the level-0
   counter at 0 while a `level 1` rule against the same path counted 2 packets
   for the same traffic. On 6.8.0-31 the match form that fires is the
   **first-component compare**:

   ```
   nft add rule ip cgprobe output socket cgroupv2 level 1 "probe.scope" counter
   ```

   This is not a blocker — it is the form ADR-0023 wants anyway: membership is
   *one class*, matched by a shared top-level directory, not by per-app paths.

3. **Inheritance is real.** A descendant spawned inside the scope (`bash -c
   'ping ...'`) was counted without anything being re-classified, and a child
   scope of a member (`/probe.scope/browser/tab`) also counted under the same
   single rule. This is the kernel-inheritance property the membership
   decision leans on; it measured up.

4. **Traffic from real sockets counts.** ICMP (`ping`) and TCP (python3 client
   sockets; two connect attempts counted across SYN retransmits) both hit the
   rule. The unscoped control ping stayed at 0 through the rule's life in
   every clean run, so the discriminator is real, not just a counting rule.

5. **The ADR's exact model, measured.** One rule `level 1 "probe.scope"`
   counted traffic from BOTH member scopes `/probe.scope/browser` and
   `/probe.scope/chat` (2 + 2), the nested child (+2), and nothing outside the
   class — one mark, one rule, per tunnel, at any member depth.

## Verdict

PROBE-PASS on the remote harness. ADR-0023's mechanism is feasible on this
kernel in the form the ADR states, provided the rule uses **level 1** and the
member scopes are created **before** any classification table is installed.

## The local-harness leg (same day)

The sandbox runs unprivileged (uid 1000, no CAP_NET_ADMIN), so the remote
form of the probe cannot repeat verbatim — but a systemd-delegated subtree
covers the local side, and this is the environment the gate's own unprivilege
runs in (`unshare -Urn --map-root-user`, kernel 7.0.0-38, nft 1.0.9):

- a process inside the userns (host kuid 1000) moves itself into a member
  scope under `user@1000.service` — delegation reaches mapped credentials;
- the installable spell differs from the probe's: a single component name
  only resolves for a **top-level** class (`nft` validates the string against
  the hierarchy root at rule-add time), and slashes are unnameable through
  the argv grammar at all (`unexpected /`). The deep-class form the
  delegated case needs is only writable through `nft -f`:

  ```
  socket cgroupv2 level 4 "user.slice/user-1000.slice/user@1000.service/vallum-e2e"
  ```

  which installed and — with a machinery control (`ip daddr 127.0.0.1
  counter`, counting everything loopback-destined) — counted exactly the
  traffic of a member process and nothing from outside it: control 6 packets,
  class 0; after the move, class 3 of 3 sends. This also re-explains level 0:
  an exact-path compare needs slashes in the compare string, so argv-level
  `level 0` can never fire — not a kernel quirk, a grammar boundary.

## The gate case

The probe is now repo code: `scripts/e2e-netns.sh` carries a member-only
assertion phase that creates the class directory before any rule names it,
installs one rule, and requires three things: unscoped traffic misses the
class while a daddr control proves counting works; a class member's traffic
hits the rule; and a nested member is counted by the same single rule — the
shared-class shape ADR-0023 decided. On a host with neither a writable
hierarchy root nor a delegated subtree it prints a note and skips, named as
skipped, never as passed. First full run 2026-10-23 (kernel 7.0.0-38,
delegated subtree): all three `ok` and the gate's `== PASS`.

The same phase now carries the pair the plan's addendum required. The same
mark rule in a `type route hook output` chain steers a member's datagram into
a blackhole table — the send dies with `EINVAL` before it leaves — while the
same rule in a `filter` chain matches (its counter says so) but cannot steer:
the datagram is emitted, because routing already read the mark. That is the
reason the class rule is a `route` chain, measured rather than preferred.

The verb lifecycle also used to live in the full-tunnel phase: the gate left an
empty leaf before `attach` and required it swept, ran `vallum-quick app CONFIG
probe -- sh -c 'sleep 2; ping …'`, saw `probe-<pid>` appear under the class
while it ran, watched a gate-added counter increment, required the leaf gone
when the clean launch exits, and flushed the chain and required the pre-flight
to refuse rather than launch outside the class. First full run with these cases,
2026-10-28 (kernel 7.0.0-38, nft 1.0.9, delegated subtree): `== PASS`.

**Both class phases are retired (2026-10-28).** When the mechanism became the
shared member namespace, the class directory, the `socket cgroupv2` rule and
the leaf sweep stopped being the enforcement boundary, so the gate phases that
asserted them were removed rather than kept green over dead machinery. What
replaced them is the member-namespace phase: the device leaves the client's
namespace, the client keeps its own path, a launched member's lookup and DNS
resolve inside the tunnel, `detach` returns the device, and the verb refuses
afterwards. The findings above remain the record of why that class could not
carry the traffic it classified.

## The exclusive attempt, and why v1 is a classifier (2026-10-28)

Dogfooding the landed v1 through the operator path rather than the gate — a
real server daemon in one netns, an "internet" host beside it, the client
brought up with `vallum-quick up`, then `vallum-quick app … -- curl …` — found
that the class discriminates but changes no packet's path. Counting rule added
beside the class rule, internet host behind a default route only:

```
class counter after the HOST fetch:   0
class counter after the MEMBER fetch: 5
seen: /host   from 10.7.0.2
seen: /member from 10.7.0.2
route for a host process: 203.0.113.9 dev vallum0 table 51820
```

The full tunnel's `not fwmark` rule claims every process, so `app_class` is
additive: members are marked and nothing else changes. The repair the ADR's
"no new `ip rule`" economy implied — `ip rule add fwmark 5140 table 51820` and
leave the main table's default alone — was implemented and measured. It
installs and discriminates (`ip rule` shows `32765: from all fwmark 0x1414
lookup 51820`, no `not fwmark`, no `suppress_prefixlength`; the non-member's
fetch stays physical with the class counter at 0; the member's fetch is
counted at 7). It does not carry traffic:

```
# tcpdump on the client's vallum0 during a member ping to 203.0.113.9
IP 192.0.2.1 > 203.0.113.9: ICMP echo request
```

The packet enters the tunnel with the **physical** source address. The socket
chose its route and source at connect time, before the mark existed;
`ip_route_me_harder` re-routes the destination and keeps the source, so the
peer's cryptokey routing drops it (source not in `allowed_ips`) — 100 % loss,
TCP connect timeout. The control isolates the cause: a member pinging the
tunnel's own address (`10.7.0.1`) works, because that destination picks
`vallum0` at creation and the source is then `10.7.0.2`.

A NAT-to-tunnel-address hairpin at output would give the packet the tunnel
source, with conntrack restoring the socket's local address on the reply. It
could not be measured here: `snat` returns `EOPNOTSUPP` in the unprivileged
netns this gate runs in, and there is no root to run it outside. It stays an
open option.

Verdict: mark-at-output steers packets but cannot give member sockets a
tunnel-owned source, so v1 is a classifier on a host-wide tunnel. Exclusive
per-app routing needs a shared member netns or socket marking at creation
(eBPF connect hook, or an `LD_PRELOAD` shim that misses static binaries) —
ADR-0023's 2026-10-28 amendment carries the decision and both candidates, and
the netns form is now measured in `docs/proof/member-netns.md`.

ADR-0023's risk notes record the measured form; this file is the record; the
ADR is the decision.
