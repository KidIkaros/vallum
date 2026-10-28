# The shared member namespace prototype (ADR-0023 amendment, mechanism 1)

ADR-0023's 2026-10-28 amendment records why mark-at-output cannot split a host:
a socket chooses its route and source before any output-chain mark exists, so a
"member" packet enters the tunnel carrying the physical source and the peer
drops it. It names two mechanisms that could give members a tunnel-owned source.
This file is the measurement of the first: **one shared member namespace**, with
the tunnel device moved into it.

Prototyped 2026-10-28, lab only — no product code changed. Unprivileged
`unshare -Urn --map-root-user`, kernel 7.0.0-38. No `nft` rule and no cgroup
class were involved: the point was to test whether the namespace alone decides
the route.

## The question

Does a process launched into a namespace that owns the tunnel interface carry
the *tunnel* source address, and does the host outside that namespace keep its
own path?

## Method

- Server daemon in its own netns (`10.7.0.1/24`, listening on `192.0.2.2:51820`),
  with an "internet" host at `203.0.113.9:8080` beside it.
- Client daemon on the host netns (`10.7.0.2/24`, endpoint `192.0.2.2:51820`,
  `allowed_ips 0.0.0.0/0`, `fwmark = 51820`), session established first.
- A shared member netns created, then `ip link set vallum0 netns <member>`; the
  namespace gets `vallum0 up`, `10.7.0.2/24`, and `default dev vallum0`.
- Member: `nsenter -t <member> -n curl http://203.0.113.9:8080/member`.
- Control: the same fetch from the host namespace (a non-member).
- Both requests land on the same HTTP server, which logs the source address.

## Findings

1. **The device moves and the daemon keeps working.** The host no longer has
   `vallum0` (`Device "vallum0" does not exist`); the daemon, still in the host
   namespace with its tun fd and outer UDP socket, carried the session across the
   move without a restart.
2. **The member's lookup is the tunnel's, with the tunnel's source.**

   ```text
   member lookup: 203.0.113.9 dev vallum0 src 10.7.0.2
   ```

3. **The member's traffic carries the tunnel source.** The fetch returned
   `200`, and the internet host logged:

   ```text
   /member from 10.7.0.2
   ```

   That is the exact property the mark could not deliver: no mark, no cgroup
   rule, no source rewrite, no app cooperation.
4. **The host is unaffected.** The control fetch also returned `200`, and the
   same server logged it from the host's own address:

   ```text
   /host from 192.0.2.1
   ```

   One interface, two paths, decided by namespace membership rather than by
   packet inspection.
5. **The tunnel still works inside the namespace.** A member ping to `10.7.0.1`
   answered (0 % loss). The member's own default route is the tunnel, so a dead
   session would be fail-closed by structure rather than by a blackhole rule;
   that state was not exercised here.
6. **The control plane survives the move.** After moving the device,
   `vallum show --config` answered with the interface, address and listen port
   (`vallum_interface=vallum0`, `vallum_address=10.7.0.2/24`,
   `listen_port=51821`), and the end of `doctor --config` was PASS lines (config
   mode, path-mtu, clock, tool presence). No command had to learn about the
   namespace for this prototype.

One server log line is worth keeping so a later reader does not mistake it for
a drop: the reply from the local `203.0.113.9` was carried by the tunnel's relay
path (`relaying packet from 203.0.113.9: not an address here, and
[interface] forward is on (ADR-0020)`). That is the documented relay behaviour
for a packet whose source is not the interface's own address; the fetch
completed.

## Verdict

Mechanism 1 delivers the missing property. The namespace decides the route
before the socket exists, so the source is the tunnel's by construction, and the
host keeps its physical path with no rule of any kind. Nothing about the
measurement depends on cgroups, marks or `nft`, which also means the class rule
and the leaf machinery stop being the enforcement boundary: `app` would become a
launcher into the namespace, and membership would be "in the namespace".

That is what landed: `crates/vallum-quick/src/member.rs` is the prototype's
shape with the lifecycle the ADR amendment describes, so this file is the
measurement behind the code rather than a proposal for it.

## DNS in the namespace (measured)

A namespace with a private `resolv.conf` was measured against one without it:

- **Control (net namespace only):** `/etc/resolv.conf` inside is the host's file
  (same `sha256`), so a member would resolve through the host's resolver — the
  leak the ADR's namespace alternative warned about.
- **Member (net + mount namespace):** `mount --bind` a file naming
  `nameserver 10.7.0.1` over `/etc/resolv.conf`, with a resolver bound on the
  tunnel address. Inside the namespace:

  ```text
  member resolv: nameserver 10.7.0.1
  getent:        203.0.113.9     probe.test
  ```

  and `curl http://probe.test:8080/member` returned `200`, arriving at the
  internet host as `/member from 10.7.0.2 via probe.test:8080` — resolved in the
  namespace, carried by the tunnel, with the tunnel's source address.
- **The host was untouched:** `/etc/resolv.conf`'s `sha256` was identical before
  and after the member's bind mount, and the host's own fetch used its own
  resolver.

So the DNS story the ADR deferred is solvable without new product machinery:
`resolv.conf` is per mount namespace, and one bind mount is enough. What remains
is who owns that mount namespace and when it is created — product work, not a
kernel question.

## What this prototype did **not** decide

These were the design tasks before an amendment; ADR-0023's second amendment
records what the landed implementation decided for each. The open ones are
marked:

- **DNS.** Measured above: a private `resolv.conf` bind-mounted in a mount
  namespace, naming the tunnel's resolver, resolves through the tunnel and
  leaves the host's file alone. The open part is ownership — who creates the
  mount namespace and how `detach` tears it down — not whether it works.
- **Membership surface.** The cgroup class, the mark and the leaf/sweep
  machinery become redundant as enforcement; either they go, or they stay as
  bookkeeping while the namespace is the boundary. `vallum-quick app` and
  `detach` need to own the namespace's creation, device move, member launches
  and teardown.
- **Lifecycle and crash recovery.** A device left in a namespace whose holder
  died, a daemon restart while the device is elsewhere, and `down` moving the
  device back were not exercised.
- **Sharing semantics.** One namespace means members share loopback and can
  reach each other's local services; a browser's helper processes must live in
  the same namespace to talk to it. This is the cost the ADR's namespace
  alternative named, now scoped to one shared namespace instead of one per app.
- **Guard and alerts.** Fail-closed would be structural inside the namespace,
  but the product's blackhole plan, verdicts and alerts are host-side today and
  would need to be re-stated for the member namespace; the dead-session path was
  not exercised.
- **IPv6 and the interface-name ceiling.** Not exercised; one shared namespace
  needs one interface, so the 15-character concern that argued against
  namespace-per-app does not apply in this form.
