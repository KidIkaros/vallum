# H9 — dual-stack interface addressing, and a v6 outer path

**Status:** closes the gap the H7 review exposed — one `address` field meant a
tunnel could carry IPv4 **or** IPv6 on its interface, never both — and the
remaining outer-path gap, a transport bound to IPv6.
**Depends on:** H7 (`docs/proof/ipv6.md`) for the netlink assignment this
generalises, H6 (`docs/proof/mtu.md`) for the budget, P6.4 for the daemon.
**Wire change:** none. Inner addressing and the outer socket only.

---

## 1. The gap

```toml
[interface]
address = "10.7.0.1/24"   # or fd00:7::1/64 — not both
```

- `tun2`'s configuration path is an `AF_INET` ioctl and holds **one** address.
  H7 added netlink for the v6 case but kept the single field, so a dual-stack
  tunnel needed a manual `ip -6 addr add` (or the reverse) after the daemon
  started.
- The transport could bind a v6 socket, but nothing tested it: the e2e's outer
  veth was v4-only. `IPV6_DONTFRAG` and the v6 cookie-address encoding were
  exercised only by unit tests.

---

## 2. The surface

```toml
[interface]
addresses = ["10.7.0.1/24", "fd00:7::1/64"]
```

- `address` remains the single-address shorthand; both fields may be used and
  are merged in config order. An exact duplicate is dropped with a warning.
- **Every** address is now assigned over netlink after `tun2` creates the
  device — v4 and v6 alike. That removes both `tun2` limits at once (one
  address, AF_INET only) and means the v4 path is no longer a special case.
- `IFA_LOCAL` **and** `IFA_ADDRESS` are both sent, as `ip addr add` does. The
  v4 kernel path requires the second (`ERANGE` without it) — found the hard way
  by the gate.
- `IFA_F_NODAD` for v6 only; v4 has no equivalent.
- An **IPv4-mapped IPv6 prefix** (`::ffff:10.0.0.1/128`) is refused at load — as
  an interface address **and** in a peer's `allowed_ips` — with the v4 form to
  write instead. It is a v6 prefix, so it matches no v4 source and routes no v4
  packet: a trap, not a shorthand.
- The IPv6 MTU floor (1280) applies when **any** configured address is v6; the
  v4 minimum (576) always applies.

---

## 3. The outer path

The e2e now gives the veth pair both families (`fd00:99::/64`) and runs one
lifecycle with:

- `listen = "[fd00:99::1]:51820"` and `endpoint = "[fd00:99::2]:51820"` — a v6
  outer socket, `IPV6_DONTFRAG` set, cookies keyed by a v6 `SocketAddr`;
- `addresses = ["10.8.0.1/32", "fd00:8::1/128"]` — one address of each family,
  both `/32`-sized so no connected route exists and the operator's host routes
  are exercised (and the config warning names them).

---

## 4. Measured

```text
── restarting with a v6 outer path and dual-stack /32 inner addresses
   ok    one interface carries both families, assigned by the daemon
   ok    IPv4 crossed a dual-stack tunnel over a v6 outer path
   ok    IPv6 crossed the same tunnel
   ok    both families crossed back
── shutting the dual-stack daemons down
   ok    the dual-stack daemons exited on SIGTERM
```

The reverse direction proves the responder's learned v6 endpoint and the
inbound `allowed_ips` check for both families. The `nodad` flag is visible on the
assigned address (`inet6 fd00:8::1/128 scope global nodad`).

Unit tests:
`a_dual_stack_config_assigns_both_families`, `address_and_addresses_merge_and_dedupe`,
`an_ipv4_mapped_v6_address_is_refused`, `an_ipv4_mapped_v6_allowed_ip_is_refused`;
the message layout, without privileges —
`a_v4_request_is_af_inet_with_both_attributes` and
`a_v6_request_is_nodad_and_carries_the_128_bit_address`; and the routing tests
`a_default_route_covers_every_v4_destination`,
`multicast_and_broadcast_destinations_are_matched_by_prefix`,
`a_default_route_peer_owns_every_v4_destination`.

---

## 5. What this does **not** claim

1. **No SLAAC/DHCPv6.** Every address is static config.
2. **No address removal or reconfiguration.** The set is fixed at startup.
3. **No route management.** A `/32` or `/128` installs no connected route; the
   operator adds host routes (the config warning prints them). A wider prefix
   still gets its connected route from the kernel.
4. **No dual-stack *peer* endpoint.** A peer has one `endpoint`; if it is v6, the
   outer path is v6 for that peer. Mixed-family outer paths are per-deployment.
5. **No v4-mapped v6.** Refused, §2.
6. **No multicast routing.** A peer granted `224.0.0.0/4` will carry multicast
   the kernel routes to the interface; installing that route is the operator's
   job, and the routing layer itself has no special case (tested).
7. **The configured budget is still `outer_mtu − 48`**, the v6 worst case,
   because a peer's endpoint can roam to the other family. The *segmenter* uses
   the destination family per message (`budget_for`), so a v4 peer gets the 20
   header bytes back — see `mtu.md` §5. The config's derived inner MTU stays
   conservative for the same reason.
