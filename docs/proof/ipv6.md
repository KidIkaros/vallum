# H7 — IPv6 interface address assignment

**Status:** closes P6.4's limitation that an IPv6 interface address was a warning
with an `ip -6 addr add` command attached, leaving the daemon half-configured.
**Depends on:** P6.4 (`docs/proof/daemon.md`) for the interface setup order, H6
(`docs/proof/mtu.md`) for the inner-MTU floor this interacts with.
**Wire change:** none. Inner addressing only; the outer transport is unchanged.

---

## 1. The gap

`tun2` configures an address with `SIOCSIFADDR` and an `AF_INET` sockaddr. It
cannot express an IPv6 address, so the daemon warned and printed the command the
operator should run. A tunnel that starts half-configured is a tunnel whose
symptom — "the peer is up but nothing routes" — is indistinguishable from a
broken handshake.

---

## 2. The mechanism

After `tun2::create` returns the interface name, a v6 address is added over
netlink (`RTM_NEWADDR`):

- `netlink-sys` owns the socket and `netlink-packet-route` the message, so
  Vallum's crates keep `unsafe_code = "forbid"`.
- Header: `AF_INET6`, the prefix length, `ifa_index` from `if_nametoindex`, and
  **`IFA_F_NODAD`**.
- Attribute: `IFA_LOCAL` only — what `ip addr add` sends for a normal prefix;
  `IFA_ADDRESS` is for a peer address.
- The request asks for `NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL`
  and the reply is checked: an ACK (no error code) succeeds, `EEXIST` is
  idempotent success, anything else is a startup error naming the address and the
  errno.
- A failure is fatal. The daemon does not start with an interface it could not
  configure.

---

## 3. Two things the gate found

**(a) IPv6's minimum link MTU is 1280, and the kernel enforces it by refusing
the address.** H6 derives the inner MTU from the outer budget; `outer_mtu = 1000`
derives 894, and `RTM_NEWADDR` then fails with `EINVAL` — an errno with no useful
hint. The config now:

- **floors** a derived inner MTU at 1280 when the address is v6, and warns that
  every full-size data packet will be segmented (which is exactly what the
  envelope is for);
- **refuses** an explicit `interface.mtu` below 1280 when the address is v6, with
  a message naming the minimum. The kernel would refuse it anyway; the load-time
  error says why.

**(b) Duplicate address detection is meaningless on a TUN and costs a second of
silence.** Without `IFA_F_NODAD` the address is tentative while DAD's neighbour
solicitations go nowhere, and the kernel drops traffic to it in the meantime.
`nodad` is the same choice `ip addr add ... nodad` makes, and it is what the e2e
needed to get a reply on the first ping.

A third lesson is in the gate itself, not the daemon: the v6 phase first pinged
**from B**, which has no configured endpoint and therefore nothing to dial. The
packet queued forever and the daemon correctly sent zero datagrams. The phase now
starts from A, as the IPv4 establishment phase always did.

---

## 4. Measured

```text
── restarting with IPv6 inner addresses
   ok    the daemon assigned its IPv6 address and the kernel installed the route
   ok    ping6 crossed the tunnel (fd00:7::1 -> fd00:7::2)
   ok    ping6 crossed back (fd00:7::2 -> fd00:7::1)
── shutting the IPv6-path daemons down
   ok    the IPv6-path daemons exited on SIGTERM
```

Both directions, over the same two daemons and the same v4 outer path; the
reverse direction proves the responder's learned endpoint and the inbound
`allowed_ips` check work for v6.

Unit tests cover the MTU interaction:
`a_v6_address_floors_a_narrow_inner_mtu`, `a_v6_address_below_the_minimum_mtu_is_refused`.

---

## 5. What this does **not** claim

1. **No SLAAC, no DHCPv6.** One static address from the config.
2. **No multiple addresses in H7.** One `address` per interface. **H9 lifts
   this**: `addresses = [...]` assigns any number, of either family, over the
   same netlink path — see [`dual-stack.md`](dual-stack.md). Address removal is
   still out of scope.
3. **No v6-only deployment in H7.** The outer transport is whatever
   `interface.listen` binds; H7's e2e exercised a v4 outer path. **H9 tests a v6
   outer path** end to end, including `IPV6_DONTFRAG` and the v6 cookie encoding
   — see [`dual-stack.md`](dual-stack.md).
4. **No IPv6 route management.** The connected route comes from the kernel when
   the address is assigned; peers outside the prefix still need an `ip route`
   (the existing warning covers that).
5. **No DNS, no neighbour discovery tuning.** Out of scope.
6. **`EEXIST` is treated as success.** Re-adding an address the interface already
   has is the state the operator asked for; a second daemon on the same interface
   would still conflict on the socket.
