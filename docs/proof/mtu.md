# H6 — MTU-aware segmentation

**Status:** closes the assumption P6.7 recorded — that the outer path is 1500
bytes — for paths that are narrower (PPPoE 1492, an IPsec tunnel 1400, a
provider that black-holes fragments).
**Depends on:** P6.7 (`docs/proof/segment.md`) for the envelope this changes the
budget of, P6.4 (`docs/proof/daemon.md`) for the MTU policy it extends.
**Wire change:** none. The envelope is unchanged; only how large each fragment
is, and that is a local, per-path choice. At the default the bytes are identical.

---

## 1. The gap

`MAX_OUTER_DATAGRAM` was a compile-time 1452, derived from a 1500-byte path. On a
narrower path:

- the handshake still crossed as whole UDP datagrams (P6.7's fix), but each was
  larger than the path, so the kernel fragmented them anyway — the envelope
  cannot help if its *own* datagrams are too big;
- a full-size data message was one datagram the kernel had to fragment or drop;
- nothing told the operator, because a fragment that is dropped is silence.

The daemon cannot discover the path (that is DPLPMTUD, §5), so the operator states
it.

---

## 2. The surface

```toml
[interface]
outer_mtu = 1000   # default 1500
```

- `budget = outer_mtu - 48` (IPv6 header 40 + UDP 8), so 1500 → **1452** (the
  old constant) and 1000 → **952**. That is the *configured* budget, the IPv6
  worst case; the segmenter gives a v4 destination the 20 bytes a v4 header does
  not spend (`budget_for`), so a 1000-byte path is 972 for v4 and 952 for v6.
- Validated at load:
  - `budget >= MIN_MTU (576) + DATA_OVERHEAD (58) = 634`, so the smallest legal
    inner packet still fits; the error prints the arithmetic and the minimum
    `outer_mtu` (682).
  - `budget <= MAX_OUTER_DATAGRAM` — above 1500 is refused, because the
    protocol's parse cap and const assertions are built on 1452. The knob adapts
    **downward only**.
- The inner MTU follows when it is not set explicitly:
  `mtu = min(DEFAULT_MTU, budget - 58)`, so 1000 → 894 and 1500 → 1380
  (unchanged). An explicit `mtu` that exceeds the budget is legal but warns:
  data packets are then segmented, still correct, no longer one datagram each.
- The budget is threaded to the transport: `Resolved.outer_budget` →
  `run::Attached.budget` → `Segments::with_budget`, and
  `segment::split_with_budget` cuts to it. The receiver needs no change: the
  envelope's offsets are explicit and the parse cap stays `MAX_FRAGMENT_DATA`,
  which every smaller budget is below.

### Loud failure

- `EMSGSIZE` on a send is logged once per destination at warn level, naming
  `interface.outer_mtu` and the current budget — the one error that means "the
  configured path is too large for the real one".
- **Both families ask the kernel to report, not fragment.** On an IPv4 socket
  `IP_MTU_DISCOVER = IP_PMTUDISC_DO`; on an IPv6 socket `IPV6_DONTFRAG`. Both are
  set in `UdpTransport::bind` and both are **fatal** if they fail: a daemon that
  cannot make the guarantee should not pretend it did.
  - The v4 option is set through `rustix` (`set_ip_mtu_discover`), the one safe
    wrapper that exposes it — `nix` 0.31 has `IpMtu` as a getter only and
    `socket2` 0.6 not at all. This is why no `unsafe` crate was needed.
  - A unit test reads the option back (`a_v4_socket_asks_the_kernel_not_to_fragment`),
    so the test asserts the kernel state rather than the call.

---

## 3. Why the default is byte-identical

`outer_mtu` defaults to 1500 → budget 1452 → the same fragment payload (1442) and
the same threshold. The frozen vectors do not move (the envelope is below the
message layer), and the existing unit tests that assert the default split still
pass unchanged.

---

## 4. Measured

The e2e now runs a second daemon lifecycle with `outer_mtu = 1000` appended to
both configs:

```text
── restarting on a 1000-byte outer path (outer_mtu = 1000)
   ok    a 728-byte inner packet crossed a 972-byte v4 budget
   ok    no IP fragment was created on the narrow path either
── shutting the narrow-path daemons down
   ok    the narrow-path daemons exited on SIGTERM
```

The in-process gate adds the wiring test:
`a_narrow_outer_mtu_carries_the_handshake_and_segments_data` — two daemons, a
900-byte payload (978-byte data message) over a 972-byte v4 budget, delivered after
segmentation, handshake reassembled. Unit tests cover the arithmetic and the
bounds (`a_narrow_outer_mtu_derives_the_inner_mtu`,
`an_outer_mtu_below_the_minimum_is_refused`,
`an_inner_mtu_over_the_outer_budget_warns`, `a_smaller_budget_cuts_more_and_reassembles_the_same`,
`a_narrow_budget_is_honoured_on_the_way_out`).

### Measured: a path narrower than the knob is loud

The e2e lowers the veth pair to 1200 bytes and runs with the default 1500-byte
assumption:

```text
── narrowing the outer path to 1200 bytes without telling the daemon
   ok    the kernel reported the oversize datagram instead of fragmenting it
   ok    nothing was fragmented
   ok    the handshake failed loudly rather than crossing in fragments
── naming the real MTU (outer_mtu = 1200) makes the same path work
   ok    a 1200-byte path with outer_mtu = 1200 carries traffic
   ok    and no oversize datagram was reported
```

This is the property stated as a measurement: with `IP_MTU_DISCOVER = DO` the
kernel returns `EMSGSIZE` and `FragCreates` stays flat, so the operator sees the
misconfiguration instead of a silently fragmented (or black-holed) path.

---

## 5. What this does **not** claim

1. **No discovery.** Nothing probes, pads, or learns a path MTU. DPLPMTUD would
   need probe sizes, a feedback signal, black-hole detection, and timers — a
   protocol feature, not a knob. The operator states the path.
2. **No per-path budget.** The budget follows the destination *family*, not a
   discovered path; two peers behind different path MTUs need different
   `outer_mtu` values, which means different deployments.
3. **No upward adaptation.** Jumbo paths are not used; the cap is 1452.
4. **No change to the receiver's bounds.** `MAX_FRAGMENT_DATA` still caps a
   fragment at 1442; a smaller budget is always below it.
5. **The configured budget is the IPv6 worst case, deliberately.** One daemon
   has one configured budget (`outer_mtu − 48`) because a peer's endpoint can
   roam to the other family, so `listen` is not a safe predictor. The
   **segmenter** then chooses per message: `budget_for(destination)` gives a v4
   destination the 20 header bytes back (capped at `MAX_OUTER_DATAGRAM`), and a
   v6 destination the configured budget. The config's derived inner MTU stays
   conservative for the same roaming reason.
