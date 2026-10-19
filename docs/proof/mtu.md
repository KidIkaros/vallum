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
  old constant) and 1000 → **952**.
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
- On an IPv6 socket, `IPV6_DONTFRAG` is set (best effort) so the kernel reports
  instead of fragmenting. IPv4 has no safe equivalent in `nix`; there the knob is
  the control, and the artefact says so.

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
   ok    a 728-byte inner packet crossed a 952-byte outer budget
   ok    no IP fragment was created on the narrow path either
── shutting the narrow-path daemons down
   ok    the narrow-path daemons exited on SIGTERM
```

The in-process gate adds the wiring test:
`a_narrow_outer_mtu_carries_the_handshake_and_segments_data` — two daemons, a
900-byte payload (978-byte data message) over a 952-byte budget, delivered after
segmentation, handshake reassembled. Unit tests cover the arithmetic and the
bounds (`a_narrow_outer_mtu_derives_the_inner_mtu`,
`an_outer_mtu_below_the_minimum_is_refused`,
`an_inner_mtu_over_the_outer_budget_warns`, `a_smaller_budget_cuts_more_and_reassembles_the_same`,
`a_narrow_budget_is_honoured_on_the_way_out`).

---

## 5. What this does **not** claim

1. **No discovery.** Nothing probes, pads, or learns a path MTU. DPLPMTUD would
   need probe sizes, a feedback signal, black-hole detection, and timers — a
   protocol feature, not a knob. The operator states the path.
2. **No per-destination budget.** One daemon, one outer path. A peer reached over
   a different path needs a different deployment.
3. **No IPv4 `DF` control — accepted by design.** `IPV6_DONTFRAG` is set on v6
   sockets. Neither `nix` 0.31 (`IpMtu` is a getter) nor `socket2` 0.6 exposes
   `IP_MTU_DISCOVER`, and setting it through `libc` would need `unsafe`, which
   every Vallum-owned crate forbids. So an overstated `outer_mtu` on a v4 path
   can still be fragmented by the kernel. The knob is the control, `EMSGSIZE` is
   logged when the kernel does report it, and this is recorded rather than
   papered over.
4. **No upward adaptation.** Jumbo paths are not used; the cap is 1452.
5. **No change to the receiver's bounds.** `MAX_FRAGMENT_DATA` still caps a
   fragment at 1442; a smaller budget is always below it.
6. **The 48-byte header assumption is IPv6's, deliberately.** The budget is
   **global**: one daemon has one segmenter, and its peers may be reached over
   either family, so the worst-case header is the only safe constant. An IPv4
   outer path therefore has 20 bytes of slack — conservative, not wrong. Making
   the budget depend on `listen` would be wrong for a daemon whose peers are
   reached over the other family.
