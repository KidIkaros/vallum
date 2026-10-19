# P6.7 — application-layer segmentation, and the dependence P6.4 recorded

**Status:** post-gate follow-up to P6.4. Covers `vallum_core::segment` (the wire
form), `vallum_tunnel::Segments` (the stateful half), and the four places the
daemon's loop and MTU arithmetic touch it.
**Depends on:** P6.4 (`docs/proof/daemon.md`) for the loop and the MTU policy, P6.6
(`docs/proof/keepalive.md`) for the NAT-bound peer this exists to reach, P1/P2 for
the messages being carried.
**Wire change:** **none.** The envelope sits *below* the message layer, so every
`Message` is byte-identical and the frozen vectors did not move — verified, not
assumed. This contradicts the prediction P6.4 recorded, and §0(a) says why.

---

## 0. What this gate forced

**(a) P6.4 named the gap correctly and predicted the cost of closing it
incorrectly.** That document's §5 recorded, as a non-claim, that one datagram was
one message, that the handshake therefore relied on IP fragmentation, and that
"fixing it means a new framing level — a wire change, and the frozen vectors would
move". Two of those three clauses were right.

The framing level is real. The wire change was not: the frames go *under* the
messages, on the transport, and the message bytes are untouched. The prediction
failed because it assumed the fix would be a `MessageType` — a protocol change —
when the cheaper fix is to not be a message at all. The byte that would have
collided is reserved instead (§2.1), and `Message::parse` refuses it, so the two
framings cannot be confused.

**(b) The old claim was already false, in two places, in prose.** `wire.rs` and
`daemon.md` both said a handshake "is never split across IP fragments. Nothing
relies on fragmentation." The second half was never true — §0b of `daemon.md`
measures `FragCreates +4` — and the first half was true only in the sense that the
*message* was not split; the datagram carrying it was. A comment that describes an
invariant the code does not have is worse than no comment, because it is read
during the next review and believed. Both are corrected here.

**(c) A fragment arriving after its message completed opens a new reassembly.**
Found by a test whose ordering put the duplicate fragment last, where it failed
with `pending() == 1`. This is inherent and correct: the receiver cannot remember
that a `message_id` is finished without keeping an unbounded set of spent ids, and
it must not trust the id. The cost is one bounded, expiring slot per late
duplicate, which §2.5 accounts for rather than hides. The test was changed to
duplicate a fragment *before* completion, which is the case that matters, and
§2.5's bound covers the other.

---

## 1. The obligation, stated exactly

**No datagram Vallum emits may require IP fragmentation.**

Not for throughput, and not for correctness on a well-behaved path — for
reachability on a real one. The failure mode this exists to remove:

- A fragmented IPv4 datagram is a first fragment, which carries the UDP header,
  and continuation fragments, which do not. A NAPT translates by port. In the
  fragments that have no UDP header there is no port to translate, so it drops
  them.
- The retransmission is identical, so it is fragmented identically, and it is
  dropped identically. The handshake retransmits into the same wall every 5 s, for
  90 s, and then gives up. A stateful firewall that reassembles before deciding
  commonly fails the same way, and IPv6 fragment handling is worse than IPv4's.
- The symptom is a peer that looks down. There is no error, because nothing in the
  path reports that it dropped a fragment.

A fragment in this design is a **complete UDP datagram** with a transport header,
so it traverses a NAT exactly as a data packet does. That is the entire point, and
it is the reason §2.5's other properties (bounds, timeouts, eviction) are
secondary.

The budget is therefore stated as a datagram size, not as a message size:

```text
1500  path MTU we assume by default (configurable since H6, see mtu.md)
 - 40  IPv6 header (the worst case; IPv4 has 20 bytes of slack)
 -  8  UDP header
=1452  MAX_OUTER_DATAGRAM, the largest UDP payload Vallum puts on the wire
```

---

## 2. Mechanism (normative)

### 2.1 The envelope

```text
┌─────────┬──────────┬─────────────┬──────────┬─────────┬──────────────┐
│ version │   0x07   │  message_id │  offset  │  total  │     data     │
│   u8    │    u8    │   u32 (BE)  │  u16(BE) │ u16(BE) │  ≤ 1 442 B   │
└─────────┴──────────┴─────────────┴──────────┴─────────┴──────────────┘
 10-byte header, FRAGMENT_HEADER_LEN
```

`FRAGMENT_CODE = 0x07` sits where a `MessageType` code sits, and it is **reserved**
rather than assigned. `MessageType::from_code(0x07)` returns `None` and
`Message::parse` refuses it, so `01 07` can only be a fragment and two bytes
classify a datagram. There is no second parser to disagree with the first:
reassembly produces a `Vec<u8>` that goes to the same `Message::parse` a whole
datagram would have. A test pins both halves of that invariant, because the day
someone assigns `0x07` to a message type the scheme becomes ambiguous silently.

`offset` and `total` rather than "fragment *n* of *m*": a sender is free to choose
a smaller payload (a narrower path, a future policy), and the receiver does not
have to know what that choice was. Validation on parse, all of it before anything
is allocated:

| check | why |
|---|---|
| `len >= 10`, version, code | the envelope has to be there and be an envelope |
| `total != 0` | a zero-length message is not a message |
| `total <= MAX_HANDSHAKE_MESSAGE` (16 384) | bounds a reassembly buffer to what a message could be |
| `data.len() <= MAX_FRAGMENT_DATA` (1 442) | the envelope is not a way to smuggle an oversize datagram |
| `offset + data.len() <= total` | a fragment cannot claim to belong to a message it does not fit in |

`split` applies the same rules on the way out, so an unparseable fragment is one
Vallum never built.

### 2.2 Splitting, and what a retransmission looks like

`Segments::outbound` returns one datagram unchanged when the message fits the
budget, and otherwise cuts it into fixed-size 1 442-byte pieces sharing one
`message_id` drawn from `Randomness` in that call.

Random per call, deliberately:

- The header's `sender_index` would have been free, and is what a first cut would
  reach for. It is the *recipient's* index, so every outbound message to one peer
  carries the same value — two messages in flight would share an id and interleave
  into garbage. It is the right identifier for a stream and the wrong one for a
  datagram.
- A hash of the message would be deterministic and need no new source of bytes,
  but two identical retransmissions would collide by construction, which is the
  case the id exists to separate.

A retransmission is therefore a new id and a fresh reassembly on the far side.
That is a feature: the alternative is the receiver reasoning about whether two
fragment sets are the same message, and §2.5's timeout is shorter than the 5 s
retransmission interval, so the abandoned set is gone before the replacement
arrives.

### 2.3 Why the budget is not a segment size

The rejected design was a fixed `SEGMENT_PAYLOAD = 1200` and a matching threshold:
it would have split *every* full-size TCP segment into two datagrams, because a
data message at the default MTU is 1 438 B. Buying nothing — 1 438 + 28 is already
one datagram on a 1500-byte path — and costing a datagram per packet on the data
plane. The other rejected variant, shrinking the inner MTU until data messages fit
1 200, is worse: it lowers payload throughput to fix a handshake problem.

So there is one parameter and it is used for both jobs: `MAX_OUTER_DATAGRAM`. A
message at or below it goes whole; a message above it is cut to fit it. The
arithmetic that makes this free on the data plane is asserted at compile time in
`crates/vallum/src/tun.rs`:

```rust
const _: () = assert!(SAFE_MTU_IPV6_OUTER == 1394);                    // 1452 - 58
const _: () = assert!(DEFAULT_MTU as usize + DATA_OVERHEAD <= MAX_OUTER_DATAGRAM);
```

The first says the MTU that a maximum-size data message is data for, the second
says the default MTU's message is one datagram. Segmentation is a no-op on the
data plane as configured; it exists for the handshake, whose messages are three
times the budget.

`DATA_OVERHEAD = 58` is `HEADER_LEN(8) + 4 + COUNTER(8) + 4 + PAYLOAD_LEN(2) +
tag(32)`, and the tag is the one term a suite supplies. That is why the cap is on
the datagram and not derived from the message: a suite with a larger tag, or a
padded message from P5, produces a message that overruns the budget and is
*fragmented* rather than put on the wire too big. The invariant holds whatever the
crypto does — which is the property this project needs, given the crypto is
expected to be replaced.

### 2.4 Where the halves live

| piece | home | why |
|---|---|---|
| the wire form — constants, `Fragment`, `parse`, `is_fragment`, `split`, `REASSEMBLY_TIMEOUT_MS` | `vallum_core::segment` | it is a wire format, and it sits beside the `wire` module it must not be confused with |
| the state — the table, `outbound`, `inbound`, the counters | `vallum_tunnel::Segments` | it needs `SocketAddr` and `Randomness`, and it holds state across datagrams |
| wiring — one `Segments` per device, on both directions of the socket | `vallum/src/run.rs` | the loop owns the socket, so it owns the framing on it |

`Device` never sees a fragment and never emits one. The alternative (a port on
`Device`, so the object is self-contained) was weighed and rejected on the same
ground as every other boundary in this project: `Device` is the protocol, the
envelope is the transport, and the only caller that has a socket is the daemon.

### 2.5 What an attacker can spend

A fragment is unauthenticated input of exactly the standing a whole datagram has.
The reassembled bytes are authenticated the same way they would have been arriving
whole — `mac1` for a handshake, an AEAD tag for data — so injecting a fragment
cannot forge a message and cannot make one mean something else. What remains is
memory, and it is bounded three ways:

- **A table bound.** At most `MAX_REASSEMBLIES = 16` messages are half-assembled,
  each at most 16 KiB: 256 KiB of reassembly buffer, plus a 2 KiB presence bitmap
  per slot, ≈ 288 KiB at the ceiling for the whole device. One peer's handshake is
  one slot, and a device talks to few peers.
- **A time bound.** An entry untouched for `REASSEMBLY_TIMEOUT_MS = 4 000` is
  dropped at the next fragment. Shorter than the 5 s retransmission interval, so an
  abandoned attempt cannot hold a slot into the next one, and a late duplicate
  (§0(c)) costs a slot for at most one interval.
- **An eviction rule.** When the table is full, the entry that has waited longest
  makes room. Every fragment refreshes its entry, so a live handshake is never the
  oldest — a flood of half-finished ones cannot starve it, and a hundred addresses
  with a hundred partial messages still occupy sixteen slots.

The reader already allocates a 16 385-byte buffer per `recvfrom`; this adds
retained memory, not per-datagram memory, and the retained bound is what is
documented. In the live gate a 64-deep flood of first fragments under random ids
draws no reply and leaves the tunnel carrying traffic.

### 2.6 What the envelope reveals

The header is plaintext, so an on-path observer learns that a message was split
and roughly how long it was — the same information the datagram sizes already
carry, plus the correlation between fragments of one message, which is inferable
from timing and order. The one thing worth stating is that it does not *undo* P5:
`Pad` pads to a target inside the AEAD, so every packet padded to the same target
splits identically, into the same number of the same sizes. Padding stays
indistinguishable from padding at the same target.

### 2.7 Configuration

There is none. The budget is a wire constant, because the alternative — an
`outer_mtu` knob, or deriving it from the inner `mtu` — has no defensible default
different from 1500, and a knob whose only sensible value is its default is a way
to misconfigure a tunnel. The operator's lever remains the inner `mtu`, as it was;
`mtu` below `MIN_MTU` is still an error and above `SAFE_MTU_IPV6_OUTER` is still a
warning, and neither changes what the envelope does. See §3.4 for the case this
does not cover.

---

## 3. Evidence

### 3.1 The format (`crates/vallum-core/src/segment.rs`, 6 tests)

Round-trip; `is_fragment` against a real `InitHello`; a truncated fragment is
still classified as a fragment and refused with a fragment-shaped reason; a
4629-byte message in 4 datagrams each ≤ 1452, reassembled in reverse to the exact
bytes; refusal of an empty message, an oversize one, `total = 0`, `total` past the
cap, oversize data, and data outside `0..total`; the reserved-code invariant
(`from_code(0x07) is None`, `Message::parse(fragment)` is an error).

### 3.2 The state machine (`crates/vallum-tunnel/src/segment.rs`, 10 tests)

A message at the budget is one datagram and one byte over is cut; 4609, 4378 and
16 384-byte messages produce no oversize datagram; out-of-order with a duplicate
before completion, and completion exactly once; two interleaved messages from one
address do not mix; the same fragment set from two ports reassembles separately;
a whole message passes through untouched; six shapes of bad fragment are refused
and claimed nothing; a stale entry is abandoned, counted, and the fragment that
follows opens a fresh one that completes; 20 partial messages from 20 ports leave
the table at 16 with 4 evictions; a message longer than the cap is dropped rather
than sent whole.

### 3.3 The daemon (`crates/vallum/tests/gate.rs`)

`two_daemons_establish_and_carry_traffic_both_ways` now also asserts
`stats.reassembled >= 1` on each side. This is the assertion that makes the test
*about* segmentation rather than merely compatible with it: a `Device` fed whole
messages would pass the rest of the test unchanged, and this fails.

### 3.4 The live gate (`scripts/e2e-netns.sh`)

The capture reassembles the Vallum envelope instead of the IPv4 one, and reports
four figures. Measured output:

```text
captured 4629 bytes after reassembly: 4609 B message + 20 B mac1 field
it crossed as 4 Vallum fragments, the largest UDP payload being 1452 B
ns1, daemon A:  FragCreates +0   ReasmReqds +0
ns2, daemon B:  FragCreates +0   ReasmReqds +0
veth MTU:       1500   largest UDP payload our capture saw: 1452
```

Two independent proofs of the same statement: the kernel counters say nothing was
fragmented anywhere in the run, in either direction, and the measured maximum
datagram says nothing was large enough to need it. The gate now *fails* if either
moves, where it previously explained a non-zero count as a known limitation.

The adversary section gained its own probe, because the envelope is new attack
surface: a lone first fragment, an envelope claiming a message past the cap, one
claiming an offset past its own message, and a 64-deep flood of first fragments
under random message ids. All drew no reply, and the tunnel still carried traffic
afterwards. That is the same invariant as every other probe — *an unauthenticated
datagram never draws a reply* — applied to a datagram that is now unauthenticated
input to a stateful table.

The frozen vectors were re-run and are byte-identical: `init_hello_len`
2337/2412/4609, transcripts `846d8887…`, `f36118a9…`, `6c22bee3…`. The prediction
in §0(a) is the thing to check, and it held.

### 3.5 The cost

One extra 10-byte header on a message that overruns the budget, and 4 datagrams
for the `InitHello` where the kernel produced 4 IP fragments. Nothing on the data
plane at or below `SAFE_MTU_IPV6_OUTER`, which the const assertion in §2.3 pins. No
new dependency and no new configuration.

---

## 4. What P6.7 does **not** claim

1. **No reliability.** A fragment set is all or nothing: one fragment lost and the
   message is lost, after 4 s of holding a slot. Nothing retransmits a fragment,
   and nothing should — the layer above (handshake retransmission, or the inner
   transport's own loss recovery) is the right place for that, and duplicating it
   here would fight it.
2. **No path MTU discovery.** The budget assumed a 1500-byte path, exactly as the
   inner-MTU policy did. H6 makes it configurable (`interface.outer_mtu`), so a
   narrower path is honoured rather than fragmented — but the operator states it;
   nothing probes. See [`mtu.md`](mtu.md). Discovery remains a separate feature,
   and it needs the MTU feedback P6.4 does not have.
3. **No authenticity in the envelope.** It is framing, not a security boundary. A
   fragment carries no MAC; the message it delivers is checked by the same code
   that checks a whole one. An attacker who can inject fragments can waste a slot
   and delay a message, which is what §2.5 bounds.
4. **No defence against reordering beyond the timeout.** Fragments are assembled
   by offset, so reordering is free, and reassembly completes exactly once
   including under duplicates and overlaps. But a fragment that arrives after the
   timeout does not help the entry it missed; it starts a new one (§0(c)).
5. **No change to the protocol.** Nothing above the envelope knows segmentation
   exists, which is why the vectors did not move. `docs/proof/transport.md` for the
   `Device`, and `docs/proof/daemon.md` for the loop, remain accurate as written,
   with the one §0(b) correction.
