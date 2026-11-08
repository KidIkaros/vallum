# P6.3 gate — the transport, and the two bugs that only integration could find

**Status:** P6.3 gate artefact. Covers `crates/vallum-tunnel/` — the sans-IO
`Device`, cryptokey routing, and the per-peer handshake driver.
**Depends on:** P1 (`docs/proof/eck-pfs-psk.md`), P2/P4
(`docs/proof/committing-aead-multikey.md`, `docs/proof/ratchet-pcs.md`), P3
(`docs/proof/hybrid-identity.md`), P5 (`docs/proof/traffic-shaping.md`), P6.1/P6.2
(the cookie reply and the sealed peer hint).
**Wire change:** none. The frozen vectors are byte-identical; 18 interop tests
pass and the single ignored test is the regeneration harness.

---

## 0. What this gate forced

**(a) The responder must cache its answer, and the first cut did not.** Both ends
run retransmission timers, and on a real link they eventually fire on the same
tick. The initiator retransmits the *same* `InitHello` — same index, same bytes —
and the responder, on the first cut, answered it by allocating a **new** index and
replacing its `Responding` state. The initiator meanwhile had processed the older
answer and sent its confirmation naming the *old* index. The responder no longer
owned that index, so it dropped the confirmation in silence, then sat in
`Responding` until it gave up; the initiator sat in `PendingConf` until *it* gave
up. A 5-second retransmit pair turned into a 120-second stall with no error on
either side.

The fix is a **response cache**: a repeated initiation whose index matches the
outstanding state is answered with the bytes already held (§2.4). It is not only
a correctness fix. It removes a decapsulation from the retransmission path, and it
cannot amplify, because the answer is smaller than the message that asks for it
(measured: 131 B/108 B/227 B smaller for suites `0x0001`/`0x0002`/`0x0003`).

**(b) The lost third message costs exactly one packet, and that is now written
down rather than discovered in production.** The initiator treats the handshake as
complete when it *sends* the confirmation, so it releases the packet it was
holding at that instant. If the confirmation is lost, that packet reaches a
responder with no keys and is dropped. Buffering it instead — "hold data for a
peer with no session" — is exactly the unbounded queue an attacker wants to exist,
so the loss is accepted and recovered by the next packet. WireGuard takes the same
loss.

**(c) A configuration bug that only an end-to-end test could see.** `Peer::new`
took the peer's configured endpoint and then stored `None`, so a device with a
dialable peer never dialled, queued its first packet, and reported nothing wrong.
Every unit test of every part passed. The gate is the test that fails when a
packet is queued forever: `two_hosts_establish_and_carry_traffic_both_ways`.

**(d) One addition to `vallum-core`, and no change to anything else.**
`Session::seal_padded` is a delegation to `Sender::seal_padded` (refusing a target
larger than the wire allows), because the shaping hook needs it on the
transport-facing object. No new wire form, no new tag, no change to the SDK.

---

## 1. The obligation, stated exactly

**A transport that is correct without a network.** Two device instances in one
process, exchanging datagrams through a `VecDeque` and a function call, must
complete the P1 handshake, carry layer-3 packets in both directions under the P2
data plane, and refuse every one of the following without losing the session:

| Refused | Where |
|---|---|
| a handshake with no `mac1` | `admit_handshake`, before any KEM work |
| a handshake under load with no `mac2` | cookie reply, then `mac1`-keyed retry |
| a handshake whose timestamp is not fresh | `Tai64nGuard::check`, read-only |
| an inner source address outside the peer's `allowed_ips` | `on_data` |
| a replayed data packet | the P2 sliding window, after the tag |
| a data packet naming an index no peer owns | the index map |
| a datagram in a suite this device does not speak | `on_datagram` |
| a malformed, truncated or oversize datagram | `Message::parse` |
| a configuration whose addresses overlap or whose identity is duplicated | `Device::new` |

And, positively: **an endpoint is learned only from authenticated traffic.** An
`InitHello` is answered at the address it came from, but a peer's endpoint is
updated only when `InitConf` or an opened data packet proves the peer's key. A
junk handshake therefore cannot redirect a peer.

**Success criterion.** `cargo test -p vallum-tunnel` — 24 integration tests and 11
unit tests, all over the real tri-hybrid suite, with a deterministic RNG and a
simulated clock, in 8 seconds and with no network privileges.

---

## 2. Mechanism (normative)

### 2.1 The sans-IO boundary

```text
  UDP datagram ─┐                                   ┌─ send this datagram
  IP packet    ─┼─▶  Device::handle  ──▶ Vec<Action> ─┼─ deliver this IP packet
  timer tick   ─┘   (clock, rng)                     └─ a session was established
```

The crate opens no socket, reads no clock, generates no randomness, and touches no
interface. `#![forbid(unsafe_code)]`, and its only dependency outside Vallum is
`ipnet` (§2.6).

Two clocks, and they never substitute for each other:

- `Clock::monotonic_ms` drives everything that must be *reproducible*: rekey
  deadlines, keepalive and retention windows, block windows, and cookie rotation.
  A wall-clock step can only delay an action in those, because every comparison
  saturates.
- `Clock::wall` is a `Tai64n`, read exactly once per handshake, and only because
  the timestamp has to be comparable between two hosts.

### 2.2 The index map is a projection, not a second source of truth

An index is reserved the moment a handshake starts or is answered, and `0` is
never allocated because a cookie reply carries `sender_index = 0`. The rule that
keeps the map honest is that `remap(index)` **rebuilds** a peer's entries from the
peer's own state — current session, retained epoch, outstanding handshake — rather
than inserting and forgetting. A peer's index set is therefore always derivable,
and a superseded epoch keeps its index so a straggler is demultiplexed to the right
receiver instead of guessed at.

### 2.3 The handshake is stored as inputs, not outputs

`InitiatorState` is consumed when the response is processed, so storing it would
mean that one forged `RespHello` ends the attempt. `Initiating` instead holds the
*sender index, seed, timestamp, `mac1`, cookie, and framed `InitHello`*, and
rebuilds the state on demand. `initiator_hello` is deterministic in its seed, so
the rebuild is byte-identical and a bad reply is a dropped packet rather than a
lost handshake.

The same asymmetry decides where the handshake is *committed*: the responder
becomes established only when it processes `InitConf`, at which point it commits
the timestamp and the peer's endpoint. Committing either on arrival would let one
forged `InitHello` lock the real peer out, or point the peer's traffic at an
attacker.

The initiator retains its `InitConf` and resends it every `REKEY_TIMEOUT_MS` until
an authenticated packet arrives, so the last message's loss costs one packet (§0b)
rather than two minutes.

### 2.4 Retransmission: answered from the cache

A repeated initiation that matches the outstanding `Responding` state's peer index
is answered with the stored `RespHello`, byte for byte. Requirements for a cache
hit are that admission passed (so `mac1` verified) and the timestamp is still
fresh; a peer that has already completed the handshake is not `Responding`, so a
later replay falls through to the guard and is dropped.

An attacker who replays an observed `InitHello` therefore obtains at most the
answer the initiator already had: no secret, no new index, no decapsulation, and a
message smaller than the one it sent.

### 2.5 Simultaneous initiation

Two hosts with traffic for each other start handshakes at the same time, and
neither may simply prefer its own attempt: if both do, both play initiator and
both answers are discarded, re-colliding on every retry. The tie is broken **by
static public key** — on receiving an `InitHello` while initiating, the side with
the lexicographically smaller KEM public key keeps its attempt and the other
abandons its own and answers. The rule is symmetric and depends only on public
keys, so the two ends always agree; the test asserts exactly one `Established` per
host and opposite roles.

### 2.6 Cryptokey routing, in both directions

A peer's `allowed_ips` are the destinations routed *to* it and the source addresses
accepted *from* it.

- **Outbound** is longest-prefix match. Overlapping prefixes across peers are
  refused at `add_peer`, so a routing decision never depends on configuration
  order; the LPM is what makes that refusal a guarantee rather than a hope.
- **Inbound** is the anti-spoofing rule, and it is the important one: a packet that
  opens under the session key proves *who* sent it and says nothing about which
  address that peer may claim. A source outside the peer's `allowed_ips` is
  rejected, and the test drives a device into emitting a packet with a source its
  peer never granted — which the *receiving* end refuses, because that is the only
  place a peer cannot lie its way past.
- Overlap and duplicate identity are `ConfigError`, not a warning; a v4 prefix and
  a v6 prefix never conflict.

### 2.7 Bounds

`MAX_QUEUED_PACKETS = 256`, `MAX_QUEUED_BYTES = 4 MiB`, drop-newest with a
counter. `MAX_INJECTION_BURST = 64` clamps a shaping machine's `Inject`, and an
injection is never fed back into the shaper. A `Pad` target is clamped to
`[payload.len() + 2, max_pad_target()]` with a fallback to an unpadded seal, so a
machine that asks for an impossible size cannot blackhole the traffic it exists to
protect. A keepalive is *sent through* the shaper — it is a shaped event, not an
invisible one — but ignores `Block`, because a machine that held a keepalive would
suppress the traffic that keeps the path reachable.

### 2.8 A stream carrier, and what it would cost

ADR-0026's TCP fallback sits on a seam that was already here: the device emits
`Action::Send { destination, bytes }` and never a socket, and the daemon's
`DatagramSocket` is the only thing that knows the transport. What a stream carrier
needs beyond that is **framing** — a length prefix, because a stream has no
message boundaries — and that is `vallum_tunnel::stream`:
`frame`/`unframe`/`FrameReader`, two bytes of prefix, a 32 KiB ceiling below the
prefix's own range so a bogus length is refused rather than buffered, and no I/O,
no socket and no connection state. `[interface] carrier = "tcp"` selects
`TcpTransport`, which is that framing inside a `DatagramSocket`: one connection per
peer, `SO_MARK` set before the dial, and the same loop and handshake above it.

Measured over a real TCP connection on loopback with real sealed packets
(`tests/carrier.rs`): a 1 456-byte data packet goes out as 1 458 bytes — **+2
bytes of frame per packet, nothing else** — and comes back byte-identical and
openable. Add the header difference (TCP+IP 40 bytes against UDP+IP 28, arithmetic
rather than measurement) and the carrier costs about 1 % more on the wire at a
full-size packet.

What is shown is that a stream forces one order: the second packet cannot be
handed over before the first, whatever the application asked for
(`a_stream_orders_everything_behind_the_slowest_read`). That is the property the
fallback trades for reachability.

**Loss, measured.** This was ADR-0026's open number, and it is open no longer.
`the_carrier_pays_retransmissions_on_a_lossy_path` puts the two ends of a veth
pair in separate network namespaces, attaches `netem` to the client's end, and
drives 32 MiB through the carrier in 23 014 real sealed frames on five paths. The
retransmission count is the kernel's own (`/proc/net/snmp`, `RetransSegs` against
`OutSegs`), not a model of it. The 40 ms paths delay one direction by 20 ms, so
the round trip costs 40 ms; the value is quoted from the handshake the test
measures, not from the label:

| path | time for 32 MiB | segments retransmitted | frames delivered |
|---|---|---|---|
| 1 ms round trip, clean | 0.03–0.18 s | 0 of ~23 185 | 23 014 |
| 1 ms round trip, 2 % loss | 0.04–2.5 s | 288–725 of 23 178 | 23 014 |
| 1 ms round trip, 5 % loss | 13.2–17.9 s | 1 167–1 344 of 23 175 | 23 014 |
| 40 ms round trip, clean | 0.28–0.42 s | 0 to 90 of ~23 180 | 23 014 |
| 40 ms round trip, 2 % loss | 26–48 s | 410–554 of 23 176 | 23 014 |

Ranges are the spread across seven runs on a machine that was also building, not a
confidence interval: the retransmission counts hold roughly still between runs and
the wall clock does not.

Not one byte lost on any path: a stream loses time, not data. The retransmission
rate matches the offered loss — 1.2–2.9 % at 2 %, 5.0–5.8 % at 5 % — so TCP with
SACK repairs what `netem` drops without amplifying it, and what the repairs cost is
the round trips they wait for rather than the bytes they resend. Dividing the
excess time by the number of repairs makes that literal on the paths where the
stream actually stalls: **11–14 ms per repair at 5 % loss on a 1 ms round trip**
(the congestion window collapses as well as being repaired) and **46–116 ms on the
40 ms path**. Loss costs a round trip, and a round trip costs what the path says it
does.

The 1 ms round trip at 2 % loss is the row that will not sit still, and the reason
is worth stating rather than averaging away. A lost segment is repaired one round
trip later, and at one millisecond there are hundreds of round trips available
inside the time the window needs to drain: the fastest run finished in 44 ms — as
fast as a clean path — having retransmitted 288 segments, because every repair fit
inside a window far larger than the path's delay. In other runs the same path took
2.5 s, with the congestion window collapsing and the connection running at the
Mathis bound instead. Both are the carrier behaving correctly; neither is the
carrier's cost on a real path, where a round trip is not one millisecond. The
rows that answer the question are 5 % at 1 ms and 2 % at 40 ms.

The two clean rows are the control for both claims. Delay alone barely moves a
bulk transfer: 0.29–0.42 s for 32 MiB over 40 ms against 0.04–0.18 s over 1 ms,
because at this size the window is doing the work, and a 40× larger window is 40×
more in flight rather than 40× the time. Loss does move it once the round trip is
long enough that a repair cannot hide — the same 40 ms path at 2 % is 26–48 s — and
that is the whole argument for the carrier being a fallback: it is not the
retransmissions that hurt, it is that each one is repaid a round trip later, and a
real path's round trip is not one millisecond.

The `netem` queue limit is raised to 100 000 packets. Its default of 1 000 overflows
during a burst of this size and drops segments the path was not asked to drop —
observed as 45 retransmissions on a *clean* path, which would have been read as
noise in every lossy row below.

A retransmission on a *clean* path is a statement about the harness, not about the
carrier, so the run reports the counters that can explain one. The far end reports
its receive-queue drops (`RcvPruned` + `TCPRcvQDrop`); the sending end reports
which of the two mechanisms fired — `TCPTimeouts` against `TCPFastRetrans` — because
a fast retransmit means duplicate acknowledgements reached the sender (so something
was dropped or reordered) and an RTO means the sender gave up waiting (so an
acknowledgement was). The table carries both, so a lossy row says not only that it
paid for repairs but which repairs it paid for: at 5 % loss a handful of timers and
most of the retransmissions are fast retransmits, which is TCP recovering without
stalling.

The clean paths retransmit nothing in most runs, and the test allows up to one
percent of a clean path's segments so that a rare timer cannot fail a measurement
nobody asked to be perfect — but "up to one percent" is not an explanation. Across
about a dozen runs, two of the 40 ms clean rows retransmitted 64 and 95 segments of
23 180 with the far end's receive queue empty, which is 0.3–0.4 %, and **why is not
established**. The cause columns are the instrument for the next occurrence: a
nonzero `fast` count would point at reordering or a dropped datagram in the delayed
path, a nonzero `rto` at a stalled acknowledgement. Until one of those is measured,
the 40 ms clean baseline should be read as "about 0.3 s, occasionally with a few
hundred segments of extra work", not as a path that is provably drop-free.

The measurement needs a network namespace, `tc` and `nsenter`. The namespace comes
from `unshare -Urn` where the host allows unprivileged user namespaces, and from
`sudo -n unshare -n` where it does not — the same two-step the end-to-end gate uses,
because the CI runner is one of those hosts. Where neither is available the test
names what is missing and returns rather than reporting a pass it did not earn; the
gate runner sets `VALLUM_LOSSY_REQUIRED=1`, where that same absence is a failure
instead — the transport's cost is evidence, and evidence that can disappear while
the suite stays green is not. It takes about 75 seconds where it runs, most of it
the 40 ms and 2 % path.

The tables are also what the gate runner keeps: `VALLUM_LOSSY_TABLE` names a file
the test writes them to, and `ci.yml` appends it to the run's step summary. A green
check then carries the numbers the run measured — a change in the transport's cost
shows up in the run that changed it, not in a document nobody re-measures.

### 2.9 The same path as datagrams

The carrier's cost is only half the comparison: the other half is what the default
carrier does with the same traffic over the same qdisc. After each stream run the
same namespaces, the same `netem` and the same sealed packets carry 4 MiB as
datagrams — one send each, nothing waiting for an acknowledgement — and the far end
reports both what arrived and what its kernel dropped because a queue was full
(`RcvbufErrors`). The drop count is what makes an arrival count mean anything: a
datagram socket has no flow control, so a fast sender overruns a slow reader and
the missing datagrams look exactly like a lossy path.

That is why the datagrams are paced, 64 at a time (93 KiB) every 40 ms. Sixty-four
datagrams fit inside the 208 KiB a UDP socket gets by default, so a burst always
drains over any path here, and every datagram that does not arrive was dropped by
the qdisc. The pacing is also why this leg carries 4 MiB rather than 32: at that
rate it is two seconds per path, and the comparison is of loss rates, not bytes.

| path | datagrams sent | arrived | dropped on arrival |
|---|---|---|---|
| 1 ms round trip, clean | 2 880 | 2 880 (100 %) | 0 |
| 1 ms round trip, 2 % loss | 2 880 | 2 804–2 828 (97.4–98.2 %) | 0 |
| 1 ms round trip, 5 % loss | 2 880 | 2 734–2 746 (94.9–95.3 %) | 0 |
| 40 ms round trip, clean | 2 880 | 2 880 (100 %) | 0 |
| 40 ms round trip, 2 % loss | 2 880 | 2 813–2 829 (97.7–98.2 %) | 0 |

Four runs. Random loss is random, so the test's assertion is not the exact count:
arrivals must fall within two percent of what the offered loss predicts, which is
five times the spread 2 880 draws have and still far tighter than the gap between
"no loss" and "the loss that was offered".

The two carriers, same path, same offered loss: the datagram run loses the
datagrams and stays quick, and the stream loses the time and delivers everything.
At 5 % loss on a 1 ms path that is 95 % of the arrivals against every frame in
14–18 s; at 2 % on a 40 ms path it is 98 % of the arrivals against every frame in
26–48 s. Neither number is an argument that one carrier is better: the datagram is
what a VPN carries, and a frame that never arrives is a retransmission the
*application* decides about, at whatever cost it chooses. The stream is the
fallback that promises delivery where UDP is blocked, and this is the promise's
price.

---

## 3. What P6.3 does **not** claim

1. **Nothing here is a defence against an on-path attacker.** The device enforces
   local policy and honest bookkeeping. Confidentiality, authenticity and PCS are
   the business of P1–P5, and their argument is the proofs, not this code.
2. **The residual decapsulation cost is real and named — and P6.8 closed it.**
   An attacker who has observed an `InitHello` knows the initiator's index and can
   make it decapsulate twice per forged `RespHello`; worse, the transport rebuilds
   the initiator state first (an ephemeral keygen and an op-A encapsulation), so
   the measured pre-P6.8 price was keygen + encaps + two decaps. P6.8's op-A-keyed
   `PRE_TAG` is that wire change: the initiator checks it before the rebuild, so a
   forgery costs one KDF and the handshake survives. See
   `docs/proof/resp-tag.md`. On the responder side there is **no** equivalent and
   cannot be one — the decapsulation is what produces the key the tag would be
   checked against — so that cost stays behind `mac1`, and behind a cookie under
   load.
3. **The `allowed_ips` model is WireGuard's, including its limitation.** A peer may
   claim any address inside a prefix it was granted; the model does not verify that
   the host at that address exists or consented.
4. **No amplification claim is proved in general.** §0a's numbers are for the three
   suites shipped. The general form `InitHello − RespHello = 12 + (pk_e − ct)`
   holds whenever a public key is at least as large as one ciphertext, which is
   true of any KEM but is not enforced by a type.
5. **No timing or volume claim.** Shaping is P5's, is off by default, is local
   policy, and is never negotiated. The device does not add cover traffic of its
   own.
6. **No rekey-specific transport test beyond the timers.** The epoch axis is P4's
   obligation and is tested there; P6.3 exercises `Session::advance` only through
   `install_session`.
7. **No performance claim.** Latency and throughput are P6.5's, and only after this
   correctness gate.
8. **The cookie's client key is the responder's own encoding** of address and port.
   It is injective and both parts are covered, so a NAT rebinding invalidates the
   cookie — which is desirable, and is asserted only for the encoder, not for a
   real NAT.

---

## 4. Correlation with the code and the tests

Line numbers are as of this gate.

| Rule | Code | Test |
|---|---|---|
| admission before KEM work | `on_init_hello` (619) | `an_under_load_responder_makes_the_initiator_prove_its_address` |
| hint resolves, does not authenticate | `peer_with_hint` (1489) | `a_peer_configured_with_the_wrong_key_cannot_establish` |
| timestamp read-only on arrival | `on_init_hello` (676) | `a_forged_init_hello_cannot_lock_a_peer_out` |
| timestamp + endpoint committed on `InitConf` | `on_init_conf` (874) | `two_hosts_establish_and_carry_traffic_both_ways` |
| response cache | `on_init_hello` (689) | `a_repeated_initiation_is_answered_from_the_cache` |
| retransmission race resolved | `retransmit_handshake` (1161), `retransmit_conf` (1061) | `a_lost_resp_hello_is_recovered_by_the_initiator` |
| third message lost, one packet lost | `on_resp_hello` (807) | `a_lost_init_conf_is_retransmitted_until_the_responder_answers` |
| first message lost | `resend_init_hello` (1184) | `a_lost_init_hello_is_recovered_by_the_initiator` |
| simultaneous initiation tie-break | `on_init_hello` (702) | `simultaneous_initiation_converges_on_one_session` |
| inbound anti-spoofing | `on_data` (919) | `a_packet_claiming_an_address_the_peer_does_not_own_is_rejected` |
| replay refused after the tag | `Session::open` (P2) | `a_replayed_data_packet_is_not_delivered_twice` |
| reserved index is never a session | `alloc_index` (1494) | `a_data_packet_naming_the_reserved_index_matches_no_peer` |
| unknown suite ignored | `on_datagram` (590) | `a_wrong_suite_id_is_ignored` |
| junk is inert | `on_datagram` (590) | `junk_datagrams_are_dropped_without_effect` |
| index map is a projection | `remap` (1510) | `a_second_packet_rides_the_established_session_with_no_handshake` |
| overlap and duplicate refused | `add_peer` (446), `AllowedIps::overlaps` | `overlapping_allowed_ips_are_refused`, `a_duplicate_peer_identity_is_refused`, `a_v4_and_a_v6_peer_do_not_conflict` |
| longest-prefix routing | `route` (1456) | `routing_picks_the_peer_that_claims_the_destination` |
| no route, no send | `on_outbound_ip` (964) | `a_destination_no_peer_claims_is_dropped_locally` |
| `Pad` reaches the wire | `seal_and_send` (1365), `pad_target` (1575) | `a_pad_machine_fixes_the_sealed_size_of_every_data_packet` |
| `Block` holds and releases | `apply_effects` (1320), `flush` (1430) | `a_min_interval_machine_holds_and_then_releases_traffic` |
| bounded queue drops | `enqueue` (1413) | `a_full_queue_drops_rather_than_grows` |
| keepalive is not a packet | `on_data` (944) | `an_empty_payload_is_a_keepalive_and_delivers_nothing` |

---

## 5. References

- Jason A. Donenfeld, *WireGuard: Next Generation Kernel Network Tunnel*, NDSS
  2017 — cryptokey routing, the TAI64N guard, `mac1`/`mac2` and the cookie reply,
  and the endpoint-learned-from-authenticated-traffic rule.
- `docs/proof/eck-pfs-psk.md` §8 — the P6.1/P6.2 amendment defining the
  `CookieReply` message and the sealed peer hint the device consumes.
- `docs/proof/ratchet-pcs.md` §2.3 — why the *index*, not a trial decryption,
  decides which epoch owns a packet's verdict; the device relies on it.
- `docs/proof/traffic-shaping.md` §3 — the measured cost the clamping in §2.7
  preserves.
