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

---

## 3. What P6.3 does **not** claim

1. **Nothing here is a defence against an on-path attacker.** The device enforces
   local policy and honest bookkeeping. Confidentiality, authenticity and PCS are
   the business of P1–P5, and their argument is the proofs, not this code.
2. **The residual decapsulation cost is real and named.** An attacker who has
   observed an `InitHello` knows the initiator's index and can make it decapsulate
   twice per forged `RespHello`. The work is bounded — one outstanding handshake,
   and the initiator's own send rate is the ceiling — but not free. Closing it
   needs a wire change (an op-A-keyed tag checked before decapsulation) and is
   recorded as a follow-up rather than smuggled in. On the responder side the
   equivalent cost is behind `mac1`, and behind a cookie under load.
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
