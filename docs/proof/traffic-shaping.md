# P5 gate — traffic-analysis shaping, and what it costs

**Status:** P5 gate artefact. Covers `crates/vallum-core/src/shaping.rs`, the
padded payload of `crates/vallum-core/src/data.rs`, and the measurement harness
in `crates/vallum-protocol-tests/tests/shaping.rs`.
**Depends on:** plan §7 obligation 7 (traffic-analysis shaping), obligation 6
(`docs/proof/committing-aead-multikey.md`, whose data-plane format this amends),
and the SDK's AEAD.
**Amends:** `docs/proof/committing-aead-multikey.md` §5 item 8 — the sealed
plaintext gains a 2-byte authenticated length prefix.

A tunnel can be cryptographically perfect and still be read from the outside.
The ciphertext says nothing; the *shape* of the traffic says a great deal — how
large each packet is, which direction is heavy, how long the silences are. This
gate is the response to that, and its central claim is a cost, not a defence:
**the length channel can be closed completely, and here is the exact price.**

---

## 0. The fork this gate resolved, and the direction it took

The plan left P5 as three options. The one built is **A: pad inside the AEAD,
with an always-on authenticated length prefix.**

| option | what it hides | why it was not built |
|---|---|---|
| **A — pad inside the AEAD** *(built)* | the *real* payload length, for every packet, with no per-packet marker | — |
| B — a local-policy toggle | nothing, until a deployment flips it | a 2-byte saving for a misconfiguration that silently breaks the tunnel's privacy; and whether padding is on becomes a *deployment* bug instead of a protocol constant |
| C — packet-level actions only (inject/delay) | timing and volume | leaves the strongest and cheapest signal, packet length, fully visible |

The decisive argument for A is that the length prefix makes padding
**recoverable**, so a shaper can pad *every* packet to one target without any
field on the wire saying "this one was padded". The observer sees a stream of
equal-sized packets; the receiver reads the true length from *inside* the AEAD.
Option B would instead have put the padded/unpadded distinction in the frame,
which is precisely the distinction an observer wants.

**Cost of A, with no shaper installed: +2 bytes per data packet.** The sealed
plaintext is `u16 BE length ‖ payload ‖ zeros` whether or not anything is padded.
A minimal keepalive goes from 56 to 58 bytes on the wire (+3.6%); on this gate's
unshaped trace, 1176 → 1190 bytes (+1.2%). That is the whole always-on cost, and
it is deliberately paid unconditionally so that a shaped deployment is
indistinguishable from an unshaped one at the format level.

---

## 1. The obligation, stated exactly

**What is the privacy parameter?** A shaped tunnel's residual signal has exactly
two components, and they are the two things a machine trades against:

1. **The size set** — the set of distinct observable packet lengths. Its
   cardinality bounds the length channel: one length carries zero bits, `n`
   lengths carry up to `log₂ n` bits per packet. `Machine::pad_to_size` reduces the
   set to `{target}`, so **the length channel is closed**, not merely narrowed.
   That is the strongest statement this gate makes, and §3 measures what it costs.
2. **The timing and volume profile** — inter-packet gaps and packet-count bursts.
   `Machine::min_interval` edits the gaps; `Machine::respond_with_padding` edits
   the counts. **Neither is closed**, only blurred, and the blur is paid for in
   latency (`min_interval`) or bandwidth (injection).

The obligation is therefore: *document both components, and measure the cost of
acting on each.* It is not to claim an unlinkability property, because no local
mechanism can provide one — see §4.

**Normative shape of a defence.** A defence is a probabilistic finite state
machine (Maybenot's model): the transport feeds it events
(`NormalSent`/`NormalRecv`/`TunnelSent`/`TunnelRecv`/`Timeout`), the machine
answers with actions (`Pad`/`Inject`/`Block`), and the caller supplies one
uniform `u64` per event. `vallum-core` holds no RNG, exactly as in P1 — where the
shaping entropy comes from is a deployment decision, so it stays outside the
crate. Nothing here is on the wire; nothing in the handshake or key schedule
depends on it.

---

## 2. Mechanism (normative)

### 2.1 The sealed plaintext

```
sealed plaintext := u16 BE length ‖ payload ‖ 0x00 …
```

* The sender writes `length = payload.len()` and appends zeros to reach
  `target` bytes. `Seal::seal(payload)` is `seal_padded(payload, payload.len() + 2)`
  — the unpadded case is the degenerate one, not a separate path.
* The receiver reads the first two bytes, checks `length + 2 ≤ pre_image.len()`,
  and returns exactly `payload`. It never looks at the padding.
* The prefix lives **inside** the AEAD, so it is as authentic as the payload.
  Flipping it fails the tag (`a_forged_length_prefix_fails_the_tag`), and no
  ciphertext whose tag verifies can propose a length other than the one the
  sender chose. This is why the scheme is safe: a length field an observer or a
  forger could touch would be worse than no padding, because it would tell them
  which packets were padded *and* let them lie about it.
* The associated data is unchanged — still `header ‖ counter_be` (16 bytes) — and
  the nonce is unchanged. P2's multi-key and key-commitment arguments concern
  `(key, nonce, AD, ciphertext)` and are indifferent to the plaintext's contents.
* `CookieReply` deliberately keeps its fixed-size plaintext and does *not* gain a
  prefix: it has no variable-length payload to hide.

### 2.2 The machine framework

| item | meaning |
|---|---|
| `Event` | what the transport reports: `NormalSent` (fires **before** the seal, so a `Pad` applies to that packet), `NormalRecv`, `TunnelSent`/`TunnelRecv` (padding packets), `Timeout` (time passed: a `Block`'s deadline elapsed, or an armed state's wake-up came due) |
| `Branch { weight, action, next }` | one weighted choice out of a state: what to do, and where to go. `next = MACHINE_END` ends the machine |
| `State { limit, on }` | transitions keyed by event, plus a cap on how many actions the state may produce. `UNLIMITED` opts out |
| `Machine` | a list of states; state `0` is the start |
| `Shaper::handle(event, draw) -> Vec<Effect>` | the driver. `Effect` carries the producing machine's index, so the transport can tell which defence asked for what |
| `State::wake(after_ms)` / `Shaper::wake_after()` | a state that wants to be told time passed. The transport owns the clock, so it turns the interval into a deadline (`now + interval`) and leaves it unarmed when there is none |
| `Shaper::state_of` | the current state, for introspection and tests |

Three properties are worth stating because they are what a reviewer will look for:

* **The limit suppresses the action, not the transition.** A machine past its
  budget still tracks the traffic; it simply stops acting on it. A defence that
  silently stopped *observing* would resume from a stale picture.
* **`Timeout` is delivered only to machines that asked for it** — blocked ones,
  and ones whose current state is armed with `State::wake` — and it is addressed
  by the `Shaper` rather than by the machine, so a machine never needs to know its
  own index. One clock, one wake-up. `Shaper` holds no clock of its own: the
  transport reads `wake_after()` after every event and re-arms its deadline, so
  every event restarts an armed interval. That is what makes the floor fill
  silence rather than add to a burst that is already moving.
* **`NormalSent` fires before the seal.** This is the one deliberate deviation
  from Maybenot's `NormalSent`, which is a post-send notification; Vallum's
  ordering is what lets a `Pad` action actually apply to the packet in flight.

### 2.3 The reference machines

* `Machine::pad_to_size(target)` — one unlimited state: every `NormalSent` yields
  `Pad { target }`. The size set becomes a singleton.
* `Machine::respond_with_padding(size, injections, cap)` — on `NormalRecv`, with
  exact integer odds `injections / (injections + 1)`, inject one `size`-byte
  keepalive, up to `cap` times. `injections = 0` is an inert machine, which is
  how a config file disables a defence without deleting it.
* `Machine::min_interval(interval_ms)` — after each `NormalSent`, `Block` until
  the timeout, then wait for `Timeout`. A crude rate limiter: it turns a burst
  into a train. It exists because it is the smallest machine that exercises the
  `Block`/`Timeout` pair.
* `Machine::constant_rate_floor(interval_ms, size)` — one unlimited state, armed
  with `wake(interval_ms)`, that injects one `size`-byte packet on `Timeout` and
  re-enters itself. Every other event passes through the same state, which does
  nothing but restart the interval. The floor therefore says something only when
  nothing else does, and its rate is limited by its own parameter — so the
  interval is clamped up to `FLOOR_MIN_INTERVAL_MS` (100 ms) at construction. A
  config file must not be able to describe a flood.
* `Machine::front_padding(count, interval_ms, size)` — a chain of `count` states,
  each armed with `wake(interval_ms)`, each injecting one `size`-byte packet and
  moving on. Two things spend it: a `NormalSent`, which is accompanied by one
  padding packet, and `interval_ms` of silence, which is filled by one. After the
  last state the machine reaches `MACHINE_END` and is inert for good. `count` is
  clamped to `FRONT_MAX_PACKETS` (60) and the interval to `FRONT_MAX_INTERVAL_MS`
  (1 000 ms), so the window cannot be stretched into a long-lived floor.

**Where "the front" is.** The front of this machine's life, which the transport
starts when it builds the peer: for the daemon, a peer added or the daemon
started. It is not the front of each session — padding a rekey would cost
`count` packets per rekey, which is a rate wearing a burst's name, and the floor
is the shape for a rate.

An injected padding packet is an **empty payload padded to `size`** — an ordinary
keepalive. It needs no message type, and an observer cannot pick it out of the
stream by form (`an_injected_padding_packet_is_an_openable_keepalive`).

---

## 3. The cost, measured

`tests/shaping.rs` is a **simulator**, and this is its output. It replays one
synthetic trace — a page load: small outbound requests, an asymmetric burst of
1400-byte responses, acknowledgements, a long idle tail — through a real
`Sender`/`Receiver` pair, applies whatever the machines ask for, and records what
actually left the wire. Every number below is printed by the test on every run;
the assertions are relations between the numbers (same size, more bytes, bounded
delay), not magic constants. Reproduce with:

```
cargo test -p vallum-protocol-tests --test shaping -- --nocapture
```

**Baseline (`Shaper::new(vec![])`):** 7 packets, **1190 bytes**, **5 distinct
sizes** `{98, 118, 142, 178, 458}`. The size set is as rich as the trace. That is
the leak.

**Closing the length channel** (`pad_to_size`): every packet becomes one size.

| target | packets | bytes | distinct sizes | bandwidth vs baseline |
|---|---|---|---|---|
| 512  | 7 | 3 976  | 1 | **+234.1 %** |
| 768  | 7 | 5 768  | 1 | **+384.7 %** |
| 1 024 | 7 | 7 560 | 1 | **+535.3 %** |
| 1 400 | 7 | 10 192 | 1 | **+756.5 %** |

The packet count is unchanged — padding adds no packets — and the single size is
bit-exact, not approximate: it equals what a full-size payload produces
(`pad_to_size_collapses_the_size_set_to_one_value`). The 756 % figure is the
honest headline: on traffic as asymmetric as a page load, *closing* the length
channel is expensive, because every small request is inflated to the size of the
largest response. A deployment chooses its target against that curve.

**Cost, as the target grows.** `bandwidth_cost_grows_with_the_padding_target`
asserts the overhead is monotonically non-decreasing — a larger target can never
cost less bandwidth — which is the only relation a cost table has to satisfy.

**Injection** (`respond_with_padding(1400, 1, UNLIMITED)`): 13 packets,
**9 926 bytes**, 6 distinct sizes, +734.1 % — 6 injected padding packets across 10
inbound events, which is the machine's `1/2` odds doing exactly what it says.
`a_bigger_machine_budget_lasts_longer` shows the state limit biting at exactly the
cap: `cap = 3` yields 10 packets / 5 558 bytes, and injection stops there. The
`limit` field is the cost bound, and its effect is measured, not asserted.

**Latency** (`min_interval(20)`): 7 packets, 1 190 bytes — **the same bytes** —
with **7 packets held for 136 ms total** (mean 19.4 ms, bounded above by the
20 ms interval). The `Block` path delays traffic, it never drops it:
`min_interval_trades_latency_for_timing_obscurity` asserts that the packet count
and byte count are *unchanged* and that the lost time is exactly what was
measured. Timing obscurity is bought with latency and nothing else.

**The constant-rate floor** (`constant_rate_floor`): the one defence whose cost
is independent of the traffic, so it is priced on an idle hour — one 40-byte
packet, then nothing for 3 600 s.

| interval | injected | bytes per hour | rate | bytes per packet |
|---|---|---|---|---|
| 2 000 ms | 1 800 | 2 620 898 | 5.82 kbit/s | 1 455 |
| 500 ms | 7 200 | 10 483 298 | **23.30 kbit/s** | 1 455 |
| 100 ms | 36 000 | 52 416 098 | **116.48 kbit/s** | 1 455 |

The count is exactly `3 600 000 / interval`, so the cost of a floor is
arithmetic a deployment can do before it enables one: it buys a fixed number of
packets per second and pays for it whether or not anybody is using the tunnel.
1 455 bytes is a 1 400-byte sealed plaintext with its framing (header, counter,
plaintext, tag), and it is the same on every injection, so the floor adds volume
at one known size rather than a second size channel. 100 ms is the clamp, so
116.48 kbit/s is the most expensive floor the framework can express.
`the_constant_rate_floor_costs_a_flat_rate_per_hour` pins the count and
`a_shorter_floor_interval_costs_more_bandwidth` asserts monotonicity. The
daemon-level proof is separate, because the machine alone cannot pass it:
`a_constant_rate_floor_keeps_speaking_through_silence` runs two real `Device`s
and checks that a configured floor puts ten packets on the wire over ten
intervals of silence, at the configured size, that the peer opens them as empty
data, and that a user packet inside the window restarts the interval rather than
adding to it.

**The front burst** (`front_padding`): the one defence whose cost is a *count*
rather than a rate, so it is priced on the trace where that difference shows — the
same page load, and then two idle hours.

| trace | config | injected | packets | bytes | vs baseline |
|---|---|---|---|---|---|
| page load | `count = 4` | 4 | 11 | 7 014 | **+489.4 %** |
| two idle hours | `count = 60`, 100 ms, 1 400 B | 60 | 61 | 87 458 | 1 456 B per packet |
| two idle hours, *floor* at 100 ms | — | 72 000 | 72 001 | 104 832 098 | 1 456 B per packet |

The last two rows are the reason both shapes exist. Over the same two hours the
front burst spends 85 KiB once and then stops; the floor at the same interval
spends 100 MiB and keeps going. Neither is a better defence — a burst says
nothing about the second hour — but they are priced on different curves, and a
deployment that wants chirp at the start of a peer's life and silence afterwards
pays 85 KiB for the privilege, not a monthly bill.

The count is exact, which is the whole cost bound:
`a_busy_front_spends_the_burst_on_traffic` shows four injections over a trace
with more outbound packets than that, and
`a_front_burst_cannot_be_configured_past_its_rails` caps both rails — 10 000
configured packets yield 60, and a 60 000 ms interval is cut to 1 000 ms. The
daemon-level proof is `a_front_padded_session_spends_its_burst_and_then_stops`:
two real `Device`s, a burst of three, one slot spent on the packet that
establishes the tunnel, the other two filled out of silence at the configured
size, the payloads discarded on receipt, and ten further intervals of silence
producing nothing at all.

**Padding is authenticated.** `padding_is_stripped_so_the_payload_arrives_unchanged`
pads payloads from 0 to 1398 bytes to 1400 and recovers each one byte-for-byte,
and the unit test `a_forged_length_prefix_fails_the_tag` flips a ciphertext byte
and confirms the tag — not the length field — is what rejects it.

---

## 4. What P5 does **not** claim

1. **It hides size, not timing.** `pad_to_size` closes the length channel and
   does nothing about inter-packet gaps, which are the stronger fingerprint. Only
   `min_interval`/injection touch timing, and they *blur* it rather than close
   it. A deployment that wants both installs both, and pays both costs.
2. **No adversarial inference is measured.** The simulator measures *local* cost
   (bytes added, milliseconds held). It does not model an observer, and it makes
   no claim about defeating website fingerprinting or any named attack. Measured
   cheap and measured effective are different claims; this gate only makes the
   first, and says so.
3. **Shaping is per-endpoint local policy.** Like identity mode, it is never
   negotiated. The two ends may run different machines, or none on one side,
   because padding changes a packet's *size*, not its *meaning*. Because it is
   local, the simulator shapes only the local outbound direction — inbound
   traffic generates events but is not reshaped.
4. **`pad_to_size` can fail loudly.** If the target is smaller than a payload
   plus the 2-byte prefix, the seal returns `DataError::PaddingTooSmall` rather
   than emitting an unpadded packet that would break the indistinguishability the
   machine exists to provide. A machine bug is an error, not a silent downgrade.
5. **Injected padding consumes counters.** Every padding packet is a real data
   packet against the 2⁴⁹ ceiling. At any plausible shaping rate this is
   irrelevant, but it is real and it is bounded.
6. **No formal model.** There is no Tamarin/ProVerif model of shaping, and there
   could not usefully be one: the property is statistical, not symbolic. The
   durable output is the framework, the documented privacy parameter, and the
   measured cost table.
7. **The floor is a constant, not noise.** It makes an idle tunnel speak at a
   known rate, which removes the coarse "nothing is happening" signal and
   replaces it with a metronome — evenly spaced packets are themselves a
   signature, and the floor does nothing about volume. Making gaps *shaped*
   rather than *regular* needs the rest of ADR-0025's techniques, which are not
   implemented.
8. **The front burst is a burst, not a disguise.** It spends its packets where the
   front is most revealing and then the tunnel is as silent as it was before. An
   observer that watches past the first minute learns nothing it would not have
   learned without it, and a front that begins with real traffic spends its slots
   *accompanied* by that traffic rather than hiding its shape.
9. **`maybenot` is not vendored.** The FSM semantics were reimplemented to
   Vallum's conventions (no RNG in the crate, caller-supplied draws, errors not
   panics); no crate dependency was added.

---

## 5. Included and omitted from the Maybenot model

| Maybenot feature | Vallum | why |
|---|---|---|
| probabilistic FSM defences | **included** (`Machine`) | the whole model |
| `NormalSent`/`NormalRecv` events | **included**, with `NormalSent` moved *before* the seal | so a `Pad` applies to the packet in flight |
| padding actions | **included** (`Pad`, `Inject`) | the length and volume channels |
| blocking, with a timeout | **included** (`Block`, `Timeout`) | the timing channel |
| per-state action limits | **included** (`State::limit`) | the cost bound |
| simulator to measure overhead pre-deployment | **included** (`tests/shaping.rs`) | the gate's evidence |
| framework-wide fraction limits (total blocking budget) | **omitted** | coarser per-machine/per-state limits suffice; a deployment that wants a global budget bounds the machines it installs |
| sampled-timeout scheduler | **omitted** | the transport owns one clock, as in `timer.rs`; a long-lived action carries its own duration |
| machine negotiation / replacement | **omitted, by design** | local policy; the ends need not agree |
| network model (adversary inference) | **omitted** | §4 item 2 |

---

## 6. Correlation with the code

| claim | code | test |
|---|---|---|
| sealed plaintext is `u16 BE len ‖ payload ‖ zeros`, padding discarded | `data.rs::{Sender::seal_padded, strip_padding}` | `padding_hides_the_payload_length_and_is_recovered_exactly` (unit), `padding_is_stripped_so_the_payload_arrives_unchanged` |
| the length prefix is authenticated, not malleable | `data.rs::strip_padding` (inside the AEAD) | `a_forged_length_prefix_fails_the_tag` (unit) |
| a too-small target fails instead of downgrading | `data.rs::Sender::seal_padded`, `error.rs` | `padding_hides_the_payload_length_and_is_recovered_exactly` (unit) |
| a keepalive is an empty payload, and padding reuses it | `data.rs::Sender::seal_padded` | `a_keepalive_is_an_empty_payload` (unit), `an_injected_padding_packet_is_an_openable_keepalive` |
| a machine acts only on its event; unknown events are no-ops | `shaping.rs::Running::step` | `a_machine_acts_only_on_its_own_event` (unit) |
| weighted branches are exact and draw-driven | `shaping.rs::Running::step` | `the_weights_are_exact_and_draw_driven` (unit) |
| the state limit suppresses the action, not the transition | `shaping.rs::Running::step` | `a_state_limit_caps_the_actions_it_can_produce` (unit) |
| `Timeout` reaches only machines that asked for it | `shaping.rs::Shaper::handle` | `a_block_arms_and_only_a_timeout_disarms_it` (unit) |
| `MACHINE_END` stops a machine | `shaping.rs::Running::ended` | `a_machine_that_reaches_the_end_stops` (unit) |
| an empty shaper changes nothing | `shaping.rs::Shaper::new` | `an_empty_shaper_is_a_no_op` (unit), `unshaped_traffic_exposes_every_payload_length` |
| **the length channel closes** | `Machine::pad_to_size` | `pad_to_size_collapses_the_size_set_to_one_value` |
| **the bandwidth cost is monotone in the target** | — | `bandwidth_cost_grows_with_the_padding_target` |
| **injection costs bytes and respects the cap** | `Machine::respond_with_padding` | `injected_padding_costs_bandwidth_and_is_counted`, `a_bigger_machine_budget_lasts_longer` |
| **blocking costs latency and loses nothing** | `Machine::min_interval` | `min_interval_trades_latency_for_timing_obscurity` |
| an armed state is woken by `Timeout` and re-arms itself | `shaping.rs::{State::wake, Shaper::wake_after}` | `the_floor_injects_after_silence_and_rearms_itself` (unit) |
| traffic restarts the interval, so the floor fills only silence | `shaping.rs::Machine::constant_rate_floor` | `the_floor_says_nothing_when_traffic_is_moving` (unit) |
| the floor's rate cannot be configured into a flood | `shaping.rs::FLOOR_MIN_INTERVAL_MS` | `the_floor_interval_cannot_be_shortened_into_a_flood` (unit) |
| **the floor costs a flat rate per hour** | `Machine::constant_rate_floor` | `the_constant_rate_floor_costs_a_flat_rate_per_hour`, `a_shorter_floor_interval_costs_more_bandwidth` |
| **the daemon turns a configured floor into packets** | `device/{timer,data,state}.rs` (`shape_wake_ms`) | `a_constant_rate_floor_keeps_speaking_through_silence` |
| the front burst is spent on traffic or on silence, and ends | `shaping.rs::Machine::front_padding` | `a_front_burst_spends_its_count_and_then_ends`, `a_busy_front_spends_the_burst_on_traffic` (unit) |
| the front cannot be configured past its count or its window | `shaping.rs::{FRONT_MAX_PACKETS, FRONT_MAX_INTERVAL_MS}` | `a_front_burst_cannot_be_configured_past_its_rails` (unit) |
| **a front burst costs a count, not a rate** | `Machine::front_padding` | `the_front_burst_is_a_one_off_and_the_floor_is_a_rate` |
| **the daemon spends a configured front burst and then stops** | `device/{timer,data,state}.rs` (`shape_wake_ms`) | `a_front_padded_session_spends_its_burst_and_then_stops` |
| a hand-written machine costs what the built-in one costs | `Machine::new`/`State`/`Branch` | `the_same_padding_target_costs_the_same_bytes_however_it_is_reached` |

---

## 7. References

* D. Pulls, L. Witwer, *Maybenot: A Framework for Traffic Analysis Defenses* —
  the probabilistic-FSM model, the event and action vocabulary, the fraction
  limits, and the lightweight simulator whose role `tests/shaping.rs` fills here.
  **The source of obligation 7.** Vallum implements the core, not a port (§5).
* `docs/proof/committing-aead-multikey.md` — the AD, nonce, and multi-key
  arguments, none of which the length prefix changes; §5 item 8 there records the
  amendment.
* `docs/proof/ratchet-pcs.md` — the epoch axis; a shaped deployment shapes within
  an epoch, and an epoch change is invisible to the machines.
* Plan §4 L3, §5 V6, §6 P5 gate, §7 obligation 7.
