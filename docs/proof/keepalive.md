# P6.6 — persistent keepalive, and the first observable tick

**Status:** post-gate follow-up to P6.4. Covers `PeerConfig::with_persistent_keepalive`,
the per-peer deadline in `vallum-tunnel`, and the daemon's `persistent_keepalive`
field.
**Depends on:** P6.4 (`docs/proof/daemon.md`) for the loop that drives it, and P2
for the *reactive* keepalive this sits beside.
**Wire change:** none. A keepalive is an empty data packet under the existing data
framing; the frozen vectors are untouched.

---

## 0. What this gate forced

**(a) The P6.4 non-claim named both the gap and the order to close it.** That
document said, correctly, that `KEEPALIVE_TIMEOUT_MS` only keeps an *established*
path warm, that `Device` had no way to inject a keepalive, and that adding the
config field before the timer "would be a lie about what the daemon does". This
change adds the timer and the field together, in that order.

**(b) The tick had never been observed to run.** The daemon's loop does work on
every `recv_timeout` expiry (`Device::poll`), but nothing shorter than the reactive
keepalive's 10 s of silence or the 120 s rekey could distinguish a working tick
from a loop that only ever reacted to packets. Every gate so far was faster than
both. A one-second keepalive is the first check whose failure mode is literally
"the tick is not running", so `scripts/e2e-netns.sh` now measures it.

**(c) Writing the tests found a peer that could never come back.** Proving that a
keepalive dials an idle peer meant simulating a path that stays dead for longer
than a rekey — which no earlier test did. At 180 s the key expires mid-rekey and
`poll` returns `Expire`, correctly, because expiry outranks everything. But
`tear_down` removed only the session: `established_at` stayed set, so every later
`poll` reported `Expire` again. The rekey could not retransmit, `GiveUp` never ran,
and `start_handshake` refused because the handshake state was not `Idle`. **A peer
that lost connectivity for three minutes was dead until the process restarted.**
A second, smaller case: after `GiveUp` the attempt run stayed armed, so the first
message of any later run was abandoned by the very next tick.

Both are fixed here. `Timers::on_torn_down` clears the session clock but keeps an
in-flight attempt run — the key is spent, the replacement handshake is not — and
`Timers::begin_handshake` starts a fresh budget for a new run. They belong in this
gate because a keepalive that holds a NAT binding open is worthless if the peer it
reaches cannot re-establish.

---

## 1. The obligation, stated exactly

**A peer with nothing to send must still be reachable through a mapping it did
not create.**

A NAT binding usually exists because *the inside host* sent something. A peer that
only answers is silent until called, and a mapping created from the outside is the
one most likely to be missing or short-lived. Holding the path warm therefore has
two cases, and they are not the same packet:

| state | what is due | why |
|---|---|---|
| established | an empty data packet | there is a key and an address; send one packet |
| no session | a handshake (`InitHello`) | there is nothing else that can create the mapping |

The interval is **local policy and never negotiated**. It changes only when the
peer sends packets it was already allowed to send, never what they contain, so two
ends may disagree about it freely.

---

## 2. Mechanism (normative)

### 2.1 Where the deadline lives

`Peer.next_keepalive_ms: Option<u64>`, initialised in `Peer::new` to
`now_ms + interval` and advanced by exactly one interval each time it fires. It is
**not** in `Timers`, deliberately: `Timers` owns the *reactive* rule
(`last_sent > last_received` for 10 s), which is about a path we already spoke on.
The persistent rule is about a path we may never have spoken on, and its
no-session branch is a device decision — it needs the peer's endpoint, which
`Timers` does not have.

### 2.2 Ordering against the reactive keepalive

The tick runs the persistent rule *before* `Timers::poll`. With a session, the
persistent keepalive goes through `send_keepalive`, which goes through
`seal_and_send`, which calls `Timers::on_sent`. By the time `poll` runs, the
reactive rule's `now - last_sent` is zero, so it stands down on its own. The
`TimerAction::SendKeepalive if persistent` arm is a second guard for the same
property: the two rules produce the same packet, and two in one tick is one more
than the path needs.

The same step keeps a keepalive off a spent key: it consults `Timers::is_expired`
before sending, so a peer whose key the state machine is about to reject never puts
an empty packet on it.

### 2.3 With no session

The persistent rule calls `start_handshake`, which is a no-op while a handshake is
in flight and a no-op when the peer has no endpoint. A roaming-only peer is
therefore left alone — the same no-op an outbound packet would be — while a
dialled peer comes up with **no application traffic at all**. That is the case a
NAT-bound host cannot otherwise reach.

### 2.4 Shaping and blocking

A keepalive is a `ShapingEvent::TunnelSent`, exactly like the reactive one, so a
`Pad` machine fixes its size and a `MinInterval`/`RespondWithPadding` machine sees
it. It is not an invisible packet: an unshaped keepalive carries the very timing
signature shaping exists to blur. A `Block` is ignored, as it already was for the
reactive keepalive — the packet that holds the path open is the last one a shaper
should hold.

### 2.5 Configuration

```toml
[[peer]]
persistent_keepalive = 25   # seconds; omitted means off
```

Whole seconds, because that is the unit an operator reasons in. `0` is an **error**,
not a synonym for off, for the reason P6.5 F3 made `mtu = 0` an error: a value the
operator wrote and the daemon quietly reinterpreted is how a setting goes missing.
The type is `Option<u16>`, so the upper bound is the field width; this is a cadence,
not a cryptographic parameter.

---

## 3. Rule → code → test

| Rule | Code | Test |
|---|---|---|
| absent means off | `PeerConfig::persistent_keepalive` → `None` | `an_idle_tunnel_without_an_interval_says_nothing` |
| `0` is refused, `N` is `N` seconds | `config.rs`, the `persistent_keepalive` match | `a_persistent_keepalive_is_optional_and_zero_is_not_off` |
| established: one empty packet per interval, not per tick | `Device::persistent_keepalive` | `a_persistent_keepalive_is_sent_once_per_interval` |
| no session: the interval dials | same | `a_persistent_keepalive_peer_with_no_session_dials_itself` |
| no endpoint: wait to be called | `Device::start_handshake` | `a_keepalive_peer_with_no_endpoint_waits_to_be_called` |
| persistent runs first, so coincident deadlines emit one packet | `Device::tick_peer` step (4) before step (5) | `a_persistent_keepalive_suppresses_the_reactive_one_when_they_coincide` |
| the reactive rule is unchanged | `vallum_core::timer` | `the_reactive_keepalive_still_fires_without_an_interval` |
| a spent key carries no keepalive | `Timers::is_expired` guard in step (4) | `a_persistent_keepalive_is_sent_once_per_interval` (the guard consults `timer.rs`'s expiry test) |
| expiry stops repeating once the session is gone, and an in-flight rekey still retransmits | `Timers::on_torn_down`, `Device::tear_down` | `tearing_down_a_spent_session_lets_the_rekey_finish` |
| a new run after give-up starts from attempt one | `Timers::begin_handshake`, `Device::start_handshake` | `a_new_run_after_giving_up_is_not_abandoned_immediately` |
| a peer that gave up recovers when the path returns | `Device::tear_down` + `start_handshake` | `a_peer_that_gave_up_recovers_when_the_path_comes_back` |
| the daemon wires the field to the tick | `config.rs` → `PeerConfig` → `Peer` | `scripts/e2e-netns.sh` |

---

## 4. The live check

B is configured `persistent_keepalive = 1` and has no endpoint of its own: A dials
it, so B is precisely the peer a NAT would forget. After the last ping, the script
watches `veth-a` for **2.5 s with no traffic** and counts whole UDP datagrams from
B to A's outer address and port.

Two runs:

```
B sent 2 keepalives in 2.5 idle seconds with no traffic to send
B sent 3 keepalives in 2.5 idle seconds with no traffic to send
```

Two or three is the arithmetic: a 1 s cadence over a 2.5 s window. The lower bound
is asserted at 2. The same run also confirms the rest of the gate is undisturbed:
`FragCreates +4 / ReasmReqds +3` on the initiator's side and the mirror on the
responder's, because a keepalive is one 86-byte IPv4 datagram and never fragments.

A keepalive is `58 B` of Vallum message (8 B header, 20 B of counter and tag
framing, 2 B payload length, 32 B AEAD tag) plus 8 B UDP and 20 B IPv4 — **86 B on
the wire** before any shaper pads it. At 25 s that is 3.4 B/s; at 1 s, 86 B/s ≈
0.7 kbit/s.

---

## 5. What P6.6 does **not** claim

1. **It is not NAT traversal.** There is no STUN, no ICE, no hole punching. The
   keepalive *maintains* a mapping; it does not discover an address or create a
   mapping that no packet could create.
2. **It does not guarantee a mapping survives.** NAT lifetimes vary. The interval
   must be shorter than the smallest lifetime on the path, and the daemon does not
   know or tune that number.
3. **It is not a liveness proof.** A keepalive sent is not an answer received. The
   reactive rule and handshake retransmission remain the ways a dead path is
   noticed.
4. **It is per peer, not per interface.** There is no global default and no
   inheritance.
5. **It adds traffic.** 86 B per interval before shaping, and whatever a `Pad`
   machine makes of it. An operator who sets one second on many peers is choosing
   to pay for it.
6. **No actual NAT was tested.** The end-to-end check uses a veth pair, not a NAT.
   It proves the peer sends on schedule with nothing to send; it does not prove a
   third-party NAT kept a mapping.
7. **No sub-second cadence.** The unit is whole seconds and the field is `u16`.
8. **No new authentication.** A keepalive is an ordinary data packet under the
   session key; it cannot be forged, and the replay window already covers it.
9. **No wire change.** A keepalive is the empty data packet the framing already
   allowed, which is why the frozen vectors did not move.

---

## 6. Correlation with the code

| Path | What it does |
|---|---|
| `crates/vallum-tunnel/src/peer.rs` | `PeerConfig::with_persistent_keepalive`, `persistent_keepalive` |
| `crates/vallum-tunnel/src/device.rs` | `Peer.next_keepalive_ms`, `keepalive_millis`, `Device::persistent_keepalive`, tick step (4), `tear_down` |
| `crates/vallum-core/src/timer.rs` | `begin_handshake`, `on_torn_down` |
| `crates/vallum/src/config.rs` | `PeerEntry.persistent_keepalive`, range check, `with_persistent_keepalive` |
| `crates/vallum-tunnel/tests/tunnel.rs` | the eight device-level tests in §3 |
| `crates/vallum-core/src/timer.rs` (tests) | the two timer tests in §3 |
| `crates/vallum/tests/gate.rs` | the config test in §3 |
| `scripts/e2e-netns.sh` | B's field, the idle window, and the live count in §4 |
