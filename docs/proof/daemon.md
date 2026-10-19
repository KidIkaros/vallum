# P6.4 gate — the daemon, and the bug only a kernel could find

**Status:** P6.4 gate artefact. Covers `crates/vallum/` — the `vallum` binary: the
TOML configuration, the key-file format, the loop, and the two operating-system
seams.
**Depends on:** P6.3 (`docs/proof/transport.md`) for the device this drives;
P1–P5 for everything the device does. P6.4 adds no cryptography.
**Wire change:** none. The frozen vectors are untouched; the daemon is a caller of
`vallum-tunnel`, not a participant in the protocol.

---

## 0. What this gate forced

**(a) The interface was created down, and every test passed anyway.** `tun2` only
sets `IFF_UP` if asked, and the first cut never asked. The daemon started, logged
`tunnel up on interface vallum0`, the socket bound, the loop ran — and the kernel
had no connected route for the interface's own prefix, so `ping` answered
`Network is unreachable`. The in-process gate cannot see this: its interface is a
pair of channels, which has no state to be down. Neither can any unit test.

The fix is one call, `Configuration::up()`, and the lesson is the reason
`scripts/e2e-netns.sh` exists: **a mock can prove the logic, only a kernel can
prove the integration.** The daemon now reports the failure it used to hide, too —
`Error::Interface` names the interface and, on `EPERM`, says that creating one
needs root or `CAP_NET_ADMIN`, instead of printing a bare `Operation not
permitted`.

**(b) The handshake does not fit in a packet, and the tunnel depends on IP
fragmentation.** As of P6.4 there was no application-layer segmentation anywhere in
the stack: one UDP datagram was one `Message`. A tri-hybrid `InitHello` is 4609 B
of message
(including a 40 B sealed peer hint) plus a 20 B `mac1` field — a 16 B MAC under a
4 B tag and length — for **4629 B** on the wire, and the `RespHello` is **4378 B**
with no `mac1` at all (`mac1` is carried on `InitHello` only). Both go against a
1500 B path MTU, as one datagram, and the kernel fragments them.

This is measured, not asserted. In the two-namespace run the counters move
`FragCreates +4` on the initiator's side and `+3` on the responder's, which is
`ceil((4629 + 20 + 8)/1480) = 4` and `ceil((4378 + 20 + 8)/1480) = 3` for 1480 B
of IPv4 payload per fragment, and `ReasmReqds` mirrors them on the other side. It
is recorded in §5 as a limitation rather than hidden: a middlebox that drops IP
fragments drops the tunnel, and a future framing level (which is a wire change) is
the fix.

> **Corrected in P6.5.** Earlier revisions of this document said `+ 32 B of mac1`
> and gave 4641 B and 4410 B. `MAC_SIZE` is 16, and `RespHello` carries no `mac1`.
> The fragment counts were right for the wrong reason (both pairings round up to
> 4 and 3), which is why the error survived: the live capture the pentest added
> measures the actual bytes, not the arithmetic.
>
> **Closed in P6.7.** The limitation is gone. `vallum-core::segment` frames a
> message that does not fit a datagram into fragments that are each a complete UDP
> datagram, and `vallum-tunnel::Segments` reassembles them below the `Device`, so
> nothing in the protocol moved and the frozen vectors are unchanged. The counters
> this section used to report now read `+0`, which is the fix stated as a
> measurement: see [`segment.md`](segment.md). The prediction recorded here — "a
> future framing level (which is a wire change)" — was wrong about the wire: the
> envelope sits *below* the message layer, so it is not a wire change at all.

**(c) There is no persistent keepalive, so a NAT-bound responder is silent.**
`KEEPALIVE_TIMEOUT_MS` is WireGuard's rule — send a keepalive after 10 s of
sending without hearing back — which keeps an *established* path warm. It does not
help a host that has never sent anything: `Device` has no way for the daemon to
inject a keepalive, and the configuration therefore has no
`persistent-keepalive` field. A responder behind NAT that has no traffic to send is
unreachable until it does. Adding the timer is a small, separate change; adding the
config field before the timer would be a lie about what the daemon does, so it is
absent.

> **Closed in P6.6.** The timer and the field landed together, in the order this
> paragraph asked for: `PeerConfig::with_persistent_keepalive`, a per-peer deadline
> in the device, and `persistent_keepalive = <seconds>` in `[[peer]]`. It is also
> the first feature that makes the loop's 100 ms tick observable before the 120 s
> rekey, and the end-to-end script now measures it. See
> [`keepalive.md`](keepalive.md).

**(d) A config that names its own key file was resolved against the working
directory.** Found while wiring the end-to-end test, which starts daemons from
`/`: `private_key = "a.key"` next to `vallum.toml` only worked if the operator
happened to `cd` into the config's directory first. Relative key paths now resolve
against the config's directory (`config::resolve_key_path`), so `vallum run -c
/etc/vallum/vallum.toml` finds `/etc/vallum/private.key` from anywhere. Absolute
paths are used as written.

**(e) The public key is a 4.7 KB single line, and it is fine — but only after the
decoder learned to ignore whitespace.** A tri-hybrid public line is 4764 bytes of
hex. It works as one TOML string, but an editor that wraps it would otherwise
produce a key that fails to parse. `decode_public` now strips all whitespace
before splitting: every field is hex, hex contains no whitespace, so stripping can
only rescue a wrapped line and can never change the meaning of a well-formed one.

---

## 1. The obligation, stated exactly

**A process that turns a configuration file and two key files into a running
tunnel, without owning any of the decisions the layers below already make.**

The daemon may not re-implement policy. It parses, validates, opens, and pumps; the
peer table's rules stay in `vallum-tunnel`, the crypto stays in `vallum-core`, and
the suite stays in the SDK. What it must get right on its own is exactly the
operating-system surface:

| Must hold | Where it is enforced |
|---|---|
| an unknown config field is an error, never a silent default | `deny_unknown_fields` on every table |
| a peer line from another suite is refused at startup | `Config::resolve` |
| the suite is a property of the key, not a flag | `Config::suite_id` |
| a relative key path resolves next to the config | `resolve_key_path` |
| a key file is created `0600` and never overwritten | `keys::save_secret` |
| overlapping `allowed_ips` are refused, not resolved by order | `Device::new` |
| a peer outside the interface prefix is loud, not fatal | `Resolved::warnings` |
| the interface is up, with the configured MTU | `tun::platform::open` |
| packets flow both ways through a real kernel | `scripts/e2e-netns.sh` |
| an inner source outside `allowed_ips` is dropped at the receiving end | `vallum-tunnel::Device` |
| junk on the socket never costs a tunnel packet | `Message::parse` |
| the loop reports what it did | `LoopStats`, the shutdown log line |
| `SIGTERM`/`SIGINT` stop it | `Shutdown`, `signal-hook` |
| a failed draw from the OS RNG is fatal | `entropy::OsRng` |

**Success criterion.** `cargo test --workspace` — 215 tests, 214 of which run (the
one ignored test is the frozen-vector regeneration harness), including the 10
daemon gate tests in `crates/vallum/tests/gate.rs` and 8 unit tests in the crate.
Plus `scripts/e2e-netns.sh`, which needs no root and exits 0 only if a real ping
crosses two real interfaces.

---

## 2. Mechanism (normative)

### 2.1 Process shape

Two reader threads and one loop. Each reader owns exactly one blocking call and
nothing else:

```text
  /dev/net/tun ─▶ [vallum-tun]  read_packet ─┐
                                              ├─▶ mpsc<Input> ─▶ run loop ─▶ Device
  UdpSocket    ─▶ [vallum-udp]  recv_from   ─┘                   │
                                                                 ├─▶ send_to
                                                                 └─▶ write_packet
```

The loop is single-threaded and owns the `Device` outright, so there is no lock
around the handshake state and no ordering question between two events. The tick
comes from `recv_timeout`: an empty timeout is a `Tick`, so timers run every 100 ms
while idle and are never starved by continuous traffic, because any event also
runs the timer pass inside `Device::handle`.

The channel is bounded by the reader, not by the queue: each reader adds to an
`AtomicUsize` before sending, and the loop decrements it on receipt. Depth feeds
`Device::set_under_load` before each event, which is what turns the device's own
cookie rule into a decision based on how far behind the loop is
(`DEFAULT_UNDER_LOAD_DEPTH = 64`).

### 2.2 The two seams

Both are traits with a real backend and an in-process one, and the loop cannot tell
them apart:

| Trait | Real | Test |
|---|---|---|
| `tun::TunReader` / `tun::TunWriter` | `tun2` on Linux | `tun::mock::pair` — two channels |
| `net::DatagramSocket` | `UdpTransport` | `MemoryNetwork` / `MemorySocket` — mailboxes by address |

`tun::open` returns `InterfaceParts`, which carries the interface's *actual* name
(the kernel may pick one) and MTU alongside the reader and writer, so nothing
downstream assumes the requested name was the one granted.

The TUN backend is Linux-only in this phase. On any other target `tun::open`
returns `Unsupported` rather than half-working.

### 2.3 Configuration and keys

TOML, because an operator edits it by hand. `[interface]` names the interface, the
key file, the address/prefix, the MTU (default `1380`), and the listen address
(default `0.0.0.0:51820`); each `[[peer]]` carries a name, a public line, an
optional endpoint, and `allowed_ips`; `[log]` sets `trace`…`error`.

`deny_unknown_fields` is on every table. The failure it prevents is not
cosmetic: `allowed_ip` for `allowed_ips` would otherwise parse and leave a peer
with no addresses at all — a peer that can never be reached, with no error.

A private key is a small TOML file: `version`, `suite`, `seed` (32 hex), `signing`.
The seed *is* the key; it is expanded on load and nothing derived is stored, so a
reload and a regeneration cannot disagree. `save_secret` opens with `create_new`
and mode `0600`, so it refuses to clobber an existing key rather than silently
replacing the identity a peer has pinned.

A public key is one line: `vallum1:<suite hex4>:<kem hex>:<signature hex or ->`.
The tag makes a future encoding a different tag instead of a guess.

The suite is read from the key file and nowhere else — a flag could contradict the
key, and a seed is only a key under the suite it was expanded with. Resolving a key
against the wrong suite is a startup error that names both ids.

### 2.4 Routing, and what the daemon will not do

The daemon assigns `address/prefix` to the interface and relies on the kernel's
connected route to send the prefix into the tunnel. When a peer's `allowed_ips`
falls outside that prefix, the kernel has no route for it, and the peer is
unreachable — a failure mode that otherwise looks exactly like a broken handshake.
So `resolve` emits a warning naming the address and the `ip route add` command to
run. It does not run it: the daemon spawns no processes, uses no shell, and writes
no routing table entries.

For the same reason an IPv6 interface address is a warning with the exact
`ip -6 addr add` command: `tun2`'s configuration path is `AF_INET`, and a
half-configured interface is worse than one the operator finished. The data plane
does not inspect the address family — a packet is routed by its destination prefix
and sealed as bytes — and `allowed_ips` accepts v6 prefixes, but this phase has no
test that carries inner IPv6, and the daemon cannot put a v6 address on the
interface for you.

### 2.5 Shutdown, entropy, and the CLI

`Shutdown` is a flag over `Arc<AtomicBool>`; `signal-hook` registers `SIGINT` and
`SIGTERM` on it. The loop checks it each iteration, so stopping takes at most one
tick plus the current event. There is no draining: a packet in the queue at that
moment is lost, and the shutdown log line says what was actually sent and
delivered.

Randomness is `getrandom` behind `entropy::OsRng`. A failed draw aborts. That is
deliberate: a handshake or a key generated from a silent fallback would be worse
than a process that refuses to start, and the SDK's deterministic paths are for
tests, not for production entropy.

Three subcommands: `keygen` (write a key, print the public line), `pubkey` (print
the public line for an existing key), `run` (the tunnel). The library crate is
signal-free and `unsafe_code` is forbidden; everything unsafe lives in the
dependencies.

---

## 3. Rule → code → test

| # | Rule | Code | Test |
|---|---|---|---|
| 1 | an unknown config field is refused | `config.rs`, `deny_unknown_fields` | `a_mistyped_field_is_a_config_error_not_a_silent_default` |
| 2 | a peer line from another suite is refused | `Config::resolve` | `a_peer_for_another_suite_is_refused` |
| 3 | the suite comes from the key, not a flag | `Config::suite_id` | `the_suite_is_taken_from_the_key_not_from_a_flag` |
| 4 | a relative key path resolves next to the config | `resolve_key_path` | `a_relative_key_path_is_resolved_against_the_config_not_the_cwd`; the e2e starts daemons from `/` |
| 5 | a key file is `0600` and is never overwritten | `keys::save_secret` | `a_key_file_is_owner_only_and_expands_to_the_same_key_twice` |
| 6 | the public line round-trips, wrapped or not | `keys::{encode,decode}_public` | `a_public_line_round_trips`, `a_wrapped_public_line_still_loads` |
| 7 | overlapping `allowed_ips` are refused | `Device::new` | `two_peers_claiming_the_same_address_are_refused` |
| 8 | a peer outside the interface prefix warns with the command | `Config::resolve` | `a_peer_outside_the_interface_prefix_is_warned_about` |
| 9 | two daemons establish and carry traffic both ways | `run::run` | `two_daemons_establish_and_carry_traffic_both_ways`; e2e |
| 10 | an inner source outside `allowed_ips` is dropped | `vallum-tunnel::Device` | `a_packet_claiming_a_disallowed_source_is_dropped` |
| 11 | junk on the socket costs no tunnel packet | `Message::parse`, `on_datagram` | `junk_datagrams_do_not_disturb_the_tunnel` |
| 12 | the interface is up, with the configured MTU | `tun::platform::open` | **e2e only** (§0a) |
| 13 | the loop reports what it did | `LoopStats` | gate asserts `established`, `datagrams_sent`, `packets_delivered`; e2e asserts the log line |
| 14 | `SIGTERM` stops the loop and logs the counters | `Shutdown`, `run.rs` | e2e |
| 15 | a failed OS draw is fatal | `entropy::OsRng` | `entropy::tests` |
| 16 | an endpoint is learned only from authenticated traffic | `vallum-tunnel::Device` | gate and e2e (B is configured with no endpoint) |
| 17 | a wrong privilege level is reported as a privilege problem | `Error::Interface` | manual: the binary prints the hint (§0a) |

Rows 12 and 17 are the honest gaps: no test in `cargo test` covers them, because no
in-process substitute has a kernel or a capability check. They are covered by the
script and by hand, respectively, and the table says so.

---

## 4. The real-network gate

`scripts/e2e-netns.sh` builds two network namespaces joined by a veth pair, one
`vallum0` in each, and runs the actual binary in both. It needs no root: an
unprivileged user namespace grants `CAP_NET_ADMIN` over interfaces in a network
namespace it owns, which is enough for `TUNSETIFF`.

It checks, in order: the outer network is up; both keys differ; both daemons stay
up; `ping 10.7.0.2` from one namespace succeeds; both daemons log an establishment
with opposite roles; B's config has no endpoint, so B learned A's address from the
handshake; the reverse direction succeeds; a 1228-byte inner packet succeeds; both
daemons exit on `SIGTERM` after logging their counters.

The measured output of a clean run on this host, as of P6.7:

```text
ns1, daemon A:  FragCreates +0   ReasmReqds +0
ns2, daemon B:  FragCreates +0   ReasmReqds +0
   it crossed as 4 Vallum fragments, the largest UDP payload being 1452 B
```

The `+4`/`+3` this section used to report were `ceil((4629 + 28)/1480) = 4` for
the `InitHello` and `ceil((4378 + 28)/1480) = 3` for the `RespHello`. They now
cross as datagrams the kernel never has a reason to touch: the capture reassembles
the segmentation envelope and reports 4629 B, and the kernel counters stay at
zero. Those are two independent measurements of the same statement. See
[`segment.md`](segment.md).

A note on the round-trip times it prints: the first packet pays the handshake, and
this is an unoptimised build in a test namespace. Those numbers are not a
performance claim and should not be quoted as one.

---

## 5. What P6.4 does **not** claim

1. ~~**No application-layer segmentation.**~~ **Closed in P6.7:**
   [`segment.md`](segment.md) adds the envelope. A message larger than
   `segment::MAX_OUTER_DATAGRAM` (1452 B) is cut into fragments that are each a
   whole UDP datagram and reassembled below the `Device`, so a NAT — which cannot
   translate an IP fragment with no transport header — no longer sees anything to
   drop. The prediction recorded in P6.4 that this "is a wire change, and the
   frozen vectors would move" was **wrong**, and the reason is worth keeping: the
   envelope sits below the message layer, so the messages themselves are
   byte-identical and the vectors did not move.
2. **No persistent keepalive.** A responder behind NAT with nothing to send is
   unreachable until it sends something (§0c). The config does not pretend
   otherwise. **Closed in P6.6:** [`keepalive.md`](keepalive.md) adds the timer and
   the field; a peer may now be dialled on a cadence with no traffic to send.
3. **No IPv6 address configuration, and no tested inner IPv6 path.** `tun2`'s
   config path is `AF_INET`, so the daemon cannot assign a v6 address; it says so
   and prints the command. `allowed_ips` accepts v6 prefixes and the data plane
   treats packets as opaque bytes, but nothing in this phase carries v6 end to end.
4. **No routing-table management.** The daemon installs nothing and spawns
   nothing. A peer outside the interface prefix produces a warning, not a route.
5. **No privilege separation.** The process runs as the user that started it and
   keeps the TUN descriptor for its lifetime. There is no capability drop, no
   sandbox, and no per-peer isolation. Running it as root is the simple thing, not
   the safe thing, and this phase does not claim otherwise.
6. **No performance or scale claim.** The under-load threshold (64 queued
   packets), the 100 ms tick, and the reader→loop queue bound (256 packets, ≈4 MiB
   — enforced by the channel, see `pentest.md` F1) are reasoned, not tuned. Nothing
   here has been measured at a high packet rate.
7. **No drain on shutdown.** `SIGTERM` stops the loop within a tick; queued packets
   are dropped and the log line says what got through.
8. **No defence against an on-path attacker.** The daemon moves bytes. The
   confidentiality, authenticity and PCS argument is P1–P5 and lives in their
   proofs.
9. **No rekey-under-load test in the daemon.** The epoch machine is P4's and is
   tested there; the loop carries its actions without understanding them, which is
   the point, but that is not the same as a soak.
10. **Not portable.** The TUN backend is Linux-only this phase; other targets get
    `Unsupported` from `tun::open`.
11. **`tun2` is WTFPL-licensed.** Fine for use, worth knowing for distribution. It
    is an implementation detail behind `tun::TunReader` / `TunWriter`, so replacing
    it does not touch the daemon.

P6.5 attacked this daemon and its operator surface directly. Its findings — four
silent-failure bugs in configuration and queueing, one wrong size table in this
document, and the two residual risks above it chose to accept rather than fix —
are in [`pentest.md`](pentest.md). The queue bound in item 6 is one of its
findings: this document claimed it before the code enforced it, and the test that
now pins it is named there.
