# G5 — data-plane performance (spike outcome)

**Status:** spike complete; **GSO/GRO and multi-queue deferred** at the gate, with
the blocker and the patch path recorded. No unsafe code was added.
**Depends on:** H3 (`benchmarks.md`) for the baseline, P6.4 for the loop.

---

## 1. Baseline

From `benchmarks.md`, on the reference host:

- data plane at 1 380 B: seal ~4.07 µs, open ~3.93 µs (~323/335 MiB/s);
- tri-hybrid handshake: ~54 ms, dominated by the SDK's sntrup761;
- the loop does one `read`/`write` per packet on one thread.

The crypto is not the bottleneck at realistic packet rates; syscalls and
per-packet copies are.

---

## 2. Spike: what the ecosystem actually offers

| Capability | Availability | Verdict |
|---|---|---|
| Batched UDP receive | `nix::sys::socket::recvmmsg` is a **safe** function over `MultiHeaders`/`MultiResults` (Linux, 0.31) | Available |
| Batched UDP send | `nix::sys::socket::sendmmsg` is **safe** in the same way | Available |
| TUN GSO/GRO (`IFF_VNET_HDR`, `TUNSETOFFLOAD`) | `tun2` has the flags internally, but `PlatformConfig::vnet_hdr` is `pub(crate)`; `Configuration::platform_config` exposes only a closure over a type whose fields are private | **Blocked by the crate** |
| Multi-queue (`IFF_MULTI_QUEUE`) | Same: `queues_num` is private to `tun2` | **Blocked by the crate** |
| Safe raw ioctls | `nix`'s ioctl macros would generate the calls, but creating the TUN ourselves means duplicating `tun2`'s ownership and lifecycle | Not worth it without the crate's support |

The blocker is concrete: `tun2` 4.0's `platform_config` closure receives a
`PlatformConfig` whose `vnet_hdr` and `queues_num` are `pub(crate)`. There is no
public setter. GSO/GRO without it means either patching/forking `tun2` or
hand-rolling `TUNSETIFF`/`TUNSETOFFLOAD` — the latter is a second TUN backend,
not a performance tweak.

---

## 3. Decision

- **GSO/GRO and multi-queue: deferred.** The headline win needs a `tun2` change
  (public setters, or a documented offload API) or an owned TUN backend. That is
  its own project, and it must not be smuggled in as an `unsafe` block.
- **Batched UDP I/O: available but not implemented in this cut.** The send path
  is one datagram per `Action::Send`, with per-destination `EMSGSIZE` accounting;
  batching would need a per-message result path (`MultiResults`) and a redesign
  of that accounting. The measured win without GSO/GRO is modest, so it is
  deferred together rather than shipped half-done.
- **No regression:** the baseline stays as recorded; nothing in this phase
  changes the data path.

---

## 4. What is visible now

`vallum bench` measures the data plane's seal/open on the host and prints the
per-packet cost and throughput, with a note that a debug build is not a
measurement. `vallum show` reports `vallum_offload=false` and
`vallum_batching=false`, so the state is visible rather than inferred.

```text
suite 3 (x25519+sntrup761+ml-kem-768), 1380 B payload, 2000 iterations
  seal: 4.9µs/packet, 267 MiB/s
  open: 4.1µs/packet, 318 MiB/s
  crypto only; the loop adds one read/write syscall per packet
```

## 5. The patch path, when it is picked up

1. `tun2`: add public `vnet_hdr(bool)` and `queues_num(usize)` (or a fork), and
   a `TUNSETOFFLOAD` call after creation.
2. `vallum`: `[interface] offload = true`, off by default; the loop must handle
   the 10-byte virtio header and GSO-sized writes.
3. Batching: a `DatagramSocket::send_many` default loop plus a `UdpTransport`
   `sendmmsg` implementation; per-message errors feed the existing counters.
4. Measure with `iperf3` over the two-namespace e2e (not available on this host;
   the method is `iperf3 -c <peer> -t 10 -P 4` inside the netns, with the
   tunnel's `allowed_ips` covering the client address).

The gate stays: e2e with offload on and off, no checksum/GSO-size regressions,
and a recorded before/after.

---

## 6. What this does **not** claim

No throughput improvement was made. The existing crypto benchmarks stand; the
loop is still one packet per syscall.
