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
| TUN `IFF_VNET_HDR` | `tun2` exposes `PlatformConfig::vnet_hdr(bool)` through `Configuration::platform_config` | **Available** |
| `TUNSETOFFLOAD` (GSO/TSO/checksum offload) | Not implemented in `tun2` 4.0; the daemon would need the ioctl **and** virtio-header segmentation/checksum handling | **The real blocker** |
| Multi-queue (`IFF_MULTI_QUEUE`) | `Configuration::queues(n)` exists, but Linux returns `InvalidQueuesNumber` for `n != 1` | **Blocked by the crate's Linux path** |
| Safe raw ioctls | `nix`'s ioctl macros would generate the calls, but creating the TUN ourselves means duplicating `tun2`'s ownership and lifecycle | Not worth it without the crate's support |

The earlier note was wrong on one point: `vnet_hdr` **is** public, and
`Configuration::queues` exists. What is missing is `TUNSETOFFLOAD` and the
daemon's handling of the 10-byte virtio header and GSO super-packets — copying
IP headers, adjusting lengths and checksums, and segmenting before sealing.
That is the real work, not a private-field workaround.

---

## 3. Decision

- **GSO/GRO and multi-queue: deferred.** The headline win needs a `tun2` change
  (public setters, or a documented offload API) or an owned TUN backend. That is
  its own project, and it must not be smuggled in as an `unsafe` block.
- **Batched UDP I/O: implemented.** `DatagramSocket::send_many` defaults to a
  loop; `UdpTransport` uses `sendmmsg` on Linux. The loop collects the datagrams
  one event produced, sends them in one call, and retries the unsent tail
  individually so the per-destination `EMSGSIZE` warning is preserved.
  `show` reports `vallum_batching=true` on Linux.
- **No regression:** the baseline stays as recorded. Batching changes the send
  syscall count, not the bytes or the crypto.

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
