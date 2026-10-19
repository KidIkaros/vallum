# §8 — benchmarks

**Status:** discharges the benchmark item of the plan's §8. The correctness
gates came first, as the house rule requires; this is the first place the cost is
written down.
**Depends on:** P1 (the handshake measured), P2/P5 (the data plane and the padded
seal), P6.8 (the wire the numbers describe).
**Code change:** none. Benches only.

---

## 1. Method

- Criterion 0.8.2, release profile, single-threaded.
- Handshake: sample size 20, warm-up 0.5 s, measurement 2 s per benchmark.
- Data plane: sample size 50, same windows.
- Machine: Intel Core i7-10750H @ 2.60 GHz, Linux 7.0.0-38-generic, rustc 1.97.1,
  `powersave` governor.
- Seeds and timestamp are fixed, so a rerun on the same machine is comparable and
  the messages are exactly the ones the frozen vectors describe.

The short windows are a deliberate trade: this is a recorded baseline, not a
tuning exercise. The intervals are printed by criterion and the medians below are
the point estimates; a wide interval (the tri-hybrid `responder_accept`) is
reported as measured, not smoothed.

```sh
cargo bench -p vallum-protocol-tests --bench handshake -- --warm-up-time 0.5 --measurement-time 2
cargo bench -p vallum-protocol-tests --bench dataplane -- --warm-up-time 0.5 --measurement-time 2
```

---

## 2. Handshake

Median time per stage. "Full" is one complete exchange: `InitHello` →
`RespHello` → `InitConf` → verify.

| Suite | initiator_hello | responder_identify | responder_accept | initiator_process_resp | full |
|---|---|---|---|---|---|
| 0x0001 X25519+sntrup761 | 17.94 ms | 9.40 ms | 6.85 ms | 18.74 ms | 52.72 ms |
| 0x0002 X25519+ML-KEM-768 | 358.6 µs | 251.6 µs | 504.6 µs | 581.1 µs | 1.81 ms |
| 0x0003 tri-hybrid | 18.47 ms | 9.51 ms | 7.23 ms | 19.06 ms | 54.27 ms |
| 0x0003 tri-hybrid, signed | 18.47 ms | 9.46 ms | 8.05 ms | 20.26 ms | 56.30 ms |

**The number that matters is the gap between rows 2 and 3.** The tri-hybrid is
dominated by sntrup761: the ML-KEM suite completes an exchange in 1.81 ms, the
sntrup761 suites take 53–55 ms. The custom NTRU Prime implementation costs
roughly 9.4 ms per decapsulation and 18 ms per keygen+encapsulation on this host —
two orders of magnitude above the reference sntrup761 figures (~0.1–0.2 ms). That
is a property of the SDK implementation, not of the protocol: the same wire, the
same schedule, with a different KEM leg is 20–30× cheaper. It is recorded here
because a default suite that costs ~54 ms per handshake is an operational fact,
and because it is the strongest argument for the code-based/alternative-suite
work in §10.

The signed row is not slower in the handshake stage because Falcon's cost is a
verification (~0.3 ms) against a ~9.5 ms decapsulation; the signature's real cost
is the wire (+1649 B per field) and the one-time keygen, both in
`hybrid-identity.md`.

---

## 3. Data plane (tri-hybrid)

| Payload | seal | open | seal throughput | open throughput |
|---|---|---|---|---|
| 64 B | 941 ns | 780 ns | 64.9 MiB/s | 78.2 MiB/s |
| 512 B | 2.01 µs | 1.77 µs | 242.8 MiB/s | 276.0 MiB/s |
| 1380 B | 4.07 µs | 3.93 µs | 323.2 MiB/s | 334.6 MiB/s |
| padded to 1400 | 4.13 µs | — | 323.2 MiB/s | — |

At the default inner MTU a data packet costs ~4 µs in each direction, so the
crypto is not the bottleneck at any realistic packet rate; the padded seal costs
the same as an unpadded 1380-byte packet because the work is the AEAD, not the
payload's contents. Throughput here is per-operation on one core and does **not**
include the daemon's loop, sockets, or TUN — those are not measured (see §5).

---

## 4. Against PQ-WireGuard's reported numbers

The plan asked for this comparison, and the honest form is a table of what is and
is not comparable.

| Quantity | PQ-WireGuard (paper) | Vallum (measured/frozen) | Comparable? |
|---|---|---|---|
| Handshake messages | 3 | 3 | yes |
| Bytes on the wire | ≤ 1232 B per message; 2654 B total | 4609 + 4414 + 52 = **9075 B** | **no** — different design |
| Static key material on the wire | none (McEliece pk ~1 MB, configured out of band) | full hybrid ciphertext (1039/1088 B) in op A and op C | **no** |
| Handshake cost vs WireGuard | < 70 % slower client, ~50 % server | not measured against WireGuard | **no** — no implementation here |
| KEM family | McEliece (code-based) + Saber (lattice) | X25519 + sntrup761 + ML-KEM-768 | **no** — different diversity |

The size difference is the protocol's design, not an inefficiency: PQ-WireGuard
assumes a ~1 MB McEliece public key is provisioned out of band, which is
incompatible with a peer line a human pastes into a config. Vallum pays for
self-contained peer configuration with bytes. A real timing comparison would
require building PQ-WireGuard and running both on this host with the same message
pattern; that is not done here, and no claim rests on it.

---

## 5. What this does **not** claim

1. **No daemon throughput.** The loop, the socket, the TUN, and the segmentation
   envelope are not in these numbers.
2. **No head-to-head with PQ-WireGuard or WireGuard.** Different hardware, no
   implementation in the repo, different wire design.
3. **No tuning.** Short measurement windows, `powersave` governor, a laptop CPU.
   The numbers are a baseline for a regression, not a capability claim.
4. **No claim that the sntrup761 cost is inherent.** It is this implementation's
   cost; the reference figures are cited to show the gap, not to promise a fix.
5. **No multi-core or batched figures.** One operation at a time, one thread.
