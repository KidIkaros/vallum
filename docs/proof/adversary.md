# Adversary — what unauthenticated traffic costs the server

**Status:** measures the DoS claim in ADR-0007 (a keyed admission check before
any key work) and the "no reflector" property. It is a measurement, not a
penetration test: it sends packets, it does not try to break the cryptography.
**Depends on:** the handshake framing (`vallum-core/src/wire.rs`), the admission
tag, and the MAC1 cookie.
**Code change:** none. `scripts/redteam.py` is the harness.

---

## 1. Method

- A server on `127.0.0.1:51921`, built by `server init --no-host --no-service`,
  inside a user namespace so nothing leaves the machine.
- The harness sends four classes of packet, each from a distinct source port so
  the kernel cannot deduplicate them by 5-tuple:

  | Class | Shape | What it reaches |
  |---|---|---|
  | noise | 1–1400 random bytes | the framing check |
  | header | 8-byte valid header, empty body | the message parser |
  | tlv | header + one plausible TLV | tag dispatch |
  | full | header + 4096-byte body | everything a sender can reach without a key |

- Cost is the server's own `utime + stime` from `/proc/<pid>/stat`, divided by
  the packet count. It excludes the sender entirely, which is the point: the
  question is what the *server* pays.
- Every packet is checked for a reply, and RSS is sampled before and after.

## 2. Result

| Class | Packets | Server CPU | Answered | RSS change |
|---|---|---|---|---|
| noise | 40 000 | 10.0 µs/packet | 0 | +240 kB |
| header | 40 000 | 8.0 µs/packet | 0 | 0 kB |
| tlv | 40 000 | 8.8 µs/packet | 0 | +44 kB |
| full (4 KiB) | 4 000 | 10.0 µs/packet | 0 | +20 kB |

The decisive number is the last row against the second: a 4 KiB body costs the
same as an 8-byte header. Nothing in the body is parsed, and no KEM operation is
attempted, before the packet is rejected. That is the admission check doing its
job, and it is what makes a cheap flood cheap to *reject*.

- **No reflector.** Zero replies across 124 000 unauthenticated packets, so a
  spoofed-source flood cannot bounce bytes off a Vallum server.
- **No unauthenticated state.** RSS moved by at most 240 kB over 40 000 distinct
  source ports — allocator noise, not a peer table. A spoofed flood cannot
  exhaust memory.
- For scale: a real handshake performs sntrup761 and ML-KEM-768 encapsulation or
  decapsulation, which costs hundreds of microseconds (see `benchmarks.md`).
  Rejection is roughly two orders of magnitude cheaper than acceptance, which is
  the ratio that matters for a flood.

## 3. What this does not claim

- **Not a volumetric test.** It ran on loopback with no packet loss and no
  bandwidth limit. It says what one packet costs the CPU, not what a link
  survives.
- **Not a fuzz run.** Malformed *inputs to the parser* are covered by
  `docs/proof/fuzzing.md`; this measures the cost of the shapes, not the
  robustness of every branch.
- **Not a spoofing test.** Source addresses were real. The reflector claim rests
  on the fact that no reply is emitted at all, which is a stronger property than
  "the reply is small".
- **Not a defence against a network that drops UDP.** Nothing here changes the
  documented limitation that Vallum is UDP-only.
- **The handshake remains fingerprintable.** A real `InitHello` is a fixed-shape
  ~4.7 KB UDP datagram with a fixed suite ID (measured in the namespace E2E as
  4665 bytes after reassembly). That is inherent to a non-obfuscated design and
  is recorded in ADR-0014, not fixed here.

## 4. Reproducing

```sh
cargo build --release -p vallum
unshare -Urn --map-root-user bash -c '
  ip link set lo up
  target/release/vallum server init --config /tmp/s.toml --no-host --no-service \
      --address 10.99.77.1/24 --listen 127.0.0.1:51921 --control /tmp/s.sock
  target/release/vallum run --config /tmp/s.toml & sleep 1.5
  python3 scripts/redteam.py --port 51921 --pid $! --count 40000
'
```
