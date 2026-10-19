# Vallum

[![CI](https://github.com/KidIkaros/vallum/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/KidIkaros/vallum/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust 1.95+](https://img.shields.io/badge/rust-1.95%2B-orange.svg)](Cargo.toml)

A hybrid **post-quantum layer-3 tunnel** — a real userspace VPN, not a reference
crate.

Vallum is built *on top of* `origin-crypto-sdk` but never *inside* it: every
cryptographic operation Vallum performs goes through a Vallum-owned boundary
trait, so the SDK can be swapped — or replaced with from-scratch cryptography —
without touching the protocol.

## Why it exists

PQ-WireGuard (Hülsing–Ning–Weber–Schwabe–Zimmermann, 2023) proved a KEM-only
handshake can replace WireGuard's non-interactive DH. Vallum takes that design as
the floor and pushes on the five things it leaves on the table:

| Vector | Gap in PQ-WireGuard | Vallum |
|---|---|---|
| Hybrid KEM | one classical + one PQ leg, single KEM each | tri-hybrid `X25519 + sntrup761 + ML-KEM-768`, combined with HKDF-SHA3-256 |
| Hybrid signature auth | none (static KEM keys only) | Ed25519 + Falcon-1024 over the transcript, with CA-issued identity documents and a signed validity window |
| Key reuse | none | **rejected on purpose** (P3): one master seed → a KEM key *and* an independently derived signing key; no dual-use key |
| Epoch axis | no epoch, no erasure discipline | rekey is a fresh hybrid handshake (root independence), 2⁴⁸/2⁴⁹ caps, one superseded epoch erased after `REJECT_AFTER_TIME` |
| Traffic analysis | none | Maybenot-style shaping, off by default, padding inside the AEAD |

It also keeps the good parts of WireGuard (cryptokey routing, TAI64N, keyed MAC
cookies, roaming by authenticated source) and strengthens suite negotiation:
WireGuard offers no negotiation, Vallum *binds the suite id into the transcript*,
so a downgrade is **detectable**.

## The boundary (the load-bearing idea)

```
   protocol (handshake · key schedule · framing · data plane)
        │  bytes only — no provider type crosses this line
        ▼
   vallum-crypto        -- CryptoSuite trait + protocol combiners (no deps)
        ▲
   ┌────┴─────────────────────────┐
   │                              │
vallum-crypto-sdk            (future: from-scratch adapter)
(origin-crypto-sdk)          same trait, new suite id
```

- **`vallum-crypto`** — the `CryptoSuite` trait and the protocol-level combiner
  and transcript hash. Zero dependencies, zero cryptographic implementations.
- **`vallum-crypto-sdk`** — the only crate that names an SDK type.
- **`vallum-crypto-contract`** — a suite-agnostic test harness. It depends on
  `vallum-crypto` only, so it applies unchanged to any adapter.

Swapping crypto = one new adapter + one new suite id + refreshing the KATs. The
handshake, key schedule, framing, and data plane do not change.

## Handshake

Three messages, three hybrid-KEM operations, one round trip:

```
Initiator                                              Responder
InitHello    ── STATIC_CT (A) · EPHEMERAL_PK · TIMESTAMP ──▶   [static key]
             ◀── EPHEMERAL_CT (B) · STATIC_CT (C) · conf_r ──   RespHello
InitConf     ── conf_i ────────────────────────────────────▶   [verify]
```

| op | direction | peer key | purpose |
|----|-----------|----------|---------|
| A | init → resp | responder **static** | responder authentication |
| B | resp → init | initiator **ephemeral** | forward secrecy |
| C | resp → init | initiator **static** | initiator authentication |

Both static operations are **MEX-bound** (`KDF1(σ, r)`): the sender's own
long-term secret is mixed into the encapsulation randomness, so a subverted RNG
cannot fix the shared secret. Confirmation is **mutual and explicit** — the
responder proves key possession in `RespHello`, the initiator in `InitConf` — so
neither party accepts a key before authenticating the other. That is the property
whose absence kept WireGuard out of eCK-PFS-PSK; see `docs/proof/eck-pfs-psk.md`.

## Suite registry

| id | legs | status |
|----|------|--------|
| `0x0001` | X25519 + sntrup761 | supported (non-NIST-pure fallback) |
| `0x0002` | X25519 + ML-KEM-768 | supported |
| **`0x0003`** | **X25519 + sntrup761 + ML-KEM-768** | **default** |
| `0x0100+` | reserved for from-scratch cryptography | — |

The two post-quantum legs are **independently implemented** (SDK NTRU Prime vs
pinned RustCrypto ML-KEM), so an implementation fault in either is covered by
the other. This does **not** protect against a break of the lattice family
itself — a code-based leg would be needed for that, and the SDK does not ship
one (recorded as an open limitation).

## Layout

```
Cargo.toml                        workspace
crates/
  vallum-crypto/                  boundary: trait + combiners (no deps)
  vallum-crypto-sdk/              origin-crypto-sdk adapter (and the CT harnesses)
  vallum-crypto-contract/         suite-agnostic contract tests
  vallum-core/                    handshake · key schedule · TLV wire · data plane
                                  · epoch · shaping · segmentation · identity
  vallum-tunnel/                  sans-IO transport: peers, routing, handshakes
  vallum-protocol-tests/          suite-dependent tests and benchmarks
  vallum-quick/                   routes, DNS, firewall and hooks (admin tool)
  vallum/                         the daemon: TOML, TUN, UDP, privileges, CLI
packaging/                        systemd unit, man pages, completion
scripts/install.sh                first install and client add/remove
fuzz/                             cargo-fuzz workspace (four targets)
docs/proof/                       one artefact per gate
  eck-pfs-psk · committing-aead-multikey · hybrid-identity · ratchet-pcs
  traffic-shaping · transport · segment · keepalive · pentest · daemon
  constant-time · benchmarks · fuzzing · privileges · mtu · ipv6 · dual-stack
  identity-validity · tamarin
scripts/
  e2e-netns.sh                    two namespaces, real kernel, four lifecycles
  ct.sh · fuzz.sh                 the measurement and fuzzing gates
```

## Build

The workspace pins the SDK by path, so clone both repositories as siblings:

```sh
git clone https://github.com/KidIkaros/vallum.git
git clone https://github.com/KidIkaros/OriginSDK.git origin-crypto-sdk
cd vallum
cargo test --workspace
```

`scripts/bootstrap.sh` does the sibling clone for you. The `fast` profile is
suite `0x0002` (X25519+ML-KEM-768): generate a key with `vallum keygen --suite 2`.
It completes a handshake in ~1.81 ms versus ~54 ms for the default tri-hybrid;
the default stays tri-hybrid for KEM diversity.

## TUI

`vallum tui` is a terminal operations console: live device and peer state, peer
add/edit/remove, key generation, client-bundle QR export, runtime device
changes, start/stop, and journald logs. It talks to the 0600 control socket and
needs no root for status or peer changes.

```text
┌Vallum────────────────────────────────────────────────────────────────────────────────────────┐
│ vallum0                                                                                      │
│listen 127.0.0.1:41403  suite 0x0003  fwmark 0  079c12170a8fb63b                              │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
┌Peers────────────────────────────────────────────────────────────────────┐┌Details──────────────┐
│name         fingerprint      endpoint   allowed        handshake rx/tx    ││laptop               │
│laptop       1a0888aca6183e92 (none)     10.7.0.2/32    —         0B/0B     ││allowed  10.7.0.2/32 │
└──────────────────────────────────────────────────────────────────────────┘└─────────────────────┘
Tab interface  j/k peer  a add  e edit  d remove  g keygen  q QR  c device
C interface  E edit config  s start/stop  l logs  f follow  ? help  Q quit
```

Generate that frame yourself with
`vallum tui --config <file> --snapshot --width 160 --height 30`. The QR export
asks for the server endpoint (an unspecified `0.0.0.0`/`[::]` is rejected);
`vallum import-bundle <file> --output-dir DIR` unpacks a bundle into a config
and a 0600 key. See [`docs/tui.md`](docs/tui.md) for the key map and limits.

## Test

```sh
cargo test --workspace      # unit + integration + boundary contract tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt -p vallum-core -p vallum-tunnel -p vallum -p vallum-crypto \
          -p vallum-crypto-sdk -p vallum-crypto-contract -- --check
cargo deny check            # licenses, sources, bans, advisories
bash scripts/e2e-netns.sh   # two namespaces, a real kernel, four lifecycles
bash scripts/ct.sh          # DudeCT constant-time gate
bash scripts/fuzz.sh 60     # four cargo-fuzz targets
cargo bench -p vallum-protocol-tests  # handshake and data-plane baselines
```

Byte-exact handshake vectors are frozen in `crates/vallum-protocol-tests/tests/interop.rs`
and regenerate with:

```sh
cargo test -p vallum-protocol-tests --test interop -- --ignored --nocapture
```

The contract tests (`crates/vallum-crypto-contract`) exercise KEM keygen/round-
trip/tamper-rejection, the combiner, the transcript hash, committing-AEAD seal/
open + forgery rejection, and hybrid signature verify/reject — for every shipped
suite, plus an adapter-swap smoke test.

## Status

Every phase is implemented and gated: **P0–P6.8** (boundary through the daemon,
keepalive, segmentation, and the admission tag), all seven proof obligations
(including the Tamarin model and the PSK-tag DoS/replay model), **H1–H9**
(constant-time, benchmarks, fuzzing and CI, privilege separation, MTU-aware
segmentation, IPv6, identity validity, dual-stack addressing), the **G1–G6**
operational surface (configured PSK, UAPI, runtime rebind, `vallum-quick`,
batching, platform tier), and the **TUI**. The architecture decisions are in
[`docs/adr/`](docs/adr/). `docs/proof/` holds one artefact per gate, and each one
states what it does **not** claim.

Known open items are product decisions rather than missing work: a code-based
(non-lattice) KEM suite for true family diversity, the Rosenpass-style PSK bridge,
and the final name. The SDK's custom sntrup761 is the cost centre — ~9 ms per
decapsulation here, versus ~0.25 ms for the ML-KEM leg — which is why the
alternative-suite work matters.

A dual-stack tunnel is one config: `addresses = ["10.7.0.1/24", "fd00:7::1/64"]`.
