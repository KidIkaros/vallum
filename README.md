# Vallum

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
| Hybrid signature auth | none (static KEM keys only) | Ed25519 + Falcon-1024 over the transcript (identity documents) |
| Dual-use identity key | none | Thormarker Ed25519→X25519 construction (planned) |
| Bounded ratchet | none | fresh hybrid ephemerals per rekey, 2⁴⁸ cap, key erasure (planned) |
| Traffic analysis | none | Maybenot-style shaping, off by default (planned) |

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
  vallum-crypto-sdk/              origin-crypto-sdk adapter
  vallum-crypto-contract/         suite-agnostic contract tests
  vallum-core/                    handshake · key schedule · TLV wire framing
docs/
  proof/eck-pfs-psk.md            P1 gate: eCK-PFS-PSK adaptation
```

## Test

```sh
cargo test --workspace      # unit + boundary contract tests
cargo clippy --workspace --all-targets
```

Byte-exact handshake vectors are frozen in `crates/vallum-core/tests/interop.rs`
and regenerate with:

```sh
cargo test -p vallum-core --test interop -- --ignored --nocapture
```

The contract tests (`crates/vallum-crypto-contract`) exercise KEM keygen/round-
trip/tamper-rejection, the combiner, the transcript hash, committing-AEAD seal/
open + forgery rejection, and hybrid signature verify/reject — for every shipped
suite, plus an adapter-swap smoke test.

## Status

Phase **P1** (handshake core). The three-message KEM-AKE, MEX, the staged
transcript, and both explicit key confirmations are implemented and test-green.
Data plane, identity, ratchet, and shaping are not yet implemented. See the plan
for the phase gates and `docs/proof/eck-pfs-psk.md` for the P1 proof adaptation.
