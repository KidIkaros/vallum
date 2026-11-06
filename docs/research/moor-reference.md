# MOOR as a reference implementation

What a small C onion router does that Vallum does not, read from the source at
commit `98bb70c` (29 April 2026) of `codeberg.org/sickkk/MOOR_PQ`. Evidence is
marked with its file and line.

Scope: this is a **code and design read**, not an audit. Nothing here is a
security assessment of MOOR, and no MOOR code has been run. The question is
narrow: does it contain anything Vallum should adopt, and if so, in what form.

## What it is

A three-hop onion network with hybrid post-quantum cryptography. MIT licensed.
49,953 lines of C in `src/*.c` (76,436 with headers), 48 modules, 932 KB of
vendored PQClean code in `src/pqclean/` (34 files: ML-KEM-768, ML-DSA-65,
Falcon-512, each directory carrying its own upstream `LICENSE`).

Its own `docs/security.md` is unusually candid for a project of this age, and
that candour is the most useful thing in the repository:

- no third-party audit (an internal pass in April 2026 is claimed, not published);
- "The code is C" — no memory-safety claim beyond stack protector and FORTIFY;
- the vendored PQ wiring is *its own* code and "inherits our risk";
- a global passive adversary is **not** defeated;
- the default network has two directory authorities, so a compromised majority
  forges consensus.

## Verified in the code

| Claim | Where | What it actually is |
|---|---|---|
| Fixed-size cells | `include/moor/limits.h:14-20` | 514 bytes on the wire, 5-byte header, 509 payload, 11-byte relay header, 498 relay data. Fixed three-hop topology. |
| Cell commands | `include/moor/cell.h:8-17` | Tor-shaped command set plus `CELL_CREATE_PQ`, `CELL_CREATED_PQ`, `CELL_KEM_CT` for the hybrid hop exchange. |
| WTF-PAD machines | `src/wfpad.c` | Three tables (web, stream, generic), each a Markov chain over inter-arrival distributions with transitions on real/pad events. Parameters are per-circuit randomised. |
| FRONT padding | `src/wfpad.c:11-12,149-151` | Randomised front padding over a circuit's first seconds (Gong & Wang 2020), cell count sampled from a Rayleigh distribution. |
| Constant-rate floor and volume padding | `src/wfpad.c`, `src/main.c:1985` | A minimum cover-traffic rate, and cell counts padded to the next power of two. |
| SKIPS scheduling | `src/scheduler.c:216-244`, `src/circuit.c:1811-1835`, `src/socks5.c:1587-1595` | Real: a persistent timer picks a circuit via EWMA fairness and `TCP_INFO`, then flushes. |
| Vegas congestion control | `src/circuit.c:1828-2029` | Real: `min_rtt` tracking, BDP estimate, delay-based cwnd adjustment. |
| Conflux multi-path | `src/conflux.c` (449 lines) | Four-leg aggregation with a Feistel PRP over sequence numbers. |
| seccomp sandbox | `src/sandbox.c:191` | Syscall allow-list including `getrandom`, `no_new_privs`, rlimits. |
| Pluggable transports | `src/transport_{mirage,nether,scramble,shade,shitstorm,speakeasy}.c` | Six transports, ~3,000 lines for the largest. |

Its RNG is libsodium's `randombytes`, which is the correct answer, and the
non-vendored code has no `strcpy`, `strcat` or `gets`; the one `sprintf`
(`src/directory.c:490`) fills a 65-byte buffer two bytes at a time and is
correct. The single `system()` in `src/main.c:3998-4003` is the one worth
naming: the crash handler builds an `addr2line` command with the executable
path interpolated, so a path containing shell metacharacters reaches a shell on
the crash path. Small, on a rare path, and the sort of thing a port carries
over unnoticed.

## Where the repository does not support its own claims

- **The test suite cannot run.** `Makefile:223` declares 31 test binaries
  (`test_crypto`, `test_cell`, `test_kem`, `test_scheduler`, …). `tests/`
  contains one file, `test_transport.c` (241 lines, zero assertions). `make test`
  stops at `No rule to make target 'tests/test_crypto.c'`. Whatever testing
  happened, the harness that did it is not in the repository.
- **No CI.** There is no workflow configuration; the host reports no actions.
- **Provenance drift.** The README's quick start clones
  `github.com/0xdeadbeefnetwork/MOOR_PQ` and pipes a remote `setup.sh` into
  `sudo bash`. The permission granted covers the Codeberg repository; the
  README points somewhere else.
- **Licence defect.** `LICENSE` is MIT but reads `Copyright (c) 2026` with no
  holder. MIT's only obligation is the notice, and the notice names nobody.

None of that is an argument that the design is wrong. It is an argument that
copying the code into a security product would import unverified behaviour with
no way to check it, which is the opposite of what Vallum's gates are for.

## Where Vallum is already ahead

| | Vallum | MOOR |
|---|---|---|
| KEM | X25519 + sntrup761 + ML-KEM-768 (tri-hybrid) | X25519 + ML-KEM-768 |
| Signatures | Ed25519 + Falcon-1024 | Ed25519 + Falcon-512, ML-DSA-65 |
| Language | Rust, one SDK adapter crate, `cargo deny` clean | C, PQClean vendored in-tree |
| Tests | 680 `#[test]` functions | one harness, zero assertions |
| Shaping | Maybenot-modelled machine framework with per-state cost bounds, padding inside the AEAD, measured in `docs/proof/traffic-shaping.md` | hand-written Markov tables, padding as separate cells |

The shaping comparison is the surprising one. Vallum's framework is the stronger
design: an action model (`Pad`/`Inject`/`Block`), an authenticated length prefix
so padding is recoverable and therefore indistinguishable, explicit cost
accounting, and a proof document that measures the bandwidth and latency price.
MOOR's `wfpad.c` is the thing Vallum's framework is built to express.

## Where MOOR is ahead, and it is a short list

1. **It ships defences at all.** Vallum's framework is off by default and
   exposes three shapes (`PadToSize`, `MinInterval`, `RespondWithPadding` —
   `crates/vallum-config/src/lib.rs:306-333`). A framework with no defence
   configured protects nothing.
2. **Front padding.** Defence over the first seconds of a flow, when the shape
   is most revealing. Vallum has no notion of "front".
3. **A constant-rate floor.** Vallum's `RespondWithPadding` fires on receipt, so
   an idle tunnel stays silent and its idleness is itself the signal. A VPN is
   idle far more than a web session; this is the single defence most mismatched
   to Vallum's traffic today.
4. **Volume padding.** Normalising cell counts per window to a power of two.
   Vallum shapes size and timing, not volume.
5. **Censorship resistance.** Six transports, a scanner honeypot, and a bridge
   configuration. Vallum has none, and this is a product gap, not a module.

The first four are expressible in Vallum's existing framework as *new bounded
shapes*, which is exactly the extension the shaper was designed for. The fifth
is a different project.

## What to take

Take the designs, as specifications, and express them in the existing machine
model. In order of value per unit of work:

1. **A constant-rate floor** — a new `ShapingSpec` that injects a padded packet
   whenever the tunnel has been silent for a bounded interval, with an explicit
   bits-per-second ceiling. The cost is arithmetic: one 514-byte cell per second
   is ~4.1 kbit/s per tunnel; ten is ~41 kbit/s. It should be a named shape with
   bounded parameters, never a raw rate, for the reason
   `vallum-config/src/lib.rs:306-310` already gives: a config that can describe
   arbitrary machines can describe a flood.
2. **Front padding** — a bounded burst over the first seconds of a flow, then
   inert. Fits the `max_pads`-style cap MOOR uses and Vallum's per-state cost
   bounds already support.
3. **Volume padding** — pad a window's packet count up to the next power of two.
   Needs a window concept in the shaper, so it is the largest of the three.
4. **Parameter noise** — randomise a machine's thresholds per session so the
   defence itself is not fingerprintable by a fixed timing signature. MOOR does
   this per circuit; Vallum's machines are static per config.

## What not to take

- **The C code.** 50k lines of C whose own tests cannot be built, inside a Rust
  daemon, means FFI, `unsafe`, a second build system and a second audit surface
  — to gain nothing in cryptography, where Vallum's suite is stronger.
- **Its cell format.** Tor's 514-byte cell is a whole protocol, not a feature.
- **The anonymity stack** (consensus, hidden services, PIR, vanguards,
  OnionBalance). That is a different product with a different threat model, and
  a decision for an ADR of its own, not a port.
- **The transports as written.** Six unreviewed protocol emulations are the
  least verifiable code in the repository — and the most security-sensitive.

## If any code is ever copied

MIT permits it, and Vallum's Apache-2.0 can include it, on three conditions:
the copyright line must name the holder (ask the author to fix `LICENSE`), the
permission notice must ship in a `THIRD-PARTY` file, and the copied files must
stay identifiable as MOOR's rather than being silently rewritten into Vallum's
style. None of the recommendations above require copying any.
