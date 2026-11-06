# §8 — fuzzing

**Status:** discharges the fuzzing item of the plan's §8, and `pentest.md`'s
"no coverage-guided fuzzing" non-claim.
**Depends on:** P1 (the handshake decoder), P2 (the replay window), P5 (the
shaping framework), P6.7 (the segment envelope), P6.8 (the admission tag).
**Code change:** none. `fuzz/` is a separate workspace; nothing in it is linked
into the daemon.

---

## 1. Targets and invariants

| Target | Input | Invariants |
|---|---|---|
| `enroll_parse` | arbitrary bytes | `parse_hello`, `parse_cookie`, `reply_framing` never panic; a `HELLO` that parses **re-encodes to the same framing** — the parser must not accept a datagram the builder would never emit |
| `message_parse` | arbitrary bytes | never panic; a message that parses **round-trips** — rebuilt field by field it is byte-identical; `mac1_input`, `mac2_input`, and `resp_tag_input` never panic; `segment::parse`/`is_fragment` never panic |
| `handshake_decode` | arbitrary bytes into the three pre-session decoders | never panic; every rejection is a typed `HandshakeError`; `responder_identify`, `initiator_process_resp`, and `responder_process_conf` are each exercised |
| `replay` | 9-byte chunks: `u64` counter + flag | `next()` never decreases; a counter is accepted at most once; nothing panics |
| `shaping` | 9-byte chunks: event selector + `u64` draw | no panic; every effect names a real machine; all reference machines are driven through arbitrary interleavings |
| `epoch_open` | arbitrary bytes as a data packet | after a rekey the session holds two epochs at once: arbitrary bytes never panic and never open; a packet sealed under the retired epoch **and** one under the current epoch both open; past `RETAIN_PREVIOUS_EPOCH_MS` the retired epoch's straggler is refused |

`epoch_open` is the target a rekey made necessary: `Session::open` is fed by the
network on every packet, and a rekey is the only thing that makes it demultiplex
between a current and a retained epoch. Its fixture is a key schedule rather than
a handshake — two sessions derive the same epochs from fixed keys with the
indices swapped — so it runs at ~500 inputs/s instead of paying a KEM per input
(the measured cost: 23 702 runs in 46 s). The positive half is what keeps the
negative half honest: a session that rejected everything would fail the two
`sealed … opens` assertions.

The round-trip invariant in `message_parse` is the strongest one: the parser
accepts TLV fields in any order and the builder emits them in the order given, so
a parsed message must rebuild to exactly its input. A mismatch would mean the
parser accepts a non-canonical encoding that a second implementation could
disagree about — the class of bug the whole self-describing-framing decision
exists to avoid.

### Why `handshake_decode` uses suite 0x0002

The decoder and the transcript code are suite-independent, but the fixture must
perform real KEM operations to build states. The tri-hybrid's sntrup761 costs
~25 ms per operation here (see `benchmarks.md`), which would cap the fuzzer at a
few dozen inputs a second. The ML-KEM suite exercises the same code paths at
~2 ms per iteration. The fuzzer's throughput is KEM-bound, not parser-bound —
that is stated rather than hidden.

---

### What `enroll_parse` found

On its first run — 35,000 executions — the round-trip invariant failed:
`parse_hello` masked the flags byte to the one bit it knew and ignored the
rest, so a datagram with `flags = 0xfe` parsed, then re-encoded as
`flags = 0x00`. Two implementations could be made to disagree about the same
bytes. Reserved bits are now a rejection, and the input is kept as
`seeds/enroll_parse/regression-reserved-flags.seed`. After the fix: 3.7 M
executions, no crash.

## 2. Seeds

`fuzz/seeds/<target>/` holds a committed seed corpus:

- `enroll_parse`: a well-formed `HELLO` and a `REPLY` framing, plus the
  reserved-flags regression input
- `message_parse` and `handshake_decode`: the three frozen tri-hybrid messages
  from `tests/interop.rs` (4 609 B `InitHello`, 4 414 B `RespHello`, 52 B
  `InitConf`), so the first run starts from valid, maximum-size inputs.
- `replay`: a sequence with duplicates, gaps, and probes.
- `shaping`: an event/draw stream that reaches `Timeout` and the block path.
- `epoch_open`: none. Its interesting state is derived, not parsed, so the first
  run starts from the empty corpus and the assertions build the epochs.

`scripts/fuzz.sh` copies the seeds into `fuzz/corpus/<target>/` (which is
git-ignored, because libFuzzer writes new inputs there) before running.

---

## 3. Policy

| Context | Duration per target |
|---|---|
| Pull request / push (CI) | 60 s |
| Nightly (CI, `schedule`) | 900 s |
| Local gate (`scripts/fuzz.sh [seconds]`) | 60 s default |

A crash writes its input to `fuzz/artifacts/<target>/`; the CI job uploads both
the artifact and the corpus, and the artifact should be committed with the fix as
its regression test. `-rss_limit_mb=2048` bounds memory so an allocation bug is a
finding rather than an OOM kill, and `-timeout=10` bounds a single input.

---

## 4. Result of the gate run

`scripts/fuzz.sh 15` on this host (16 s wall per target):

```text
fuzz: message_parse for 15s     Done 1141775 runs
fuzz: handshake_decode for 15s  Done 1056 runs
fuzz: replay for 15s            Done 1167920 runs
fuzz: shaping for 15s           Done 364519 runs
fuzz: PASS
```

No crash. The run counts are a measure of coverage opportunity, not of
assurance: the parser targets are fast because the input is small, and
`handshake_decode` is slow because each iteration rebuilds a real handshake
state.

---

## 5. What this does **not** claim

1. **No cryptographic fuzzing.** The KEM arithmetic, the AEAD, and the signature
   code are exercised only through their public entry points with decoded input;
   the fuzzers do not mutate internal state or check for differential behaviour.
2. **No differential fuzzing.** There is one implementation per primitive; a
   second provider is the point of the `CryptoSuite` boundary, and comparing two
   is future work.
3. **No coverage measurement.** libFuzzer's edge coverage drives the search, but
   no coverage report is published or thresholded.
4. **No corpus minimisation policy.** The seed corpus is small and hand-chosen;
   the growing corpus is cached in CI, not curated.
5. **ASan only.** No MSan/TSan/UBSan runs in this phase.
6. **No proof of absence.** A green run means these inputs, for this long, found
   nothing.
