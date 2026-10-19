# §8 — constant-time measurement (DudeCT)

**Status:** discharges the constant-time item of the plan's §8, which
`eck-pfs-psk.md`, `hybrid-identity.md`, and `committing-aead-multikey.md` all
deferred here by name.
**Depends on:** P0 for the primitive boundary, P2 for the AEAD and the tag
comparisons, P6.8 for the admission tag.
**Code change:** none. The harness is measurement only; §6 records why no
Vallum-owned code needed a fix.

---

## 0. What this gate forced

**(a) The first AEAD result was a false positive, and the reason is the useful
part.** Comparing a valid ciphertext with one whose tag byte was flipped gave
`max t ≈ +275` — a clear "leak" by any threshold. It is not a tag-comparison
leak. `ChaCha20Blake3::decrypt` computes the MAC, compares in constant time, and
*then* runs ChaCha over the plaintext on success; the failure path returns before
that work. The outcome — accepted or rejected — is public: a peer either answers
or it does not. The harness had conflated the public success/failure difference
with the private question "how much of the tag matched".

The fix is the whole methodology: hold the post-verification work constant and
vary only the thing under test. `aead_tag_compare` now flips the **first** tag
byte against the **last**, so both messages fail and only the comparison's early
exit can differ. It reports `max |t| = 2.5`. The success-vs-failure case is kept
as an explicitly informational benchmark, so the benign difference is documented
rather than hidden by a better-chosen class.

**(b) A harness with no positive control proves nothing.** `ct_control` is a
deliberately early-exit byte comparison. It must report a leak; if it does not,
the machine is too noisy, the classes are not different, or the optimizer removed
the work, and no other result is trusted. It reports `max |t| ≈ 1186`.
`scripts/ct.sh` fails when the control does not leak.

**(c) The NTRU leg holds under both failure classes.** The custom sntrup761
decapsulation is the only from-scratch primitive in the suite and its failure
path is a decryption-failure oracle if it branches. A bit-flipped ciphertext
(the implicit-rejection path) and a ciphertext for a different key both report
`|t| < 3`, consistent with the source's arithmetic-select claim.

---

## 1. What is measured

| Benchmark | Left class | Right class | What a leak would mean |
|---|---|---|---|
| `control` | equal 64-byte arrays | differ at byte 6 | harness/environment check — **must leak** |
| `ntru_decaps_bitflip` | valid ciphertext | one random bit flipped | implicit-rejection path branches on the decryption outcome |
| `ntru_decaps_wrong_key` | ciphertext for this key | ciphertext for another key | failure path depends on the key relation |
| `aead_tag_compare` | tag differs at byte 0 | tag differs at byte 31 | comparison returns at the first differing byte |
| `aead_failure_causes` | wrong key, valid ciphertext | correct key, body flipped | failure path depends on the cause |
| `aead_success_vs_failure` | valid | tag flipped | **informational** — the success path decrypts; expected |

The harness lives in `crates/vallum-crypto-sdk/examples/`, not `benches/`:
`cargo bench` injects `--bench`, which dudect-bencher's CLI refuses, and examples
get dev-dependencies and no injected arguments. `scripts/ct.sh` runs
`cargo run --release -p vallum-crypto-sdk --example <name>`.

---

## 2. Method

DudeCT (Reparaz, Balasch, Verbauwhede, ePrint 2016/1123) as implemented by
`dudect-bencher 0.7.0`: two input distributions, interleaved timing samples,
Welch's t-test over cropped runtime distributions; the reported statistic is the
largest absolute t over the crops. A large t means the two distributions are
distinguishable and the function is not constant-time *for that class pair*.

`scripts/ct.sh`:

- pins to one CPU with `taskset -c 2` when available;
- runs each example `RUNS=2` times and keeps the worst `|t|` per benchmark;
- treats `|t| ≥ 10` on a gated benchmark as a failure, `5 ≤ |t| < 10` as
  "suspicious, rerun", and `< 5` as no evidence of a leak;
- requires `control ≥ 5`.

---

## 3. Result

Machine: Intel Core i7-10750H @ 2.60 GHz, Linux 7.0.0-38-generic, rustc 1.97.1,
`powersave` governor, release profile. Two runs each, worst `|t|` kept:

```text
benchmark                    kind      max |t|  verdict
---------------------------- ------ ----------  -------
aead_failure_causes          gate        2.245  ok
aead_success_vs_failure      info      543.489  informational (expected to differ)
aead_tag_compare             gate        2.548  ok
control                      control   1186.269  leaked as required
ntru_decaps_bitflip          gate        2.873  ok
ntru_decaps_wrong_key        gate        2.791  ok

ct: PASS
```

The absolute numbers are machine-specific; the *relation* is the claim: the
control is three orders of magnitude above the gate, and every gated benchmark is
at or below the "no evidence" threshold.

---

## 4. Interpretation rules

- `|t| < 5` — no evidence of a leak **for this class pair**. It is not proof of
  constant-time behaviour; another input distribution may still separate.
- `5 ≤ |t| < 10` — rerun. A single run at this level is as likely to be a noisy
  host as a real signal.
- `|t| ≥ 10` — treat as a leak until explained. The explanation must be a public
  outcome (like §0(a)), not a shrug.
- A run where the control does not leak is discarded entirely.

---

## 5. Why no Vallum-owned fix

The two measured primitives are the SDK's; the adapter passes bytes through and
performs only public length checks before the call. Vallum's own comparisons are
`verify_value` (`handshake.rs`), `verify_confirmation`, and `mac_equal`
(`cookie.rs`): each hashes both operands under a fixed domain and compares the
two 32-byte digests. The accept/reject outcome is public by construction, and the
digest values are unpredictable to an attacker who does not hold the key, so the
final comparison cannot leak a secret prefix. That is an argument, not a
measurement, and it is recorded as such — the harness deliberately does not test
it, because the class pair would be "correct vs incorrect MAC", whose timing
difference is the public outcome itself.

No SDK patch is proposed: both primitives held under their failure classes, and
the only large t is the documented post-verification work.

---

## 6. What this does **not** claim

1. **Not a proof.** Statistical evidence under specific classes, on one machine.
2. **Not the whole surface.** Key generation, encapsulation, signature
   verification, and the KDF are unmeasured here.
3. **No microarchitectural claim.** Cache-timing, speculative execution, and
   power are out of scope; DudeCT is a wall-clock test.
4. **No claim about the SDK's future versions.** A primitive swap re-runs this
   harness; that is the point of keeping it in the adapter crate.
5. **The governor is `powersave`.** Frequency scaling adds noise; it also makes
   the control's leak harder to see, and it was seen at t ≈ 1050, so the
   environment is adequate. A dedicated machine would give tighter numbers.
6. **The informational AEAD difference is not a defect.** §0(a) explains why.
