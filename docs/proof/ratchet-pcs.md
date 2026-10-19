# P4 gate — the epoch axis and erasure-based post-compromise security

**Status:** P4 gate artefact. Covers `crates/vallum-core/src/session.rs` and the
`epoch` axis of `crates/vallum-core/src/{keys,data}.rs`.
**Supersedes:** plan §5 **V4** as it was written (a *bounded symmetric ratchet*) —
see §3. **Depends on:** plan §7 obligation 5 (ratchet PCS argument), obligation 3
(`docs/proof/eck-pfs-psk.md`, which produces `KEY`), obligation 6
(`docs/proof/committing-aead-multikey.md`, which produces the epoch key schedule).

This obligation is where a VPN usually tells a story about a ratchet. Vallum does
not have one, and this document is mostly an argument that that is the stronger
position rather than the cheaper one.

---

## 0. The corrections this gate forced

**(a) The plan's V4 was ambiguous, and the reading that shipped is the opposite of
a chain.** The row read *"fresh hybrid ephemeral per rekey; 2⁴⁸ cap; erasure"*,
which was written to mean *a bounded symmetric ratchet with a periodic KEM
refresh*. The implementation instead moves the epoch by **re-running the
handshake**, with no symmetric chain at all (§3). The `epoch` counter is carried
across; nothing else is. The gate's title changed accordingly: this is an
*epoch axis*, and the PCS argument is that the new epoch's key is **independent**
of the old one, not that a chain link was forgotten.

**(b) The demultiplexer was wrong on the first cut, and a test caught it.**
`Session::open` tried the current epoch, then the retained one, and returned the
*current* epoch's error. That silently relabelled every retained-epoch packet
failure: a replayed straggler reported as `WrongIndex` (the current epoch's
complaint) instead of `Replay`. The rule is now: the **index** decides the epoch,
and the epoch whose index matched owns the verdict (§2.3). The test that caught it
is `stragglers_open_inside_the_window_and_are_erased_after_it`.

---

## 1. The obligation, stated exactly

**Post-compromise security, as an independence claim.** Let an adversary hold
*every byte* of epoch *n*: the epoch root, both directional keys, the nonce
prefixes, and the packet counters. After the peers advance to epoch *n+1*, the
adversary's advantage in distinguishing epoch *n+1* traffic from random is
negligible.

That is stated as independence deliberately. In a symmetric ratchet the
adversary *would* ratchet forward — a chain `root_{i+1} = KDF(root_i)` is
computable by anyone holding `root_i` — so PCS must be argued from the chain
eventually being *refreshed*. Here the new root is not a function of the old one
at all:

```text
root_{n+1} = KDF(salt = KEY_{n+1}, ikm = frame([TR_{n+1}, n+1]), info = "vallum/data/root/v1")
KEY_{n+1}, TR_{n+1}  ←  a new hybrid handshake (X25519 + sntrup761 + ML-KEM-768)
```

No window of iterator is open to the adversary, because there is no iterator.

**Bounded.** The superseded epoch is not erased the instant the new one lands: a
rekey is not atomic at the peer, so packets sealed under epoch *n* may still be in
flight. Epoch *n* is retained **receive-only** for
`RETAIN_PREVIOUS_EPOCH_MS` (= `REJECT_AFTER_TIME_MS`, 180 s), then erased. The
sending key is dropped immediately — from the instant the advance returns, every
outbound packet is under epoch *n+1*.

**Erasure-based.** The PCS guarantee and the erasure are the same act: the moment
the retained receiver is dropped, the only remaining copy of epoch *n*'s key
material in the process is gone (`DirectionalKey` zeroizes on drop). §5 records
what that does and does not mean.

---

## 2. Mechanism (normative)

### 2.1 What an advance is

```rust
Session::establish(suite, keys, role)              // epoch 0, from the first handshake
Session::advance(suite, keys, role, now_ms) -> u64 // epoch n+1, from a NEW handshake's SessionKeys
```

`advance` is not a key-schedule operation; it is a *session* operation that takes
a completed handshake. The caller runs the P1 exchange (or the P3 signed variant)
and hands the resulting `SessionKeys` in. Nothing about the handshake changes: a
rekey is a handshake, and P1/P3's frozen vectors are untouched.

### 2.2 What is carried, and what is dropped

| value | on advance |
|---|---|
| `epoch` counter | carried, `+1`, monotonic, refuses to wrap (`EpochExhausted`) |
| `suite_id` | carried; a rekey on a different suite is refused (`SuiteChanged`) — one epoch axis, one suite |
| current **sending** key | **dropped immediately**; we send under the new epoch from the next packet |
| current **receiving** key + replay window | moved to `previous`, receive-only |
| own / peer index | replaced by the new handshake's (data packets name the recipient's index) |
| the handshake root `KEY_n`, `TR_n` | never stored by the session; they were consumed by `establish_epoch` at epoch *n* |

Because `epoch` is folded into the key derivation
(`keys.rs` doc: `epoch_root` is the *salt*), reusing an
epoch value with a different root is the one error the schedule cannot detect —
which is why the counter lives in the session and not in the caller (§7, test
`the_same_handshake_keyed_at_two_epochs_does_not_cross_decrypt`).

### 2.3 How a received packet picks an epoch

The epoch is **not on the wire**. A rekey adds **zero bytes** to the data plane.

A receiver demultiplexes on the recipient index the packet already carries in its
header, which `Receiver::open` checks *before* any cryptography. Rules:

* If the current epoch does not return `WrongIndex`, the packet was addressed to
  it and its verdict is final.
* Otherwise the packet is offered to the retained epoch, and **the retained
  epoch's verdict replaces the default** — unless that verdict is itself
  `WrongIndex`, in which case the packet names neither epoch and the current
  epoch's mismatch is reported.

So a straggler replayed twice reports `Replay`, a forged straggler reports `Aead`,
and a packet for neither epoch costs two integer comparisons and no AEAD work.
An epoch counter on the wire would have replaced all of that with an oracle for
which epoch a guess landed in, and cost bytes in every packet to do it.

### 2.4 One superseded epoch, never two

`advance` **drops any already-retained epoch before installing the new one**. A
peer that rekeys rapidly therefore cannot accumulate a growing window of live old
keys: at any instant the session holds at most the current epoch and one
receive-only predecessor. This is the "bounded" in bounded ratchet, expressed
structurally rather than as a policy.

---

## 3. Why there is no symmetric chain (the plan reversal)

Mattsson, *Hidden Stream Ciphers and TMTO Attacks on TLS 1.3, DTLS 1.3, QUIC, and
Signal*, models a key ratchet `k ← KDF(k)` as a **non-additive synchronous stream
cipher**. That is exactly the object Babbage–Golić time/memory tradeoff attacks
apply to: with a chain of `n` steps from a state of `κ` bits, an attacker with
`M` memory and `T` time trades `TM² ≈ 2^k`-style — so a 256-bit chain stepped
many times does **not** deliver 256-bit security against an adversary willing to
precompute. The paper's recommendations are (a) **bound the number of ratchet
steps** and (b) **keep fresh ephemeral key exchange** as the mechanism that
actually provides security.

Now the engineering decision. Vallum's rekey already *is* a fresh hybrid
handshake — that is V4's own text, *"fresh hybrid ephemeral per rekey"* — so the
only thing a symmetric chain would add is *cheap rotation between* handshakes. The
cost/benefit:

1. **The chain's benefit is latency, and a VPN does not need it.** A rekey is
   triggered by `REKEY_AFTER_TIME_MS` = 120 s or `REKEY_AFTER_MESSAGES` = 2⁴⁸
   packets. A ~12 KB signed handshake every two minutes is not a cost a tunnel
   notices. A chain would buy sub-second rotation granularity that nothing
   consumes.
2. **The chain's cost is the entire security argument.** Every symmetric chain
   makes PCS a *refresh-interval* claim (a compromise is cured only at the next
   KEM refresh) and makes the effective security a *state-size* claim bounded by
   the TMTO analysis above. Removing the chain removes both claims, and the
   argument becomes "the new key is fresh" — which is not an argument, it is a
   construction.
3. **It would have added an on-the-wire-adjacent failure mode.** A chain advance
   must be implicit and lockstep (or it needs a message). Either the peers can
   silently desynchronise the epoch, or the protocol grows a rekey header. Both
   are worse than a handshake that already exists and is already tested.

So V4 ships as: **the epoch axis exists, the epoch is advanced by a handshake, and
the session's contribution is monotonicity, one bounded superseded epoch, and
erasure.** The plan's §5 V4 row is updated to say this rather than "bounded
symmetric ratchet".

---

## 4. Threat model, precisely

**PCS holds against** an adversary that compromises the session state *between*
epochs: the root, the directional keys, the nonce prefixes, and the counters. It
learns every packet of the compromised epoch and nothing of the next one, whose
root is a fresh hybrid encapsulation. This is the standard PCS statement, and
Vallum gets it at the *first* packet of the new epoch rather than after a
refresh interval.

**PCS does not hold against** an adversary that also holds the long-term static
secret *and* the new handshake's ephemeral secret. That is a total compromise, and
no ratchet of any construction survives it. V2/V3's identity work is what makes
the static half a signed, transferable statement; it does not change this bound.

**An honest consequence of retention.** While epoch *n* is retained, an adversary
holding epoch *n*'s keys can still *forge* epoch-*n* packets that the peer will
accept — because they hold the key, and acceptance is a key property. The PCS
guarantee is about epoch *n+1*'s **confidentiality**, and about the eventual
**erasure** that ends epoch *n*'s usefulness. The retention window is the price of
not dropping legitimate in-flight packets, and it is bounded (§5).

---

## 5. The bound, and what "erasure" means in Rust

Two bounds live at two layers, and they are not the same kind of thing:

| bound | value | enforced by | kind |
|---|---|---|---|
| messages per key | `REKEY_AFTER_MESSAGES` 2⁴⁸ (ask) / `REJECT_AFTER_MESSAGES` 2⁴⁹ (refuse) | `Sender::seal` — hard | cryptographic (nonce/key lifetime) |
| retention of a superseded epoch | `RETAIN_PREVIOUS_EPOCH_MS` = 180 s | `Session::expire_previous` | policy, caller-scheduled |

The **hard** bound is the counter: `Sender::seal` refuses past 2⁴⁹, so no epoch
can outlive its key regardless of what the caller does. The **time** bound is
advisory by nature — the session cannot know a handshake happened without being
told — so `Session::needs_rekey()` reports the condition and the transport loop
(P6) is what polls `Timers` and calls `advance`. Recorded as a P6 obligation,
not a property of P4.

On erasure: `DirectionalKey` is non-`Copy`, has no accessor, and zeroizes on
`Drop` (best-effort scrub plus `black_box`, the same helper the rest of the crate
uses). `advance` drops the superseded sending key by value; `expire_previous`
drops the retained receiver. What this claim is and is not:

* It **is** "the session holds no copy of the superseded key material once
  `expire_previous` returns true, and there is no API path that kept one."
* It **is not** a proof about the allocator, the OS, or swap. Rust gives no such
  proof, and a document that implied one would be lying.

---

## 6. What P4 does **not** claim

1. **No per-message forward secrecy.** Forward secrecy's granularity is the
   *epoch*: within one epoch, all packets share one key pair, so a compromise
   reveals that whole epoch — before and after the compromise instant — until the
   next `advance`. This is a deliberate, stated property (it is why the epoch
   lifetime is bounded at all), not an oversight.
2. **No time-based rekey enforcement.** §5. The message ceiling is hard; the
   epoch *lifetime* is driven by the caller.
3. **No machine-checked proof.** Same as P1/P3: the Tamarin model covering the
   handshake does not yet cover the epoch axis (plan §7 obligation 4).
4. **No claim about the transport.** Loss, reordering across an epoch boundary,
   and the scheduling of `advance` against `Timers` are P6's. P4 supplies the
   mechanism and the bound; the loop is not written.
5. **No key-commitment statement.** Inherited from P2: the data plane's
   committing-AEAD property is a *requirement on a swapped suite*, unchanged
   here, because a rekey changes the suite's inputs, not its contract.

---

## 7. Correlation with the code

| claim | code | test |
|---|---|---|
| both ends advance to one epoch from one handshake | `Session::advance` | `both_ends_advance_to_the_same_epoch_and_talk` |
| the epoch counter is monotonic and never compounds retention | `Session::{advance, previous_epoch}` | `many_epochs_stay_monotonic_and_separated`, `a_rapid_rekey_does_not_compound_retention` |
| the epoch is fixed to one suite | `Session::advance` → `SuiteChanged` | `a_different_suite_is_refused` |
| the counter refuses to wrap | `Session::advance` → `EpochExhausted` | unit: `EpochExhausted` arm (unreachable, kept total) |
| the epoch is folded into the key | `DataKeys::derive` | `the_same_handshake_keyed_at_two_epochs_does_not_cross_decrypt` |
| **PCS**: no epoch from the compromised root opens new traffic | `establish_epoch` + `Session` | `no_epoch_from_the_old_root_opens_next_epoch_traffic` |
| a fresh handshake never reproduces the root | P1 handshake | `a_compromised_epoch_does_not_yield_the_next_epoch_keys` |
| stragglers open inside the window | `Session::open` (retained epoch) | `stragglers_open_inside_the_window_and_are_erased_after_it` |
| straggler replays are still dropped | retained `ReplayFilter` | `stragglers_open_inside_the_window_and_are_erased_after_it` |
| erasure at the window, and immediately on teardown | `Session::{expire_previous, retire_previous}` | `stragglers_open_inside_the_window_and_are_erased_after_it`, `retiring_the_previous_epoch_is_immediate` |
| the epoch adds **zero** wire bytes | `data.rs` (no epoch field) | byte-identical `interop` frozen vectors |

Wire cost of P4: **0 bytes.** No message type, no field, no header bit.

---

## 8. References

* J. Preuß Mattsson, *Hidden Stream Ciphers and TMTO Attacks on TLS 1.3, DTLS 1.3,
  QUIC, and Signal* — the §3 source: ratchets as non-additive synchronous stream
  ciphers, TMTO on them, and the two recommendations (bound the steps, keep
  ephemeral key exchange) that map onto V4. Read at abstract/intro depth here; the
  body's two-column extraction is unreliable, so §3 cites it at that precision and
  no further.
* A. Babbage, *Improved exhaustive search attacks on stream ciphers*; J. Golić,
  *Cryptanalysis of alleged A5 stream cipher* — the tradeoff being cited.
* Plan §7 obligations 3, 5, 6; §5 V4 (reversed here); §6 P4 gate.
* `docs/proof/eck-pfs-psk.md` — produces `KEY` and `TR`, the inputs to epoch 0.
* `docs/proof/committing-aead-multikey.md` — the epoch key schedule P4 drives.
* `origin-tools/*` (`origin-channel`) — reference only; not extended or depended on.
