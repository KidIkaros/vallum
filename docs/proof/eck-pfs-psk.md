# P1 gate — adapting the eCK-PFS-PSK proof to Vallum's handshake

**Status:** P1 gate artefact. Covers the KEM-only handshake in
`crates/vallum-core/src/handshake.rs` (no signatures — those are P3).
**Supersedes:** nothing. **Depends on:** plan §7 obligation 1 (combiner lemma, P0).

This document is the *adaptation*: it maps PQ-WireGuard's proof skeleton onto
Vallum's exchange, records where the substitution is mechanical, and records every
place where it is **not** — with an explicit verdict on whether the deviation is
covered, and by what. It is not a machine-checked proof. A Tamarin model of the
handshake is a separate P1/P4 artefact.

---

## 0. The correction this gate forced

Writing this document caught a real defect. PQ-WireGuard's handshake puts an
explicit confirmation in **both** directions:

| message | field | direction confirmed | where |
|---|---|---|---|
| `RespHello` | `zero = AEAD.Enc(κ9, 0, H9, ∅)` | **responder → initiator** | Alg. 2 step 15 |
| `InitConf` | `conf = AEAD.Enc(κ10, 0, H10, ∅)` | **initiator → responder** | Alg. 2 step 19 |

The paper's prose only advertises the `InitConf` addition ("we add this explicit
key-confirmation"), so it is easy to read the 3-message exchange as having
one-directional confirmation. It does not. `zero` is inherited from WireGuard's
`msg.response` framing but *repurposed* — it is an AEAD encryption of the empty
string under a key the responder can only hold if it decapsulated op A.

Vallum's first implementation had only `conf_i` in `InitConf` and left
`confirm_responder` derived-but-unsent. That is exactly the shape that made
WireGuard unprovable in eCK-PFS-PSK: **the initiator would accept the session key
on the strength of an unauthenticated `RespHello`.** The fix landed with this
document:

* `RespHello` now carries a `CONFIRMATION` field (the responder's `conf_r`).
* `initiator_process_resp` **verifies** `conf_r` before returning any key, and
  returns `HandshakeError::Confirmation` if it fails.
* The transcript was split into stages so the responder can hash `RespHello`
  before its own confirmation exists (§3).

The frozen vectors in `tests/interop.rs` were regenerated; `RespHello` grew by the
36-byte `CONFIRMATION` TLV (e.g. suite `0x0003`: 4342 → 4378 bytes).

---

## 1. The model, in the terms we actually use

eCK-PFS-PSK = **e**xtended **C**anetti–**K**rawczyk, with **P**erfect **F**orward
**S**ecrecy and **P**re-**S**hared **K**ey. PQ-WireGuard uses Dowling & Rösler's
WireGuard instantiation and **extends it in two ways** that matter to us:

1. the adversary **may subvert an honest party's RNG** (this is what MEX defends
   against; the WireGuard model did not allow it), and
2. the model covers **full PFS**, not only weak PFS.

The game gives the adversary `Send`, `RevealSession`, `RevealStatic`,
`RevealEphemeral`, `RevealRandomness`, and a `Test` oracle, subject to a
**cleanness predicate** that forbids the reveal combinations that would trivially
break the tested session. Success = distinguishing the tested key from random.

**Vallum's cleanness predicate.** The session key `KEY` is
`HKDF(salt = ROOT, ikm = psk, …)` where `ROOT` is the combiner output over
`ss_A ‖ ss_B ‖ ss_C`. `psk` is public (§5, deviation D3) and the transcript is
public, so `KEY` is unpredictable iff the adversary cannot produce *all three* of
`ss_A`, `ss_B`, `ss_C`. For each op the adversary has two routes:

| op | receiver secret (decapsulation) | sender-side route (re-encapsulation) |
|---|---|---|
| A (init → resp static) | `σ_r` | `σ_i` **and** `r_i` (MEX-mixed) |
| B (resp → init ephemeral) | `esk_i` | `e` (plain) |
| C (resp → init static) | `σ_i` | `σ_r` **and** `r_r` (MEX-mixed) |

So a Vallum test session is clean unless the adversary obtains, in combination,
one decapsulation-side route (or a full break of every leg of that op) for **each**
of A, B and C. Concretely, possessing *any single* receiver secret yields *one*
op, not three:

* `σ_r` alone → op A only; B still needs `esk_i`, C still needs `σ_i`.
* `esk_i` alone → op B only.
* `σ_i` alone → op C only.

In particular **revealing every long-term secret still does not break the session
key** (op B needs the ephemeral), which is precisely the full-PFS property, and it
is why op B deliberately uses *plain* randomness while A and C use MEX (§5, D1).

---

## 2. Mapping: model element → Vallum artefact

| eCK-PFS-PSK element | Vallum artefact | Notes |
|---|---|---|
| Party static key pair | `StaticIdentity` (`σ`, `KemPublicKey`) | one hybrid KEM key pair, dual-use (Thormarker) |
| Ephemeral key pair | `InitiatorState::ephemeral_{public,secret}` | op B target; fresh per handshake |
| Session identifier `sid` | header `sender_index` (u32) + peer echo in `RECEIVER_INDEX` | `sid_i` in `InitHello`, `sid_r` in `RespHello` |
| `Send(sid, m)` | `responder_process_init` / `initiator_process_resp` / `responder_process_conf` | the three messages |
| `RevealStatic` | compromise of `StaticIdentity::secret()` | op A (resp) or op C (init) |
| `RevealEphemeral` | compromise of the initiator's ephemeral secret | op B |
| `RevealRandomness` | knowledge of `handshake_seed`-derived seeds — **without** the static secret | MEX keeps A, C safe |
| Partnering | agreed `sid_i`, `sid_r`, and equal `SessionKeys` | asserted by `every_suite_completes_and_agrees` |
| **Accept** (initiator) | return from `initiator_process_resp` after `conf_r` verifies | guarded by `verify_confirmation` |
| **Accept** (responder) | return from `responder_process_conf` after `conf_i` verifies | guarded by `verify_confirmation` |
| Test key | `SessionKeys::key` | `ROOT`-derived, pre-data-plane |

Wire-format names: `InitHello = STATIC_CT(A) ‖ EPHEMERAL_PK ‖ TIMESTAMP`,
`RespHello = EPHEMERAL_CT(B) ‖ STATIC_CT(C) ‖ RECEIVER_INDEX ‖ CONFIRMATION(conf_r)`,
`InitConf = CONFIRMATION(conf_i) ‖ RECEIVER_INDEX`.

---

## 3. The transcript, and why it is staged

PQ-WireGuard keeps a **running chained hash** (`H9`, `H10 = H(H9 ‖ zero)`, …)
rather than hashing a finished byte sequence. Vallum needs the same property for
the same reason, so the transcript is built in three stages from **parsed field
values** rather than from raw received bytes:

```text
TR1 = H("vallum/tr/init", suite_id ‖ sid_i ‖ epk_i ‖ ct_A ‖ timestamp)
TR  = H("vallum/tr/resp", suite_id ‖ TR1 ‖ sid_r ‖ ct_B ‖ ct_C)
TR2 = H("vallum/tr/conf", suite_id ‖ TR  ‖ conf_r)
```

* `TR` is the key-schedule transcript. It must **exclude** `conf_r`, because the
  responder derives `conf_r` from `TR` — hashing the message that contains it
  would be circular.
* `TR2` includes `conf_r`, and `conf_i` commits to `TR2`. This is exactly
  PQ-WireGuard's `H10 = H(H9 ‖ zero)` shape.
* Every concatenation is length-framed (`vallum_crypto::kem::frame`), so the
  encoding is unambiguous.
* Hashing parsed values, not bytes, means no TLV canonicalisation step is needed,
  and a message carrying unknown tags is still bound by all the fields we use.

Hash domain labels are versioned (`…/v1`) and are part of the frozen vectors.

---

## 4. Key schedule and confirmation (normative)

```text
TR1    = H("vallum/tr/init", suite_id ‖ sid_i ‖ epk_i ‖ ct_A ‖ timestamp)
TR     = H("vallum/tr/resp", suite_id ‖ TR1 ‖ sid_r ‖ ct_B ‖ ct_C)
ROOT   = KDF(salt = TR,   ikm = ss_A ‖ ss_B ‖ ss_C, info = "vallum/kem/v1")
psk    = H("vallum/psk/v1", frame([spk_i, spk_r]))        // UKS mitigation, public
KEY    = KDF(salt = ROOT, ikm = psk,                info = "vallum/psk-mix/v1")
conf_r = KDF(salt = KEY,  ikm = TR,                 info = "vallum/confirm/resp/v1")
TR2    = H("vallum/tr/conf", suite_id ‖ TR ‖ conf_r)
conf_i = KDF(salt = KEY,  ikm = TR2,                info = "vallum/confirm/init/v1")
```

`ROOT` comes from the P0 combiner (IKM = concatenated per-leg secrets, salt =
`length-prefixed(context ‖ ciphertexts)`, fixed info `origin-crypto-sdk:kem:hybrid:v1`),
called here through `vallum_crypto::kem::derive_kem_key` with `TR` as the context.

**Op order is `A ‖ B ‖ C` on both sides.** The responder recovers A by
*decapsulation* and the initiator by *encapsulation*, but the order is identical —
that identity is what makes the two derivations agree, and it is asserted by
`legs_are_bound_to_all_three_operations`.

Confirmation comparison goes through the suite hash
(`verify_confirmation`, domain `"vallum/confirm-cmp/v1"`). Both sides hash a value
the protocol already binds, so digest equality *is* input equality, and a timing
signal on a hash comparison reveals nothing about the confirmation.

---

## 5. Deviation register

Each deviation from PQ-WireGuard is listed with an explicit verdict. "Covered" means
the security argument survives unchanged; "covered, stronger" means Vallum's variant
is at least as strong; "open" means it is a named obligation, not a hand-wave.

| # | PQ-WireGuard | Vallum | Verdict |
|---|---|---|---|
| **D1** | MEX on the two static ops (steps 4, 13): `KDF1(σ, r)` | same two ops; `KDF(salt = fresh, ikm = σ, info = "vallum/mex/v1")` — i.e. arguments swapped | **Covered.** A dual-PRF is required to be a PRF with *either* argument fixed, which is exactly why the paper may write `KDF1(σ, r)` and we may write `KDF(salt = r, ikm = σ)`. Op B uses plain fresh randomness, matching step 12. |
| **D2** | `CCAKEM` static (IND-CCA) + `CPAKEM` ephemeral (IND-CPA) — two KEMs, two jobs | one hybrid KEM for all three ops; every op is therefore IND-CCA-strength | **Covered, stronger.** The ephemeral slot's requirement is IND-CPA; we supply IND-CCA. The higher bar is real and must be paid for — see §7. |
| **D3** | `psk = H(spk_i ⊕ spk_r)`, mixed in at `KDF1(C3, psk)` and again at `KDF1(C8, psk)` | `psk = H("vallum/psk/v1", frame([spk_i, spk_r]))`, mixed **once** as HKDF `ikm` with `ROOT` as salt | **Covered.** The property needed is "session keys are linked to both static public keys". Length-framed concatenation is at least as binding as XOR, and additionally fixes the argument order. Single vs double mixing is a strength-margin question, not a property question; recorded as a margin loss. |
| **D4** | `conf`/`zero` are `AEAD.Enc(κ, 0, H, ∅)` — empty-plaintext AEAD under keys from the seed chain | KDF outputs keyed by `KEY`, bound to `TR`/`TR2` | **Covered** with a substituted assumption: the proof term `2·Adv^auth-aead` becomes a confirmation-forgery term under the dual-PRF assumption on the suite KDF. Same property (only a key holder can produce it), different primitive. |
| **D5** | WireGuard's `msg.response` `zero` repurposed as responder confirmation | `CONFIRMATION` tag in `RespHello` | **No deviation** — this *is* PQ-WireGuard's step 15. Called out here because the paper's summary bullets omit it; see §0. |
| **D6** | explicit `InitConf` last message | same | **No deviation.** |
| **D7** | `1tk ← AEAD.Enc(κ3, 0, H3, H(spk_i))` hides the initiator's identity; `time` is authenticated under κ4; `zero`/mac fields | P1 sends `TIMESTAMP` in the clear and nothing identity-bearing; no `1tk` | **Open — deferred to P2/P3 by design.** Identity hiding and DoS mitigation are *not* eCK-PFS-PSK properties (PQ-WireGuard obtains them from the Tamarin model). P1 clears the plaintext field so the P3 identity work is visible. |
| **D8** | `m1`/`m2` (mac1/mac2 cookie DoS checks) | absent in P1 | **Open — P2.** Pure DoS mitigation, explicitly outside eCK-PFS-PSK. |
| **D9** | running chained hash over wire bytes; fields interleaved | three staged hashes over parsed fields | **Covered.** Same structural property (`conf_r` commits to the transcript before it, `conf_i` to the transcript including it). Reviewed in §3. |
| **D10** | `psk` may be a real out-of-band secret, restoring DoS protection independent of key secrecy | no configured-secret PSK in P1 | **Open — plan §10 open decision.** Until then, Vallum's `psk` is *public* and provides UKS-linking only, **not** the compromise-resilience a secret PSK would give. Named limitation. |

---

## 6. Theorem shape

PQ-WireGuard's theorem (paper §"Security proof", Appendix B has the tighter form):

```text
Adv^{eCK-PFS-PSK}_{PqWG, clean, n_P, n_S, A}(λ)
  ≤  n_P·n_S / 2^λ
   + (n_S + 2)·Adv^{IND-CCA}_{CCAKEM,R}(λ)
   +      n_S ·Adv^{IND-CPA}_{CPAKEM,R}(λ)
   +      2   ·Adv^{auth-aead}_{AEAD,R}(λ)
   + (n_S + 2)·n_S / 2^λ
```

Substituting per §5:

```text
Adv^{eCK-PFS-PSK}_{Vallum, clean, n_P, n_S, A}(λ)
  ≤  n_P·n_S / 2^λ
   + (n_S + 2)·Adv^{hyb}(λ)          // was IND-CCA(CCAKEM)
   +      n_S ·Adv^{hyb}(λ)          // was IND-CPA(CPAKEM)
   +      2   ·Adv^{conf-forge}(λ)   // was auth-aead(AEAD)
   + (n_S + 2)·n_S / 2^λ
```

where

* `Adv^{hyb}(λ)` is bounded by the **P0 combiner lemma** (plan §7 obligation 1):
  *if at least one leg is IND-CCA, the combined key is unpredictable* — so
  `Adv^{hyb} ≤ min over legs of the leg's IND-CCA advantage`, not a sum and not a
  product.
* `Adv^{conf-forge}(λ)` is a dual-PRF term on the suite's `kdf`/`hash` with a
  transcript-bound input, replacing AEAD authenticity.

**Honest boundary on this section.** What is established here is the *reduction
map*: which PQ-WireGuard term each Vallum term stands in for, and which
assumption pays for it. The displayed bound is inherited modulo substitution; the
tighter, explicit-constant bound (with the dual-PRF terms written out rather than
absorbed) is P6/paper work, not P1. This is stated rather than implied.

---

## 7. The either-leg side-result, and why tri-hybrid strengthens it

PQ-WireGuard observes a "pleasant side-result" of using two KEMs with different
roles:

> If we model the break of a KEM as the reveal of all secret keys … then a break
> of either KEM does not break the confidentiality of PQ-WireGuard as long as
> there is no further corruption.
> * A break of the CCA-KEM ⇔ corruption of all **static** secrets, but not the
>   ephemeral keys. As long as no ephemeral secrets are compromised, eCK-PFS-PSK
>   still promises confidentiality. (Authenticity is trivially broken.)
> * A break of the CPA-KEM ⇔ corruption of all **ephemeral** secrets, but not the
>   static ones. As long as no static secrets are compromised, eCK-PFS-PSK still
>   promises authenticity and confidentiality — **losing PFS though**.

They note this "already provides some of the properties of hybrid protocols that
aim at redundancy … by combining schemes that use different assumptions (e.g. ECC
and lattice-based schemes)."

Vallum makes that redundancy **explicit and per-operation** instead of incidental
to role assignment. Within each op, the three legs are combined by the P0
combiner, whose lemma is *any single leg suffices*. So:

* A break of **one** leg family (say, all lattice schemes) leaves ops A, B and C
  each still keyed by X25519 — **confidentiality intact**.
* A break of **all** legs of **one** op compromises exactly that op.
* A break of all legs of all three ops is required to reach `KEY`.

The honest limit is recorded in the plan and repeated here: the default suite's
two PQ legs (`sntrup761`, `ML-KEM-768`) are **both lattice-based**, so a
lattice-wide break defeats two of three legs at once, leaving only X25519. Family
diversity requires a code-based KEM that the SDK does not yet have; that is a
future `0x01xx` suite value, not a fork. **This is a stated limitation of the
current suite, not of the construction.**

---

## 8. What P1 does **not** claim

1. **No machine-checked proof.** No Tamarin model exists yet. P1's gate is this
   adaptation plus the code/tests it corrected.
2. **No signature layer.** P3 adds hybrid-signature identity; the argument above
   is for the KEM-only exchange, matching PQ-WireGuard's Algorithm 2.
3. **No identity hiding, no DoS mitigation.** D7/D8; these are symbolic-model
   properties in the source paper, and the paper itself flags that the symbolic
   model's implicit KEM assumptions for identity hiding are *not* implied by the
   standard assumptions — an extra requirement on the CCA KEM. Vallum inherits
   that caveat and must not assume identity hiding comes free.
4. **No data-plane or ratchet claims.** P2/P4.
5. **`psk` is not a secret.** D10. No compromise-resilience from it.
6. **No timing/constant-time claim.** P1 asserts structure, not side-channel
   resistance; that is the `dudect`-style work in plan §8.

---

## 9. Correlation with the code

| claim | code | test |
|---|---|---|
| 3 messages, 3 KEM ops | `handshake.rs` | `every_suite_completes_and_agrees` |
| op order `A ‖ B ‖ C` | `handshake.rs::schedule` callers | `legs_are_bound_to_all_three_operations` |
| MEX on A and C only | `derive_seed`/`mex_randomness` | `mex_makes_the_static_secret_feed_the_encapsulation` |
| responder confirmation verified before accept | `initiator_process_resp` + `verify_confirmation` | `forged_responder_confirmation_is_rejected` |
| initiator confirmation verified | `responder_process_conf` | `forged_confirmation_is_rejected` |
| transcript binding prevents replay across handshakes | `transcript_*` | `a_responder_confirmation_cannot_be_replayed_from_another_handshake` |
| suite degradation rejected | `expect_suite` | `suite_downgrade_is_rejected` |
| byte-exact protocol surface | all of the above | `frozen_vectors_match` |

---

## 10. References

* A. Hülsing, K.-C. Ning, P. Schwabe, F. Weber, P. R. Zimmermann, *Post-quantum
  WireGuard*, 25 Sep 2023 — Algorithm 2, Table II, three-MEX/UKS/authinit fixes,
  theorem statement, either-KEM-break side-result. (`PQWIREGUARD.pdf`, extracted
  with `rapidocr`; the PDF is image-only.)
* B. Dowling, K. G. Paterson, *A cryptographic analysis of the WireGuard
  protocol* — the eCK-PFS-PSK instantiation PQ-WireGuard extends, and the
  observation that WireGuard's proof must be relaxed around key confirmation.
* Plan §7 obligation 1 (combiner lemma), §4.1 (handshake), §10 (open decisions).
