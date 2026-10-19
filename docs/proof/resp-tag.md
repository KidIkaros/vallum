# P6.8 — the op-A-keyed `RespHello` admission tag

**Status:** post-gate follow-up to P6.3, named there as a non-claim and carried in
the plan's §11. Covers `vallum_core::handshake` (the tag and the check),
`vallum_core::wire` (the field and its input bytes), and `vallum_tunnel::Device`
(the pre-rebuild check).
**Depends on:** P6.2 (`docs/proof/eck-pfs-psk.md` D11) for the op-A-keyed idiom
this reuses, P6.3 (`docs/proof/transport.md` §3.2) for the residual it closes,
P6.5 (`docs/proof/pentest.md`) for the measurement that kept it visible.
**Wire change:** **one field on `RespHello`**, +36 B (4 B TLV header + 32 B tag).
`resp_hello_len` moves; every transcript, key, confirmation, `InitHello`, and
`InitConf` byte is **identical** — verified, not assumed.

---

## 0. What this gate forced

**(a) P6.3 named the gap precisely and the plan then described it from the wrong
end.** `transport.md` §3.2 says it exactly: *"An attacker who has observed an
`InitHello` knows the initiator's index and can make it decapsulate twice per
forged `RespHello`. … Closing it needs a wire change (an op-A-keyed tag checked
before decapsulation)."* That is the gap, and this closes it.

The plan's §11 entry calls the same item *"the one wire change that would bound
the responder's decapsulation work before admission"*. That phrasing does not
describe anything buildable, and §2.4 states why as a structural fact rather than
a limitation of effort: the responder's decapsulation of op A is what *produces*
the key any such tag would be checked against, so a tag on `InitHello` cannot
precede it. The initiator is the party that holds op A's secret **before** doing
KEM work, because it made the encapsulation. This document follows P6.3's wording,
which is the one that corresponds to a mechanism.

**(b) The real cost was larger than the non-claim said, and in the same
direction.** `transport.md` counted two decapsulations per forged `RespHello`.
That is what `initiator_process_resp` spends — but the transport never reaches it
directly: `Device::on_resp_hello` first *rebuilds* `InitiatorState` by calling
`initiator_hello` again, which costs an ephemeral `kem_keygen` and an op-A
`kem_encaps`. So the pre-P6.8 price of one forged message was keygen + encaps +
two decaps. A check inside `initiator_process_resp` alone would have saved the
last two and left the first two, so the transport stores the one derived secret
it needs (`Initiating::resp_tag_key`) and checks **before** the rebuild. §5
measures both layers with a counting suite.

**(c) The tag must cover the optional signature, or it re-opens the gap it
closes.** The obvious construction — MAC over the transcript `TR` — leaves
`IDENTITY_SIG` outside, because the signature is over `TR` and is not part of it.
An attacker holding a captured signed `RespHello` could then flip a signature byte,
have the tag verify (TR unchanged), and still buy the decapsulations the tag
exists to deny. The tag therefore covers the **serialized message minus itself**,
which includes the signature field and, deliberately, any tolerated unknown
fields. This is the `mac1` construction with a secret key instead of a public one.

---

## 1. The obligation, stated exactly

**A forged `RespHello` must reach no KEM operation.**

Not "must be rejected" — a rejection that happens after two decapsulations is the
attack. The security property the mechanism relies on:

> Only a party that decapsulated op A can derive `ss_A`, and only a holder of the
> responder's static secret `σ_r` can decapsulate the initiator's `ct_A`.
> Therefore a value derived from `ss_A` proves `σ_r` possession *for this
> handshake*, at the cost of a KDF rather than a KEM.

The proof of possession is weaker than `conf_r` (it proves op A, not ops B/C), so
it is an **admission token**, never an authentication result: `conf_r` still gates
session acceptance, and the identity signature still gates identity.

---

## 2. The mechanism

### 2.1 Wire form

`tag::PRE_TAG = 0x0008` — the next free core tag after `PEER_HINT = 0x0007` —
emitted **last** in `RespHello`, after `IDENTITY_SIG` when present:

```text
RespHello body (order as emitted):
  EPHEMERAL_CT (0x0002)   ct_B
  STATIC_CT    (0x0001)   ct_C
  RECEIVER_INDEX (0x0005) sid_i
  CONFIRMATION (0x0010)   conf_r
  IDENTITY_SIG (0x0020)   optional
  PRE_TAG      (0x0008)   32 B
```

It is **not** folded into the key schedule: the tag is derived *from* the message,
so it cannot also be part of what the message derives. `TR`, `KEY`, `conf_r`, and
`conf_i` are untouched; §5 pins that.

### 2.2 Derivation

```text
tag_key = KDF(salt = "vallum/resp-tag/seal/v1",
              ikm  = frame(ss_A legs),
              info = "vallum/resp-tag/key/v1", 32)
pre_tag = KDF(salt = tag_key,
              ikm  = serialize(header ‖ every RespHello field except PRE_TAG),
              info = "vallum/resp-tag/v1", 32)
```

The first step mirrors P6.2's `hint_crypt` — derive once from op A, use per
message. The second is the `mac1` construction (`wire::MessageBuilder::resp_tag_input`)
with an op-A key. Because HKDF's salt is the HMAC key, `KDF(tag_key, input)` is a
PRF keyed by `tag_key`; unforgeability is the suite KDF's.

### 2.3 Check order

`initiator_process_resp`, after `expect_type` / `expect_suite` /
`expect_receiver_index` and the field-requirement pass:

```text
parse → type → suite → receiver index
      → require EPHEMERAL_CT, STATIC_CT, CONFIRMATION, PRE_TAG
      → recompute TR, derive the tag, verify          ← no KEM work above this line
      → decapsulate op B, op C
      → schedule → verify conf_r → verify identity signature
```

The receiver index is checked first because it is free and selects the handshake.
A missing tag is a `Wire` error; a wrong one is `HandshakeError::RespTag`, a
distinct variant so a tag failure never reads as framing or as a failed
confirmation.

The transport adds the same check one layer earlier (`Device::on_resp_hello`,
before the `initiator_hello` rebuild), using the `resp_tag_key` captured at send
time. The library check remains, so every caller of `initiator_process_resp` —
including a future one that does not rebuild — is protected.

### 2.4 Why the other direction has no equivalent

The responder's only decapsulation is op A on `InitHello`, and its input is the
responder's own static secret. A tag the responder could check **before** that
decapsulation would have to be keyed by something derivable without `ss_A`; the
only candidates are public (`σ_r.pk`, `ct_A`, the header), and a public-key-keyed
MAC filters nothing an attacker cannot compute. This is why `transport.md` says
the responder side is bounded by `mac1` and, under load, the cookie — and why
P6.5's `pentest.md` measured the residual as *work, not bytes*. The structural
statement is:

- **initiator side:** a secret (`ss_A`) exists before the KEM work, so a tag can
  gate the work. Closed here.
- **responder side:** the KEM work *produces* the secret, so no tag can precede
  it. Bounded by admission (mac1/cookie), unchanged.
- **post-decap fast path:** already present — the sealed peer hint's AEAD fails
  before `responder_accept` does any encapsulation, so a mangled `InitHello` costs
  one decapsulation and stops.

### 2.5 What the tag covers, and what that costs

Covering the serialized message means:

- a mutated ciphertext, confirmation, index, or **signature** fails the tag
  (`a_tampered_resp_hello_fails_the_tag`, `a_mutated_signature_fails_the_admission_tag`);
- a tag lifted from another handshake fails, because `tag_key` is per-handshake
  (`a_resp_hello_tag_does_not_replay_across_handshakes`);
- a byte-identical retransmission still verifies, because the responder's cache
  resends the same bytes (`a_retransmitted_resp_hello_still_verifies`);
- tolerated unknown fields are covered too. An attacker appending junk to a
  captured `RespHello` fails the tag rather than reaching the parser's
  forward-compatibility path — tighter than necessary, and free.

---

## 3. What P6.8 does **not** claim

1. **The tag is not authentication.** It proves op-A knowledge only. `conf_r`
   still gates the session key, and the identity signature still gates identity;
   removing either would be a protocol change this phase does not make.
2. **The responder's decapsulation cost is unchanged.** §2.4: it is structurally
   ungateable by this mechanism and remains behind `mac1` + the cookie ladder.
3. **No protection for `InitConf`.** The responder does no KEM work on it; the
   confirmation check is already one KDF and runs before the signature verify.
4. **No new confidentiality.** The tag is a MAC over bytes an observer already
   sees; it reveals nothing and hides nothing.
5. **No claim about a forged `RespHello`'s *bandwidth* cost.** The work is
   bounded; the packet still arrives and is parsed. That is the same posture as
   every other unauthenticated message.
6. **No timing measurement.** The counting suite asserts *zero KEM calls*, which
   is a stronger statement than a wall-clock comparison and does not depend on the
   host.
7. **No protection against an attacker who holds `σ_r`.** Such an attacker can
   produce the tag — and can also complete the handshake. The tag bounds work for
   everyone else.

---

## 4. Correlation with the code and the tests

| Rule | Code | Test |
|---|---|---|
| tag covers the whole message minus itself | `wire::MessageBuilder::resp_tag_input`, `wire::Message::resp_tag_input` | `a_tampered_resp_hello_fails_the_tag` |
| tag key is derived from op A | `handshake::derive_resp_tag_key` | `a_resp_hello_tag_does_not_replay_across_handshakes` |
| responder emits it last | `handshake::responder_accept` | `frozen_vectors_match` (`resp_hello_len`) |
| initiator checks before decaps | `handshake::initiator_process_resp` | `a_forged_resp_hello_costs_no_kem_work` |
| transport checks before the rebuild | `Device::on_resp_hello`, `Initiating::resp_tag_key` | `a_forged_resp_hello_costs_no_kem_work` (tunnel) |
| missing tag is a framing error | `Message::require_array` | `a_missing_resp_hello_tag_is_a_framing_error` |
| signature field is covered | `resp_tag_input` (no exclusion) | `a_mutated_signature_fails_the_admission_tag` |
| retransmission still verifies | deterministic rebuild | `a_retransmitted_resp_hello_still_verifies` |
| distinct error, not `Wire`/`Confirmation` | `HandshakeError::RespTag` | the forged/tampered cases above |

The two zero-KEM tests use a delegating `CountingSuite` (in
`vallum-core/tests/interop.rs` and `vallum-tunnel/tests/tunnel.rs`) so the claim
is *measured*: an outcome-only assertion would pass with the decapsulations still
running.

---

## 5. Measurement

**Wire cost:** +36 B on `RespHello`, for every suite, signed or not:

| suite | `RespHello` before | after | delta |
|---|---|---|---|
| 0x0001 `X25519+sntrup761` | 2202 | **2238** | +36 |
| 0x0002 `X25519+ML-KEM-768` | 2300 | **2336** | +36 |
| 0x0003 tri-hybrid | 4378 | **4414** | +36 |
| 0x0003 signed (P3) | 6027 | **6063** | +36 |

**Frozen vectors:** `resp_hello_len` is the only field that moved. Re-run of
`dump_frozen_vectors`:

```text
suite 0x0001  transcript 846d8887…  key c4f2772b…  conf_r 60c6bda4…  conf_i eec128c0…
suite 0x0002  transcript f36118a9…  key 439f0600…  conf_r 9391b08e…  conf_i bbcb651c…
suite 0x0003  transcript 6c22bee3…  key 53b04bac…  conf_r 84891b56…  conf_i 52171e40…
```

— all byte-identical to P1/P6.2, as are `init_hello_len` (2337/2412/4609) and
`init_conf`. The narrowest bump a message change can have: a field that is derived
from the transcript cannot be inside it.

**End-to-end:** `scripts/e2e-netns.sh` PASS. `RespHello` still crosses as **4**
Vallum fragments (`⌈4414/1442⌉ = 4`, the same count as 4378), the captured
`InitHello` is still 4629 B, `FragCreates`/`ReasmReqds` still **+0/+0**, and the
live adversary still draws no reply.

**Tests:** **265** workspace tests green (266 total, 1 ignored = the frozen-vector
regen harness), up from 258: five in `vallum-core/tests/interop.rs` (zero KEM
work, missing tag, tampered field, cross-handshake tag replay, retransmission),
one in `vallum-core/tests/identity.rs` (mutated signature fails the tag), one in
`vallum-tunnel/tests/tunnel.rs` (zero KEM work at the transport, handshake
preserved). Clippy clean across all targets, scoped `cargo fmt` clean.
