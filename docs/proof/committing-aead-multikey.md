# P2 gate — committing-AEAD multi-key security in the data plane

**Status:** P2 gate artefact. Covers the transport data plane in
`crates/vallum-core/src/{keys,data,replay,cookie,timestamp,timer}.rs`.
**Supersedes:** nothing. **Depends on:** plan §7 obligation 5 (primitive exists),
obligation 3 (`docs/proof/eck-pfs-psk.md`, which produces `KEY`).

This document states proof obligation 6 — *committing-AEAD multi-key security: no
key ambiguity* — as two separable claims, records which of them the code and
tests actually establish, and is explicit about the one that they cannot. That
last part is the substance of the gate, not a disclaimer: the obligation is
**satisfiable but not test-provable** for this primitive, and the honest move is
to freeze the boundary behaviour and state the primitive assumption where a
suite swap can see it.

---

## 0. The implementation correction this gate forced

P2's plan entry (§4/§5) said the associated data would be
`transcript ‖ suite ‖ epoch ‖ counter`. The implemented split is different and
better:

| value | where it is bound | why there |
|---|---|---|
| `transcript`, `epoch` | the **key derivation** (`keys.rs`) | constant per session/epoch; re-binding them per packet costs 32 B/packet for no gain |
| `suite_id`, header fields, `counter` | the **associated data** (`data.rs`) | the only values that vary within one key |

So `AD = header.encode() ‖ counter_be(8)`, 16 bytes, and the key schedule is
`epoch_root = KDF(salt = KEY, ikm = frame([transcript, epoch]), info = "vallum/data/root/v1")`.
Between the two, all four of `{transcript, epoch, suite, counter}` are bound to
every packet — the plan's intent, at 16 bytes instead of 48. The plan's §4/§5/§12
entries were corrected to match.

The second correction: the *receiver* demuxes on a **32-bit index the peer
chooses** (`Header.sender_index` carries the recipient's index — WireGuard's
`receiver` semantics). That public, peer-controlled, 32-bit selector is what
makes wrong-key openings a *design* concern here rather than a hypothetical one,
and it is why this obligation exists at all (§3).

---

## 1. The obligation, stated exactly

Two claims travel under "no key ambiguity". They are different, with different
status.

**(A) Multi-key security.** Vallum runs many concurrent sessions, each with
several epochs, each with two directions, all under one suite. A tested session
key must remain indistinguishable from random even though the adversary sees
unbounded traffic under the *other* keys. Formally, the standard multi-key
generalisation of AEAD security with `μ` keys and the usual `μ·Adv` loss.

**(B) Key commitment.** For any ciphertext that verifies, the `(key, nonce, AD,
plaintext)` tuple that produced it is pinned: an efficient adversary cannot
produce two pairs `(K₁, P₁) ≠ (K₂, P₂)` such that the *same* ciphertext verifies
under both and decrypts to different plaintexts. This is Grubbs–Luykx–Paterson–
Ristenpart's non-committing-AEAD failure, and it is what makes a *partitioning
oracle* possible (§3).

---

## 2. (A) Multi-key: established structurally

Every key the data plane uses is an independent HKDF invocation:

```text
epoch_root = KDF(salt = KEY,   ikm = frame([transcript, epoch]), info = "vallum/data/root/v1")
dir_key    = KDF(salt = epoch_root, ikm = [direction], info = "vallum/data/key/v1",   32)
dir_nonce  = KDF(salt = epoch_root, ikm = [direction], info = "vallum/data/nonce/v1", 16)
```

Two properties do the work, and both are *structural* — visible in the code, so
a provider swap cannot quietly remove them:

1. **The inputs are unique per key.** `KEY` is unique per handshake (it commits
   to the staged transcript, obligation 3); `epoch` disambiguates ratchet steps;
   `direction` is a distinct one-byte `ikm`; `info` separates the key from the
   nonce prefix. No two derived keys share an input tuple.
2. **Each derivation is a separate HKDF-Extract, not a slice of one stream.**
   `dir_key` and `dir_nonce` are two invocations with different `info`, so even
   the fact that they share a root cannot make one observable from the other.
   `keys.rs::directions_and_purposes_are_all_distinct` asserts exactly this.

Given (1) and (2), the multi-key claim reduces to the single-key claim for HKDF
plus the standard `μ`-fold loss. That is not a novel argument and this gate does
not pretend otherwise; what it establishes is that **Vallum's schedule meets the
hypothesis**, which is the part a protocol can actually get wrong.

The reduction is *not* free, and the loss is where the real engineering is:

* `eph`/`epoch` reuse would collapse distinct keys onto one root — bounded by
  `REKEY_AFTER_MESSAGES = 2⁴⁸` and `REJECT_AFTER_MESSAGES = 2⁴⁹`, and by P4's
  epoch monotonicity (which `establish_epoch` documents as the caller's
  responsibility, not something the schedule can detect).
* A 32-bit index collision would let a peer address another session's receiver.
  Collisions cost the *attacker* nothing to attempt; what stops a packet from
  being *opened* under the wrong session's key is (B), plus the tag check. The
  index is a demultiplexer, never an authenticator — the code reflects this:
  `Sender::seal` stamps `peer_index`, `Receiver::open` checks `own_index` and
  returns `DataError::WrongIndex` **before** any crypto.
* Nonce reuse under one key is impossible by construction: the nonce is
  `prefix(16) ‖ counter_be(8)`, the prefix is per-`(session, epoch, direction)`,
  and the counter is capped at `2⁴⁹ ≪ 2⁶⁴`.

---

## 3. (B) Commitment: why it matters here, and what the primitive gives

### 3.1 The attack this obligation is named after

Grubbs, Luykx, Paterson and Ristenpart (USENIX Security 2022) show that
AES-GCM — and AES-GCM-SIV in the "Invisible Salamanders" work (USENIX Security
2020) — are **not** key-committing, and demonstrate live partitioned-oracle attacks in
messaging systems. The mechanism is algebraic: GHASH is a polynomial evaluation,
so an adversary holding a ciphertext can *solve for* a second key under which it
verifies to a plaintext of the adversary's choosing. Ciphertexts are then
re-usable across sessions with attacker-chosen meaning.

The pattern repeats wherever (i) a receiver will try a *peer-supplied* key, and
(ii) the ciphertext is transferable between keys. Vallum has both halves:

* The receiver's key is selected by a **32-bit public index the peer picks**.
* During a rekey there are **several concurrent valid keys** per peer, and P4
  will add more (one per epoch).
* Across a **suite swap** (the whole point of the P0 boundary), the AEAD changes
  underneath a protocol surface that was written against a committing one.

In the usual deployment — every key derived from a completed handshake — an
adversary that can *influence* a key is already inside the trust boundary. So (B)
is honest defence-in-depth here: cheap, structural, and exactly the property the
protocol surface is written to rely on.

### 3.2 What `ChaCha20Blake3` actually does

From the `chacha20-blake3` crate (v0.10, `ChaChaBlake3<20>`, the *stateless*
per-message-KDF variant — Vallum deliberately does **not** use the `Session`
type, whose documented counter is not bound into the MAC):

```text
kdf_out           = BLAKE3-KDF(key, nonce)              // keyed XOF
encryption_key    = kdf_out[0..32]
authentication_key= kdf_out[32..64]
encryption_nonce  = kdf_out[64..72]

tag = BLAKE3-keyed(authentication_key,
                   AD ‖ len_le64(AD) ‖ CT ‖ len_le64(CT))
```

Commitment therefore reduces to this: a ciphertext that opens under two
different `(key, nonce)` pairs requires

```text
B3_{a₁}(AD₁ ‖ len ‖ C ‖ len) = B3_{a₂}(AD₂ ‖ len ‖ C ‖ len)
```

with `a₁ ≠ a₂` derived from distinct `(key, nonce)`. Because the tag is a **keyed
hash over the ciphertext and the AD**, not a polynomial evaluation of them, there
is no algebraic route from a ciphertext to a second acceptable key. Finding one
means either colliding BLAKE3's keyed hash across two distinct keys, or colliding
the keyed KDF to force `a₁ = a₂`. The bound is the key/state space, not the
ciphertext structure.

**This is the sharp difference from GCM, and it is the reason the obligation was
satisfiable at all with an SDK primitive.** It is also a heuristic argument, not
a theorem — see §5.

---

## 4. The claim this gate freezes

Since (B) cannot be *demonstrated* against a keyed-hash AEAD — there is no
known feasible partitioning-oracle instance to run, and a passing test would
prove nothing about infeasible attacks — the gate freezes the property the
protocol can actually violate: **no key ambiguity is reachable through the
protocol surface.** Enumerated exhaustively by construction:

| ambiguity axis | why it cannot open | test (`tests/dataplane.rs`) |
|---|---|---|
| the other direction | distinct key **and** distinct nonce prefix; header names only the recipient | `the_two_directions_do_not_share_a_key`, `a_packet_only_opens_in_the_direction_it_was_sealed` |
| another session, same indices | distinct `KEY`, hence distinct `epoch_root` and both directional keys | `another_session_cannot_open_our_packets` |
| another epoch, same root/transcript/indices | `epoch` is folded into `epoch_root` | `another_epoch_cannot_open_our_packets` |
| another suite | suite id bound in the header **and**, through the header, in the AD | `a_packet_with_a_foreign_suite_id_is_refused` |
| a counter the sender never sealed | counter is in the AD | `a_tampered_tag_ciphertext_or_counter_is_rejected`, `a_forged_counter_cannot_advance_the_window` |
| a different recipient index | index checked before any crypto | `a_packet_only_opens_in_the_direction_it_was_sealed` |
| a malformed/relabelled packet | strict TLV parse, duplicate-tag rejection | `a_data_packet_is_a_data_message_and_nothing_else` |

Supporting primitive-level negatives (wrong key / wrong nonce / wrong AD /
forged tag rejected) are the **contract's** job and are already asserted once for
every suite by `check_aead` in `crates/vallum-crypto-contract/src/lib.rs:223`.
This gate references them and does not duplicate them — a second copy would rot.

---

## 5. What P2 does **not** claim

1. **No formal CMT proof.** `ChaCha20Blake3` is not SIV and has no published
   CMT-1/CMT-4 reduction. §3.2 is an argument, not a theorem. The *requirement*
   is documented (§6) so a suite swap is judged against it.
2. **No constructive partitioning-oracle demonstration.** There is no test that
   distinguishes a committing from a non-committing AEAD here; a test that passed
   would not show the property, and the honest report of that is the value of
   this section.
3. **`mac1` is not authentication.** It is computable from public data alone —
   that is its purpose (a cheap filter). Only `mac2` costs an attacker, and only
   under load. `cookie.rs` documents this; the *identity* of a peer is P3's
   problem, not the cookie layer's.
4. **Index is not authenticated.** A peer chooses its index; a collision is a
   demultiplexing event, resolved by the tag check and never by trust.
5. **No timing/constant-time claim.** `mac_equal` and the AEAD's tag comparison
   are delegated to the suite; the `dudect`-style work is plan §8.
6. **No cookie-reply wire framing.** `seal_cookie_reply`/`open_cookie_reply`
   exist and are tested, but the `CookieReply` message type and its scheduling
   are P6; P2 supplies the crypto halves only.
7. **No ratchet.** `establish_epoch` takes an `epoch` value; monotonicity is
   P4's obligation and is documented as the caller's responsibility.
8. **No length privacy on its own.** As written in P2, a data packet's ciphertext
   length is `plaintext + tag`, so the *payload length is visible on the wire*.
   The AD covers the header and the counter, not the length. P5 closes that
   channel by making the sealed plaintext `u16 BE length ‖ payload ‖ zeros`
   (`data.rs::seal_padded`): the length is now carried *inside* the AEAD and the
   visible length is a chosen target. Nothing above changes — the AD is still 16
   bytes, the nonce is still unchanged, and every multi-key and commitment
   argument is about `(key, nonce, AD, ciphertext)` and is indifferent to what
   the plaintext contains. The change *strengthens* requirement 3 (below): the
   length field is read only after the tag verifies, so a forged ciphertext can
   no longer even propose a length. See `docs/proof/traffic-shaping.md`.

---

## 6. The requirement this places on a swapped suite

The P0 boundary exists so the crypto can be replaced. A replacement AEAD must
satisfy, at minimum:

1. **32-byte key, 24-byte nonce, 32-byte tag** — enforced at runtime by
   `DataKeys::derive`, which *refuses* a suite whose `sizes()` disagrees rather
   than truncating a key.
2. **Authenticate the AD and the ciphertext with a key separate from the
   encryption key**, derived from both the key and the nonce (so the nonce is
   committed too) — i.e. **committing** in the (B) sense, not merely IND-CCA.
3. **Reject-then-decrypt**: no plaintext is released before the tag verifies
   (`Receiver::open` verifies, *then* consults the replay window, *then* returns).
4. **Pass `check_aead`** in the contract crate: wrong key / wrong nonce / wrong AD
   / forged tag all rejected, ciphertext length is `plaintext + tag`.

Requirements 2–3 are what a **suite swap smoke test** (plan §6, P0 gate) must
re-check with the new adapter; requirement 4 is the mechanical part. A suite that
satisfies only IND-CCA — GCM, for instance — would break the boundary's contract
while every existing test still passed, which is why §3.2 and this list, not the
tests, are the gate's durable output.

---

## 7. Correlation with the code

| claim | code | test |
|---|---|---|
| key inputs unique per `(session, epoch, direction, purpose)` | `keys.rs` | `directions_and_purposes_are_all_distinct`, `transcript_epoch_and_root_all_change_the_keys` |
| role selects mirrored halves | `keys.rs::split` | `role_selects_opposite_halves` |
| AEAD geometry enforced, not truncated | `data.rs::establish_epoch` | enforced; a dedicated negative needs a mock suite and lands with the P0 swap harness |
| AD = header ‖ counter | `data.rs::associated_data` | `the_associated_data_is_the_header_then_the_counter` (unit) |
| nonce = prefix ‖ counter, BE | `data.rs::nonce` | `the_nonce_is_the_prefix_then_the_counter` (unit) |
| tag verified before the window moves | `data.rs::Receiver::open`, `replay.rs` | `a_forged_counter_cannot_advance_the_window` |
| reorder accepted, duplicate refused | `replay.rs` | `reordered_packets_all_open_and_duplicates_do_not`, `a_counter_may_not_be_reused_after_it_ages_out_of_the_window` |
| counter ceiling both sides | `data.rs`, `replay.rs` | `a_spent_key_refuses_to_seal_again` (unit), `replay.rs::the_message_ceiling_is_enforced` (unit) |
| index demux before crypto | `data.rs::Receiver::open` | `a_packet_for_another_session_is_refused_before_any_crypto` (unit) |
| `mac1` covers the message, `mac2` covers `mac1` | `wire.rs` | `mac_inputs_exclude_the_right_fields`, `mac_inputs_follow_wire_order_not_tag_order` |
| cookie bound to client address | `cookie.rs::verify_mac2` | `a_cookie_is_bound_to_the_client_address` |
| fail closed under load with no cookie facility | `cookie.rs::admit_handshake` | `under_load_without_a_cookie_gets_a_cookie_and_nothing_more` |
| cookie survives one rotation, not two | `cookie.rs::CookieSecret` | `a_cookie_keeps_working_across_a_rotation_but_not_forever` |
| cookie reply needs the request it answers | `cookie.rs::seal/open_cookie_reply` | `a_cookie_reply_is_readable_only_with_the_request_it_answers` |
| payload length is a chosen target, not a leak | `data.rs::{seal_padded, strip_padding}` (P5) | `padding_hides_the_payload_length_and_is_recovered_exactly`, `a_forged_length_prefix_fails_the_tag` (unit); `tests/shaping.rs` |
| no key ambiguity across the whole surface | all of the above | the §4 matrix |

*(`DataKeys::derive` refuses a suite whose AEAD geometry is not 32-byte key /
24-byte nonce, so a swap cannot silently truncate a key. The per-suite contract
run in `crates/vallum-crypto-contract/tests/contracts.rs` covers every shipped
suite and the `SwapSuite` adapter.)*

---

## 8. References

* P. Grubbs, A. Luykx, K. Paterson, T. Ristenpart, *How to Abuse and Fix
  Authenticated Encryption Without Key Commitment*, USENIX Security 2022 — the
  committing-AEAD definitions (CMT-1/CMT-4), the GCM key-multicollision
  technique, and the in-the-wild partitioned oracles. **The source of obligation
  6.**
* M. Albertini, T. Duong, S. Gueron, A. Kölbl, A. Luykx, S. Schmieg, *Invisible
  Salamanders in AES-GCM-SIV*, USENIX Security 2020 — the SIV case, and the
  counterexample to "SIV is automatically committing".
* `chacha20-blake3` (kerkour), v0.10 — ChaCha20 + keyed-BLAKE3, 24-byte nonce,
  32-byte tag; the tag construction quoted in §3.2. The `Session` type's
  documented "MAC does not bind the counter" caveat is why Vallum uses the
  stateless variant with its own counter in the AD.
* Plan §7 obligation 6, §4/§5 (corrected here), §6 P2 gate, §8 (validation).
* `docs/proof/eck-pfs-psk.md` — produces `KEY`, the root this schedule expands,
  and the KEM-side counterpart of the "no ambiguity" argument.
