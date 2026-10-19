# P3 gate — hybrid-signature identity

**Status:** P3 gate artefact. Covers `crates/vallum-core/src/identity.rs` and the
`IDENTITY_SIG` field in `crates/vallum-core/src/handshake.rs`.
**Supersedes:** the plan's §5 **V3** row (*dual-use identity key*, Thormarker) —
see §3. **Depends on:** plan §7 obligation 2 (hybrid-signature unforgeability),
obligation 3 (`docs/proof/eck-pfs-psk.md`, which produces `TR`, the signed value).

This document states proof obligation 2 — *"both must verify"* — records what the
code and tests actually establish, and records the **design reversals** the
obligation forced. The reversals are the substance: implementing the obligation
proved that the plan's V3 mechanism was the wrong one, and the honest move was to
say so rather than build it anyway.

---

## 0. The correction this gate forced

Two changes to the plan, both from building the obligation rather than from
reading about it.

**(a) `IDENTITY_SIG` is over `TR`, and it is verified *after* the confirmation.**
The plan (§3.3) sketched the identity signature as a field with no stated target.
It is taken over `TR` — the same transcript the key schedule consumes — which
means the signer commits to every KEM ciphertext in the session, not to a detached
string. And it is verified **only after** the peer's confirmation value checks
out, for a concrete reason (§2.3): a Falcon-1024 verification is the most expensive
operation in the handshake, and the confirmation is what proves the sender holds
the KEM secret before we spend it.

**(b) V3 was not built.** The plan (§5, V3) said: reuse the Ed25519 identity key as
the X25519 KEM key via the RFC 7748 birational map, per Thormarker, and hash the
*untranslated* encapsulation. Implementing obligation 2 showed this saves 32 bytes
and costs a key-reuse assumption Vallum does not need. §3 is the reassessment; the
replacement — one master seed, two **independently derived** key pairs — is what
shipped.

---

## 1. The obligation, stated exactly

**(A) Hybrid-signature unforgeability — "both must verify".** A hybrid signature
verifies only if **every** component signature verifies. The adversary's advantage
against the hybrid scheme is therefore bounded by the **minimum** over components,
not the product and not the sum:

```text
Adv^{euf-cma}_{Hyb}(A)  ≤  min over components c of Adv^{euf-cma}_{c}(A_c)
```

For the shipped identity that is `min(Ed25519, Falcon-1024)`. A break of Ed25519
*or* of Falcon-1024 does not yield a forgery. The two components are deliberately
from **different families** — Ed25519 is elliptic-curve, Falcon-1024 is NTRU-lattice
— so this is a genuine hedge, unlike the KEM suite (§1 of the eCK-PFS-PSK doc),
where both PQ legs share the lattice family.

**(B) What "identity" means here.** The obligation is *unforgeability of the
binding*, not a statement about a PKI. Vallum supplies:

* a signature over `TR` that a **third party** holding the peer's signing key can
  check (this is the capability PQ-WireGuard lacks — it is KEM-only, so its
  authentication is symmetric),
* a **fail-closed** rule for when a signature is required, and
* an **identity document** that binds a KEM key to a signing key, so a
  certificate path exists.

Whether the peer's signing key is trusted because it was typed into a config file
or because a CA signed a document over it is **local policy**, never a wire
protocol. The two deployments share one wire path (§4).

---

## 2. Mechanism (normative)

### 2.1 What is signed

```text
input = frame([ domain, suite_id_be(2), identity_pk, TR ])
```

* `domain` — `"vallum/identity/resp/v1"` for the responder's signature,
  `"vallum/identity/init/v1"` for the initiator's. Two distinct statements, so
  neither role's signature can be replayed as the other's.
* `suite_id_be` — bound into the signature as well as the transcript, so a suite
  substitution is a signature failure, not merely a key-schedule failure.
* `identity_pk` — the signer's own hybrid public key. This is the
  `CertificateVerify`-style binding: a signature cannot be lifted onto a different
  public key.
* `TR` — the key-schedule transcript (`TR = H("vallum/tr/resp", …)`). It binds
  `sid_i`, `epk_i`, `ct_A`, `timestamp`, `sid_r`, `ct_B`, `ct_C`.

`frame` is the suite's length-prefixed concatenation, so the input is unambiguous:
no `(domain, pk, TR)` split can be reinterpreted as another.

The signature covers `TR`, **not** `TR2`. `TR2 = H("vallum/tr/conf", TR ‖ conf_r)`
includes the responder's confirmation, and both signatures are sent *after* the
peer's confirmation has been verified — so a valid signature over `TR` is
accompanied, in every accepted session, by a confirmation that proves the peer
holds the key `TR` derives. The confirmation is what carries the freshness; the
signature carries the name.

### 2.2 Where it rides, and in which order

| message | field | signer | verified by | verified after |
|---|---|---|---|---|
| `RespHello` | `IDENTITY_SIG` | responder | initiator | `conf_r` verifies |
| `InitConf` | `IDENTITY_SIG` | initiator | responder | `conf_i` verifies |

`InitHello` is unchanged: the initiator's signature has no earlier place to live,
so the initiator's identity statement arrives in the last message. This matches
PQ-WireGuard's shape, where the initiator's authentication commitment
(`1tk = AEAD.Enc(κ3, 0, H3, H(spk_i))`) also arrives late.

### 2.3 Why verify-after-confirm is deliberate

`initiator_process_resp` checks `conf_r` **before** the responder's signature;
`responder_process_conf` checks `conf_i` **before** the initiator's. The reason is
cost and reachability:

* `conf_r` can only be produced by a party that decapsulated ops A, B **and** C —
  i.e. the real responder, holding `σ_r`. So the initiator never runs a Falcon
  verification for a party that has not already proved the KEM secret. A blind
  forgery is rejected by a 32-byte hash comparison, not by an ~1.6 KB signature
  check.
* Symmetrically, `conf_i` requires the initiator to have completed all three ops
  (it chose `r_i`, holds `esk_i`, and decapsulated `ct_C` with `σ_i`).

The honest caveat: **anyone can initiate**. A fresh initiator can always compute
`KEY` (it encapsulated op A itself) and therefore `conf_i`, so an initiator that
sends a valid `InitConf` will make the responder pay one Falcon verification. That
is the ordinary "unauthenticated first message" surface, and it is what the P2
`mac1`/`mac2` cookie ladder exists for; the cookie *wire framing* is P6, so in P3
the mitigation is present in the crypto layer but not yet scheduled. Recorded as
an open item, not a solved one.

---

## 3. The V3 reassessment (the plan reversal)

The plan (§5, V3) proposed adopting Thormarker's construction: **use one Ed25519
key pair for signing *and* as the X25519 KEM key**, via the RFC 7748 birational
map from the Ed25519 public key to a Montgomery point. The paper proves joint
security (SDH + ROM) without random-oracle domain separation.

The mechanism was mine and I am reversing it. The reasons, in order of weight:

1. **It saves 32 bytes of a 2374-byte key.** The tri-hybrid KEM public key is
   2374 B. Reusing Ed25519 *in place of the X25519 leg* removes exactly the 32-byte
   X25519 share. That is a 1.3% saving on a value that is configured out of band
   and never sent in the handshake; the handshake cost is identical. There is no
   product motivation left once the number is written down.
2. **It does not deliver "one key pair" for Vallum's suite, because Vallum has
   four public keys.** Thormarker's theorem is about a *single* Ed25519↔X25519
   reuse. Vallum's identity also carries sntrup761 (or ML-KEM-768) *and*
   Falcon-1024. Those keys are not covered by the theorem and cannot be — they are
   distinct algorithms with no birational relation. So the composition Vallum
   would ship is "Thormarker for one pair, plus two more ordinary key pairs", i.e.
   key *reuse* plus key *separation*. The property the plan's V3 row advertised —
   provable dual use — would hold for part of the identity and not the rest, while
   being documented as though it held for all of it. That is the failure mode to
   avoid.
3. **The theorem's premise is key reuse; Vallum's replacement has none.** The
   alternative below derives two keys from one seed with a domain separator, so
   the KEM scalar and the signing scalar are independent. A proof of joint security
   *under reuse* is not needed where there is no reuse. Adopting V3 would
   *introduce* the reuse the security proof has to defend.
4. **Haber–Pinkas is the default advice against exactly this.** Cross-protocol key
   reuse is the setting that makes "the same key in two protocols" attacks
   possible; the conservative position is to avoid it unless there is a proof *and*
   a reason. Vallum had a reason-shaped hole (key-distribution savings) and it does
   not survive §3.1.
5. **It puts curve-translation code inside the narrow boundary.** The birational
   map is a new, subtle primitive (sign handling, non-canonical encodings, the
   untranslated-encapsulation hashing needed to defeat malleability). Every line
   of it is inside the `CryptoSuite` boundary that exists so the crypto can be
   *swapped*. A future from-scratch suite would have to reimplement it or the
   identity layer would silently depend on the SDK's curve code — the exact
   coupling §3 of the plan forbids.

**Not a reason, for the record:** Thormarker's *swapped-KDF-fix* — hash the
**untranslated** encapsulation `A` to avoid malleability — is genuinely good
advice, and Vallum already satisfies it structurally: the P0 combiner puts the
*raw ciphertexts* into the HKDF salt, so a re-encoded ciphertext changes `ROOT`.
Verified by `check_combiner` in the contract crate (a mutated ciphertext never
reproduces the secret). So the one durable engineering lesson from the paper was
already taken.

### 3.1 What replaced it

`StaticIdentity::generate_with_signing(suite, seed)`:

```text
sign_seed = KDF(salt = "vallum/identity/v1", ikm = seed, info = "vallum/identity/sign-seed/v1")
```

* The KEM half is `StaticIdentity::generate(suite, seed)` — **byte-for-byte
  unchanged**, which is what keeps the P1 frozen vectors valid.
* The signing half is derived from the same master seed under its own label, then
  the seed is scrubbed.
* One seed → two independent key pairs. The two public halves are bound to each
  other for the life of a session by the signature over `TR` (which binds the KEM
  ciphertexts the KEM keys produced).

This is **key derivation with domain separation**, not key reuse. The threat model
is a single compromised seed, which is the deployment reality (one config secret
per peer) rather than a cryptographic assumption.

---

## 4. Fail-closed semantics

The requirement comes from local configuration — `PeerIdentity::signing` — and
never from the wire:

| `PeerIdentity::signing` | `IDENTITY_SIG` | outcome |
|---|---|---|
| `Some(pk)` | present | verify; reject on failure (`IdentityInvalid`) |
| `Some(pk)` | absent | reject (`IdentityMissing`) |
| `None` | present | reject (`IdentityUnexpected`) |
| `None` | absent | accept |

Consequences, and they are the point:

* **No downgrade.** There is no wire flag to negotiate, so an attacker stripping
  `IDENTITY_SIG` cannot move a peer from "verify" to "don't". The field's absence
  is a hard failure against a peer configured to require it.
* **No silent upgrade.** A peer *not* configured with a signing key rejects a
  signature rather than ignoring it. This matters because an ignored signature can
  be read as "the peer signed and we accepted" by operators skimming logs. The
  asymmetry is loud.
* **One wire path, two deployments.** Pre-shared KEM keys (`kem_only`) and
  certificates (`with_signing`) are the same three messages with one optional
  field. There is no second protocol.

`None`/`absent` is exactly the P1 behaviour, so a KEM-only configuration produces
the P1 bytes and the P1 frozen vectors still match.

---

## 5. Identity documents (the certificate path)

`IdentityDocument` is `frame([domain, suite_id, label, kem_pk, sign_pk])` signed by
an issuer:

```text
IdentityDocument::decode(bytes)?  →  doc.to_peer(&suite, issuer_pk)?  →  PeerIdentity
```

`to_peer` returns the peer **only if** the issuer signed *that* binding. Self-signed,
the document is the subject's own key binding; issued by a CA, it is a certificate
— same struct, same encoder, the difference is which key the operator passes as
`issuer`. It reuses the handshake TLV framing (`MessageType::IdentityDoc = 0x05`,
tags `IDENTITY_LABEL`/`KEM_PUBLIC`/`SIGN_PUBLIC`/`IDENTITY_SIG`) rather than a
second parser.

This is the capability PQ-WireGuard does not have: its identity is a pre-shared KEM
public key, so there is no artefact a third party can check. Vallum's document is
such an artefact, and the binding it forges — KEM key ↔ signing key — is the one
the handshake then re-proves per session by signing `TR`.

What this does **not** include: no revocation, no validity window, no name
constraints, no chain depth. It is one signature over one binding. A deployment
that needs revocation has to supply it (the label is free-form for exactly this
reason). Stated, not implied.

---

## 6. Measured cost (tri-hybrid, default suite)

Measured by `a_signature_adds_exactly_one_field_per_message`:

| message | unsigned | signed | delta |
|---|---|---|---|
| `InitHello` | 4565 | 4565 | 0 |
| `RespHello` | 4378 | 6027 | +1649 |
| `InitConf` | 52 | 1701 | +1649 |
| **handshake total** | **8995** | **12293** | **+3298** |

Delta = `tag u16 | len u16 | signature` = 4 + 1645. The 1645-byte signature is
`u32 BE falcon_len | falcon (≤1577) | ed25519 (64)`, i.e. the maximum-size
Falcon-1024 signature. The plan's §4.2 note ("add ~1.3 KB") was an estimate; the
measured worst case per field is 1649 B and is what the table now records.

Consequence for the transport: a signed tri-hybrid handshake is ~12.3 KB, ~9 UDP
datagrams at 1400 B. The multi-packet-by-count rule (§0 rule 1) is unchanged; no
IP fragmentation is introduced. Which is to say the identity layer does not create
a new DoS surface, it enlarges an existing bounded one.

Falcon-1024 **key generation is the expensive operation, and it happens once per
identity, never per handshake**: `sign_keygen` goes through the SDK's
`from_seed_cached`, pinned by `crates/vallum-crypto-sdk/tests/keygen_cache.rs`.

---

## 7. What P3 does **not** claim

1. **No machine-checked proof.** There is no Tamarin model; the signature layer
   adds the standard "signature over a session-transcript hash" step, which is the
   shape symbolic models are best at — but it has not been run. Plan §7
   obligation 4.
2. **No new hardness assumption** — but also **no new hardness theorem**. §3.1 is
   key derivation, not a dual-use theorem; the security of the identity is the
   security of the hybrid signature (`min(Ed25519, Falcon-1024)`) plus the KDF.
3. **No revocation / expiry / name constraints.** §5.
4. **No privacy.** The identity signature reveals *who* is talking to an observer
   who can guess the candidate public key (the signature is not encrypted; the
   PKI is not anonymous). PQ-WireGuard's identity hiding is a different property
   (`1tk`), deferred with D7 in the P1 doc. Vallum's `RespHello` grows by 1.6 KB of
   signature that a passive observer can inspect. Stated.
5. **No anti-replay beyond `TR`.** A signature is bound to `TR`, which includes
   the timestamp and all ciphertexts, so a replay on the same `TR` would require
   re-using the ephemeral secrets — which `initiator_hello` never does. The
   freshness guarantee is inherited from the KEM transcript, not added by P3.
6. **No constant-time claim.** The signature path adds a `frame` + a hybrid verify;
   the `dudect`-style work is plan §8.

---

## 8. Correlation with the code

| claim | code | test |
|---|---|---|
| signature input is `frame([domain, suite_id, pk, TR])` | `identity.rs::identity_signature_input` | `signed_peers_complete_and_the_signatures_cover_the_transcript` (reconstructs the input from public constants) |
| role domain separation | `IDENTITY_RESP_DOMAIN` / `IDENTITY_INIT_DOMAIN` | `a_signature_is_bound_to_its_role`, `identity_signatures_are_bound_to_key_role_and_transcript` |
| bound to suite, key and transcript | `identity_signature_input` | `identity_signatures_are_bound_to_key_role_and_transcript` |
| both components must verify | `CryptoSuite::verify` (adapter) | `signing.rs::both_halves_must_verify` (breaks each half separately) |
| **every** byte matters, suite-agnostically | `vallum-crypto-contract` | `check_signatures` byte sweep + truncation/padding |
| `Some(pk)` + absent ⇒ reject | `check_identity_signature` | `a_stripped_responder_signature_is_rejected`, `a_stripped_initiator_signature_is_rejected` |
| `None` + present ⇒ reject | `check_identity_signature` | `an_unexpected_signature_is_rejected_in_both_directions` |
| forged signature ⇒ reject | `verify_transcript` | `a_forged_responder_signature_is_rejected` |
| replay across sessions ⇒ reject | `TR` binding | `a_signature_does_not_replay_across_sessions` |
| KEM-only config is byte-identical to P1 | `StaticIdentity::generate` | `unsigned_peers_still_complete_with_no_signature_fields`, `frozen_vectors_match` |
| one seed, two independent keys | `generate_with_signing` | `one_seed_yields_independent_kem_and_signing_keys` |
| document round-trip + CA path | `IdentityDocument` | `an_identity_document_configures_a_peer_end_to_end`, `identity_document_round_trips_and_verifies` |
| wrong issuer ⇒ reject | `to_peer` | `an_identity_document_configures_a_peer_end_to_end`, `a_tampered_document_is_rejected` |
| keygen cached, once per identity | `SdkSuite::sign_keygen` | `keygen_cache.rs::sign_keygen_populates_the_bundle_cache` |
| measured wire cost | `handshake.rs` | `a_signature_adds_exactly_one_field_per_message` |

---

## 9. References

* J. Thormarker, *On using the same key pair for Ed25519 and an X25519 based KEM*,
  Ericsson — the V3 source, and §3's reversal. Construction: `Encap(A, Z) =
  (X25519(a, G), KDF_H(A, X25519(a, X)))`, `Decap(A) = KDF_H(A, X25519(x, A))`,
  `KDF_H(A, Z) = HMAC_H(salt, A ‖ Z)`, assumption SDH + ROM, `H` = SHA-512,
  Ed25519ph excluded; the hashing of the **untranslated** `A` and the recommendation
  to include both parties' EdDSA public keys in the KDF are the two engineering
  details worth keeping — the latter is subsumed by `TR`, the former by the
  combiner's ciphertext salt.
* S. Haber, B. Pinkas, *How to Securely Replicate Services* (and the wider
  cross-protocol key-reuse literature) — the default advice §3.3 weighs against.
* RFC 7748 §4.1 — the Montgomery↔Edwards birational map V3 would have needed.
* Plan §7 obligation 2, §5 V3 (reversed here), §4.2 (cost corrected here), §9.7
  (Falcon keygen caching), §6 P3 gate.
* `docs/proof/eck-pfs-psk.md` — produces `TR`, the signed value, and D7 (identity
  hiding deferred).
* `origin-crypto-sdk/src/signing/hybrid/` and `src/signing/wire.rs` — the hybrid
  bundle, `both_must_verify`, and the `[u32 len][falcon][ed25519]` wire layout.
