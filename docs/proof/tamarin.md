# Obligation 4 — the Tamarin symbolic model (handshake + epoch axis)

**Status:** obligation 4, the last unstarted item in the plan's §7. Model:
[`tamarin/vallum.spthy`](tamarin/vallum.spthy).
**Depends on:** P1 (`docs/proof/eck-pfs-psk.md`) for the handshake the model
mirrors, P4 (`docs/proof/ratchet-pcs.md`) for the epoch axis it encodes, P6.8
(`docs/proof/resp-tag.md`) for the `PRE_TAG` pattern it includes.
**Wire change:** none. The model follows the shipped protocol.

---

## 0. What the gate forced

**(a) Two encoding bugs that would have made a "verified" model meaningless.**
The first run reported two wellformedness failures — `RespHello` had unbound
`~freshB`/`~freshC` (the `Fr` premises were missing), so Tamarin was reasoning
about a rule that could pick arbitrary values. The second was subtler and is the
kind of thing this obligation exists to catch: the PFS lemma as first written
said *"there is a reveal after completion"*, and the prover found a trace that
satisfied it while a **second** firing of the reveal rule had leaked the key
earlier. `!Ltk` is persistent, so a reveal rule can fire repeatedly; the
existential later reveal is then a decoy. The lemma now says *"no reveal earlier
than completion"* (§3), which has no such loophole. Both are recorded because
they are exactly the failures a symbolic model is supposed to expose — in the
model, before they can be believed about the protocol.

**(b) The agreement lemma exposed a modelling choice, not a protocol flaw.** The
responder's `Commit` was first emitted on receiving `InitConf`. Agreement then
failed for a trivial reason: the adversary can drop the last message, so the
initiator commits and the responder never does. That is not a violation of
authentication — the responder *did* commit when it sent `RespHello`. The model
now emits `RunningResp` at send time (the standard Running/Commit split), and
agreement holds.

**(c) What the model does *not* show is as important as what it does.** It is a
Dolev–Yao model: perfect cryptography, no probabilities, no cost. It cannot state
the time/memory-tradeoff bound that motivated dropping the symmetric ratchet
(P4), nor any computational reduction. `pcs_root_independence` is therefore the
symbolic shadow of P4's argument — *no derivation path from an old root to a new
one* — and the artefact says so rather than letting a green lemma imply more.

---

## 1. Model ↔ code

| Model rule | Code | Notes |
|---|---|---|
| `Register_key` | `StaticIdentity::generate` | one static KEM key per name |
| `InitHello` | `handshake::initiator_hello` | op A, MEX randomness, `ct_A`, `epk_i`, `ts` |
| `RespHello` | `handshake::responder_identify` + `responder_accept` | ops B/C, `TR`, key schedule, `conf_r`, `conf_i`, `PRE_TAG` |
| `InitConf` | `handshake::initiator_process_resp` | verifies `conf_r` and the tag, then sends `conf_i` |
| `RespConf` | `handshake::responder_process_conf` | verifies `conf_i` |
| `Reveal_Ltk` | the eCK long-term-key oracle | a modelling device, not a code path |
| `Reveal_Session_*` | the P4 epoch oracle (a compromised root) | a modelling device, not a code path |

### Abstractions, each deliberate

| Abstraction | Why | What is lost |
|---|---|---|
| A KEM is public-key encryption of the shared secret: `dec(enc(pk(sk), r), sk) = r` | the standard symbolic KEM encoding; keeps the theory subterm-convergent | no IND-CCA reduction (that is P0's lemma, assumed) |
| The hybrid combiner is `kdf(TR, <rA, rB, rC, psk>)` | the combiner is a PRF over three secrets; symbolically one constructor | the P0 combiner lemma is *not* reproved here |
| `psk = h(<pk_i, pk_r>)` | the UKS fix is public by construction | none — it adds no secrecy, which is the point |
| The peer hint is omitted; the peer name rides in `InitHello` | D11 says the hint is a routing index, not authenticated | nothing symbolic: it protects no key or agreement property |
| `PRE_TAG` is a required pattern `mac(tagkey(rA), <ctB, ctC, confR>)` | matches the code's check: a message without it cannot be matched | the tag's *work-bounding* purpose is a cost argument (P6.8), not a symbolic one |
| `ts` is fresh and bound into `TR` | it is a transcript input | replay prevention itself is P2's guard, not modelled |
| No identity signatures, cookies, shaping, segmentation | each is another phase's obligation | out of scope here; see §5 |

---

## 2. Lemmas and results

Run with Tamarin 1.12.0 / Maude 3.5.1, `+RTS -M3G -RTS`:

```text
/* All wellformedness checks were successful. */
processing time: 20.39s
executable (exists-trace):                     verified (12 steps)
key_secrecy (all-traces):                      verified (25 steps)
key_secrecy_responder (all-traces):            verified (45 steps)
agreement_initiator (all-traces):              verified (17 steps)
agreement_responder (all-traces):              verified (84 steps)
injective_agreement_initiator (all-traces):    verified (2 steps)
pfs (all-traces):                              verified (25 steps)
pcs_root_independence (all-traces):            verified (109 steps)
```

| Lemma | Claim | Honest reading |
|---|---|---|
| `executable` | a run completes | the model is not vacuous |
| `key_secrecy` | a **clean** session key is never derivable | "clean" = neither static revealed, session not revealed. Corruption is not a secrecy claim: with both statics the adversary can forge a session it completes (§0(a)). |
| `key_secrecy_responder` | same, from the responder's commit | symmetric |
| `agreement_initiator` | the initiator's commit implies the responder ran `RespHello` with the same names and key | authentication of the responder |
| `agreement_responder` | the responder's commit implies the initiator ran `InitConf` with the same key | authentication of the initiator |
| `injective_agreement_initiator` | the responder runs at most once per `(I, R, key)` | with the previous lemma: injective agreement; a replay into a second session is impossible because the key term pins the fresh op-B/op-C randomness |
| `pfs` | no static reveal *before* completion ⇒ the key stays secret | forward secrecy; later reveals buy nothing |
| `pcs_root_independence` | revealing epoch *n*'s key does not reveal epoch *n+1*'s | P4's "root independence" in the symbolic sense; the TMTO bound is not symbolic (§5) |

---

## 3. Why the lemmas are phrased the way they are

**"Clean session" is explicit, not implicit.** Tamarin checks a lemma against
*all* traces, including ones where the adversary has every long-term key. A
secrecy lemma that does not exclude corruption is simply false for this protocol
— and correctly so: a holder of both static keys can compute `rA` from op A and
choose `rB`/`rC` itself, producing a session it completes. The lemma names the
exclusion so the claim is precise.

**PFS uses universal absence, not an existential later reveal.** `!Ltk` is
persistent, so `Reveal_Ltk` can fire many times. "There exists a reveal after
completion" is satisfied by a second firing while an earlier firing leaked the
key. The model states `not (Ex #r. RevealLtk(A)@r & #r < #i)` — no reveal before
completion — which is the property PFS actually needs.

**Injective agreement is stated over responder runs.** Two `RunningResp` actions
with the same `(I, R, key)` would have to share the key term, hence the same
fresh `rB`/`rC`, which `Fr` uniqueness forbids. Written this way the prover
discharges it in two steps; written as a uniqueness clause inside the
implication, the search exhausted a 3 GB heap without concluding.

**`pcs_root_independence` also excludes static reveals.** Without that, the
search explores the forged-session branches and times out; the property under
test is epoch independence, and long-term compromise is not part of it.

---

## 4. Running it

The model needs Tamarin and Maude. The native route (no container, no memory
pressure on the host):

```sh
# Tamarin 1.12.0 prebuilt binary + Maude 3.5.1
curl -sLO https://github.com/tamarin-prover/tamarin-prover/releases/download/1.12.0/tamarin-prover-1.12.0-linux64-ubuntu.tar.gz
tar xzf tamarin-prover-1.12.0-linux64-ubuntu.tar.gz
curl -sLO https://github.com/maude-lang/Maude/releases/download/Maude3.5.1/Maude-3.5.1-linux-x86_64.zip
unzip Maude-3.5.1-linux-x86_64.zip -d maude

PATH="$PWD/maude:$PATH" ./tamarin-prover --prove docs/proof/tamarin/vallum.spthy +RTS -M3G -RTS
```

`+RTS -M3G` caps the GHC heap: the injective-agreement search can otherwise
exhaust memory. Per-lemma runs (`--prove=<lemma>`) are the cheap way to iterate.

---

## 5. What this does **not** claim

1. **Not a computational proof.** Dolev–Yao only; no IND-CCA/PRF reductions. The
   KEM and KDF assumptions are P0's and the suite's.
2. **The combiner lemma is assumed, not proved.** `kdf` over the three leg
   secrets is a black box here; the P0 obligation remains the argument.
3. **PCS is root independence, not a TMTO bound.** The symbolic model cannot
   express the time/memory tradeoff that motivates dropping the symmetric chain
   (`ratchet-pcs.md`). The lemma shows there is no derivation path from an old
   root to a new one; the quantitative argument is that document's.
4. **eCK is approximated.** Reveal oracles exist for static keys and session
   keys; there is no ephemeral-reveal oracle, no session-state reveal, and no
   matching of the full eCK-PFS-PSK game. The model is a sanity/agreement model,
   not a re-derivation of P1's computational proof.
5. **No DoS, cookies, timestamps, shaping, segmentation, or identity.** Each is
   another phase's obligation; `PRE_TAG` appears only as the pattern the
   initiator requires.
6. **No claim that the model matches the code byte for byte.** §1 maps rules to
   functions; a wire change must be reflected here by hand.
