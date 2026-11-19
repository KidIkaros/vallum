# Premortem: the Vallum validation alpha (does the idea validate, not "is it ready to run")

**Date:** 2026-11-19 · **Frame:** it is May 2027; the validation alpha has failed.
**Method:** Klein premortem, six parallel investigators, citations verified against the
freshest code per `premortem/references/codebase-premortems.md`. This is distinct from
`premortem-alpha-verification.md` (which premortemed the *verification system*); this one
premortems the *validation itself*.

**What success means here:** the alpha tells the operator whether a real stranger *wants and
uses* a post-quantum VPN with this no-PII account model — enough to decide whether to pursue
the project. Failure is not "the service fell over"; it is "the cohort never engaged, or the
operator learned nothing about desire."

## Synthesis

**Most likely failure — no cohort, no desire signal.** Every stranger-facing path terminates
at an operator-only gate with no request channel, and nothing captures whether a joiner
*wants* the product or why they leave. The alpha can only be exercised by the operator, so it
produces a demo, not demand signal.

**Most dangerous failure — the experimental crypto undercuts the core promise.** The pitch is
post-quantum security, but every leg (X25519, the HKDF combiner, the AEAD, the RNG, signatures)
comes from one unaudited SDK. Hybrid composition diversifies *algorithm* risk, not
*implementation* risk: one SDK bug in KDF/RNG/AEAD defeats all three legs at once. The security
process routes SDK findings upstream, away from the operator, so the validation never learns
about the exact claim it rests on.

**Hidden assumption — "a correct, well-gated, deployable tunnel is what needs validating."**
The idea to validate is whether people *want* a PQ VPN with a no-PII account model. Operational
correctness does not answer desire. All six modes share one shape: the artefact records
operational intent, but no actor performs the validation — recruit strangers, capture desire,
make the value legible. The polish went into making it *work*, not into learning whether it is
*wanted*.

## Failure modes (cited; verified)

1. **Stranger first-run friction** *(acute symptom FIXED)* — the documented first command
   `install.sh -- --from-release --install-only` hard-failed: `--` is the server-passthrough
   separator (`scripts/install.sh:146`), so MODE stayed `local` → "no local build found", exit 1
   (reproduced). Fixed in `873a984` across quickstart/server/backup/upgrades. Residual friction:
   hidden prerequisites (`openssh-client`, UDP 51820 **and** 51821), the invite wall
   (`service/vallum-desk:624-629`). *Watch for:* a stranger's first command failing where the gate
   passes — the gate invokes the installer correctly, the docs did not.
2. **Measures operations, not desire** *(most likely, with 6)* — the exit bar is M1 conversion +
   M2-M4 capacity/restore/replay (`docs/qa/alpha-exit-bar-2026-11-19.md:16-31`); its purpose is
   "the alpha proves the protocol and harness work" (:7-8). The funnel records only signup /
   add_device POST outcomes with HTTP-class refusal reasons (`service/vallum-desk:602-603,861-862`);
   a reader who leaves generates no event; no feedback channel exists (grep: zero); return usage is
   unmeasurable ("handshaked" = live+offline snapshot, :1127,1717-1728). Every drop-off is framed
   as a bug to fix (`packaging/vallum-alerts.yml:406-420`), never a preference to learn.
   *Watch for:* an exit-bar review with only M1-M4 numbers and zero statements about why users stayed.
3. **PQ value illegible** — the one legible pitch, "A tunnel built for the day the quantum computer
   arrives," lives only in `site/index.html:27`, which the README never links (grep: 0). The README
   leads with mechanism (X25519+sntrup761+ML-KEM-768, :60-61) and a five-author paper citation
   (:118-124); no "quantum computer / harvest / decrypt later" anywhere in README; Tailscale: zero
   mentions. The only plain-language security message is "experimental, don't trust it" — risk
   legible, benefit invisible. *Watch for:* strangers asking "what does post-quantum do for me?"
4. **Account-model churn** — signup shows TWO shown-once secrets (32-hex number + 16-hex recovery
   code) in bare `<pre>`, no copy/download/confirm (`service/vallum-desk:1863-1902`); closing the tab
   loses them. Login is paste-32-hex with no "lost your number?" link; a wrong/lost number → 404 →
   "Try again" → signup, but the invite code is burned (:641) — a dead-end loop (:2021-2033).
   Recovery is admin-gated CLI only, out-of-band, via a channel the desk never shows (:1462,1584).
   The decided `vallum://account` deep link (ADR-0047:125-128) is unimplemented. *Watch for:* failed
   account opens (invisible to the funnel) and lost-number support requests with no channel.
5. **Experimental crypto undercuts the promise** *(most dangerous)* — all legs + combiner KDF + AEAD
   + RNG share one SDK (`crates/vallum-crypto-sdk/src/lib.rs:24-30`); the combiner's security lemma is
   conditioned on the KDF not failing (`crates/vallum-crypto/src/kem.rs:36-38`), and that KDF is SDK
   code. Fallback suites 0x0001/0x0002 ride the same SDK (:16-17,84-95). SECURITY.md:29 routes SDK
   findings to another repo; the trust journey terminates in a disclaimer, not assurance.
   *Watch for:* validator crypto-trust issues closed "out of scope, report upstream" with no follow-through.
6. **No real cohort** *(most likely, with 2)* — `open_signup` defaults False; a code-less stranger
   gets 403 "ask the operator" (`service/vallum-desk:624-629,499`), presupposing a relationship with
   no channel to form it. The site CTA's only escape is "run your own desk" (`site/index.html:35-36`).
   Codes mint only via admin token, distributed out-of-band; the named cohort is a "colleague cohort"
   (`docs/qa/alpha-production-plan-2026-11-19.md:13`). Both quickstarts end at `sudo vallum peer invite
   laptop` — the operator inviting their own device (`docs/quickstart.md:115`, `README.md:200`).
   *Watch for:* the exit bar's "over the cohort" measured entirely on the operator's own devices.

## Revised plan (concrete, this week; each maps to a mode)

1. **Open a request channel + recruit real strangers** (6, 1): add an invite-request path (form or
   mailto) on the desk landing and site; define where strangers discover Vallum; recruit ≥N genuine
   strangers (not colleagues). Add an exit criterion: ≥N stranger arrivals, not operator devices.
2. **Capture desire, not just conversion** (2): add a feedback channel (mailto/form) on desk + site;
   measure return usage (distinct days connected per account); reframe the exit bar to ask "why did
   they stay/leave," and add "≥N strangers can state why they want it."
3. **Make the value legible** (3): bring the site's one-sentence pitch into the README + quickstart;
   link `site/` from the README; add a plain-language "why over WireGuard/Tailscale" (harvest-now-
   decrypt-later) sentence at first hands-on contact.
4. **Soften the account first-run** (4): copy button + download for the shown-once secrets; a
   "lost your number?" recovery-code field on the login page; implement the decided `vallum://account`
   deep link (ADR-0047) so the number hands itself to the client.
5. **Compensating evidence + a crypto feedback loop** (5): surface the self-conducted pentest summary
   and a plain-language hybrid rationale on the trust path; route SDK findings back to the operator
   (not only upstream) so the validation learns about crypto trust.

## Before you commit (pre-launch checklist)

- [x] A stranger's documented first command works (the `--` bug fixed, `873a984`; dry-run verified).
- [ ] A real stranger (not the operator) completes install→enrol→tunnel using ONLY the docs.
- [ ] An invite-request channel exists and ≥N real strangers are recruited.
- [ ] A feedback/return-usage signal exists; the exit bar includes a desire criterion.
- [ ] README/quickstart state the value in one plain sentence and link `site/`.
- [ ] Shown-once secrets have copy/download + a lost-number recovery path on the login page.

## Provenance

Six investigators (deleg_fd72fe2d, deleg_dd8a1d1b), all completed; citations spot-checked by the
parent (exit bar, site pitch + README link count, SECURITY.md:29, invite/feedback grep, install.sh:146
arg parse + live dry-run). Mode 1's acute bug was reproduced and fixed before this write-up landed.