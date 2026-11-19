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
   (reproduced). Fixed in `873a984` across quickstart/server/backup/upgrades. Residual friction
   (verified): (a) hidden prerequisites — signed install hard-refuses without `openssh-client`/
   `iproute2`, which the gate pre-installs so PASS never surfaces it (`scripts/install.sh:216-220`,
   `accept-install.sh:69`); (b) the **Connect button burns the single-use ticket without bringing the
   tunnel up** — `vallum-uri.desktop` Exec has no sudo/pkexec, so `join` runs as the desktop user,
   writes config to cwd and skips service install + `prove_tunnel` (`setup.rs:1119-1128`); the invite
   is spent, zero packets, retry needs a fresh ticket; the scheme binding registers only for
   `SUDO_USER` (`install.sh:527-531`), so a root-shell install leaves Connect dead; (c) the enrolment
   responder is opt-in (`--enroll` defaults off, `server.rs:367-370`) and never boot-armed, while the
   desk mints tickets without checking it and `/healthz` checks only DB+daemon — a filtered/stopped
   51821 yields a join timeout whose fixes are operator-only; (d) the invite wall
   (`service/vallum-desk:624-629`). The gates prove components, not the stranger path: `accept-install`
   uses an operator-SSH-minted ticket (no desk/invite/account); `accept-agent-enrol` is a veth netns lab
   (loopback-HTTP desk, pre-placed code, no install.sh/browser/HTTPS front/upstream firewall).
   *Watch for:* a stranger's command failing where the gate passes, or "enrolled" with zero packets
   and a burned ticket.
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
6. **Make Connect actually connect** (1): the deep-link `join` must bring the tunnel up (pkexec
   escalation, or a guided `sudo vallum run` step) without burning the ticket on a no-op; arm the
   enrolment responder by default — or have the desk refuse to mint a ticket when the responder is
   down, and check it in `/healthz`; register the scheme binding for the desktop user, not only
   `SUDO_USER`.

## Before you commit (pre-launch checklist)

- [x] A stranger's documented first command works (the `--` bug fixed, `873a984`; dry-run verified).
- [ ] A real stranger (not the operator) completes install→enrol→tunnel using ONLY the docs.
- [ ] The Connect deep-link brings the tunnel up (not "enrolled" + burned ticket + zero packets);
      the responder is armed when a ticket is minted.
- [ ] An invite-request channel exists and ≥N real strangers are recruited.
- [ ] A feedback/return-usage signal exists; the exit bar includes a desire criterion.
- [ ] README/quickstart state the value in one plain sentence and link `site/`.
- [ ] Shown-once secrets have copy/download + a lost-number recovery path on the login page.

## Progress (2026-11-19 polish pass — "do all")

Done and verified (gate PASS, desk suite 303, deployed to the alpha server):
- **Rev 3 (value legible):** README + quickstart carry the plain-language
  harvest-now-decrypt-later pitch and link `site/` (`f772257`).
- **Rev 4 (account first-run, partial):** shown-once secrets get a no-script
  download + local copy buttons; login/error pages offer a lost-number recovery
  path (`f772257`). **Residual:** the decided `vallum://account` number-handoff
  deep link (ADR-0047) is still unimplemented.
- **Rev 1/2 (channel + desire, partial):** a configurable operator `contact`
  drives an invite-request link + feedback link; `connection_days` (schema v6)
  records distinct return days, surfaced as `days_connected`; the exit bar gains
  **M5** (desire/learning) + a recruitment prerequisite (`f772257`, `67809e5`).
  **Residual:** `contact` is unset on the live desk (operator must set it), and
  recruiting real strangers is an operator action, not code.
- **Rev 6 (Connect connects):** `vallum-uri` routes through the audited
  privileged dispatcher so the ticket buys a working tunnel (root → service +
  proof), with a guided fallback; a trailing-newline bug fixed; responder state
  surfaced in `/healthz` (informational, ADR-0034 started-not-armed); scheme
  binding guidance for root-shell installs (`9b714ad`). 16 URI tests green.

Still open:
- **Rev 5 (crypto trust):** compensating evidence on the trust path + routing SDK
  findings back to the operator — not started.
- **Release parity:** HEAD is 16 commits ahead of v1.10.0; the client-side fixes
  (Connect flow, doctor false-positive, install guidance) reach strangers only
  via a new release. Desk-side changes deploy directly.
- **Live dogfood:** a real stranger completing install→enrol→tunnel end-to-end
  (the gates prove components; the stranger path needs a real cohort).

## Provenance

Six investigators (deleg_fd72fe2d, deleg_dd8a1d1b), all completed; citations spot-checked by the
parent (exit bar, site pitch + README link count, SECURITY.md:29, invite/feedback grep, install.sh:146
arg parse + live dry-run). Mode 1's acute bug was reproduced and fixed before this write-up landed.