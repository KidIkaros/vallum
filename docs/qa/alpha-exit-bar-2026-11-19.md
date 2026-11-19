# Alpha exit bar — pre-registered 2026-11-19

**Window:** two weeks, 2026-11-19 → 2026-12-03.
**Enrolment:** single-use invite codes at `desk.wingman.gold`, closed mode
(operator distributes codes out-of-band; 20 minted at start, 14-day / 50 GiB
trial payload). **Posture:** the desk is the enrolment front, not a service
launch — the alpha proves the protocol and harness work AND whether real
strangers want a post-quantum VPN with this account model. Operational
correctness (M1–M4) is necessary but not sufficient: M5 asks whether the idea
validates (validation premortem 2026-11-19). (ADR-0039, ADR-0044, ADR-0046,
`CONTEXT.md` "Alpha").

Every number below is **measured (with source) or explicitly marked unmeasured**
(`docs/requirements.md` discipline). A criterion that cannot fail is not a
criterion.

## Exit criteria

- **M1 — Conversion.** Ticket→handshake within the 15-minute TTL **≥ 50%** over
  the cohort. Baseline was **0/14** (open experiment, 2026-11-16); the cause
  (install-first, expired ticket, burned code) is fixed by #27. Source:
  `vallum_alpha_handshaked_devices` against tickets issued. If < 50%, the path is
  diagnosed and fixed before beta — the alpha's purpose is to learn this.
- **M2 — Ceiling behavior.** The account cap (200) and the address pool
  (`/20` = 4,094 devices) refusal paths are **exercised and recorded**, not
  discovered by a stranger. Source: the 503 "at capacity" and address-exhaustion
  paths, hit deliberately in the harness.
- **M3 — Reliability under load.** `/healthz` answers 200 sustained; the backup
  timer fires daily and the off-host pull lands a valid copy; **one restore drill
  recorded as a signed verdict** (`accept-desk-restore`); the restart window is
  measured at the actual peer count (quote the 110–160 s range or neither).
- **M4 — Adversarial floor.** Cookie-gate behavior under a bounded fragment
  replay is measured **locally** (`references/capacity.md` §8), never on the live
  box. The amplifier cost and the admission-placement lever are recorded.
- **M5 — Desire and learning (validation).** The alpha must produce demand
  signal, not just a working demo:
  - **≥ 5 real strangers** (not the operator, not colleagues) request an invite
    via the desk's request channel and enrol. Source: the contact channel +
    `signup_ip` attribution (distinct origins, not one laptop).
  - **Return usage:** ≥ 2 stranger accounts connect on ≥ 2 distinct days
    (`connection_days`), so "wanted" is measured by coming back, not one join.
  - **Why:** ≥ 3 strangers can state why they want a PQ VPN (feedback channel),
    and every drop-off has a captured reason — a preference to learn, not only a
    bug to fix. If strangers cannot say why they want it, the value pitch
    (README/site) is the defect, not the stranger.

## Safety net — must be live before the clock starts

- [x] Pager: vmalert → Alertmanager → ntfy (delivery proven; caught 3 failed units day one).
- [x] Off-host backup: host timer + laptop pull (valid SQLite copies proven).
- [x] Host health: 0 failed units; tunnel carrying; NAT masquerade widened to /20.
- [x] Gate of record: `scripts/verify.sh` PASS on main.
- [x] Two-host stamp fresh at the release commit (`verify-remote` at aff6a37, 42 assertions, signed).
- [x] Signed restore-drill verdict at the release commit (`accept-desk-restore`, 8 assertions).
- [ ] Recruitment: the desk request channel live (`contact` set) and a defined
      step for where strangers discover Vallum; the cohort is strangers, not the
      operator's own devices (validation premortem mode 6).

## Out of scope for the alpha (beta or later)

GUI account card (the console does not ship — ADR-0039); the desk endpoint across
sudo (#32 — fixed); enrolment-front TLS decision (#31); per-app split; L4 carriers; any
uptime SLA (the requirement is failure behavior, not uptime — `requirements.md`).

Deviations are recorded with a reason, never silent.
