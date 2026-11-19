# ADR-0047: The account is not the device; the daemon owns the physical truth

**Date**: 2026-11-19
**Status**: proposed (spine decided in discussion; open questions await operator ratification)
**Deciders**: operator (Ikaaros) + Hermes agent, from the 2026-11-18/19 architecture audit

## Context

The desk's web signup conflates two acts: creating an **account** and enroling the first
**device** — it asks for a device name and mints a device ticket in the same request
(`service/vallum-desk:404–473`). A read-only audit (three investigators, 2026-11-18) showed
the *data model* is already separated (`accounts` 1—N `peers`, `:81–88`; a device is a row
keyed by a stable name `u####-label`; rotation mutates key material in place under that name,
`config_edit.rs:237–283`, `device/mod.rs:617–619`). The conflation is in the **flow**, not the
model. Three forces push a redesign:

1. **Freedom.** A per-account device cap mistaken for a physical law feels tyrannical. The
   real limit is **server capacity** — hardware-bound, scales with the box — not policy.
   WireGuard lets a user enrol phone/laptop/desktop freely; Vallum should not be stricter.
2. **The 0/14 conversion failure.** A web-minted ticket (15-min TTL, `enroll.rs:87`) expires
   during the install gap before the client joins. The durable account, not the ephemeral
   ticket, must be the centre of the flow.
3. **A service for strangers.** The goal is an on-demand VPN for humans *and agents*, which
   others self-host and monetize. That needs multi-tenant isolation, an agent device
   lifecycle, and operator-independent branding — none of which a personal-tunnel
   architecture provides.

## Decision

1. **Daemon is the source of truth** for peer existence and server capacity. The desk owns
   account *policy* and reconciles its device count against `vallum show --json` (which it
   already calls for counters, `:263–267`). The desk's `peers` table holds *pending
   reservations* + labels, not an independent claim of reality.
2. **Two limits, two layers.** *Server capacity* (daemon/resource): address pool (`/20`=4094,
   config-driven), handshake CPU (~2000 peers default suite, measured), single-thread data
   plane, memory (8.9 KB/peer). Enforced race-free at allocation (`peer.rs:1138–1143`, "no
   free address left"); scales with hardware. *Account device cap* (desk/policy): a plan
   attribute, optional, operator-set for paid tiers; never below the physical ceiling.
3. **Account ≠ device in the flow.** Web signup creates an account only (code → token; no
   device name on the web, ever). Devices enrol **client-driven, on demand**: client keygens
   locally (custody, ADR-0013) → presents public line + label + token to `POST /api/devices`
   → desk authenticates, counts against the policy cap (the reservation row is atomic,
   `:544–566`), mints a **pinned** single-use invite (`peer invite --public-key`,
   `peer.rs:766–773,810–834`) → client joins, names its *local* config; the server enrols
   under the stable `u####` identity. Each device gets its **own** pinned invite — preserving
   the single-use invariant (`enroll.rs:1185–1191`); no reusable account-bound ticket.
4. **Rotation preserves the slot.** `peer rotate <name> --public-key <client line>` (custody
   preserved; server-generation is an explicit `--ship-key` opt-in) under the stable name,
   then `finalize`. The desk gains a rotation endpoint; rotation is never `add_device`.
5. **Tenancy mode is first-class.** *Personal* = flat (devices reach each other — a feature).
   *Service* = per-account isolated (strangers must not reach each other). Isolation is opt-in
   and must not break the flat personal default (`accept-pair` stays green).

## Alternatives Considered

### Alternative 1: Account-bound reusable ticket (one ticket enrols many devices)
- **Pros**: one capability per account; simple client.
- **Cons**: breaks the single-use invariant — `decide_invite` refuses a second device's
  different key (`enroll.rs:1189`); needs per-device spend state and a wire change.
- **Why not**: fights the protocol's own seam. Per-device pinned invites reuse the existing
  single-use + pin machinery unchanged.

### Alternative 2: Desk reservation table stays authoritative (no daemon reconciliation)
- **Pros**: less new code; the cap is already race-free within one desk process.
- **Cons**: two stores (desk SQLite + daemon config) diverge on failed joins, desk-free CLI
  changes, crashes; a permanent special-case factory; ghost reservations burn the cap.
- **Why not**: the load-bearing assumption "desk count == daemon peers" is false. Deriving
  from the daemon defines the split-brain error out of existence (deep module).

### Alternative 3: Keep device-name-at-signup, patch the TTL (warn + recovery only)
- **Pros**: smallest change.
- **Cons**: shifting-the-burden — treats the symptom (expiry) not the structure (the flow
  centres the ephemeral ticket); the device-name decision still has no clean owner.
- **Why not**: the 0/14 failure is structural; a parameter tweak cannot fix a loop whose
  delay (install time) exceeds the ticket's life.

## Consequences

### Positive
- WireGuard-parity freedom: devices enrol on demand up to capacity; the desk counts, it does
  not approve names. The pin even improves security (a stolen token enrols nothing without
  the matching private key).
- The TTL race is defined out of existence: the client is installed before it enrols; the
  invite is minted + joined immediately; the durable account re-derives tickets freely.
- Rotation no longer risks burning the cap (identity is the stable name/slot, never the key).
- A clean personal-vs-service spine makes the white-label service goal architecturally honest.

### Negative
- The desk queries the daemon on the enrolment path (latency; behaviour when the daemon is
  unreachable must be defined — fail-closed).
- A schema migration (legacy `accounts.peer` first-device column, `:560–561`) and a new
  client "enrol this device" flow are required.
- The web→client handoff changes: signup returns a token, not a ticket+connect URI; the token
  delivery to the client needs a specified flow.

### Risks
- **Multi-tenant isolation is un-designed** (flat `/20` today; `accept-pair` proves peer↔peer
  flows). Mitigation: opt-in service-mode isolation + a dedicated gate before the service tier.
- **Agent device lifecycle** mismatches the durable-device model (ephemeral agents strand
  reservations). Mitigation: an agent device class / auto-expiring slots — open question.
- **Account token has no lifecycle** (no rotation/recovery; lost = lockout). Open question for
  a paid service.
- **Vertical-only scaling** (single-thread data plane); horizontal scaling un-designed. State
  the single-server capacity model honestly; name multi-server as future.

## Open questions (await operator ratification — do NOT decide unilaterally)
1. Tenancy isolation mechanism: per-account subnets vs nft tunnel→tunnel drop keyed by account.
2. Agent device class: ephemeral/auto-expiring slots vs a separate agent quota.
3. Account token lifecycle: rotation/recovery vs the PII-free no-recovery stance (ADR-0045).
4. Web→client token handoff: shown-once vs a `vallum://account` URI.
5. Protocol wire-versioning rule for adding enrolment fields without breaking old clients.
