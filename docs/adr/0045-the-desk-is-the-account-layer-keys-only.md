# ADR-0045: The desk is the account layer — keys-only, Mullvad-shaped

**Date**: 2026-11-16
**Status**: accepted
**Deciders**: operator

## Context

The alpha proved the desk can serve a stranger end to end, but the flow was
bare: a signup handed out a ticket string and nothing else. The beta question
was what the service layer grows into — and which model of "account" it
adopts. The operator's stated direction: a self-hostable service layer other
operators can deploy, with identity, promo codes, durations, and a real
connection between the webpage and the client.

Mullvad's published architecture (`mullvadvpn-app`, GPL — used here as a
*model*, no code copied) supplies the reference shape: a 16-digit account
number IS the credential (no email, no password, no PII); the server keeps
account rows (expiry, devices) keyed by it; `submit-voucher` extends an
existing account; `www-auth-token` bridges client → webpage.

## Decision

**Keys-only identity.** The account *token* — which the desk already mints —
is the credential, in the Mullvad account-number role. No email, no password,
no person table: the server cannot distinguish "one person, two devices" from
"two people", and does not try. The token rides into the sealed client config
(new field) so the client can reach its account page after join.

**One token holds N device peers.** The strict `1 account = 1 peer` shape
becomes 1:N — a `peers` relation under the account, a device cap (default 5,
operator-configurable), and an add-device endpoint (`POST /api/devices`,
bearer-token auth) that mints a ticket bound to the existing account's plan
and expiry. `bytes_cap` is a **shared pool** across the account's peers — the
plan is an account attribute, not a per-device one.

**Codes carry plans, and vouchers ship now.** The `codes` table gains payload
columns (days, byte cap, plan label); a code consumed at signup overrides the
trial defaults. `POST /api/voucher` (bearer-token auth) applies an unused code
to an existing account — Mullvad's `submit-voucher` shape — extending expiry
and bytes. Single-use codes only; public multi-use codes were rejected.

**`vallum://` deep link, layered.** The ticket page gains a Connect button
emitting `vallum://join?ticket=<t>&account=<token>` — the account token rides
in the URI, never the enrolment wire (ADR-0044's boundary holds: the
responder stays ignorant of desk accounts). Baseline handler: a packaged
`x-scheme-handler/vallum` desktop entry that execs `vallum join`, working
with no GUI. `vallum-gui` takes over the scheme when installed, handling join
in-app.

**The desk is a self-hostable product, operated by us first.** Operator UX =
a shipped `vallum-desk-admin` CLI wrapping the admin API (mint codes with
payloads, list accounts, set plans, revoke) — not curl recipes, not an admin
web panel. Page design = functional polish: install block, Connect button,
the token shown as "your account number", an account page with
expiry/devices/voucher; branding is an operator-name config string, not a
redesign.

## Alternatives Considered

### Alternative 1: Person-level identity (login/email → many accounts)
- **Pros**: real multi-device identity, password recovery, the shape most
  commercial VPNs use
- **Cons**: collects PII, builds authentication machinery, and breaks the
  property that the desk knows nothing about its users
- **Why not**: keys-only was chosen explicitly — the Mullvad account number
  proves a credential can be PII-free and still carry plans, devices and
  expiry

### Alternative 2: Stateless ticket mint (no accounts at all)
- **Pros**: smallest service surface; nothing to secure but ticket issuance
- **Cons**: makes plans, expiry, caps and vouchers impossible — no state to
  enforce them against; directly contradicts the chosen code/duration work
- **Why not**: the beta explicitly wants plan semantics; "keys-only" means a
  key-shaped *credential*, not the absence of server state

### Alternative 3: Public multi-use codes (e.g. LAUNCH26)
- **Pros**: marketing-friendly; one code spreads far
- **Cons**: a leaked code is an unbounded signup faucet; per-code payload
  already covers the promo use case with traceable redemptions
- **Why not**: operator chose payload-carrying single-use codes; multi-use
  can be a later column (`max_uses`) if ever wanted

### Alternative 4: Ticket replay for extra devices
- **Pros**: no new endpoint — reuse the original join ticket per device
- **Cons**: a leaked ticket means unlimited peers on your account, forever
- **Why not**: the add-device endpoint binds each new peer to the account at
  mint time, keeping single-use semantics per ticket

## Consequences

### Positive
- The desk gains a real account model with zero PII: no auth machinery beyond
  the bearer token that already exists
- `vallum://` closes the last gap in the stranger flow: webpage → installed
  client in one click, with a paste fallback everywhere
- Codes-with-payload + vouchers give the operator a promo/top-up surface
  without building payments
- Admin CLI makes the desk operable by strangers who deploy it — the
  self-hostable product goal — with no new daemon API (ADR-0013/0044 hold:
  everything is still `vallum` subprocesses + the desk's own HTTP)

### Negative
- Schema migration: `accounts`/`codes` gain columns and `peers` becomes its
  own table; existing `desk.sqlite` files need a migrate step on upgrade
- The account token in the sealed config is a second credential in the file —
  same custody rules as the key, but one more thing `0600` must protect
- N peers per account widens one credential's blast radius: a leaked token
  exposes every device slot

### Risks
- The `vallum://` handler is OS-integration that differs per desktop
  environment; the CLI desktop entry is the guaranteed baseline and the GUI
  takeover is progressive enhancement, never a hard dependency
- URI-carried tokens can leak through browser history/referrers; the ticket
  page must keep the full URI behind the Connect button (not in `href` on a
  visible anchor that leaks via prefetch) and documents the paste path
