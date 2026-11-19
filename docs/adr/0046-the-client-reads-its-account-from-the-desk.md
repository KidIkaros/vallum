# ADR-0046: The client reads its account from the desk

**Date**: 2026-11-18
**Status**: accepted
**Deciders**: operator + Hermes (grilling session, 2026-11-18)

## Context

The desk mints bearer account tokens and already serves full account state
(`/api/account`: plan, status, expires, bytes_cap, bytes_used, devices,
conversion). The token already lands in the client config's `[account]` table
at join (written 0600), but that table holds **only the token — no desk
endpoint** — and no CLI verb, TUI panel, or GUI view ever reads it back. A user
whose account expires or hits its byte cap sees only `stale`/`degraded`, and
`doctor` advises "Re-enrol with `vallum peer add`" — a server-side verb an
invite-code user cannot run. The alpha enrols via invite codes at a public desk
and ships the CLI + TUI + UTCP manual, not the console (ADR-0039); the account
reference must reach the surfaces that actually ship.

## Decision

The client reads account state **directly from the desk over HTTPS**, using the
bearer token already stored in `[account]`. The `[account]` table gains an
`endpoint` field, recorded at join from the desk origin carried in the
`vallum://` connect URI (`desk=<origin>`). A new `vallum account` verb and a TUI
panel render the desk's `/api/account` response. The daemon stays
account-ignorant — ADR-0044 and ADR-0045 are unchanged. The read is
**best-effort**: a desk that cannot be reached renders `unknown`, never a
confident false state (the same discipline as the desk's own `bytes_used`).

## Alternatives Considered

### Alternative 1: Link-out only (no API call)
- **Pros**: no new network edge; the simplest change; the client just opens the account page.
- **Cons**: the bearer token never travels in a URL (the desk's own security rule), so the user must re-enter their token on the page; no inline usage/expiry; a failure hint cannot show actual state.
- **Why not**: the token is already on disk; re-entering it is friction the alpha's 0/14 ticket→handshake conversion cannot afford.

### Alternative 2: The desk pushes account state into the peer record / config
- **Pros**: the client reads local state; no desk call at read time.
- **Cons**: violates ADR-0044 (the desk is a third party; the daemon has no account concept) and ADR-0013 (no control plane); couples the daemon to the desk; pushed state goes stale between pushes.
- **Why not**: it re-introduces the control-plane coupling two accepted ADRs deliberately refused.

## Consequences

### Positive
- Account state reaches every shipping surface from one read path; expiry/quota failures become explainable ("your account expired — see desk.wingman.gold/account") instead of misattributed to a stale config.
- The token's only network use is to its own desk, over TLS.

### Negative
- A new client→desk trust edge: the client now makes an HTTPS call the daemon never made.
- `[account].endpoint` is a new config field; `deny_unknown_fields` means a binary older than this field refuses a config carrying it — the same documented compatibility cost as the token field itself.
- The connect URI gains a `desk=` param; old clients ignore it, and the desk still emits `ticket` + `account`.

### Risks
- **Token exposure** — mitigated: the token stays 0600 on disk, is sent only to the recorded endpoint over HTTPS, never in a URL or log (support-bundle redaction already covers it).
- **A malicious desk origin in the URI could phish the token** — mitigated: the endpoint is recorded once at join from the desk the user enrolled through, and `vallum account` shows the endpoint it is calling, so the user can see where their token goes.
