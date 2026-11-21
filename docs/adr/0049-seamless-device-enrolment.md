# ADR-0049: Seamless device enrolment — the device pulls its ticket, the human carries nothing

**Date**: 2026-11-20
**Status**: proposed (awaiting operator ratification — two open decisions below)
**Deciders**: operator (Ikaaros) + Hermes agent
**Builds on**: ADR-0047 (account ≠ device), ADR-0046/#28 (verified desk read path), ADR-0013/0044 (machine ticket interface)
**Diagnosed with**: thinking-in-systems (Meadows) + philosophy-of-software-design (Ousterhout)

## Context

The desk is already self-service and abuse-bounded at the *account* level: open
signup, `signup_ip_day_limit=3`, `max_active_accounts=200` (the /24 ceiling),
`device_cap=5`, a 5 GiB anonymous trial, and a reservation TTL. That structure is
sound and stays.

The tedium is the **device last mile**. Today the desk mints a join ticket and shows
a long `vallum1-join:<host>:<port>/<name>/<id>/<token>/<fp>` code; the user carries it
to the device and runs `vallum join`, against a 15-minute TTL. The alpha's
**14 tickets / 0 handshakes** is this structure's output: users installed first and
joined after the code burned. The human is a slow, lossy transport for the module's
internal state.

## Diagnosis

**Systems (Meadows).** Capacity is a finite stock; signup is a flow already governed
by balancing loops (IP throttle, caps, trial bytes) — leave them. The failure is a
*delay in the information flow*: mint → human relay → install → join, TTL ticking
through the relay; delay > TTL → burned codes. Trap: **shifting the burden** (the
human relays the ticket instead of the system delivering it). Leverage: lengthening
the TTL is the weakest rung (a parameter); the high-leverage move is the information
flow + structure — deliver the ticket desk→device directly and **mint it live when the
device is ready**.

**Design (Ousterhout).** The ticket URI is a *shallow interface leaking six internal
fields* to the user — complexity exported upward. Mint→transfer→install→join is
*temporal decomposition* with the TTL as hidden coupling. **Define the error out of
existence:** mint at redeem-time and "expired during transfer" is no longer a possible
state. The deep module is `add_device(account) → connected device`, hiding
mint/redeem/key-pinning/keygen/TTL behind "approve this device."

## Decision (proposed)

**Device-pull.** The client already receives the account via `vallum://account`
(ADR-0047 Q4). Extend it:

1. Client generates its device keypair locally (the private key never leaves it).
2. Client authenticates to the desk with the account token over **verified** HTTPS
   (the ADR-0046 read path) and requests a device ticket, sending its **public line**.
3. Desk checks the account is active, under `device_cap`, and within the rate/capacity
   gates; mints a ticket **pinned to that public line** (the existing
   `mint_ticket(peer, public_key=…)` path), single-use, reserving a slot.
4. Desk returns the ticket over the same verified channel; the client **redeems it
   immediately** against the enrolment responder. No code is shown, copied, or typed.

Interface the user sees: **Add device → approve → connected.** The long code and the
TTL-burn error class both disappear. The ticket flows system-to-system; the human
approves, never transports.

### Design-it-twice (the alternative considered)

- **A — short pairing code / QR:** device and desk pair via a short code; the ticket
  then flows system-to-system. Removes the *long* code but keeps a manual pairing step
  and a pairing window. Less seamless than B; useful fallback where the client cannot
  reach the desk directly.
- **B — device-pull (chosen):** zero code; the client pulls and redeems live. Requires
  the client to reach the desk (it already does for the account read).
- **C — OCRA-derived signup code (considered, rejected):** the operator proposed using
  the SDK's OCRA (OriginSDK `src/ocra.rs`, RFC 6287; HOTP also present in `src/drbg/otp.rs`)
  to generate a short code at signup. Rejected: OCRA is challenge–response and requires a
  pre-shared key `K` both sides hold; enrolment is the act of *establishing* that key, so
  the device holds nothing and cannot compute/verify a response. An OCRA-derived signup
  code therefore collapses to a bearer token the desk looks up — identical to a random
  code, with more machinery and no added security. OCRA fits post-enrolment step-up auth,
  not bootstrap. If a human-transferable code is wanted (fallback A), use a **CSPRNG**
  8+ digit code, single-use, short-TTL, burn-after-N-failures, bound to account + device
  public line; the security is entropy + rate-limit + binding, not the derivation.

## Abuse resistance — bounded, not "impervious"

The existing gates bound every axis an anonymous visitor can push (capacity, IP/day,
device cap, trial bytes, reservation TTL). Live-mint adds: authentication (account
token), key-pinning (no ticket theft/replay), single-use, and **no pre-minted stock to
steal**.

Honest limit: *impervious* is asymptotic. A compromised account can enrol up to its
`device_cap`; a distributed botnet can consume `max_active_accounts`. The caps **bound
the damage; they do not make abuse impossible.** The lever that actually raises Sybil
cost is a **cost-per-account** (open decision 2).

## Open decisions (awaiting ratification)

1. **Seamless mechanism:** B device-pull (recommended) vs A short pairing code vs
   keep-the-long-code-fix-TTL.
2. **Abuse cost gate for open signup:** email verification per account (recommended for
   a free alpha — raises Sybil cost, low friction; needs SMTP), proof-of-work per signup
   (no identity, compute cost, harder on mobile), keep current caps only (alpha), or
   paid/invite-only (strongest, but not open self-service). The `plan`/`paid_until`
   boundary already exists for the paid path.

## Consequences

- The desk gains an authenticated `request_device_ticket` endpoint (account token +
  public line → pinned ticket); the GUI/CLI gains a live "add device" that pulls and
  redeems. The `vallum join <long-code>` path remains for the manual/SSH/bundle cases.
- The 15-minute TTL stops being a user-facing hazard: a ticket exists only between
  request and immediate redeem. The reservation TTL still bounds a slow redeem.
- No change to the account-level abuse gates; the cost-per-account gate (decision 2) is
  additive at signup.
- Security review focus: the request endpoint must authenticate the account, enforce
  device_cap/rate limits server-side, pin the ticket to the supplied public line, and
  never return a ticket for an account the caller does not own.