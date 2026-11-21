# Device-pull enrolment dogfood — 2026-11-21 (ADR-0049)

Live end-to-end proof of the seamless device-pull flow on `wingman-vps`, with the
ticket sealed to the device's hybrid KEM key (no plaintext code carried by a human).

## Flow exercised

1. **Signup** — `POST /api/signup {code}` → trial account + bearer token.
2. **Device key** — `vallum keygen` on the device; `vallum pubkey` → public line.
3. **Sealed request** — `POST /api/devices {token, name, public_key, seal:true}` →
   `sealed_ticket` + `seal_aad` + `join` + `fingerprint`. **Asserted: no `ticket`,
   no `connect` URI in the response** — only ciphertext leaves the desk.
4. **Open** — `vallum open-ticket --key <device.key> --aad <seal_aad>` → the join
   ticket, opened with the device's KEM secret key.
5. **Enrol** — `vallum join <ticket> --key <device.key>` → `enrolled dogfood —
   10.7.0.3/32`, peer registered server-side.
6. **Connected** — client run in an isolated network namespace: log shows
   `tunnel up on interface vallum-u0004-do` and `peer server established … as
   Initiator`; `ping 10.7.0.1` through the tunnel → **3/3, 0% loss**.

## Negative checks

- CLI round-trip in scratch: wrong-AAD open refused; wrong-key open refused;
  tampered ciphertext refused (seal.rs tests, 7).
- Desk: `seal:true` without `public_key` → 400; `device_cap` still enforced on the
  seal path; unsealed `add_device` unchanged (4 desk tests; full suite 271 green).
- A running client on the server itself is correctly refused (`endpoint … is this
  host's own address — a tunnel cannot carry through itself`); the namespace client
  is a distinct source, so it carries.

## Notes

- The seal is defense-in-depth over verified HTTPS: the desk *mints* the ticket so
  the daemon knows the plaintext, but the desk→device hop carries only ciphertext
  (ADR-0049 §"Ticket delivery"). PQ via the same tri-hybrid KEM the tunnel uses.
- The GUI "add device → connected" auto-button is the remaining UX layer; the CLI
  pieces (`peer invite --seal-aad`, `open-ticket`) and the desk endpoint are in place.
- The Sybil-cost gate for open signup (email-verify / PoW / caps-only) is a separate
  open decision; the existing account/device/IP caps applied unchanged throughout.

Artifacts cleaned: dogfood peer, config/key, signup code, and namespaces removed;
desk healthz green (`database/daemon/enrolment: ok/ok/active`).