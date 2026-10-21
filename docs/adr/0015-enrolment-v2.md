# ADR-0015: Enrolment v2 — the PQ-WireGuard shape, applied to provisioning

**Status:** accepted · **Date:** 2026-10-21

## Context

`docs/proof/enroll-adversary.md` recorded ten findings against the token
enrolment channel added the day before. Five were already fixed or by design;
the rest shared one root cause: **enrolment did not have the cryptographic
shape of the tunnel handshake.** It derived keys as `kdf(token, nonce)` — a
long-term secret alone — carried the peer name in the clear, had no pre-crypto
admission check, and gave no way for a client to know which server it was
talking to.

Meanwhile the tunnel itself already implements the construction from
*Post-quantum WireGuard* (Hülsing, Ning, Schwabe, Weber, Zimmermann, 2023),
Algorithm 2:

| Paper | Vallum |
|---|---|
| `KDF1(σ, r)` mixing long-term secret with fresh randomness (MEX defence) | `handshake/keyschedule.rs` `mex_randomness` |
| `psk = H(spk_i ⊕ spk_r)` default (unknown-keyshare defence) | `handshake/keyschedule.rs` psk mix |
| `m1 = MAC(H(lbl3‖spk_r), …)` pre-crypto admission | `handshake/admission.rs` `PRE_TAG` |
| `m2 = MAC(cookie, …)` anti-spoof | `core/src/cookie.rs` `CookieSecret` |
| explicit `InitConf` | `CONFIRMATION` TLV |
| identity hiding by hashing the static key | `handshake/hint.rs` `PEER_HINT` |

So the decision is not to invent cryptography. It is to apply the same shape
to the one exchange that lacked it.

## Decision

Enrolment becomes a four-message exchange on the existing `listen + 1` port,
framed `VEN2`:

1. `HELLO` — `invite_id(16) | client_nonce(24) | ephemeral KEM pk | public_line
   | [cookie(16)] | admission_tag(32)`
2. `COOKIE` — a cookie bound to the source address, issued **before** any
   invite lookup or KEM work
3. `HELLO` again, with the cookie
4. `REPLY` — `server_nonce(24) | KEM ct | sealed payload`, where
   `K = KDF(salt = nonces, ikm = frame(token, ss), info = "vallum-enroll/v2/reply")`
   and the AEAD's AD binds `invite_id ‖ client_nonce`

### Why each piece

- **Invite id, not name.** The server cannot find the invite without a lookup
  key, and the lookup key must be on the wire. Making it an opaque 16-byte id
  means the peer name never leaves the server — finding #5 — and the AEAD's AD
  binds the seal to the id, so a captured seal fails under another one.
- **Cookie before work.** A spoofed source cannot receive the cookie, so it
  never reaches an invite read or an encapsulation — finding #4. This is the
  paper's `m2`, reusing `CookieSecret` unchanged.
- **Admission tag under the token.** One KDF, no filesystem, rejects anyone
  without the token before the KEM — the paper's `m1` role, keyed by the token
  rather than the static key because the client has no static key yet.
- **Ephemeral KEM + `KDF(token ‖ ss)`.** This is `KDF1(σ, r)` with σ = token
  and r = the ephemeral shared secret: forward secrecy (ss is destroyed, so a
  later token compromise cannot open a recorded reply) *and* MEX resistance (a
  subverted client RNG leaves the attacker without the token). Finding #6.
- **Pinned invites.** `peer invite --public-key` binds the invite to the line
  the client generated; a stolen token then enrols nothing, because the
  attacker lacks the private key. Finding #2 becomes "mitigated".
- **`--expect <fingerprint>`.** The invite line is a human channel; printing
  the server's fingerprint there lets the client refuse a lying server. This
  closes the gap the review explicitly listed as uncovered.

## Alternatives rejected

- **Reuse the handshake message types for enrolment.** Superficially tidy, but
  it would mean a handshake parser in a second process with no session, and it
  would couple a provisioning exchange to the tunnel wire format's evolution.
- **A second listening port with TLS.** New dependency, new certificate story,
  new failure mode; and it solves authentication we already have via the token.
- **Forward secrecy via a full static KEM handshake.** The client has no static
  key before enrolment; a static leg would require provisioning the very thing
  enrolment exists to provision.
- **Keep v1 alongside v2.** Nothing is deployed; a dual parser doubles the
  surface of the one component that must not be buggy.

## Consequences

- Enrolment costs two round trips and a ~7 KiB request. Acceptable: it happens
  once per device.
- The responder performs one KEM encapsulation per *legitimate* enrolment, and
  none for junk.
- The invite file now holds the config in plaintext (it already held the token);
  it is `0600` in `/run/vallum`, so it dies with the machine.
- Breaking the wire is deliberate: a `VEN1` client is told to upgrade rather
  than silently timing out.
