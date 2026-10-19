# H8 — identity-document validity

**Status:** closes P3's "identity documents have no revocation/expiry" — the
expiry half. Revocation remains out of scope, and this document says why.
**Depends on:** P3 (`docs/proof/hybrid-identity.md`) for the document this
extends.
**Wire change:** the **out-of-band** identity document only. No handshake message,
no transcript, no frozen vector moves.

---

## 1. The gap

An `IdentityDocument` was a signature over `(label, kem_pk, sign_pk)` with no
time in it. Once issued it was valid forever, so a key that should have been
retired could be presented indefinitely and there was no way to say "this binding
was true in 2026 and is not in 2027".

---

## 2. The format

Two new TLV fields inside the signed body:

| tag | field | width | meaning |
|---|---|---|---|
| `0x0024` | `NOT_BEFORE` | 8, BE | first second the document is valid (inclusive) |
| `0x0025` | `NOT_AFTER` | 8, BE | first second it is **not** valid (exclusive) |

- Unix seconds. The core stays clock-free: `is_valid_at(suite, issuer, now_unix)`
  and `to_peer(suite, issuer, now_unix)` take the time from the caller, exactly as
  the handshake takes a caller-supplied `Tai64n`.
- The signature covers both fields (they are part of `signature_input`), so a
  window cannot be extended without the issuer's key.
- `Validity::new(not_before, not_after)`; `contains(now)` is
  `not_before <= now < not_after`, the TLS convention.
- **Both fields are required on decode.** There are no deployed documents
  (pre-1.0), so the fail-closed choice costs nothing: absence is refused rather
  than read as "valid forever", which would be the weakest possible default.
- `to_peer` distinguishes the failure: `IdentityInvalid` (signature),
  `IdentityNotYetValid` (before the window), `IdentityExpired` (at or after the
  end).

`is_valid` remains the structural signature check and `is_self_signed` remains
structural too; acceptance must use `is_valid_at` / `to_peer`, and their docs say
so.

---

## 3. Why not revocation

Revocation is a *distribution* problem — who publishes the list, how a verifier
obtains it, how fresh it must be, and what happens when it cannot be reached. A
format with no distribution story would be worse than none: it would look like a
control. A short validity window is the mechanism this design offers instead: a
document that must stop being accepted soon is issued with a window that ends
soon, and the issuer simply stops re-issuing it.

That is a real limitation, not a hidden one: a compromised key remains usable
until the window closes.

---

## 4. Tests

- `a_document_is_only_valid_inside_its_window` — 999 invalid, 1000 valid, 1999
  valid, 2000 invalid; `to_peer` returns `IdentityNotYetValid` / `IdentityExpired`
  at the two ends and succeeds inside.
- `a_document_without_a_window_is_refused` — stripping either field is a `Wire`
  error.
- `a_tampered_window_breaks_the_signature` — extending `NOT_AFTER` in the encoded
  body fails `is_valid`.
- The existing round-trip and certificate tests now carry a window and assert it
  survives encode/decode.

---

## 5. What this does **not** claim

1. **No revocation.** §3.
2. **No trusted time.** The verifier's clock is its own; a verifier with a wrong
   clock accepts or rejects wrongly. No timestamping authority is consulted.
3. **No freshness beyond the window.** A document can be replayed within its
   window; it is a credential, not a session token.
4. **No name constraints, no chain depth.** Unchanged from P3.
5. **No clock skew allowance.** `not_before`/`not_after` are exact; an issuer that
   wants slack widens the window.
6. **No handshake change.** The document is exchanged out of band; the handshake
   still authenticates with `conf_r`/`conf_i` and the inline signature over `TR`.
