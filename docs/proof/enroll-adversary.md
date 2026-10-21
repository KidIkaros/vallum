# Adversary evidence: the enrolment responder

The claims this makes about `vallum enroll-serve`, and how they were measured.

## Measured

A responder on `127.0.0.1` was flooded with **20,000 well-formed `VEN1`
datagrams** — real magic, a valid invite name, correct-looking ciphertext —
sealed under a *wrong* token:

| measure | result |
|---|---|
| wall time | 0.2 s (~10 µs per datagram) |
| responder RSS | flat (0 kB delta) |
| legitimate join during the flood | enrolled normally |

The cost profile mirrors the tunnel's admission check (`adversary.md`): a
request that fails its AEAD tag is dropped after an invite lookup, a KDF, and
one AEAD open — no subprocess, no config write, no allocation that grows.

## What the design already bounds

- **Silent drop on bad tags** — an attacker gets no oracle: wrong token and
  no-invite are indistinguishable from a dead socket.
- **Single-use tokens** — a spent invite answers retransmits of the *same*
  key (legitimate UDP retry) but refuses a different one; a stolen token
  cannot be replayed into a second enrolment.
- **8 req/sec per source IP** — beyond that the source is dropped before any
  crypto. Spoofed-source floods evade the per-IP cap but cannot receive
  answers, and each datagram still costs ~10 µs.
- **No daemon involvement** — enrolment is a separate process and port; the
  data plane's admission path is untouched.

## Not claimed

- Volumetric resistance: kernel and NIC limits, not measured.
- The token is a bearer credential for 15 minutes: an on-path observer who
  copies a request cannot reuse its seal under another name or nonce, but the
  token itself, if leaked, works until spent or expired.
