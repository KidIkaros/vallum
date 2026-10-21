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

## Findings, with severity and disposition

Reviewed after the first live run against a real VPS. "Accepted" means the
behaviour is deliberate and bounded, not that it is invisible.

| # | Finding | Severity | Disposition |
|---|---|---|---|
| 1 | A token on the command line lands in shell history and in `ps` for the life of the process | medium | **fixed** — `--token -` reads it from stdin; passing it as an argument now warns, and the invite says so |
| 2 | The token is a bearer credential: whoever holds it can enrol *one* device under the invited name, for 15 minutes | medium | accepted — single use, short TTL, revocable (`peer remove` drops the invite); it cannot impersonate an existing peer, only claim the name it was minted for |
| 3 | A captured request can be replayed | low | accepted — a replay under the same key returns the same public config (a legitimate retransmit); a replay under a *different* key is refused. Nothing secret is in the answer |
| 4 | Spoofed-source floods evade the per-IP cap | low | accepted and measured — ~10 µs per datagram, flat RSS; a spoofed source cannot receive the sealed answer |
| 5 | The peer name travels in the clear | info | accepted — the server cannot find the invite, and therefore the token, without it. The AEAD's AD binds the seal to the name, so a captured seal fails under another name |
| 6 | No forward secrecy for the token: a later token compromise decrypts recorded exchanges | low | accepted — that reveals public lines and a config, never a private key: the key was generated on the client and never crossed |
| 7 | Expiry uses the server's clock | low | accepted — a skewed clock expires an invite early or late; both fail closed on the server side |
| 8 | The responder runs as root | medium | mitigated — `ProtectSystem=full`, `ReadWritePaths=/etc/vallum /run/vallum`, `NoNewPrivileges`, `PrivateTmp`; it shells out to `peer enroll`, which validates the public line before writing |
| 9 | Enrolment is off unless asked for | — | by design: `[enroll] enabled` defaults to false, and `vallum server enroll --disable` stops the unit and tries to close the port |
| 10 | The bundle path still ships a client private key | **high** (custody) | pre-existing; `--remote` and `--join` are the default advice now, and the bundle is labelled as what it is. Deprecating it for new enrolments is the next step |

### What this review did not cover

- The tunnel handshake itself: covered in `adversary.md`.
- The control socket's local trust model: root-owned socket, `0600`.
- A hostile *server*: a server that lies can hand back a config pointing
  anywhere. The client authenticates the answer to the token, not to the
  server's identity — pinning the server's public line (printed as a
  fingerprint) is the mitigation, and is not implemented.
