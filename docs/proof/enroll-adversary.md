# Adversary evidence: the enrolment responder

The claims `vallum enroll-serve` makes, how they were measured, and what the
protocol does not claim. Protocol design and rationale: ADR-0015.

Enrolment is **off unless** `[enroll] enabled = true`. A stock install listens
on nothing.

## Measured

A responder on `127.0.0.1` was flooded with **20,000 well-formed `VEN2`
datagrams** per phase:

| Phase | What the server does | Wall time | RSS |
|---|---|---|---|
| cookie-less | one KDF, one cookie reply, **no invite read, no KEM** | 0.33 s (~16 µs each) | flat |
| valid cookie + wrong tag | invite read, one KDF, **no KEM** | 0.34 s (~17 µs each) | flat |
| legitimate join during the flood | one KEM encapsulation | enrolled normally | — |

The decisive property is the third column: a KEM encapsulation costs hundreds
of microseconds, so 20,000 of them would be seconds. Neither flood reaches one.
Only a request that has proven it can receive at its source address *and*
holds the token gets that far.

## The protocol's own bounds

- **Cookie before work.** The cookie is derived for the source address and
  issued before any invite lookup or KEM. A spoofed source cannot receive it,
  so a spoofed flood never reaches the expensive path — the same role `mac2`
  plays in the handshake.
- **Admission tag under the token.** One KDF over the request, no I/O beyond
  the invite file, rejects anyone without the token.
- **Silent drop on failure.** A bad cookie, tag, or invite id is
  indistinguishable from a dead socket: no oracle, no amplification (a
  datagram in produces at most one datagram out, and only to a verified
  address).
- **Single-use, pinned invites.** A spent invite answers a retransmit of the
  *same* key and refuses a different one. `peer invite --public-key` binds the
  invite to one public line, so a stolen token enrols nothing without the
  private key the client never sends.
- **Forward secrecy.** The reply key is `KDF(salt = nonces, ikm = frame(token,
  ss))` — the paper's `KDF1(σ, r)` shape. `ss` is the ephemeral KEM shared
  secret, destroyed after the exchange: a later token compromise opens no
  recorded reply, and a subverted client RNG leaves the attacker without the
  token.
- **No daemon involvement.** Enrolment is a separate process and port; the data
  plane's admission path is untouched.

## Findings, with severity and disposition

Reviewed after a live VPS run, then re-reviewed after enrolment v2 (ADR-0015).

| # | Finding | Severity | Disposition |
|---|---|---|---|
| 1 | A token on the command line lands in shell history and in `ps` | medium | **fixed** — `--token -` reads stdin; passing it as an argument warns, and the invite says so |
| 2 | The token is a bearer credential | medium | **mitigated** — `peer invite --public-key` pins the invite to one line, so a stolen token alone enrols nothing. The unpinned form is documented as a 15-minute invitation, single use, revocable |
| 3 | A captured request can be replayed | low | **accepted** — the reply is re-sealed per request under a fresh ephemeral secret, so a replay learns nothing new; a replay under a different key is refused |
| 4 | Spoofed-source floods | low | **fixed** — cookie gate before any invite access or KEM; measured above |
| 5 | The peer name travels in the clear | info | **fixed** — an opaque 16-byte invite id replaces the name on the wire, and a test asserts the name never appears in a datagram |
| 6 | No forward secrecy for the token | low | **fixed** — ephemeral KEM leg, `KDF(token ‖ ss)`; a test proves a reply does not open without the ephemeral secret |
| 7 | Expiry uses the server's clock | low | **accepted** — a skewed clock expires an invite early or late; both fail closed. The reply carries the config the client will use, so a wildly wrong server clock shows up as a failed handshake in `setup`'s proof step |
| 8 | The responder runs as root | medium | **mitigated** — in-process enrolment (no subprocess), and the unit runs with an empty capability set, `SystemCallFilter=@system-service`, `MemoryDenyWriteExecute`, `Protect*` on kernel/clock/hostname/cgroups, `RestrictAddressFamilies`, `UMask=0077`, and only `/etc/vallum` + `/run/vallum` writable |
| 9 | Enrolment is off unless asked for | — | by design — `[enroll] enabled` defaults to false; `vallum server enroll --disable` stops the unit and closes the port |
| 11 | `vallum-quick` runs `pre_up`/`post_up` hooks as root, from any config path — so a config another user can edit is root execution | **high** | **fixed** — hooks are refused unless the config is root-owned and not group/world-writable, with `--allow-insecure-config` as the explicit override. The installed path (`/etc/vallum/<iface>.toml`, `0600`) passes; `sudo vallum-quick up ~/mine.toml` does not |
| 10 | The bundle path shipped a client private key | **high** (custody) | **mitigated** — `peer add` requires a public line; generating the key needs an explicit `--ship-key` with a warning; `import-bundle` states the key came from the server. `--remote` and `--join` are the default advice |

### Hostile server

A server that lies can hand back a config pointing anywhere. The answer is
authenticated to the token, not to the server's identity, so the mitigation is
out of band: `peer invite` prints the server's **fingerprint**, and
`setup --join --expect <fingerprint>` refuses a mismatch *before writing
anything*. A user who ignores the fingerprint gets no protection — that is the
residual risk, and the mismatch error names both values.

One wrinkle worth knowing: the client checks *after* the server has already
enrolled it, because the answer has to arrive before it can be judged. So a
rejected answer leaves a peer record on that server which never connects —
harmless, and `peer remove` clears it, but it is why the error says "if the
server was rebuilt, mint a new invite".

### Not covered

- Volumetric resistance: kernel and NIC limits, not measured.
- The tunnel handshake itself: `adversary.md`.
- The control socket's local trust model: root-owned socket, `0600`.
- A compromised server *after* enrolment: out of scope for this channel.
