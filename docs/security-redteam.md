# Red team: Vallum, 2026-11-11

Targeted attacks against the live deployment and the source, run by the agent
with the operator's authorisation. Not a fuzz campaign and not an external
audit: eight surfaces were chosen from the code and attacked by hand, four of
them with traffic against the production server.

The one-line summary: **the cryptographic design held, and the parts that broke
are all admission, observability and operator convenience — the outer skin, not
the tunnel.**

---

## Findings

### H1 — Unauthenticated replay amplification (high)

One captured 1452-byte fragment of any handshake, replayed forever: no token, no
key, no account. The bytes do not expire, because the fragment layer parses and
buffers before anything is authenticated — which it must, since an initiation is
itself fragmented.

Measured on `wingman-vps` (2 vCPU, single-threaded loop):

| Offered rate | Server CPU | Tunnel |
|---|---|---|
| 31,178/s for 5 s | 4.10 s ≈ 75% of one core | 74 ms, 0% loss |
| 32,316/s for 6 s | ~same | 74 ms, 0% loss |

**26 µs of the server's core per attacker packet.** The core burned is the one
carrying user traffic, so the ceiling is a single laptop two orders below the
server's bandwidth. The tunnel survived both runs because the rate limiter is
the network, and a modest attacker with `sendmmsg` would exceed it.

Reproduction: capture with `tcpdump -w` on the responder, extract the UDP
payload, `sendto` it in a loop. A fragment needs no cookie, and the responder
answers a repeated *whole* initiation from its cached reply, so fragment replay
is strictly cheaper for the attacker than init replay.

Precedent in-tree: the enroll service already runs a per-source limiter **before**
its cookie gate (`RATE_PER_SECOND`, `RATE_LIMIT_SOURCES`). The tunnel path had no
equivalent. See ADR-0030.

**Status: mitigated, not closed.** ADR-0030's bucket is implemented (`4297e18`)
and moves the cost from 26.3 to 19.4 µs per packet — the attacker's ceiling per
core goes from ~38k to ~51k pps. A one-byte flood that is refused outright still
costs 8.7 µs, which is the userspace receive path, not the parse; closing the
rest means moving the allowance into the reader thread. The bucket is worth
keeping and is not sufficient on its own.

### H2 — The enroll port is firewalled off while the config says it is on (high, functional)

`[enroll] enabled = true` on the server; the daemon binds `0.0.0.0:51821`;
`ufw` allows `51820/udp` only. A crafted hello from the internet gets no reply
within two seconds. An operator following the invite flow from outside hits a
silent black hole — the invite is minted, the client dials, nothing answers, and
nothing says why.

### M3 — A clock step backwards locks a peer out indefinitely (medium)

Established before this pass and now pinned by tests. The timestamp guard refuses
any initiation not strictly newer than the last one accepted, and it refuses
before the peer is answered. A client whose clock steps back — an NTP correction
after suspend is the ordinary case — is locked out until its clock catches up.
Nothing bounds it. Refusals are now counted (`vallum_handshake_dropped_stale`)
but the policy is unchanged.

### M4 — `vallum-ops self-update` installs from a user-writable path as root (medium)

`self-update` copies `$REPO/packaging/vallum-ops`, where `REPO` defaults to
`/home/ikaaros/Coding/Gold/vallum`, into `/usr/local/sbin` and is run through a
NOPASSWD sudoers rule. Anything running as that user gets root at the next
self-update, so the privileged surface is exactly as protected as the home
directory. ADR-0029 designs production pinning; the dev default is what runs
today and is easy to forget once the tool is on a host with other users.

### M5 — `vallum-ops trace` writes to a predictable `/tmp` path as root (medium)

`strace -o /tmp/vallum-openat.log` with trivially guessable content and
truncation. Where the file does not exist yet — a fresh host, first use — an
unprivileged user can pre-create it as a symlink and root overwrites the target;
`/etc/sudoers` is the obvious victim. Today it is mitigated by accident: after
first use the file is root-owned and `/tmp` is sticky, so the user cannot replace
it.

### L6 — Garbage floods are invisible (low)

71,992 junk datagrams at 6,000/s: the tunnel never blinked, and
`vallum_dropped_malformed` stayed at **0** — reassembly consumes them before the
counter. No damage; no diagnosis either. An operator cannot tell a flood from a
quiet night.

### L7 — No length cap on peer names (low)

A name becomes part of a config filename and a client interface name; both have
limits and neither is checked at enrolment. Reaching it gives a bare
`ENAMETOOLONG` at import time.

### L8 — `import-bundle --force` overwrites on name collision (low)

Two bundles from different servers with the same name silently replace each
other under `--force`. Expected, undocumented.

---

## What held up

- **Bundle path traversal**: closed. The name is reduced to `[A-Za-z0-9_-]` before
  it becomes a filename; the key must be a bare file name.
- **Sandbox**: `getrandom` is in the seccomp allow-list, so the filter cannot
  silently starve the RNG; `EPERM`-instead-of-kill keeps a missing entry from
  tearing the tunnel down.
- **Init replay**: answered from the cached reply — cheap by construction.
- **Enroll admission**: per-source rate limit, cookie before KEM work, 128-bit
  token, asymmetric failure modes, invite TTL.
- **Tunnel stability under attack**: 32k pps of fragments, rtt spread under
  1.1 ms, zero loss.

## Not tested

- Fresh initiations with valid `mac1` at volume (needs generating them, not
  replaying) — the case the cookie path exists for.
- The TCP carrier and the IPv6 path.
- Whether `under_load` engages the cookie gate in practice, or only in tests.
- Fuzzing of any kind; the config parser and the bundle reader are the obvious
  next targets.
- Anything off-path: source spoofing (cannot spoof from this host), and on-path
  attackers beyond replay.

## Threat-model note

Vallum's stated threat model is a hostile network plus one server you trust, not
a global observer. Every finding above is reachable by an unauthenticated
off-path attacker or a local unprivileged user, which puts all of them inside
the model. None of them break confidentiality.
