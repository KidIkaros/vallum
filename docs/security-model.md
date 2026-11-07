# The Vallum security model

What Vallum guarantees, what it explicitly does not, and what the host and
operator must guarantee. The proofs behind the claims live in
[`docs/proof/`](proof/); this page is the map.

## What the wire guarantees

- **Tri-hybrid key establishment** — `X25519 + sntrup761 + ML-KEM-768`
  (suite `0x0003` by default), combined with HKDF-SHA3-256. Breaking session
  keys requires breaking all three legs.
- **Transcript-bound suite negotiation** — the negotiated suite is bound
  into the handshake transcript; a downgrade changes the keys, not the
  outcome.
- **Committing AEAD** — ciphertexts commit to the key, closing the
  multi-key/confused-deputy class.
- **Post-compromise security** — epoch-based rekeying; superseded epochs
  are erased, so a later key compromise does not decrypt earlier traffic.
- **Replay protection** — sliding-window timestamps; see
  [`proof/`](proof/) for the replay-window and keepalive analyses.
- **DoS posture** — bounded work queue with `under_load` signalling that
  moves handshake admission to cookie mode before KEM work; the enrolment
  responder is rate-limited per source with a capped source map.

## Trust anchors (what you verify vs what you trust)

| Anchor | What it is | What happens if it's wrong |
|---|---|---|
| Release signing key | `packaging/vallum-release.pub`, committed to this repo; `install.sh` verifies `SHA256SUMS.sig` before install | a forged release tarball is refused |
| `.deb` / `.rpm` packages | carried in the same signed `SHA256SUMS`; `dpkg -i`/`rpm -i` verify nothing themselves, so `install.sh --from-release --package` checks sig + checksum *before* calling them — a manual `dpkg -i` skips that entirely | a hand-installed package trusts the channel (GitHub + TLS) alone |
| Server fingerprint | `vallum join vallum1-join:…/<fp>` verifies the server's public line during enrolment (the fingerprint is part of the ticket `peer invite` prints) | a wrong-server enrolment is refused — treat a mismatch as an attack, not a retry |
| SSH in `--remote` | enrolment rides your existing SSH trust | the host key check is SSH's, not Vallum's |
| Bundle custody | `--ship-key` bundles carry private key material | custody is yours; client-side keygen paths exist precisely so bundles are a fallback, not a default |
| Peer public lines | pinned per peer in the config | a swapped line can't tunnel — keys won't establish |

## What the host must guarantee

- **Root custody** — `/etc/vallum` is 0600/root and the units run with
  bounded capabilities, but root on the host reads keys. Vallum does not
  protect the machine from its administrator.
- **Wall clock** — replay timestamps and identity validity windows are
  clock checks. Keep NTP on; `vallum doctor` warns when it can't confirm
  synchronization. An hour of drift breaks handshakes loudly, not silently.
- **Kernel** — TUN, UDP, and netfilter are trusted. Vallum hardens its own
  units (`vallum-enroll@` runs with no capabilities, a syscall filter, and
  `MemoryDenyWriteExecute`); the kernel is out of scope.
- **Endpoint reachability** — UDP, or the opt-in TCP carrier. A network that
  blocks UDP blocks the default configuration; `carrier = "tcp"` on both ends is
  the one answer, and it is manual by design — nothing detects the block, because
  a silent filter looks, from the client, exactly like a server that is not
  answering ([ADR-0026](adr/0026-censorship-resistance.md)). The TCP carrier is
  the same packets inside one connection per peer: about 1 % larger, one order
  for everything, and no roaming. It is reachability, not censorship resistance,
  and the retransmission cost of a lossy path is unmeasured.

## What is explicitly NOT claimed

- **Traffic-analysis resistance** — packet sizes and timing are real;
  optional shaping exists but this is not a Tor-grade anonymity system.
- **Censorship resistance** — separate from traffic analysis, and not claimed at
  all. Shaping makes a tunnel's traffic harder to *classify*; nothing here makes
  it easier to *reach* where UDP is blocked. A censor that does not need to look
  at your packets is not inconvenienced by padding them ([ADR-0026](adr/0026-censorship-resistance.md)).
- **Identity hiding (IK)** — documented non-claim in `docs/proof/`; an
  observer learns that two peers talk to each other.
- **Third-party audit** — the assessment in `docs/proof/pentest.md` is
  self-conducted. An external cryptographic audit is a roadmap item, not a
  completed one. Weight your deployment accordingly.
- **Experimental post-quantum primitives** — the underlying
  `origin-crypto-sdk` dependency states `EXPERIMENTAL — NOT FOR PRODUCTION USE`.
  Vallum mitigates implementation risks by composing classical X25519 alongside
  sntrup761 and ML-KEM-768 in a tri-hybrid design (breaking session confidentiality
  requires compromising all three algorithms simultaneously), but the post-quantum
  implementations have not undergone independent third-party audit. Weight your
  deployment accordingly.
- **Compromised-key revocation at scale** — removing a peer revokes it;
  there is no CRL broadcast. Key rotation is per-peer (`peer rotate` →
  `peer finalize`), not fleet-wide.

## Reporting

See [SECURITY.md](../SECURITY.md) — private GitHub vulnerability reporting;
`origin-crypto-sdk` issues go to that repository.
