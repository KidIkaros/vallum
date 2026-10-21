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
| Release signing key | `packaging/vallum-release.pub`, committed to this repo; `install.sh` verifies `SHA256SUMS.sig` | a forged release tarball is refused |
| Server fingerprint | `vallum setup --join … --expect <fp>` verifies the server's public line during enrolment | a wrong-server enrolment is refused — treat a mismatch as an attack, not a retry |
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
- **Endpoint reachability** — UDP only. A network that blocks UDP blocks
  Vallum; there is no TCP fallback by design.

## What is explicitly NOT claimed

- **Traffic-analysis resistance** — packet sizes and timing are real;
  optional shaping exists but this is not a Tor-grade anonymity system.
- **Identity hiding (IK)** — documented non-claim in `docs/proof/`; an
  observer learns that two peers talk to each other.
- **Third-party audit** — the assessment in `docs/proof/pentest.md` is
  self-conducted. An external cryptographic audit is a roadmap item, not a
  completed one. Weight your deployment accordingly.
- **Compromised-key revocation at scale** — removing a peer revokes it;
  there is no CRL broadcast. Key rotation is per-peer (`peer rotate` →
  `peer finalize`), not fleet-wide.

## Reporting

See [SECURITY.md](../SECURITY.md) — private GitHub vulnerability reporting;
`origin-crypto-sdk` issues go to that repository.
