# ADR-0014: Close the WireGuard gaps Vallum can win

**Status:** accepted
**Date:** 2026-10-20
**Supersedes:** nothing. Extends ADR-0007 (PSK tag), ADR-0012 (code-based KEM),
and ADR-0013 (server provisioning).

## Context

WireGuard is the floor Vallum was designed against, so it is worth being precise
about where that floor stops. WireGuard's own
[known limitations](https://www.wireguard.com/known-limitations/) are honest about
the protocol-level trade-offs; the operational literature is honest about the
rest — no control plane, no identity, no rotation, no metrics, and a DNS
integration that breaks on the distribution most people run.

Some of these Vallum already answers by construction. Others it inherited. This
record separates the two, so the remaining work is a decision rather than a
backlog nobody wrote down.

## The pain points, and where Vallum stands

### Protocol limits WireGuard states itself

| Pain | Why it hurts | Vallum |
|---|---|---|
| No DPI resistance | UDP with a fixed handshake shape is easy to block; everyone bolts on `wstunnel` | **Inherited.** Out of scope: obfuscation is an upper-layer job. |
| No TCP mode | Networks that drop non-DNS UDP kill the tunnel | **Inherited.** Same reason; a TCP wrapper is a separate component. |
| Roaming mischief | An active MITM can rewrite the endpoint and keep relaying | **Fixed here** — `pin_endpoint`. |
| Identity-hiding forward secrecy | Responder key compromise + a traffic log reveals *who* handshook | **Solved by construction.** The peer hint is a sealed 8-byte fingerprint of the public key, not the static key (`vallum-core/src/identity.rs`). |
| No PQ secrecy | Only a PSK slot, and it is not forward-secret | **Solved.** Tri-hybrid default (ADR-0010); the PSK is defence in depth. |
| DoS | ECDH cost is paid before `mac2` | **Improved.** Keyed MAC cookies plus a PSK admission tag that rejects junk before any KEM work (ADR-0007). |
| Unreliable monotonic counter | Clock jumps break handshakes permanently | **Inherited in kind.** TAI64N with an explicit window; the clock is still trusted. |
| Routing loops | Not detected, locally or over the network | **Inherited.** Cryptokey routing refuses overlaps; loops across peers are not detected. |

### Operational

| Pain | Source | Vallum |
|---|---|---|
| No control plane; every peer configured with every other peer's key | [LWN](https://lwn.net/Articles/910766/) | **Deliberate.** ADR-0013: a provisioning CLI and a `--json` contract, not a service. |
| Key = peer, not user; no SSO, no IdP | [WireHQ](https://wirehq.net/) | **Partially fixed here** — identity documents bind a key to a label and a window. No SSO, by design. |
| Manual rotation and revocation; offboarding edits every config | [birdhost](https://birdhost.de/en/blog/wireguard-im-unternehmen-einrichten) | **Fixed here** — `peer rotate` / `peer finalize` with a previous key accepted. |
| No metrics endpoint; exporters parse `wg show` | [linuxserver#309](https://github.com/linuxserver/docker-wireguard/issues/309) | **Fixed here** — `vallum metrics`. |
| Config reloads drop sessions or are O(n) over a file | [Fly.io](https://fly.io/blog/jit-wireguard-peers/) | **Already solved.** `syncconf` sends only the delta; `peer add` applies live. |
| No device onboarding | — | **Already solved.** Bundle or client-generated key, one command each way (ADR-0013). |

### Routing and addressing

| Pain | Source | Vallum |
|---|---|---|
| `AllowedIPs` does routing *and* filtering; overlap silently yields `allowed ips: (none)` | [wgcookbook](https://wgcookbook.pages.dev/guides/wireguard-allowedips-explained/) | **Mitigated, not removed.** `peer add` allocates and refuses overlaps; the field still does two jobs. |
| Routes installed even when the peer is unreachable | [adyxax](https://www.adyxax.org/blog/2023/02/21/wireguard-routing-part-one/) | **Inherited.** No health-based withdrawal. |
| No multicast or broadcast; mDNS/SSDP do not cross | [avahi#262](https://github.com/avahi/avahi/issues/262) | **Inherited.** Protocol-shaped; out of scope. |
| MTU: hardcoded 1420, PMTUD black holes, MSS clamping | [defguard](https://defguard.net/blog/mtu-mss-decision-tree/) | **Improved.** The inner MTU is derived from `outer_mtu` and the envelope segments instead of fragmenting (`config.rs`). **Probing added here.** |
| No NAT traversal; CGNAT needs a VPS | [Tailscale](https://tailscale.nixfred.com/learn/nat-traversal) | **Inherited.** Roaming covers one-public-side; NAT-to-NAT is a different product. |
| IPv6 ULA vs GUA, NAT66, no server-push | [OpenWrt](https://openwrt.org/docs/guide-user/services/vpn/wireguard/road-warrior) | **Partially solved.** One config carries both families and `server init` masquerades v6. |

### Client papercuts

| Pain | Source | Vallum |
|---|---|---|
| `resolvconf` vs `systemd-resolved`: failure or DNS leaks | [Fedora #1884352](https://bugzilla.redhat.com/show_bug.cgi?id=1884352), [wireguard list](https://lists.zx2c4.com/pipermail/wireguard/2024-December/008739.html) | **Fixed here** — backend detection, `~.` routing domain, `resolvectl revert`. |
| `wg-quick save` rewrites the config and loses comments | wg-quick(8) | **Already solved.** `toml_edit` edits preserve comments; every write keeps a timestamped backup. |
| Keepalive forgotten behind NAT | birdhost | **Already handled.** Server-generated client configs write `persistent_keepalive = 25`. |

## Decision

Implement the six gaps that are real, within reach, and do not turn Vallum into a
different product:

1. **DNS that survives `systemd-resolved`** — detect `resolvectl` (and that
   resolved is *running*, not merely installed), install the resolvers with the
   `~.` routing domain on a full tunnel so queries cannot leak, revert on detach,
   and keep `resolvconf` as the fallback.
2. **`vallum metrics`** — one-shot Prometheus text from the control socket. No
   listener, no daemon change, no new attack surface.
3. **`vallum doctor --probe-mtu`** — bisect the real path with `ping -M do` and
   report the measured `outer_mtu`, or say it is inconclusive rather than
   guessing.
4. **`pin_endpoint`** — a per-peer option that refuses a handshake whose source
   is not the configured endpoint, closing the roaming-mischief gap.
5. **Identity documents** — expose `IdentityDocument`, which `vallum-core`
   already implements and nothing used: `identity issue` (CA), `identity
   self-sign`, `identity verify`, `[[peer]] identity_file`, and a validity window
   checked at load and at every handshake.
6. **Zero-downtime rotation** — a peer accepts its current identity plus one
   previous one, so `peer rotate` installs the new key before the device has it,
   and `peer finalize` retires the old one.

## Why these six

- They are the pains that generate support load and outages, not the ones that
  are interesting to implement.
- Five of the six are operator-surface work on machinery that already exists.
  Only rotation changes the handshake path, and it changes *which identity* the
  responder uses, not the wire format.
- Each has an acceptance test that fails today: a DNS lookup on a
  `systemd-resolved` host, a scrape with no exporter, a black-holed 1500-byte
  packet, a redirected handshake, an expired credential, a rotation that drops
  traffic.

## What this does not decide

1. **No control plane.** No enrolment API, no SSO, no tokens. The `--json`
   contract remains the extension point (ADR-0013).
2. **No NAT traversal.** No STUN, no hole punching, no relay. A CGNAT-to-CGNAT
   deployment still needs a public relay, exactly as WireGuard does.
3. **No multicast or broadcast.** A layer-3 tunnel that maps destination to peer
   cannot carry a group address without inventing a mapping.
4. **No DPI resistance.** Obfuscation belongs above the tunnel.
5. **No automatic route withdrawal.** `allowed_ips` still installs its routes
   whether or not the peer is reachable.
6. **Identity is not SSO.** A document binds a key to a label and a window; it
   does not bind a key to a person or a directory account.

## Consequences

- **Expiry becomes possible.** A credential can be issued for 90 days; after that
  the handshake fails closed. That is a new operational obligation: someone must
  renew, and `doctor` must say when.
- **A previous key is a standing second credential.** Rotation is only safe if it
  is finished; `peer list` shows `ROTATING`, `doctor` warns after seven days, and
  `peer finalize` is one command.
- **`pin_endpoint` is a trade, not a default.** It breaks NAT rebinding on
  purpose; it is opt-in per peer.
- **The DNS path is now distribution-aware.** Two backends means two code paths,
  both exercised by `--dry-run` and unit tests.
- **Metrics are pull-based and stateless.** A scrape is one `get=1`; there is no
  history, and nothing to secure because nothing listens.
- **The MTU probe sends packets.** It is opt-in and documented as active; without
  the flag `doctor` stays read-only.

## What this does not claim

1. **No proof.** Unlike `docs/proof/`, this ADR is an engineering record, not a
   gate artefact.
2. **No benchmark.** The six changes are not measured for performance.
3. **No claim that WireGuard is bad.** Every limitation above is a trade
   WireGuard made deliberately; several of them are why its attack surface is
   small. Vallum inherits some of those trades on purpose.
