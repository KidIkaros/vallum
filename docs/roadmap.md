# Roadmap

**How to read this.** Now / Next / Later, not a calendar. There are no dates
because the order is the commitment. An item moves from Later to Next when the
thing it depends on lands, and from Next to Now when it is the difference between
"works in a lab" and "safe to run somewhere that matters".

**The version tag is not a deliverable.** `v1.6.2` marks a tree; it is not a goal,
and publishing it changes nothing about whether the product is ready. The number
follows the work, not the other way round.

---

## What "production ready" means here

A host someone depends on, running Vallum as its only path to the network. The
claim is earned only when all seven hold, and each is checkable:

1. **A dead tunnel does not leak.** When the session fails, traffic is blocked —
   not silently restored to the gateway.
2. **DNS cannot resolve outside the tunnel** while attached.
3. **A dropped connection recovers without a human**, and does not hammer.
4. **The MTU is right for the link it is on**, or the failure names itself.
5. **Traffic that works in the lab works in a browser** — proven, not assumed.
6. **The crypto posture is stated in the same words the dependency uses.**
7. **The operator finds out before the user does.**

Everything in Now maps to one of those seven, and nothing in Now fails to map:

| Condition | Item |
|---|---|
| 1 · a dead tunnel does not leak | 2 |
| 2 · DNS cannot resolve outside | 3 |
| 3 · recovers without a human | 5 |
| 4 · MTU right for the link | 4 |
| 5 · browser behaviour proven | 1 |
| 6 · crypto posture stated | 6 |
| 7 · operator finds out first | 7 |

Seven conditions, seven items, no orphans. Anything that does not map is not a
production-readiness task, however much it would be nice to have.

---

## Now — production readiness

Ordered by dependency, not by size. The suite in (1) comes first because it is how
the rest is proven; without it, every later item is a claim.

### 1. The browsing-impact suite

**Problem.** Nothing has measured what a browser experiences through Vallum. The
traffic evidence that exists — `scripts/e2e-netns.sh` and
`scripts/verify-remote.sh` — proves *a tunnel carries packets*. It does not prove
DNS resolves in-tunnel, that an oversized payload arrives, that nothing escapes
the tunnel's prefixes, or how split and full tunnel differ. `verify-host.sh`
cannot answer it and says so: four of its assertions are `NOT VERIFIED` because a
same-host client cannot exercise egress.

**Why it is first.** Items 2, 3 and 4 are "fix the leak". You cannot fix a leak
you cannot see, and you cannot claim you fixed it without a test that fails when
it comes back. This suite is the definition of done for all three.

**Done means** a suite that, with a real tunnel up on a host with egress, asserts:
DNS resolves through the tunnel and nowhere else; a payload larger than the tunnel
MTU arrives intact; no traffic escapes the tunnel's prefixes while attached, for
IPv4 **and** IPv6; split tunnel routes only what it was told to. Each assertion
fails loudly. It runs from `verify-remote.sh`, where egress exists.

### 2. A failure policy that defaults to closed (Closed)

**Problem.** Vallum fails **open** where Mullvad fails **closed**
(`docs/research/mullvad-reference.md`). When the session dies, routes are
withdrawn and traffic returns to the gateway. That is the right default for a VPN
you switch on for ten minutes. It is the wrong default for one you depend on, and
it is the difference between a leak and an outage.

**A second instance of the same failure, already measured.** `peer add` writes
`allowed_ips = ["0.0.0.0/0", "::/0"]` unconditionally, so a client is promised a v6
tunnel even when the server was configured with `--address` as IPv4 only. The
route plan correctly declines to install a v6 route (there is no v6 address to
route from), and nothing blocks v6, so it escapes by the physical link while the
tunnel is up. `verify-remote.sh` fails on exactly this today.

**Done means** `block-on-failure` installs a blackhole for the tunnel's prefixes
instead of reversing to the gateway, `restore` keeps today's behaviour, the choice
is recorded and reversed exactly the way the route plan is, and the suite in (1)
proves traffic is blocked rather than leaked. The verdict is already computed in
one place, so this is a policy switch, not a second mechanism.

**This is not a statement about IPv6.** Dual-stack is implemented and proven —
`docs/proof/ipv6.md` (H7), `docs/proof/dual-stack.md` (H9), and `e2e-netns.sh`
gates it with a v6-only pass. The rule is narrower: **a family the tunnel does not
carry must not escape.** When the tunnel carries v6 it routes normally; when it
carries only v4, v6 is blocked rather than leaked. Removing IPv6 support is not on
the table and never was.

**Resolved:** `failure_policy` in `[quick]` defaults to `block` (fail-closed blackhole)
over `restore` (fail-open gateway fallback). When `vallum-quick watch` trips on dead
or degraded sessions, `apply_blackhole_routes` atomically installs kernel blackholes for
the managed prefixes, dropping non-fwmark traffic while letting the daemon continue
probing the endpoint. On session recovery, `apply_routes` replaces blackholes with the
tunnel interface routes.

### 3. DNS that cannot leak

**Problem.** DNS is best-effort. A host with no working resolver manager keeps the
tunnel and resolves through whatever the host has — outside the tunnel.

**Done means** DNS is pushed into the tunnel or port 53 is blocked outside it
while attached; the "kept the tunnel, warned about DNS" fallback is gone rather
than tolerated, and the suite in (1) proves resolution does not leave the tunnel.

**Resolved:**
- `policy.rs` drops UDP and TCP port 53 egress in the killswitch filter table before any LAN/custom allow rules, preventing rogue or local resolvers outside the tunnel from answering queries.
- `vallum-quick` adds direct `/etc/resolv.conf` fallback (`DnsBackend::ResolvFile`) with symlink-aware backup and restoration at `/run/vallum/{interface}.resolv.conf.bak` when neither `systemd-resolved` nor `resolvconf` is available.
- `attach` and `up` fail-closed and abort/rollback if DNS servers are configured but cannot be installed, removing the silent fallback to physical link resolvers.

### 4. Path MTU detection

**Problem.** MTU is fixed at 1500. On PPPoE and DS-Lite that black-holes, and the
symptom is "the tunnel is up but some sites hang" — the worst kind to diagnose
remotely, and exactly what a production user on a home line hits.

**Done means** the MTU is discovered by probe, the tunnel carries a full-size
payload on a reduced-MTU link, and the failure mode is a clear message rather
than a hang.

### 5. Always-on, with backoff

**Problem.** Reconnection needs a human. The watchdog withdraws routes when the
peer stops answering but nothing brings the session back after a sustained
outage, and starting at boot is a unit that happens to be enabled rather than a
property of the product.

**Done means** the tunnel returns without intervention after a server restart, an
outage and a reboot; it backs off rather than hammering; and the suite in (1)
covers recovery, not just steady state.

### 6. Say what the crypto is (Closed)

**Problem.** `origin-crypto-sdk` opens with `EXPERIMENTAL — NOT FOR PRODUCTION
USE`. Vallum builds its handshake on it. The security model says "not
independently audited"; the SDK is blunter.

**Why it is on this list.** A production claim resting on an experimental
dependency is not a claim. This one is not fixed by code — it needs a decision,
and then the tin has to match the decision.

**Done means** either an audit, or the documentation and the `--version`/`--help`
signifier say what the SDK says. Choosing the second is a legitimate outcome; it
just has to be chosen and stated, not left for a reader to discover.

**Resolved:** `--version` reports `experimental-pq`, `--help` explicitly states the
dependency status (`origin-crypto-sdk` `EXPERIMENTAL — NOT FOR PRODUCTION USE`),
and `README.md`, `docs/requirements.md`, and `docs/security-model.md` harmonize
the exact tri-hybrid and unaudited PQ posture.

### 7. The operator finds out before the user does

**Problem.** Every alert in `packaging/vallum-alerts.yml` is a **server-side
daemon counter** — `VallumDown`, `VallumPeerHandshakeStale`,
`VallumHandshakesRefused`, `VallumFragmentsDropped`, `VallumSendFailures` — fed by
`vallum_handshakes_established`, `vallum_handshakes_refused`,
`vallum_fragments_dropped` and friends. Nothing reports from the client. On a
laptop whose tunnel is attached but carrying nothing, the server may be perfectly
happy while the user sees a dead browser, and the first person to notice is the
user.

The failures the rest of this list introduces make that worse rather than better:
fail-closed turns a dead tunnel into a *blocked* tunnel, which is the correct
behaviour and completely invisible from the server's counters.

**Done means** a client exposes enough to tell "attached and carrying" from
"attached and dead", an alert exists for each failure this list introduces
(traffic blocked, DNS failing, reconnect looping), and the signal it pages on is
the same one the suite in (1) asserts — so what pages is what was tested, not a
separate approximation of it.

---

## Next — after the seven hold

- **Per-app split tunnelling.** Destination prefixes cannot express "browser
  through the tunnel, everything else direct". Needs a decision on mechanism
  (cgroup, netns, or namespace-per-app) before any code.
- **NAT traversal and relay.** ADR-0016 is `proposed` and deliberately says what
  Vallum will *not* do. Stays proposed until someone needs it behind a symmetric
  NAT.

## Not on the roadmap, and why

- **macOS, Windows, BSD.** ADR-0011 removed them for v0.1 and the macOS CI
  workflow was deleted; `docs/proof/platforms.md` now states that the daemon on
  macOS is unverified.
- **A code-based KEM.** ADR-0012 defers it until there is a reason.
- **A public repository.** Held deliberately until production readiness is real.
- **Publishing a version.** The tag marks a tree. It becomes worth doing when
  someone needs an artifact, not before.

---

## Open questions that need a decision, not work

1. **Interface-name collisions (Resolved: Refuse).** Two peers sharing the first eight
   characters map to one 15-character Linux interface (`vallum-<peer>`). `peer add`
   and `enroll` now proactively refuse collisions with an actionable message prompting
   the operator to choose names differing within the first 8 characters.
2. **The four `NOT VERIFIED` assertions in `verify-host.sh` (Resolved: Removed in favor of gates of record).**
   Same-host namespace loopback egress was sensitive to host netfilter (Docker/Tailscale) and NAT loopback.
   Traffic and live rotation across the tunnel are now verified directly on the host, while remote
   internet egress and live multi-machine rotation are enforced by `verify-remote.sh`.
3. **What fail-closed means for a client that is also a router (Resolved: Route table blackholes).**
   Kernel routing table blackhole routes (`blackhole <prefix> table <table>`) apply to all lookups
   matching the table, dropping forwarded cleartext traffic and preventing leaks across WAN interfaces.
