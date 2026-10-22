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

Everything in Now maps to one of those seven. Anything that does not is not a
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

### 2. A failure policy that defaults to closed

**Problem.** Vallum fails **open** where Mullvad fails **closed**
(`docs/research/mullvad-reference.md`). When the session dies, routes are
withdrawn and traffic returns to the gateway. That is the right default for a VPN
you switch on for ten minutes. It is the wrong default for one you depend on, and
it is the difference between a leak and an outage.

**Done means** `block-on-failure` installs a blackhole for the tunnel's prefixes
instead of reversing to the gateway, `restore` keeps today's behaviour, the choice
is recorded and reversed exactly the way the route plan is, and the suite in (1)
proves traffic is blocked rather than leaked. The verdict is already computed in
one place, so this is a policy switch, not a second mechanism.

### 3. DNS that cannot leak

**Problem.** DNS is best-effort. A host with no working resolver manager keeps the
tunnel and resolves through whatever the host has — outside the tunnel.

**Done means** DNS is pushed into the tunnel or port 53 is blocked outside it
while attached; the "kept the tunnel, warned about DNS" fallback is gone rather
than tolerated, and the suite in (1) proves resolution does not leave the tunnel.

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

### 6. Say what the crypto is

**Problem.** `origin-crypto-sdk` opens with `EXPERIMENTAL — NOT FOR PRODUCTION
USE`. Vallum builds its handshake on it. The security model says "not
independently audited"; the SDK is blunter.

**Why it is on this list.** A production claim resting on an experimental
dependency is not a claim. This one is not fixed by code — it needs a decision,
and then the tin has to match the decision.

**Done means** either an audit, or the documentation and the `--version`/`--help`
signifier say what the SDK says. Choosing the second is a legitimate outcome; it
just has to be chosen and stated, not left for a reader to discover.

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

1. **Interface-name collisions.** Two peers sharing the first eight characters map
   to one interface. It warns; it does not prevent. Warn or refuse?
2. **The four `NOT VERIFIED` assertions in `verify-host.sh`.** Honestly labelled
   and covered elsewhere, but they are why the gate cannot be the sole evidence
   for traffic. Move them to `verify-remote.sh`, or delete them and let the gates
   of record own the claim.
3. **What fail-closed means for a client that is also a router.** Blackholing the
   host's own prefixes is obvious; what happens to forwarded traffic is not, and
   it should be decided before (2) is built rather than discovered during it.
