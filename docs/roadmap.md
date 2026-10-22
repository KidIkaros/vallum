# Roadmap

**How to read this.** Now / Next / Later, not a calendar. There are no dates
because the order is the commitment and the dates were never real. An item moves
from Later to Next when the thing it depends on lands, and from Next to Now when
someone other than the maintainer needs it.

Nothing here is a feature list. Each entry is a problem, why it matters, and what
"done" would have to mean for it to stop being a problem.

---

## Where the product is

PQ-WireGuard-shaped, tri-hybrid, Linux-only, operationally deployable on hosts
you control; handshake fragmentation managed by design; **crypto not
independently audited**. That last clause is the reason Now exists.

---

## Now — what stops someone else using it

### 1. Publish 1.6.2, or decide not to

**Problem.** `v1.6.2` is tagged locally at `7a94295` and has never been pushed or
published. Eight commits have landed since, so the release gate now refuses by
design: it verifies a commit, and HEAD has moved past the one it verified.

**Why it matters.** Everything below assumes someone can install the thing. Right
now the only installable artifact is the 1.6.1 deb.

**Done means** `scripts/release.sh --dry-run` is green at HEAD, `verify-remote.sh`
has stamped the commit being released, and the artifacts are published — or the
tag is explicitly abandoned and 1.6.3 is cut instead. Both are fine; drifting is
not.

### 2. Browsing impact under an active tunnel

**Problem.** Nobody has measured what a browser actually experiences through
Vallum. The traffic evidence that exists is `scripts/e2e-netns.sh` and
`scripts/verify-remote.sh`, and both prove *a tunnel carries packets* — not that
DNS resolves, that large responses arrive unfragmented, that nothing leaks
outside the tunnel, or how split and full tunnel differ.

`verify-host.sh` cannot answer it: its own verdict says a same-host client cannot
exercise egress, and four assertions in it are marked `NOT VERIFIED` for exactly
that reason.

**Why it matters.** This is the class of defect that looks like "the VPN is
broken" to a user and like "the gate is green" to us.

**Done means** a suite that, with a real tunnel up, asserts: DNS resolves through
the tunnel and nowhere else; a payload larger than the tunnel MTU arrives intact;
no traffic escapes the tunnel's prefixes while it is attached (IPv4 *and* IPv6);
and split tunnel routes only what it was told to. Each assertion fails loudly
when the property is violated, on `verify-remote.sh` where egress exists.

### 3. Say what the crypto is

**Problem.** `origin-crypto-sdk` opens with `EXPERIMENTAL — NOT FOR PRODUCTION
USE`. Vallum builds its handshake on it. The security model says "not
independently audited"; the SDK is blunter than that.

**Why it matters.** A product that says "not audited" in one doc and "experimental
— not for production" in its dependency is telling two stories. The honest one
wins, and it should be the one on the tin.

**Done means** either an audit, or the documentation and the `--version`/`--help`
signifier state the same thing the SDK does. Choosing the second is a legitimate
outcome — it just has to be chosen.

---

## Next — the gaps against the reference implementation

These are ranked in `docs/research/mullvad-reference.md`, which is where the
evidence lives. They are ordered by how badly their absence hurts, not by effort.

### 4. A failure policy that can default to closed

**Problem.** Vallum fails **open** where Mullvad fails **closed**. When the
session dies, routes are withdrawn and traffic returns to the gateway. That is
the safe default for a VPN you switch on; it is the wrong default for one you
rely on.

**Done means** `block-on-failure` installs a blackhole for the tunnel's prefixes
instead of reversing to the gateway, `restore` keeps today's behaviour, and the
choice is recorded the same way the route plan is — what was installed, reversed
exactly. The verdict is already computed in one place, so this is a policy
switch, not a second mechanism.

### 5. DNS that cannot leak

**Problem.** DNS is best-effort. A host with no working resolver manager keeps the
tunnel and resolves through whatever the host has — which is outside the tunnel.

**Done means** DNS is either pushed into the tunnel or port 53 is blocked outside
it while attached, and the fallback is gone rather than warned about.

### 6. Path MTU detection

**Problem.** MTU is fixed at 1500. On PPPoE and DS-Lite that black-holes, and the
symptom is "the tunnel is up but some sites hang" — the worst kind to diagnose
from a distance.

**Done means** the MTU is discovered by probe and the failure mode is a clear
message, not a hang.

### 7. Always-on, with backoff

**Problem.** Reconnection needs a human. The watchdog withdraws routes when the
peer stops answering, but nothing brings the session back on its own after a
sustained outage.

**Done means** the tunnel returns without intervention, backs off rather than
hammering, and starting at boot is the normal case rather than a unit that
happens to be enabled.

---

## Later — real, not yet worth starting

- **Per-app split tunnelling.** Destination prefixes cannot express "browser
  through the tunnel, everything else direct". Needs a decision about mechanism
  (cgroup, netns, or namespace-per-app) before any code.
- **NAT traversal and relay.** ADR-0016 is `proposed` and deliberately says what
  Vallum will *not* do. It stays proposed until someone needs it behind a
  symmetric NAT.

## Not on the roadmap, and why

- **macOS, Windows, BSD.** ADR-0011 removed them for v0.1; the macOS CI workflow
  was deleted. `docs/proof/platforms.md` now states plainly that the daemon on
  macOS is unverified.
- **A code-based KEM.** ADR-0012 defers it until there is a reason.
- **A public repository.** Held deliberately until the product is ready for it.

---

## Open questions that need a decision, not work

1. **Interface-name collisions.** Two peers sharing the first eight characters map
   to the same interface. It warns; it does not prevent. Warn or refuse?
2. **The four `NOT VERIFIED` assertions in `verify-host.sh`.** They are honestly
   labelled and covered elsewhere, but they are the reason the gate cannot be
   the sole evidence for traffic. Either move them to `verify-remote.sh` or
   delete them and let the gates of record own that claim.
