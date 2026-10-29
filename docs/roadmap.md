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

### 1. The browsing-impact suite (Built)

**Problem, corrected after building.** An early statement of this item said that
nothing measured a browser's experience and that the harnesses proved "a tunnel
that carries packets". That was stale: `verify-remote.sh` already asserted the
oversized-payload arrival intact, the egress-device checks (`ip route get` for
IPv4 and IPv6) and the foreign-source refusal, and peer-to-peer IPv6 was already
gated in `e2e-netns.sh`. What was genuinely missing — and is now built, per
`docs/qa/browsing-impact-suite.md` — was narrower and sharper:

1. **The DNS leak could not be seen from the exit side.** `dig @1.1.1.1` proved
   egress through the tunnel, never that nothing reaches port 53 outside it when
   the policy is on. Now in `e2e-netns.sh`: with a fabricated resolver bound to
   :53 on the outer link and a raw-packet capture, `policy on` visibly eats the
   lookup on the wire, and `policy off` returning the answer is the control that
   the on-case measured the guard and not the harness.
2. **Every leak check ran against a split tunnel.** The remote harness rewrites
   the config to split before testing, and `verify-host.sh` cannot touch the
   invoking host's routes. Now in `e2e-netns.sh`: a fresh pair of daemons under
   the scratch dir, B a full-tunnel client whose routes are installed by the
   product's own `vallum-quick attach` plan, and after attach no lookup B makes
   reaches the link (only B's own datagrams count; the endpoint's connected /24
   outranking the suppressed default is documented in the script, not papered
   over). `quick detach` restoring the crossing is the control.
3. **What `verify-host.sh` could not verify** is now split honestly between two
   harnesses: remote-listed egress in `verify-remote.sh`, and everything that
   would block or re-route the invoking machine in `e2e-netns.sh`'s disposable
   namespaces.

**Why it was first.** Items 2, 3 and 4 are "fix the leak". You cannot fix a leak
you cannot see, and you cannot claim you fixed it without a test that fails when
it comes back. This suite is the definition of done for all three — and each of
its assertions ships with a positive control, because a suite that can only pass
is the same defect as a `status` that only says `up`.

**Blocked on infrastructure — IPv6 internet egress.** Internet-facing IPv6
gress cannot be asserted from here yet. `wingman-vps` has no global IPv6: the
kernel is enabled (`disable_ipv6=0`) but netplan sets `dhcp6: false` with no v6
address or route, and neither delivery mechanism answers on the link — 12 s of
`accept_ra=2` produced no address and no default route, and `dhcpcd -6 -T`
solicited a DHCPv6 server and timed out. The provider must assign an address or
prefix before this is testable. The suite does not silently skip it: the
harnesses report the gap explicitly.

What *is* testable today the suite asserts: peer-to-peer IPv6 (`fd00:7::2` to
`fd00:7::1`) round-trips through a v6-only restart, dual-stack inner addresses
over a v6 outer path both crossing, and **no foreign source entering the
tunnel** — `run` enforces and logs that refusal.

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

### 3. DNS that cannot leak (Closed)

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

**Resolved:**
- `net.rs` implements active path MTU discovery (`probe_path_mtu`, `probe_path_mtu_host`) using ICMP PMTUD bisection with DF set (`ping -M do`) and parsing of kernel/router next-hop MTU error reports.
- `run.rs` automatically discovers path MTU across peer endpoints prior to opening the TUN interface whenever `outer_mtu` is omitted in the config, clamping inner MTU and outer budget so TCP MSS negotiation prevents black-holing on PPPoE (1492) and DS-Lite (1400/1280) links.
- `doctor.rs` automatically audits path MTU against each configured peer endpoint (or `--probe-mtu`), reporting passes, warnings with required `outer_mtu` values, or failures when below the 682-byte protocol minimum.
- `setup.rs` actively probes the server endpoint during client setup/join, recording `outer_mtu` into the generated configuration when a reduced link is detected.
- The probe is bounded by `PROBE_BUDGET` (3 s). It runs before the TUN interface exists, so an endpoint that silently swallows ICMP must not delay startup: each unanswered probe costs up to a second and the bisection needs ~10, which would be ~10 s per unreachable peer against systemd's 90 s `TimeoutStartSec`. Past the budget the prober reports "does not fit" and the bisection settles on the largest size it confirmed, so an unmeasured path keeps the configured default instead of blocking the interface.
- **Known limitation:** the probe shells out to `ping`. If it is not on `PATH` the probe is inconclusive and PMTU silently does not apply — the tunnel still comes up at the configured MTU, so this degrades to the pre-existing behaviour rather than failing.

### 5. Always-on, with backoff

**Problem.** Reconnection needs a human. The watchdog withdraws routes when the
peer stops answering but nothing brings the session back after a sustained
outage, and starting at boot is a unit that happens to be enabled rather than a
property of the product.

**Done means** the tunnel returns without intervention after a server restart, an
outage and a reboot; it backs off rather than hammering; and the suite in (1)
covers recovery, not just steady state.

**Measured, 2026-10-22.** A server restart was scheduled with
`systemd-run --on-active` and observed from an attached client:

```
carrying before the restart
went down at +46s
RESULT: still down 152s after the outage began
```

It does not recover, and it does not recover on the client's 120 s rekey either —
the observation ran past that interval with traffic being sent throughout. That
makes ADR-0019 the only mechanism on the table: waiting for the client's own
timer is not a recovery path, so the passive side has to re-initiate.

**A deployment defect found on the way, and fixed.** The server's daemon was a
bare process (`vallum run --config /etc/vallum/vallum0.toml`), with no unit at
all — `systemctl restart vallum` failed because there was nothing to restart.
Half of "always-on" is being supervised, and this host was not. It now runs as
`vallum.service` with `Restart=always`, which is what made the measurement above
possible: every earlier attempt was void because no restart ever happened.

**Resolved, protocol half (commits `40a76a8`, `064949c`).** The recovery path is
ADR-0019 end to end, pinned by protocol tests in the gate:
- The epoch is agreed on the wire (`40a76a8`): a peer that restarted claims its
  fresh count in `InitHello`, the responder agrees an epoch no lower than its own
  next, and both ends derive data keys at the same epoch — the measured
  "re-established every 120 s and still carried nothing" divergence cannot recur.
- The passive side re-initiates (`064949c`): a data message naming a session this
  side no longer holds offers a re-handshake, rate-limited to one offer per peer
  and one device-wide per 15 s, dialling the observed source without committing
  it as the peer's endpoint. The probe drives ten stale datagrams into a
  restarted server and pins exactly one offer granted with the tunnel back in
  the same process turn, no clock advanced and no client rekey involved.
- Both restart directions are pinned: server restarts while the client holds its
  session, and client restarts while the server holds its. Backoff/hammering is
  the existing rekey give-up budget on the active side plus the reinit budget on
  the passive side.

**Resolved on the real link, 2026-10-29 — the (1) dependency is met.**
`verify-remote.sh` now stops the *server* (the unit under `--product`, the
process for a scratch server) while the client stays attached and untouched, and
requires four things of the resulting minutes: the verdict must leave `up` and
reach `stale` once the last handshake is past `REJECT_AFTER_TIME`; the route for
a tunnel destination must still name the tunnel while every datagram sent dies
in it, so the no-leak result is the tunnel holding rather than a route that
quietly reverted; the client must carry again with nobody touching it; and the
recovered tunnel must not thrash. A ping stream fills the delivery window for
the whole outage, because the delivery rule cannot judge an idle tunnel — and an
idle client is exactly the case that used to report `up`.

**Measured against `wingman-vps`, 2026-10-29.** 731 datagrams into the dead
tunnel, none answered, with the route still naming it; `degraded` inside the
first minute, `stale` past 180 s; **carried again 4 s after the server
returned**, with the client daemon untouched; zero further handshakes in the
30 s that followed. The leg failed on its first two runs — first a `status` that
read the wrong socket, then a server-stop pattern that also matched the client —
which is what a gate is for.

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

**Resolved.** Three pieces, in the order the failure needed them.

- **The signal.** `vallum_client_verdict` rides every `--config` scrape as one
  series naming the host's state, and the `vallum-client` rule group pages on
  that label: `VallumClientLeaking` (no grace), `VallumClientBlocked`,
  `VallumClientDegraded`, `VallumClientStale`, `VallumClientReconnectLoop`. A
  `--control`-only scrape deliberately carries none of it: guard state and
  policy mode are properties of the host and the config, not of a bare socket.
  DNS failing is not a separate alert on purpose — the policy drops `:53` egress
  and the resolver install is fail-closed, so "DNS broke" *is* one of the four
  verdict states, which is what makes the paging signal the tested one.
- **The verdict was wrong in exactly the way this item exists for.** `up` was
  decided from handshake *presence*, and the delivery rule underneath it needs
  100 datagrams in the window to judge anything — so a laptop whose server died
  overnight reported `up` for as long as it stayed quiet. `stale` now decides
  first, from handshake *age* against the protocol's own `REJECT_AFTER_TIME`,
  and it is its own word rather than `blocked` (the process is alive) or
  `LEAKING` (packets still enter the tunnel and die there). The outage leg is
  the gate that exercises that word on a real link, which is also why the bug
  surfaced at all — the leg failed on its first run.
- **A config's own socket is honoured.** `vallum status` read
  `/run/vallum/<iface>.sock` whatever the config's `control` said, so a live
  daemon with its own socket was reported `not running`, and the verdict said
  `down` or `blocked` about a tunnel that was up. `vallum metrics` already
  resolved it the other way; both surfaces now agree, and `the_socket_is_the_one_the_config_names`
  is the unit gate for it.

---

## Next — after the seven hold

- **Per-app split tunnelling — v1 landed (shared member namespace).**
  Destination prefixes cannot express "browser through the tunnel, everything
  else direct". ADR-0023's first mechanism — a cgroup mark riding the tunnel's
  tables — was implemented, measured and abandoned the same day: a socket
  chooses its source address before any output-chain mark exists, so a marked
  member entered the tunnel with the physical source and the peer dropped it
  (`docs/proof/socket-cgroupv2.md`). What landed is the other measured option,
  in `vallum-quick/src/member.rs`: `[quick] app_class = true` makes `attach`
  create one shared mount+net namespace, bind a private `resolv.conf` naming
  the pushed resolvers, and move the tunnel device into it. The host installs
  no routes and rewrites no resolver; `vallum-quick app CONFIG NAME -- CMD`
  enters that namespace and carries the tunnel's source address; `detach` moves
  the device home and stops the holder. The gate carries the split (host
  lookup physical, member lookup and DNS inside the tunnel), detach, the
  refusal when detached, the re-attach cycle, and the crash-recovery cycle; the
  lab record is `docs/proof/member-netns.md`.

  Crash recovery is in the same amendment: the kernel destroys the device with
  the namespace, so the record is dropped, `attach` names the unit to restart,
  and `up` recovers on its own by restarting the daemon it owns.

  **Still out:** per-app DNS beyond the pushed resolver, per-app metrics and
  alerts, and riding a split (prefix-list) tunnel. Per ADR-0023's second
  amendment.
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
