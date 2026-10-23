# The browsing-impact suite — spec

Roadmap item 1. The suite that proves what a browser experiences through
Vallum, and the definition of done for the leak work in items 2, 3 and 4.

Runs from `scripts/verify-remote.sh` against a real server, because a same-host
client cannot exercise egress.

## Correction to the roadmap's problem statement

`docs/roadmap.md` item 1 claims nothing has measured four things. Three of them
are already asserted in `verify-remote.sh` and the claim is stale. Measured
against the script at `b973ee3`:

| Roadmap claim | Reality | Where |
|---|---|---|
| "does not prove an oversized payload arrives" | **asserted** — a 1 MB HTTPS response must arrive intact, failing as "path MTU blackhole" | line 445 |
| "does not prove nothing escapes the tunnel's prefixes" | **asserted** — `ip route get` must resolve to a `vallum*` device, for IPv4 and IPv6 | lines 455–470 |
| "cannot exercise IPv6" | **handled** — skips with an explicit note when the host has no global IPv6 | line 472 |
| "does not prove DNS resolves in-tunnel" | **partly true** — `dig @1.1.1.1` proves egress through the tunnel, not that the *system resolver* is the tunnel's | line 423 |
| "does not prove how split and full tunnel differ" | **true** — the config is rewritten to a split tunnel before testing, so full tunnel is never exercised | line 381 |

So this is not a from-scratch build. It is three gaps in an existing harness.

## What is genuinely missing

### A1 — The system resolver uses the tunnel, and nowhere else

Two distinct claims, and only the second is new:

1. A lookup succeeds through the tunnel. *Already covered* by `dig @1.1.1.1`.
2. A lookup does not succeed **outside** it. This is the leak, and it is only
   observable with the tunnel down — which is what the fail-closed policy
   (item 2) and the port-53 drop (item 3) now provide. Line 474 recorded this as
   blocked on items 2 and 3; both are resolved, so it is unblocked.

**Assertion:** with the tunnel attached and then killed, a system-resolver lookup
must fail closed — either refused or answered only through the tunnel — and must
never reach the physical link's resolver.

**Positive control:** with the policy off, the same lookup must be observed
reaching the physical link. Without this control the assertion cannot be shown
to be capable of failing.

### A2 — Full tunnel, not only split tunnel

The harness rewrites the client config into a split tunnel so the test machine's
own routing and resolver are never disturbed (line 381). That is the right
default for a test that must not break the host, but it means the leak checks
run against the configuration least likely to leak.

**Assertion:** the same leak assertions hold with a full tunnel attached, run in
a network namespace or on a disposable host so the invoking machine's routing is
still never touched.

**Positive control:** a deliberately mis-scoped split route must be caught.

### A3 — No foreign source enters the tunnel

New as of `7aa9ab8`. A packet whose inner source is not an address the interface
owns is refused by the peer's `allowed_ips` check; `run` now declines it locally
and logs the address.

**Assertion:** no datagram reaches the peer carrying a source outside the
interface's addresses, and any that is attempted appears in the client log as
`does not own that address`.

**Positive control:** inject a packet with a foreign source and confirm the
assertion goes red.

## Scope: IPv6

Internet IPv6 egress is **blocked on infrastructure**, not on code. `wingman-vps`
has no global IPv6 (see `docs/roadmap.md` item 1). The suite therefore asserts:

- peer-to-peer IPv6: `fd00:7::2` to `fd00:7::1` round-trips;
- no foreign IPv6 source enters the tunnel;
- internet IPv6 as an explicitly **blocked** check, reported as blocked rather
  than omitted or silently passing.

An assertion that can only fail is worse than a documented gap, and an assertion
that silently skips is worse than both.

## Rule for every assertion

Each assertion ships with a positive control that proves it can go red. A suite
that can only pass is the same defect as a `status` that only says `up` — which
is how a tunnel dropping half its datagrams reported healthy for a whole session.

## Tickets, blockers first

| # | Ticket | Blocked by | Done means |
|---|---|---|---|
| T1 | A3: foreign-source assertion + positive control | — | injecting a foreign source fails the suite; the clean run passes |
| T2 | A1: DNS closed with the tunnel down, plus the policy-off control | — | both directions observed; each fails when its condition is removed |
| T3 | A2: run the leak assertions under a full tunnel in a netns | T1, T2 | full-tunnel leak checks pass, host routing untouched |
| T4 | Correct item 1's problem statement in `docs/roadmap.md` | T1–T3 | the roadmap describes the suite that exists |

T4 is last because the document should describe what was built, not what was
intended. It is not optional: the stale claims in item 1 are why three existing
assertions were about to be rebuilt from scratch.
