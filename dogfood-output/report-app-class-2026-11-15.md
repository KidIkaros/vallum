# Dogfood: per-app tunnelling (`app_class`) driving a headless browser

**Date:** 2025-11-15 · **Build:** v1.7.0 line, HEAD `be290d5` + unit fix `491592d` · **Target:** `vallum-quick app` (ADR-0023) as the substrate for AI-agent browsing

**Scenario under test:** a headless Chrome for Testing (157.0.8103.78) launched as a member process of a dedicated tunnel device `vallum-app-fox` (peer `app-fox`, 10.99.90.5) against the live `wingman-vps` server (`vallumrc`, port 51921). The user's product idea: agent browsing with its own egress identity, separate from the operator's home identity.

## Executive summary

3 issues (1 High already fixed and pushed, 1 High product-gap with workaround, 1 Low ops).
The core product claim of ADR-0023 **holds on a real deployment**: members egress with the
tunnel's identity while the host keeps its own, simultaneously; DNS is namespace-private; a
dead tunnel refuses to launch members rather than leaking them to the host network; recovery
is clean. The feature was unreachable on real deployments until today's unit fix.

| # | Finding | Severity | Category | Status |
|---|---|---|---|---|
| 1 | `vallum-quick@.service` lacks CAP_SYS_ADMIN — app_class attach fails on every real deployment (`unshare: Operation not permitted`) | High | Functional | **Fixed** (`491592d`, synced to host, verified live) |
| 2 | `PrivateTmp=true` gives members an empty private /tmp — downloads/screenshots are invisible to the host and destroyed on unit stop | High | UX/Functional | Workaround verified (shared fs); product fix proposed |
| 3 | No passwordless path for member launches on a deployed host; sudoers covers `start/stop` but not `restart` for `vallum-quick@*` | Low | Ops | Noted |

## What was verified working (evidence)

- **Identity separation:** member `curl https://ifconfig.me` → `107.175.238.82` (VPS); host at the same moment → `74.101.134.101` (home ISP).
- **Rendered browser through the tunnel:** Chrome `--screenshot` of ifconfig.me shows IP `107.175.238.82`, UA `HeadlessChrome/157.0.8103.78` (`app-class-egress.png`).
- **Downloads through the tunnel:** 10 MB (`proof.ovh.net/files/10Mb.dat`) in 2.8 s (~3.8 MB/s), md5 `f1c9645dbc14efddc7d8a322685f26eb` matches the known-good file; host download in parallel unaffected.
- **DNS:** member namespace carries a private `resolv.conf` bound by attach (nameservers 1.1.1.1/1.0.0.1); `getent` resolves inside the namespace.
- **Fail-closed (stronger than the ADR states):** stopping the daemon tears the holder down, and `vallum-quick app` then **refuses to launch**: "launching `fox` now would run outside the tunnel … Refusing rather than launching, per ADR-0023's membership decision". An agent process can never silently fall back to the home IP. Host networking unaffected throughout.
- **Recovery:** `start vallum@vallum-app-fox + vallum-quick@vallum-app-fox` → handshake fresh, member egress back to the VPS.

## Issue detail

### 1. The shipped unit cannot run app_class (High — fixed)

`vallum-quick@.service` bounded capabilities to `NET_ADMIN + DAC_OVERRIDE`; the member-namespace
holder needs `unshare(CLONE_NEWNET | CLONE_NEWNS)` → `CAP_SYS_ADMIN`. Journal:
`unshare: unshare failed: Operation not permitted` → "the member namespace holder did not come up".
**Why the gates missed it:** `verify-remote --app-class` runs the client under the gate's own root,
never under the shipped unit's sandbox — the classic gap a real deployment exposes.
**Fix:** `CAP_SYS_ADMIN` added to `Ambient`/`Bounding` with a comment; synced via `vallum-ops sync`;
attach verified live. Note: `restart` is not in the passwordless sudoers rule for `vallum-quick@*`
(use `stop` + `start`), which cost a round-trip during the fix.

### 2. Member artifacts vanish into the unit's private tmp (High — workaround)

The unit runs `PrivateTmp=true`; the holder inherits that mount namespace, so every member process
sees an **empty private /tmp**: a browser screenshot or download written to `/tmp/...` is invisible
to the host and destroyed when the unit stops. For the AI-browsing use case — downloads are the point —
artifacts silently disappear.
**Workaround (verified):** the rest of the filesystem is shared; members can write to the operator's
home/lab paths and the host sees them (files land root-owned; consider a umask/ownership story).
**Product fix proposal:** in the holder's setup (it already bind-mounts the private `resolv.conf`
over `/etc/resolv.conf`), bind the host's artifact directory — reachable from the unit as
`/proc/1/root/tmp`-style paths — over a fixed member path (e.g. `/var/lib/vallum/members/<name>/out`),
so downloads survive and are host-visible by construction.

### 3. Deployment friction (Low)

Using `app_class` on a deployed host required a one-time polkit-approved script (config install +
a `NOPASSWD: /usr/bin/vallum-quick app *` sudoers rule). Neither `install.sh`'s sudoers template nor
`docs/deployment/client.md` mentions app-class setup. A doc section + an opt-in installer flag would
close it.

## Not tested (named)

- camoufox/anti-fingerprinting: declined — masking to work around a specific site ban is ban
  evasion; the underlying ban was behaviour-based (download volume), which identity separation
  does not cure. Rate/volume discipline in the agent is the fix.
- WebRTC/STUN leak behaviour of the member browser (a dedicated fingerprint/leak pass).
- The GUI's app-class surface; member attach/detach churn under repeated launches.
- Long-lived member session across a server restart (settle-window behaviour).

## Reproduction state

Device still running for hands-on use: `sudo systemctl start vallum@vallum-app-fox vallum-quick@vallum-app-fox`,
member launch: `sudo vallum-quick app /etc/vallum/vallum-app-fox.toml fox -- <cmd>`.
Teardown: stop both units, `sudo vallum peer remove app-fox` on the server, remove the
`/etc/sudoers.d/vallum-app-member` rule.
