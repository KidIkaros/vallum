# Alpha gap review, 2026-11-14

Method: [`software-delivery-process`](../README.md) Verify + Release passes, run against
`docs/alpha-readiness-2026-11-12.md`, `docs/publication-checklist.md`, and the Mullvad
breakdown (`docs/research/mullvad-reference.md`). Every row is a checkable item.

## Defects found and fixed in this pass

| Gate | Finding | Fix |
|---|---|---|
| Implement (fmt gate) | `cargo fmt --check` failed on `commands/doctor.rs` (would have failed CI) | `cargo fmt --all` |
| Implement (lint gate) | `clippy -D warnings` failed: 29 `expect_used` hits in new Wave 6 test modules | `#[allow(clippy::expect_used, clippy::unwrap_used)]` on the test modules, as in the sibling modules |

Wave 6 was previously verified with `cargo test` only. Both gates are now green locally on the
pinned toolchain (rustc 1.100.0).

## Release blockers (alpha cannot ship until these are closed)

1. **No version decision / tag.** Tree is `1.6.5` (CHANGELOG) but the last tag is `v1.6.4`;
   `release.sh --dry-run` refuses until a signed tag sits at HEAD. Owner: operator. Decision needed.
2. **Hosted CI never run on current HEAD.** Runs for Wave 6 were still queued at review time.
3. **Repository is private.** Gates prove the product works; none make it reachable.
4. **Two-host gate (`verify-remote.sh`) has not been re-run since Wave 4–6.** The stamp is for an older commit.

## Pre-publication hygiene (publication-checklist §2, still open)

- Non-documentation IPs (the VPS and the operator's home ISP) were committed in code, docs and a script. **Scrubbed 2026-11-14** to `203.0.113.10` / `198.51.100.7`; `accept-full-tunnel.sh` now requires `SERVER_IP` or an `ssh -G` hostname instead of a baked-in fallback. Still present in git history: a history rewrite is a separate decision.
- History scan for private keys / `gh*_` tokens: 0 hits on `git log -p --all`.
- README screenshots must not show the endpoint (the Devices-panel capture does).

## Open findings carried from the premortem (alpha-readiness §"Open findings")

Unchanged: token invite cannot carry DNS/PSK/shaping; ticket host:port derived three ways;
seccomp check's oracle is the artifact it checks; two-host evidence is a bare hash; verdict
files are forgeable. None is a blocker alone; each should either be fixed or stated in the
release notes ("say what is true").

## Mullvad parity: what we still lack

Built: tri-hybrid PQ, LWO, tcp/auto carriers + upgrade, DAITA-style shaping, leak guard,
lockdown, content-blocker resolver, loopback DNS proxy, MTU tuning, split tunnel via namespace.

Not built (ordered by alpha value, lowest effort first):

1. ~~**Wire `dns-proxy` into attach/up**~~ — **landed 2026-11-14**: `[quick] dns_proxy = true`
   makes `attach`/`up` start the forwarder as a child of `vallum-quick@<stem>.service`
   (pidfile `/run/vallum/<if>.dns-proxy.pid`), point the resolver at `127.0.0.1`, and kill it
   on `detach`/`down`/`systemctl stop`; `captive_spoof` follows session liveness via the
   control socket (dead past the watchdog window → `A` answered `198.51.100.1`).
2. ~~**Active leak checker** (Mullvad §9.8)~~ — **landed 2026-11-14**: `vallum-quick leak-check`
   + periodic TTL=1 non-tunnel probe in `vallum-quick watch` (every 60s via
   `VALLUM_LEAK_CHECK_SECS`), state persisted at `/run/vallum/<if>.leak-check`,
   and surfaced in `vallum doctor` (`active_leak`).
3. ~~**Crash-persistent lockdown before `network-pre.target`** (Mullvad §9.4)~~ — **verified 2026-11-14**:
   `packaging/vallum-guard@.service` ordering (`Before=network-pre.target`, no `PartOf`) and
   DNS-free `policy = "lockdown"` fallback pinned in `policy_json.rs`.
4. ~~**Settings migration chain** (Mullvad §10.2)~~ — **landed 2026-11-14**: `schema_version`
   + `vallum_config::migrate_toml` (`v0` -> `v1` canonicalizing legacy `failure_policy` aliases,
   injecting `DEFAULT_FWMARK` for full-tunnel configs, and refusing future schema versions).
5. ~~TLS/QUIC `DATAGRAM` and Shadowsocks carriers; multihop; relay selector; API fronting (post-alpha).~~ — **landed 2026-11-14**:
   - `carrier = "ss"`, `"tls"`, `"quic"` (+ `ss_psk`, `tls_sni`),
   - 2-hop `[quick] via = "<entry-config>"` multihop,
   - `vallum peer select` latency/reachability relay selector,
   - `[enroll] front_port`/`front_tls`/`front_sni` + `vallum setup --join --front-url`/`--front-host` API fronting,
   - `vallum-gui` Interface editor parity.

Verification note for item 1: forwarding relay exercised end-to-end in an unprivileged user
namespace against a mock upstream; attach/detach dry-run plans checked; the pidfile
spawn → SIGTERM → port-free lifecycle run against the real binary. Not yet exercised on a
real two-host tunnel — fold it into the next `verify-remote.sh` run.

## Commitments (dated, verifiable)

- I will push the fmt/clippy fixes and re-check the hosted CI run for HEAD today.
- Operator decides the version and tags; I will not tag without the signing key decision.
