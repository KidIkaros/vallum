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

- Non-documentation IPs are committed: the VPS address `203.0.113.10` in
  `crates/vallum/src/net.rs`, `docs/alpha-readiness-2026-11-12.md`, `docs/plan-2026-11-09.md`,
  `scripts/accept-full-tunnel.sh`, and the operator's home-ISP address `198.51.100.7` in
  `docs/proof/live-traffic-audit.md` and `docs/alpha-readiness-2026-11-12.md`.
  Replace with `192.0.2.x` / `203.0.113.x` before the repo goes public.
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

1. **Wire `dns-proxy` into attach/up** (today it is a manual subcommand; leak protection needs
   it started with the tunnel and `captive_spoof` driven by guard state).
2. **Active leak checker** (Mullvad §9.8): periodic non-tunnel probe while connected.
3. **Crash-persistent lockdown before `network-pre.target`** (Mullvad §9.4) — unit exists,
   needs a boot-time test.
4. **Settings migration chain** (Mullvad §10.2): config versioning so alpha configs survive upgrades.
5. TLS/QUIC `DATAGRAM` and Shadowsocks carriers; multihop; relay selector; API fronting (post-alpha).

## Commitments (dated, verifiable)

- I will push the fmt/clippy fixes and re-check the hosted CI run for HEAD today.
- Operator decides the version and tags; I will not tag without the signing key decision.
