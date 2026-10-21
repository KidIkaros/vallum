# Contributing

A bare clone builds on its own — the crypto SDK is pinned to an exact git tag:

```sh
git clone https://github.com/KidIkaros/vallum.git
cd vallum
cargo build
```

To iterate on the SDK itself, clone it anywhere and add a `[patch]` section to
the workspace `Cargo.toml` — locally, never committed:

```toml
[patch."https://github.com/KidIkaros/OriginSDK"]
origin-crypto-sdk = { path = "../origin-crypto-sdk" }
```

## Before you send a change

Run the local gate of record:

```sh
./scripts/verify.sh          # fmt, clippy, tests, lean tests, deny, TUI snapshot
E2E=1 ./scripts/verify.sh    # also the namespace tunnel test
```

Protocol changes also need the relevant proof artefact and, for the PSK path,
`docs/proof/tamarin/psk_tag.spthy`.

## Style

- No `unsafe` in Vallum-owned crates.
- Keep the core and tunnel crates sans-IO; effects belong at the daemon edges.
- The daemon runs no shell. Admin tools may spawn programs with argument
  arrays, never `sh -c`.
- Secrets are redacted in `Debug` and never logged.
- Add an ADR (`docs/adr/`) for a decision that changes an architecture boundary,
  a wire format, or the security posture.

## Commits and reviews

Keep commits focused and explain the *why*. The private repository uses
`main`; CI must be green.

CI runs on every push and pull request (`test` on stable and the 1.95.0 MSRV,
`end-to-end` in two namespaces, `advisories and supply chain`, and the fuzz
matrix with a weekly deep run). The release gate of record stays
`scripts/verify.sh`.
