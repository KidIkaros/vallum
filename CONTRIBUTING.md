# Contributing

Vallum is developed as two sibling repositories because the workspace pins the
SDK by path:

```sh
git clone https://github.com/KidIkaros/vallum.git
git clone https://github.com/KidIkaros/OriginSDK.git origin-crypto-sdk
cd vallum
./scripts/bootstrap.sh   # if the sibling is missing
```

## Before you send a change

Run the same gates CI runs:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo test -p vallum --no-default-features
cargo deny check
bash scripts/e2e-netns.sh
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
`main`; CI must be green and branch protection requires the checks.
