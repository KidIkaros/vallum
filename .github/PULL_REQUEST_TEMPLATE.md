## Summary

What changes and why.

## Security / compatibility

- [ ] No wire change, or the change and its proof artefact are named.
- [ ] No secrets in logs, Debug output, or the TUI's default view.
- [ ] No shell introduced into the daemon.

## Test plan

- [ ] `cargo test --workspace`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test -p vallum --no-default-features`
- [ ] `cargo deny check`
- [ ] `scripts/e2e-netns.sh` (if the data plane or control plane changed)
