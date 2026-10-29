#!/usr/bin/env bash
#
# The gate of record. `.github/workflows/ci.yml` runs the same checks on every
# push, but this script is what "green" means: it carries the checks that need
# this machine (the standalone-clone build, the release-signature round trip),
# and `scripts/release.sh` re-runs it with E2E=1 before a tag is published.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

echo "== fmt"
cargo fmt --all -- --check
echo "== clippy (all features)"
cargo clippy --workspace --all-targets --all-features -- -D warnings
echo "== tests"
cargo test --workspace
echo "== lean daemon tests"
cargo test -p vallum --no-default-features
echo "== shell syntax"
bash -n scripts/install.sh scripts/release.sh scripts/e2e-netns.sh scripts/verify-remote.sh scripts/check-zstd-ignores.sh
echo "== zstd ignore guard"
scripts/check-zstd-ignores.sh
echo "== supply chain"
cargo deny check
echo "== standalone source build"
# A release tarball and a bare `git clone` must build without a sibling
# OriginSDK checkout: the SDK is a git dependency, and this clones the
# committed state, which is exactly what a contributor receives. Only
# `cargo metadata` runs — the dep graph is what used to need the sibling.
clone_dir=$(mktemp -d)
git clone --quiet "file://$root" "$clone_dir/vallum"
( cd "$clone_dir/vallum" && cargo metadata --format-version 1 >/dev/null )
rm -rf "$clone_dir"
echo "== TUI snapshot"
cargo build -p vallum
cargo run -q -p vallum -- tui --snapshot --width 120 --height 30 > /tmp/vallum-tui.txt
grep -q Vallum /tmp/vallum-tui.txt
if [ "${E2E:-0}" = "1" ]; then
    echo "== e2e (netns)"
    bash scripts/e2e-netns.sh
fi
echo "== release signature round trip"
# install.sh's trust decision, exercised offline: sign a fake SHA256SUMS with
# a throwaway key, verify it, and prove a tampered checksum file is rejected.
sig_dir=$(mktemp -d)
ssh-keygen -t ed25519 -f "$sig_dir/key" -N '' -C vallum-release -q
echo "vallum-release $(cut -d' ' -f1-2 "$sig_dir/key.pub")" > "$sig_dir/allowed_signers"
printf 'abc123  vallum-v0.0.0-x86_64-linux.tar.gz\n' > "$sig_dir/SHA256SUMS"
ssh-keygen -Y sign -f "$sig_dir/key" -n file "$sig_dir/SHA256SUMS" 2>/dev/null
ssh-keygen -Y verify -f "$sig_dir/allowed_signers" -n file \
    -s "$sig_dir/SHA256SUMS.sig" -I vallum-release < "$sig_dir/SHA256SUMS" >/dev/null
printf 'tamper  vallum-v0.0.0-x86_64-linux.tar.gz\n' > "$sig_dir/SHA256SUMS"
if ssh-keygen -Y verify -f "$sig_dir/allowed_signers" -n file \
    -s "$sig_dir/SHA256SUMS.sig" -I vallum-release < "$sig_dir/SHA256SUMS" >/dev/null 2>&1; then
    echo "a tampered SHA256SUMS verified — the signature gate is broken" >&2
    exit 1
fi
rm -rf "$sig_dir"
echo "PASS"
