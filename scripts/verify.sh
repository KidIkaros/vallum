#!/usr/bin/env bash
#
# The local gate of record. Hosted GitHub Actions is unavailable on the
# private/free plan, so this script is what "green" means.
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
bash -n scripts/install.sh scripts/release.sh scripts/e2e-netns.sh
echo "== supply chain"
cargo deny check
echo "== TUI snapshot"
cargo build -p vallum
cargo run -q -p vallum -- tui --snapshot --width 120 --height 30 > /tmp/vallum-tui.txt
grep -q Vallum /tmp/vallum-tui.txt
if [ "${E2E:-0}" = "1" ]; then
    echo "== e2e (netns)"
    bash scripts/e2e-netns.sh
fi
echo "PASS"
