#!/usr/bin/env bash
#
# Vallum is developed as two sibling repositories: this one and the public
# OriginSDK, because the workspace pins the SDK by path. Run this from the
# Vallum checkout after cloning it.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
sibling=$(cd "$root/.." && pwd)/origin-crypto-sdk

if [ -d "$sibling" ]; then
    echo "SDK sibling already exists: $sibling"
else
    echo "Cloning OriginSDK next to Vallum: $sibling"
    git clone https://github.com/KidIkaros/OriginSDK.git "$sibling"
fi

cat <<MSG

Layout:
  $(basename "$root")/        this repository
  origin-crypto-sdk/          the pinned SDK (sibling)

Next:
  cargo test --workspace
  cargo clippy --workspace --all-targets -- -D warnings
  bash scripts/e2e-netns.sh
MSG
