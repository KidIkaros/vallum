#!/usr/bin/env bash
# Regenerate the shell completion scripts from the built binary.
#
# These are build artifacts, not source. `vallum completions <shell>` emits
# them, and they used to be committed — which is how the zsh and fish copies
# came to advertise a `--no-host` behaviour the binary had stopped having.
# `scripts/check-package-manifest.sh` compares *filenames* across the three
# distribution channels, so it could never catch a stale *description*.
#
# Run this before packaging. `packaging/vallum.{bash,zsh,fish}` are gitignored.
set -euo pipefail
cd "$(dirname "$0")/.."

BIN=${VALLUM_BIN:-target/release/vallum}
if [ ! -x "$BIN" ]; then
    BIN=target/debug/vallum
fi
if [ ! -x "$BIN" ]; then
    echo "gen-completions: no binary at target/{release,debug}/vallum" >&2
    echo "gen-completions: run 'cargo build --release -p vallum' first" >&2
    exit 1
fi

for shell in bash zsh fish; do
    "$BIN" completions "$shell" > "packaging/vallum.$shell"
    printf '  %-24s %s lines\n' "packaging/vallum.$shell" "$(wc -l < "packaging/vallum.$shell")"
done
