#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The CI feedback loop: run the same gates, in the same order, with the same
# commands ci.yml uses — locally, before a push.
#
# Why this exists: pushing to learn is not a loop. Three runs in one afternoon
# ended `cancelled` because the next push superseded them, and one was misread
# as a failure when it was a cancellation. A red-capable command that runs here
# is the only thing that makes a push an assertion instead of an experiment.
#
#   scripts/ci-local.sh          # the gates, skipping the slow e2e
#   scripts/ci-local.sh --full   # including scripts/e2e-netns.sh
#
# Each step prints PASS/FAIL and the loop stops at the first failure, so the
# output reads like the CI job summary.
set -uo pipefail
cd "$(dirname "$0")/.."

# The rehearsal is only a rehearsal if it runs on the toolchain CI runs on. The
# repo pins it in rust-toolchain.toml; if the local toolchain is not that one,
# every gate below is a different gate from the one CI executes - which is how
# a green local run and a red CI run happen on the same commit.
PINNED=$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml 2>/dev/null | head -1)
if [ -n "$PINNED" ]; then
    LOCAL=$(rustc --version 2>/dev/null | awk '{print $2}')
    case "$LOCAL" in
        "$PINNED"|"$PINNED".*) ;;
        *)
            echo "the local toolchain ($LOCAL) is not the pinned one ($PINNED)."
            echo "The gates below would not be the gates CI runs."
            echo "  rustup toolchain install $PINNED"
            exit 1
            ;;
    esac
    echo "toolchain $LOCAL (pinned: $PINNED)"
fi
cd "$(dirname "$0")/.."

FULL=0
[ "${1:-}" = "--full" ] && FULL=1
FAILED=""
STEP=0

step() {
    STEP=$((STEP + 1))
    printf '\n== %d. %s\n' "$STEP" "$1"
}

check() {
    local name=$1; shift
    if "$@" >/tmp/ci-local.out 2>&1; then
        echo "   PASS  $name"
    else
        echo "   FAIL  $name"
        tail -25 /tmp/ci-local.out | sed 's/^/         /'
        FAILED=$name
        return 1
    fi
}

# 1. The console's frontend is a compile-time dependency: `tauri::generate_context!()`
#    embeds ui/dist and panics without it, so a fresh checkout cannot compile the
#    workspace at all. CI builds it first; so does this.
step "Console frontend (ui/dist is a build artifact)"
if [ -d crates/vallum-gui/ui/node_modules ]; then
    echo "   skip  node_modules present"
else
    ( cd crates/vallum-gui/ui && npm ci --no-audit --no-fund ) >/tmp/ci-local.out 2>&1 \
        || { echo "   FAIL  npm ci"; tail -15 /tmp/ci-local.out; exit 1; }
fi
( cd crates/vallum-gui/ui && npm run build ) >/tmp/ci-local.out 2>&1 \
    || { echo "   FAIL  npm run build"; tail -15 /tmp/ci-local.out; exit 1; }
echo "   PASS  ui/dist built"

step "Format (scoped to the Vallum crates)"
check fmt cargo fmt \
    -p vallum-core -p vallum-tunnel -p vallum -p vallum-crypto \
    -p vallum-crypto-sdk -p vallum-crypto-contract -p vallum-config \
    -p vallum-quick -p vallum-gui -- --check || true

step "Clippy (all features, -D warnings)"
check clippy cargo clippy --workspace --all-targets --all-features -- -D warnings || true

step "Test (workspace)"
check test cargo test --workspace || true

step "Compile every target (MSRV)"
if rustup toolchain list | grep -q '^1\.95\.0'; then
    check msrv cargo +1.95.0 check --workspace --all-targets || true
else
    echo "   skip  1.95.0 toolchain not installed"
fi

step "Test the lean daemon (no TUI)"
check lean cargo test -p vallum --no-default-features || true

step "Package manifest parity (install.sh == deb == rpm)"
check parity bash scripts/check-package-manifest.sh || true
check "the SDK is pinned once" bash scripts/check-sdk-pin.sh || true

step "Headless TUI snapshot"
check tui bash -c 'cargo build -q -p vallum && ./target/debug/vallum tui --snapshot --ansi >/dev/null' || true

if [ "$FULL" = 1 ]; then
    step "End-to-end (two namespaces, real kernel)"
    QUICK=$PWD/target/release/vallum-quick check e2e bash scripts/e2e-netns.sh $PWD/target/release/vallum || true
fi

echo

step "Install layout (staged; no root, no container runtime)"
check "install layout" scripts/accept-install-layout.sh || true

step "The acceptance pair (a server and a client, provisioned here)"
check "acceptance pair" scripts/accept-pair.sh || true

echo
echo "the recorded verdicts (each bound to a commit):"
if [ -d .vallum-verdicts ]; then
    for f in .vallum-verdicts/*.json; do
        [ -e "$f" ] || continue
        printf '  %-22s %-8s %s assertions  %s\n' \
            "$(basename "$f" .json)" \
            "$(sed -n 's/.*"status": "\([^"]*\)".*/\1/p' "$f")" \
            "$(sed -n 's/.*"assertions": \([0-9]*\).*/\1/p' "$f")" \
            "$(sed -n 's/.*"tree": "\([^"]*\)".*/\1/p' "$f")"
    done
else
    echo "  (none recorded yet)"
fi

echo
if [ -z "$FAILED" ]; then
    echo "== PASS - every gate CI runs is green here"
    [ "$FULL" = 0 ] && echo "   (e2e skipped; run with --full before a release)"
    exit 0
fi
echo "== FAIL at: $FAILED"
exit 1
