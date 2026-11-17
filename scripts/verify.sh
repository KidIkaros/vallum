#!/usr/bin/env bash
#
# The gate of record. `.github/workflows/ci.yml` runs the same checks on every
# push, but this script is what "green" means: it carries the checks that need
# this machine (the standalone-clone build, the release-signature round trip),
# and `scripts/release.sh` re-runs it with E2E=1 before a tag is published.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

# The desktop console links the system WebView, so `--workspace` needs its
# development files. Say that here rather than let it surface as a `-sys` build
# failure halfway through clippy.
if ! pkg-config --exists webkit2gtk-4.1 gtk+-3.0 libsoup-3.0; then
    echo "vallum-gui needs the WebKitGTK development files:" >&2
    echo "  sudo apt install -y --no-install-recommends \\" >&2
    echo "    libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev \\" >&2
    echo "    libjavascriptcoregtk-4.1-dev libxdo-dev librsvg2-dev \\" >&2
    echo "    libayatana-appindicator3-dev patchelf" >&2
    exit 1
fi

echo "== fmt"
cargo fmt --all -- --check
echo "== clippy (all features)"
cargo clippy --workspace --all-targets --all-features -- -D warnings
echo "== tests"
cargo test --workspace
echo "== lean daemon tests"
cargo test -p vallum --no-default-features
echo "== shell syntax"
bash -n scripts/install.sh scripts/release.sh scripts/e2e-netns.sh scripts/seccomp-trace.sh scripts/seccomp-enforce.sh scripts/seccomp-log.sh scripts/verify-remote.sh scripts/check-zstd-ignores.sh scripts/check-state-coverage.sh scripts/accept-desk-restore.sh scripts/accept-deployment-backup.sh scripts/backup-deployment.sh
echo "== zstd ignore guard"
scripts/check-zstd-ignores.sh
echo "== durable state coverage"
# A new state store that the backup document does not name is a silent data
# loss on restore, and 1.8.0's desk was exactly that. The check is a grep
# against the document, so it costs nothing and fires on the next component
# that keeps state rather than on the incident.
scripts/check-state-coverage.sh
echo "== desk database copy/restore"
# The account database is the only state in the product that cannot be
# rebuilt, so the copy-and-restore path is a gate rather than a paragraph in
# the operator docs. Stdlib only: no daemon, no root, no network.
scripts/accept-desk-restore.sh
echo "== deployment copy/restore"
# verify-remote's --clean-remote deletes a live deployment and now refuses
# unless this backup path works, so the path is a gate rather than a promise.
scripts/accept-deployment-backup.sh
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
    # Both binaries, not just the daemon: the full-tunnel phase installs the
    # product's own route plan with `vallum-quick`, and `scripts/e2e-netns.sh`
    # refuses to start without it. Neither the TUI step above (`cargo build -p
    # vallum`) nor `cargo test` leaves a plain `target/debug/vallum-quick`, so
    # this gate failed on every clean checkout — which is what `release.sh`
    # runs before it builds anything.
    echo "== e2e (netns): both binaries"
    cargo build -p vallum -p vallum-quick
    echo "== e2e (netns)"
    bash scripts/e2e-netns.sh
    echo "== syscall allow-list (ADR-0028)"
    bash scripts/seccomp-trace.sh
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
