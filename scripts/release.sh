#!/usr/bin/env bash
#
# Build and publish a release from this checkout.
#
# Hosted GitHub Actions is unavailable on this plan, so this script is the
# release pipeline: it builds the binaries, the .deb and .rpm, the tarball, and
# SHA256SUMS, then uploads them with `gh`.
#
#   scripts/release.sh                 # build, then create or update the release
#   scripts/release.sh --no-upload     # build into dist/ and stop
#   scripts/release.sh --dry-run       # print what would be built and uploaded
#   scripts/release.sh --skip-remote "why"   # release without a recent two-host run
#
# Nothing here is remembered, it is checked. A tag whose tree has the wrong
# version, a changelog that does not mention the release, a tarball missing a
# unit, or a tree that has never crossed two real hosts — each of those is a
# refusal, not a warning, because each of them has happened.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

REPO="KidIkaros/vallum"
DRY=0
UPLOAD=1
SKIP_REMOTE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY=1 ;;
        --no-upload) UPLOAD=0 ;;
        --skip-remote)
            shift
            SKIP_REMOTE="${1:-}"
            [ -n "$SKIP_REMOTE" ] || { echo "--skip-remote needs a reason" >&2; exit 1; }
            ;;
        -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
    shift
done

say() { printf '\n== %s\n' "$*"; }
run() {
    if [ "$DRY" -eq 1 ]; then
        printf '   would run: %s\n' "$*"
    else
        "$@"
    fi
}

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
[ -n "$version" ] || { echo "cannot read the workspace version" >&2; exit 1; }
tag="v$version"
name="vallum-$tag-x86_64-linux"

say "release $tag"
if [ ! -d ../origin-crypto-sdk ]; then
    echo "the SDK must be a sibling checkout: ../origin-crypto-sdk" >&2
    exit 1
fi

# ── Preflight ────────────────────────────────────────────────────────────
# Every check here exists because it has already gone wrong once.
fail() {
    printf '   FAIL  %s\n' "$*" >&2
    echo "refusing to release" >&2
    exit 1
}
ok() { printf '   ok    %s\n' "$*"; }

say "preflight"

if [ -n "$(git status --porcelain)" ]; then
    git status --short >&2
    fail "the working tree has uncommitted changes; a release is built from a commit"
fi
ok "working tree is clean"

if git rev-parse "$tag" >/dev/null 2>&1; then
    tagged=$(git rev-parse "$tag^{commit}")
    if [ "$tagged" != "$(git rev-parse HEAD)" ]; then
        fail "$tag is at ${tagged:0:7}, but HEAD is $(git rev-parse --short HEAD); move the tag or release the tagged commit"
    fi
    ok "$tag is at HEAD"
else
    ok "$tag does not exist yet; it will be created at HEAD"
fi

grep -q "^## $version" CHANGELOG.md || fail "CHANGELOG.md has no section for $version"
ok "CHANGELOG.md documents $version"

# The two-host gate. A stamp, written by scripts/verify-remote.sh, binds a pass
# to a commit — so "we ran it last month" cannot stand in for this tree.
stamp="${XDG_STATE_HOME:-$HOME/.local/state}/vallum/remote-verified"
if [ -n "$SKIP_REMOTE" ]; then
    printf '   skip  two-host verification: %s\n' "$SKIP_REMOTE"
elif [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$(git rev-parse HEAD)" ]; then
    ok "two hosts verified this commit"
else
    fail "no scripts/verify-remote.sh pass recorded for $(git rev-parse --short HEAD).
   Run: sudo ./scripts/verify-remote.sh <ssh-host>
   Or release anyway with: --skip-remote \"reason\""
fi

if [ "$DRY" -eq 1 ]; then
    echo "   would run: E2E=1 ./scripts/verify.sh"
else
    say "gate: E2E"
    E2E=1 ./scripts/verify.sh >/tmp/vallum-release-gate.log 2>&1 \
        || { tail -20 /tmp/vallum-release-gate.log >&2; fail "scripts/verify.sh failed (see /tmp/vallum-release-gate.log)"; }
    ok "scripts/verify.sh passed"
fi

say "building"
run cargo build --release -p vallum -p vallum-quick

say "packaging"
run rm -rf target/debian crates/vallum/target/generate-rpm dist
run cargo deb -p vallum --no-build
run bash -c "cd crates/vallum && cargo generate-rpm"

say "assembling the tarball"
if [ "$DRY" -eq 0 ]; then
    mkdir -p "dist/$name"
    cp target/release/vallum target/release/vallum-quick "dist/$name/"
    cp LICENSE README.md "dist/$name/"
    cp packaging/vallum.8 packaging/vallum-quick.8 packaging/vallum.toml.5 "dist/$name/"
    cp packaging/vallum.bash "dist/$name/"
    cp packaging/vallum@.service packaging/vallum-quick@.service \
        packaging/vallum-enroll@.service "dist/$name/"
    tar -C dist -czf "dist/$name.tar.gz" "$name"
    rm -rf "dist/$name"
    cp target/debian/*.deb dist/ 2>/dev/null || true
    cp crates/vallum/target/generate-rpm/*.rpm dist/ 2>/dev/null || true
    ( cd dist && sha256sum *.deb *.rpm *.tar.gz > SHA256SUMS )

    # Inspect what we are about to publish. A release once shipped a tarball
    # without the enrolment unit because a copy line had been edited in the
    # wrong place; nobody noticed until it was installed on a host.
    for member in vallum vallum-quick vallum@.service vallum-quick@.service \
        vallum-enroll@.service vallum.8 vallum-quick.8 vallum.toml.5; do
        tar -tzf "dist/$name.tar.gz" | grep -qx "$name/$member" \
            || fail "the tarball is missing $member"
    done
    ok "the tarball carries both binaries, all three units and the man pages"
    ls -l dist
else
    echo "   would assemble dist/$name.tar.gz, the .deb, the .rpm, and SHA256SUMS"
fi

if [ "$UPLOAD" -eq 0 ]; then
    say "built (not uploaded)"
    exit 0
fi

say "publishing $tag"
if [ "$DRY" -eq 1 ]; then
    echo "   would create or update the GitHub release $tag with dist/*"
    exit 0
fi

if ! git rev-parse "$tag" >/dev/null 2>&1; then
    run git tag -a "$tag" -m "Vallum $tag"
fi
run git push origin "$tag"

if gh release view "$tag" --repo "$REPO" >/dev/null 2>&1; then
    run gh release upload "$tag" dist/* --repo "$REPO" --clobber
else
    run gh release create "$tag" dist/* --repo "$REPO" \
        --title "Vallum $tag" \
        --notes "Vallum $tag. Verification: scripts/verify.sh with E2E=1."
fi
say "published $tag"
