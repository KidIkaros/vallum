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
#
# The tag must match the workspace version: a release whose tag and version
# disagree is how a package manager installs the wrong code.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

REPO="KidIkaros/vallum"
DRY=0
UPLOAD=1
while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY=1 ;;
        --no-upload) UPLOAD=0 ;;
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
    cp packaging/vallum@.service packaging/vallum-quick@.service "dist/$name/"
    tar -C dist -czf "dist/$name.tar.gz" "$name"
    rm -rf "dist/$name"
    cp target/debian/*.deb dist/ 2>/dev/null || true
    cp crates/vallum/target/generate-rpm/*.rpm dist/ 2>/dev/null || true
    ( cd dist && sha256sum *.deb *.rpm *.tar.gz > SHA256SUMS )
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
