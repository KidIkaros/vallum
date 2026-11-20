#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Build the Vallum Desktop (vallum-gui) Linux bundle(s) and stage them into
# dist/ with clean, space-free filenames.
#
# Usage:
#   scripts/package-desktop.sh [--bundles deb[,rpm,appimage]] [--out-dir dist]
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

BUNDLES="${BUNDLES:-deb}"
OUT_DIR="${OUT_DIR:-dist}"

while [ $# -gt 0 ]; do
    case "$1" in
        --bundles)
            shift
            BUNDLES="${1:-}"
            [ -n "$BUNDLES" ] || { echo "--bundles needs a value" >&2; exit 1; }
            ;;
        --out-dir)
            shift
            OUT_DIR="${1:-}"
            [ -n "$OUT_DIR" ] || { echo "--out-dir needs a value" >&2; exit 1; }
            ;;
        -h|--help)
            sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            exit 1
            ;;
    esac
    shift
done

command -v cargo-tauri >/dev/null 2>&1 || {
    echo "package-desktop: cargo-tauri not found (install tauri-cli)" >&2
    exit 1
}

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
[ -n "$version" ] || { echo "package-desktop: cannot read workspace version" >&2; exit 1; }

# Single source of truth (#33): the workspace version drives the bundle name the
# stager looks for, so sync it into tauri.conf.json before building. A stale
# config version once produced a bundle the stager could not find (1.9.0 release).
sed -i "s/\"version\": \"[^\"]*\"/\"version\": \"$version\"/" crates/vallum-gui/tauri.conf.json

( cd crates/vallum-gui && cargo tauri build --bundles "$BUNDLES" )

mkdir -p "$OUT_DIR"
staged=0

stage_one() {
    local src=$1 dst=$2
    [ -f "$src" ] || return 0
    cp "$src" "$dst"
    echo "staged: $dst"
    staged=$((staged + 1))
}

stage_one "target/release/bundle/deb/Vallum Desktop_${version}_amd64.deb" \
    "$OUT_DIR/vallum-desktop_${version}_amd64.deb"

for rpm_src in "target/release/bundle/rpm/Vallum Desktop-${version}-1."*.rpm; do
    [ -f "$rpm_src" ] || continue
    arch=${rpm_src##*.}
    stage_one "$rpm_src" "$OUT_DIR/vallum-desktop-${version}-1.${arch}.rpm"
done

stage_one "target/release/bundle/appimage/Vallum Desktop_${version}_amd64.AppImage" \
    "$OUT_DIR/vallum-desktop_${version}_amd64.AppImage"

[ "$staged" -gt 0 ] || {
    echo "package-desktop: no desktop bundles found under target/release/bundle" >&2
    exit 1
}
