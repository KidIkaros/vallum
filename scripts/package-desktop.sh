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

( cd crates/vallum-gui && cargo tauri build --bundles "$BUNDLES" )

mkdir -p "$OUT_DIR"
staged=0

deb_src="target/release/bundle/deb/Vallum Desktop_${version}_amd64.deb"
if [ -f "$deb_src" ]; then
    deb_dst="$OUT_DIR/vallum-desktop_${version}_amd64.deb"
    cp "$deb_src" "$deb_dst"
    echo "staged: $deb_dst"
    staged=$((staged + 1))
fi

for rpm_src in "target/release/bundle/rpm/Vallum Desktop-${version}-1."*.rpm; do
    [ -f "$rpm_src" ] || continue
    arch=${rpm_src##*.}
    rpm_dst="$OUT_DIR/vallum-desktop-${version}-1.${arch}.rpm"
    cp "$rpm_src" "$rpm_dst"
    echo "staged: $rpm_dst"
    staged=$((staged + 1))
done

app_src="target/release/bundle/appimage/Vallum Desktop_${version}_amd64.AppImage"
if [ -f "$app_src" ]; then
    app_dst="$OUT_DIR/vallum-desktop_${version}_amd64.AppImage"
    cp "$app_src" "$app_dst"
    echo "staged: $app_dst"
    staged=$((staged + 1))
fi

[ "$staged" -gt 0 ] || {
    echo "package-desktop: no desktop bundles found under target/release/bundle" >&2
    exit 1
}
