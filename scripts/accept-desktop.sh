#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Gate: install and cleanly remove the vallum-desktop .deb inside a clean
# Ubuntu 24.04 container, verifying binary, .desktop, icons, and zero leftovers.
#
#   scripts/accept-desktop.sh [path/to/vallum-desktop_*.deb]
set -uo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO"

ASSERTIONS=0
NAME="vallum-desktop-accept"
DEB=${1:-}

say() { echo "[desktop] $*"; }
die() { echo "[desktop] FAIL: $*" >&2; exit 1; }
ok()  { ASSERTIONS=$((ASSERTIONS + 1)); printf '   ok    %s\n' "$*"; }

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap 'rc=$?; cleanup; "$REPO/scripts/verdict.sh" accept-desktop "$([ "$rc" -eq 0 ] && echo passed || echo failed)" "${ASSERTIONS:-0}"' EXIT

if [ -z "$DEB" ]; then
    DEB=$(ls -1t dist/vallum-desktop_*_amd64.deb 2>/dev/null | head -1 || true)
fi
if [ -z "$DEB" ] || [ ! -f "$DEB" ]; then
    say "building vallum-desktop .deb via scripts/package-desktop.sh"
    bash scripts/package-desktop.sh --bundles deb || die "package-desktop.sh failed"
    DEB=$(ls -1t dist/vallum-desktop_*_amd64.deb 2>/dev/null | head -1 || true)
fi
[ -f "$DEB" ] || die "no vallum-desktop .deb found"

pkg_name=$(dpkg-deb -f "$DEB" Package)
[ "$pkg_name" = "vallum-desktop" ] || die "expected Package: vallum-desktop, got '$pkg_name'"
ok "package name is vallum-desktop (no collision with vallum daemon)"

say "starting clean ubuntu:24.04 container"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" ubuntu:24.04 sleep 300 >/dev/null \
    || die "container would not start"

docker cp "$DEB" "$NAME:/tmp/vallum-desktop.deb" >/dev/null

say "installing vallum-desktop .deb (unpack + dependencies)"
docker exec "$NAME" bash -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq /tmp/vallum-desktop.deb >/dev/null 2>&1
' || die "apt-get install vallum-desktop.deb failed"
ok "vallum-desktop.deb installed cleanly with dependencies"

docker exec "$NAME" test -x /usr/bin/vallum-gui || die "missing /usr/bin/vallum-gui"
ok "/usr/bin/vallum-gui is executable"

docker exec "$NAME" bash -c '
    test -f /usr/share/applications/Vallum.desktop || test -f "/usr/share/applications/Vallum Desktop.desktop"
' || die "missing .desktop entry in /usr/share/applications"
ok "desktop entry installed"

docker exec "$NAME" test -f /usr/share/icons/hicolor/128x128/apps/vallum-gui.png \
    || die "missing 128x128 icon"
ok "desktop icons installed"

say "purging vallum-desktop"
docker exec "$NAME" bash -c 'DEBIAN_FRONTEND=noninteractive dpkg -P vallum-desktop >/dev/null 2>&1' \
    || die "dpkg -P vallum-desktop failed"
if docker exec "$NAME" test -e /usr/bin/vallum-gui -o -e /usr/share/icons/hicolor/128x128/apps/vallum-gui.png; then
    die "dpkg -P vallum-desktop left files behind"
fi
ok "dpkg -P vallum-desktop removed binary, desktop entry, and icons cleanly"

echo
echo "== PASS - vallum-desktop .deb installed, verified, and purged cleanly"
