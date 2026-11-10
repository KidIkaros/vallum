#!/usr/bin/env bash
# vallum-sync — make the host match the build under test, then stop.
#
# The one deployment path for binaries, unit files and recovery tools. Any
# other install of these is a fork of this script waiting to happen. Never
# starts, stops, or configures the tunnel: syncing changes what COULD run,
# never what IS running. The restore floor (vallum-cleanup) is enabled here —
# the installer's one deliberate enable, see docs/plan-2026-11-09.md Phase 0.5.
set -uo pipefail

REPO=/home/ikaaros/Coding/Gold/vallum

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
[ -d "$REPO/crates" ] || { echo "repo not found at $REPO" >&2; exit 1; }

CHANGES=0

for b in vallum vallum-quick; do
    if ! cmp -s "$REPO/target/release/$b" "/usr/bin/$b"; then
        echo "sync: $b is stale — updating"
        install -m 755 "$REPO/target/release/$b" "/usr/bin/$b"
        CHANGES=1
    fi
done

for u in vallum@.service vallum-quick@.service vallum-guard@.service \
    vallum-deadman@.service vallum-deadman@.timer vallum-cleanup.service; do
    if ! cmp -s "$REPO/packaging/$u" "/etc/systemd/system/$u"; then
        echo "sync: unit $u is stale — updating"
        install -m 644 "$REPO/packaging/$u" "/etc/systemd/system/$u"
        CHANGES=1
    fi
done

for tool in vallum-panic vallum-guard-deadman vallum-cleanup; do
    if ! cmp -s "$REPO/packaging/$tool" "/usr/local/sbin/$tool"; then
        echo "sync: tool $tool is stale — updating"
        install -m 755 "$REPO/packaging/$tool" "/usr/local/sbin/$tool"
        CHANGES=1
    fi
done

if [ "$CHANGES" = 1 ]; then
    systemctl daemon-reload
fi

# The restore floor: enabled at install, fires at boot only.
systemctl enable vallum-cleanup >/dev/null 2>&1 && echo "sync: vallum-cleanup enabled"

echo "sync complete ($([ "$CHANGES" = 1 ] && echo 'changes applied' || echo 'host already current'))"
systemctl is-enabled vallum-cleanup 2>/dev/null | sed 's/^/  cleanup unit: /'
