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
CHECK=0
[ "${1:-}" = "--check" ] && CHECK=1

maybe_install() {
    # $1 = source, $2 = destination, $3 = mode, $4 = label
    if [ "$CHECK" = 1 ]; then
        echo "sync: $4 is stale"
    else
        echo "sync: $4 is stale — updating"
        install -m "$3" "$1" "$2"
    fi
    CHANGES=1
}

for b in vallum vallum-quick; do
    if ! cmp -s "$REPO/target/release/$b" "/usr/bin/$b"; then
        maybe_install "$REPO/target/release/$b" "/usr/bin/$b" 755 "$b"
    fi
done

for u in vallum@.service vallum-quick@.service vallum-guard@.service \
    vallum-deadman@.service vallum-deadman@.timer vallum-cleanup.service \
    vallum-netlink-watch.service vallum-metrics.service vallum-metrics.timer; do
    if ! cmp -s "$REPO/packaging/$u" "/etc/systemd/system/$u"; then
        maybe_install "$REPO/packaging/$u" "/etc/systemd/system/$u" 644 "unit $u"
    fi
done

if [ "$CHECK" = 0 ]; then
    install -d -m 755 /usr/local/lib/vallum
fi
for lib in trial.sh go-full-tunnel.sh; do
    if ! cmp -s "$REPO/scripts/$lib" "/usr/local/lib/vallum/$lib"; then
        maybe_install "$REPO/scripts/$lib" "/usr/local/lib/vallum/$lib" 755 "deploy script $lib"
    fi
done

# vallum-ops is in this list because it is the operator surface itself: a
# dispatcher improvement that sync cannot reach never reaches an installed
# host, and the two copies drift exactly the way everything else does.
for tool in vallum-ops vallum-panic vallum-guard-deadman vallum-cleanup vallum-heal-runtime-dir; do
    if ! cmp -s "$REPO/packaging/$tool" "/usr/local/sbin/$tool"; then
        maybe_install "$REPO/packaging/$tool" "/usr/local/sbin/$tool" 755 "tool $tool"
    fi
done

if [ "$CHECK" = 1 ]; then
    echo "sync check: $([ "$CHANGES" = 1 ] && echo 'stale files found' || echo 'host current')"
    exit 0
fi

# Server-init backups of the enroll unit accumulate forever; the live unit
# ships with the installer, so every dated backup is a leftover.
bak_left=$(ls /etc/systemd/system/vallum@*.bak* /etc/systemd/system/vallum-*.bak* 2>/dev/null | wc -l)
if [ "$bak_left" -gt 0 ]; then
    rm -f /etc/systemd/system/vallum@*.bak* /etc/systemd/system/vallum-*.bak*
    echo "sync: removed $bak_left dated unit backups"
fi

if [ "$CHANGES" = 1 ]; then
    systemctl daemon-reload
fi

# The restore floor: enabled at install, fires at boot only.
systemctl enable vallum-cleanup >/dev/null 2>&1 && echo "sync: vallum-cleanup enabled"
# The link-event recorder is read-only and harmless: start it here because the
# operator's sudoers rule does not cover it.
systemctl enable --now vallum-netlink-watch >/dev/null 2>&1 && echo "sync: link-event recorder running"
# Metrics: a scrape every 15 s into /run/vallum/metrics.prom. Enabled here
# because a monitoring unit nobody turns on is a design document, and the last
# three outages were diagnosed from numbers that existed but were never written
# down. The unit is inert until the runtime directory exists, so enabling it
# before the daemon has ever run is safe.
systemctl enable --now vallum-metrics.timer >/dev/null 2>&1 && echo "sync: metrics timer running"

echo "sync complete ($([ "$CHANGES" = 1 ] && echo 'changes applied' || echo 'host already current'))"
systemctl is-enabled vallum-cleanup 2>/dev/null | sed 's/^/  cleanup unit: /'
