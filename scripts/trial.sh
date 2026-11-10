#!/usr/bin/env bash
#
# Apply a network change with a deadline. If the host is not healthy when the
# clock runs out, everything this script touched is reverted automatically —
# nobody has to remember the undo, and nobody has to be at the keyboard.
#
#   sudo scripts/trial.sh --config /etc/vallum/vallum0.toml [--trial 60] [--dry-run]
#
# What it does, in order:
#   1. records what the host looked like (default route, resolv.conf, unit states)
#   2. arms a transient systemd timer BEFORE changing anything, so a crash
#      between "changed" and "checked" still reverts
#   3. brings the guard and the routes up
#   4. proves the host still has internet; on success it confirms the change,
#      on failure it reverts immediately and says what failed
#
# The timer is the safety property: it exists before the risk does.
set -uo pipefail

CONFIG=/etc/vallum/vallum0.toml
TRIAL=60
DRY_RUN=0
MARK=/run/vallum/trial-ok
IFACE=

while [ $# -gt 0 ]; do
    case "$1" in
        --config) CONFIG=$2; shift 2 ;;
        --trial)  TRIAL=$2; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ -f "$CONFIG" ] || { echo "no config at $CONFIG" >&2; exit 1; }
IFACE=$(basename "$CONFIG" .toml)

plan() { printf '  %s\n' "$*"; }

echo "trial: $IFACE for ${TRIAL}s"
if [ "$DRY_RUN" = 1 ]; then
    echo "would:"
    plan "arm a ${TRIAL}s timer that runs: vallum policy off, vallum-quick detach, systemctl stop vallum-guard@$IFACE"
    plan "start vallum-guard@$IFACE (egress blocked except the tunnel)"
    plan "start vallum-quick@$IFACE (routes and DNS through the tunnel)"
    plan "verify: default route is $IFACE, ping 1.1.1.1, DNS resolves"
    plan "on success: touch $MARK so the timer stands down"
    echo "dry run: nothing changed"
    exit 0
fi

# Asking what a change would do must not require the right to make it.
[ "$(id -u)" = 0 ] || { echo "run as root to apply (or pass --dry-run)" >&2; exit 1; }

# 1. Remember enough to put it back.
BEFORE_ROUTE=$(ip route show default | head -1)
BEFORE_RESOLV=/run/vallum/trial-resolv.bak
cp /etc/resolv.conf "$BEFORE_RESOLV" 2>/dev/null || true

revert() {
    local why=${1:-"the trial failed"}
    echo "reverting: $why" >&2
    systemctl stop "vallum-quick@$IFACE" 2>/dev/null
    /usr/bin/vallum policy off --config "$CONFIG" >/dev/null 2>&1
    nft delete table inet vallum_policy >/dev/null 2>&1
    systemctl stop "vallum-guard@$IFACE" 2>/dev/null
    ip route del default dev "$IFACE" >/dev/null 2>&1
    if [ -n "$BEFORE_ROUTE" ] && ! ip route show default | grep -q .; then
        ip route add ${BEFORE_ROUTE#default } >/dev/null 2>&1
    fi
    cp "$BEFORE_RESOLV" /etc/resolv.conf 2>/dev/null || true
    rm -f "$BEFORE_RESOLV"
    echo "reverted. default route: $(ip route show default | head -1)"
}

# 2. The timer exists before the risk does. systemd-run owns it, so it survives
#    this script dying.
rm -f "$MARK"
systemd-run --quiet --on-active="${TRIAL}s" --unit="vallum-trial-$IFACE" \
    /bin/sh -c "[ -f $MARK ] || { /usr/bin/vallum policy off --config $CONFIG; nft delete table inet vallum_policy; systemctl stop vallum-quick@$IFACE; systemctl stop vallum-guard@$IFACE; ip route del default dev $IFACE; [ -f $BEFORE_RESOLV ] && cp $BEFORE_RESOLV /etc/resolv.conf; logger -t vallum-trial 'trial expired unreverted — restored egress and DNS'; }" \
    || { echo "cannot arm the revert timer; refusing to change anything" >&2; exit 1; }

# 3. The change.
systemctl start "vallum-guard@$IFACE" || { revert "the guard refused to install"; exit 1; }
systemctl reset-failed "vallum-quick@$IFACE" 2>/dev/null
systemctl start "vallum-quick@$IFACE" || { revert "vallum-quick refused to attach"; exit 1; }

# 4. Prove it before trusting it.
ok=1
ip route get 1.1.1.1 2>/dev/null | grep -q "dev $IFACE" || ok=0
ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1 || ok=0
getent hosts example.com >/dev/null 2>&1 || ok=0

if [ "$ok" = 1 ]; then
    touch "$MARK"
    systemctl stop "vallum-trial-$IFACE" >/dev/null 2>&1
    echo "trial passed: traffic is on $IFACE and the internet works"
    echo "the revert timer stood down; stop it any time with: sudo vallum-panic"
    exit 0
fi

revert "the host lost its internet during the trial"
exit 1
