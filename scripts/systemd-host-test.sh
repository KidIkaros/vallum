#!/usr/bin/env bash
#
# Real systemd/vallum-quick host test. Requires root; it creates a transient
# systemd service and a temporary TUN interface, then removes them.
#
# Usage:
#   sudo VALLUM=./target/debug/vallum VALLUM_QUICK=./target/debug/vallum-quick \
#     ./scripts/systemd-host-test.sh
set -euo pipefail

root_dir=$(cd "$(dirname "$0")/.." && pwd)
cd "$root_dir"

VALLUM=${VALLUM:-target/debug/vallum}
VALLUM_QUICK=${VALLUM_QUICK:-target/debug/vallum-quick}
UNIT=vallum@vallum0.service
WORK=/tmp/vallum-systemd-test.$$
CONFIG="$WORK/vallum0.toml"
QUICK_CONFIG="$WORK/vallum-quick0.toml"
CONTROL="$WORK/control.sock"
QUICK_CONTROL="$WORK/quick.sock"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

cleanup() {
    systemctl stop "$UNIT" >/dev/null 2>&1 || true
    VALLUM_BIN="$VALLUM" "$VALLUM_QUICK" down "$QUICK_CONFIG" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then
    cat >&2 <<EOS
This test must run as root because it starts a transient systemd service and
creates a temporary TUN interface. Run:

  sudo VALLUM=./target/debug/vallum VALLUM_QUICK=./target/debug/vallum-quick \
    ./scripts/systemd-host-test.sh
EOS
    exit 2
fi

[ -x "$VALLUM" ] || fail "vallum binary not found: $VALLUM"
[ -x "$VALLUM_QUICK" ] || fail "vallum-quick binary not found: $VALLUM_QUICK"
command -v systemctl >/dev/null || fail "systemctl not found"
command -v ip >/dev/null || fail "ip not found"

mkdir -p "$WORK"
"$VALLUM" keygen > "$WORK/server.key"
chmod 600 "$WORK/server.key"

cat > "$CONFIG" <<EOS
[interface]
name = "vallum-sys0"
private_key = "$WORK/server.key"
address = "10.99.99.1/32"
listen = "127.0.0.1:0"
control = "$CONTROL"

[quick]
table = "off"
EOS

cat > "$QUICK_CONFIG" <<EOS
[interface]
name = "vallum-quick0"
private_key = "$WORK/server.key"
address = "10.99.98.1/32"
listen = "127.0.0.1:0"
control = "$QUICK_CONTROL"

[quick]
table = "off"
EOS

echo "== transient systemd service ($UNIT)"
systemd-run --system --unit="$UNIT" --service-type=simple --collect \
    "$VALLUM" run -c "$CONFIG"

for _ in $(seq 1 50); do
    [ -S "$CONTROL" ] && break
    sleep 0.1
done
[ -S "$CONTROL" ] || {
    systemctl status "$UNIT" --no-pager || true
    journalctl -u "$UNIT" -n 50 --no-pager || true
    fail "systemd daemon did not create the control socket"
}

systemctl is-active --quiet "$UNIT" || fail "unit is not active"
"$VALLUM" show --control "$CONTROL" | grep -q vallum-sys0 ||
    fail "systemd daemon did not answer the UAPI"
echo "   ok"

echo "== systemctl stop"
systemctl stop "$UNIT"
for _ in $(seq 1 50); do
    if ! systemctl is-active --quiet "$UNIT" 2>/dev/null; then
        break
    fi
    sleep 0.1
done
systemctl is-active --quiet "$UNIT" 2>/dev/null && fail "unit is still active"
echo "   ok"

echo "== vallum-quick fallback"
VALLUM_BIN="$VALLUM" "$VALLUM_QUICK" up "$QUICK_CONFIG"
for _ in $(seq 1 50); do
    [ -S "$QUICK_CONTROL" ] && break
    sleep 0.1
done
[ -S "$QUICK_CONTROL" ] || fail "vallum-quick daemon did not create the control socket"
"$VALLUM" show --control "$QUICK_CONTROL" | grep -q vallum-quick0 ||
    fail "vallum-quick daemon did not answer the UAPI"
VALLUM_BIN="$VALLUM" "$VALLUM_QUICK" down "$QUICK_CONFIG"
ip link show vallum-quick0 >/dev/null 2>&1 && fail "vallum-quick left the interface"
echo "   ok"

echo "PASS"
