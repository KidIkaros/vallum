#!/usr/bin/env bash
#
# Prove the console's cancel gate against real systemd, in a throwaway
# container. The gate is the rule that stops `/api/apply/cancel` from running
# `vallum-ops revert` on a host that is not mid-trial — the mistake that
# restarted a live tunnel on 2026-11-11. A unit test covers the state strings;
# this covers the part a unit test cannot: that systemd actually reports those
# states for the units `scripts/trial.sh` arms.
#
#   ./scripts/gui-cancel-gate.sh
#
# Requires docker. Needs the `vallum-gui` binary and a built UI (`npm run
# build` in crates/vallum-gui/ui). The first run installs webkit into the
# container, so it takes a couple of minutes; later runs reuse the image layer
# cache only if the container is kept, which it is not.
#
# The remedy is a recording stub: what is under test here is *whether* the
# console runs `vallum-ops revert`, and with what argv. What the revert itself
# does is `packaging/vallum-ops`'s behaviour, proved separately.
set -euo pipefail

root_dir=$(cd "$(dirname "$0")/.." && pwd)
cd "$root_dir"

IMAGE=${VALLUM_GATE_IMAGE:-jrei/systemd-ubuntu:24.04}
PORT=${VALLUM_GATE_PORT:-7470}
NAME=vallum-cancel-gate.$$
GUI=target/debug/vallum-gui
UI=crates/vallum-gui/ui/dist

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

[ -x "$GUI" ] || fail "no $GUI — run: cargo build -p vallum-gui"
[ -d "$UI" ] || fail "no $UI — run: (cd crates/vallum-gui/ui && npm run build)"
command -v docker >/dev/null || fail "docker not found"
docker info >/dev/null 2>&1 || fail "docker is not reachable"

echo "== container ($IMAGE, systemd as pid 1)"
docker run -d --name "$NAME" --hostname gate --privileged \
    --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    --tmpfs /run --tmpfs /run/lock -p "127.0.0.1:$PORT:7470" \
    "$IMAGE" >/dev/null

for _ in $(seq 1 100); do
    [ "$(docker exec "$NAME" systemctl is-system-running 2>/dev/null)" = running ] && break
    sleep 0.2
done
[ "$(docker exec "$NAME" systemctl is-system-running 2>/dev/null)" = running ] ||
    fail "systemd did not come up in the container"
echo "   ok"

echo "== console's runtime dependencies (webkit, gtk) + curl, sudo, python3"
docker exec "$NAME" bash -c '
    DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        libwebkit2gtk-4.1-0 libgtk-3-0 curl sudo python3 >/dev/null 2>&1
' || fail "could not install the console's dependencies"
docker cp "$GUI" "$NAME:/usr/local/bin/vallum-gui" >/dev/null
docker cp "$UI/." "$NAME:/opt/vallum-ui/" >/dev/null
echo "   ok"

# A control socket at 0600 so the console's write gate lets the request through:
# the gate refuses wider modes, which is its own test, not this one.
docker exec "$NAME" bash -c '
    cat > /usr/local/sbin/vallum-ops <<EOF
#!/bin/sh
printf "%s\n" "\$*" >> /var/log/vallum-ops-calls
exit 0
EOF
    chmod 755 /usr/local/sbin/vallum-ops
    mkdir -p /run/vallum
    python3 - <<EOF
import os, socket
path = "/run/vallum/vallum0.sock"
try:
    os.unlink(path)
except FileNotFoundError:
    pass
sock = socket.socket(socket.AF_UNIX)
sock.bind(path)
sock.listen(1)
os.chmod(path, 0o600)
EOF
    VALLUM_UI_DIR=/opt/vallum-ui /usr/local/bin/vallum-gui --serve 7470 >/tmp/serve.log 2>&1 &
    for _ in $(seq 1 50); do
        curl -sf -m 2 -X POST http://127.0.0.1:7470/api/select \
            -H "content-type: application/json" \
            -d "{\"path\":\"/run/vallum/vallum0.sock\"}" >/dev/null && break
        sleep 0.2
    done
' || fail "the console did not start in the container"

# cancel() runs one case and prints what happened; the caller asserts.
cancel() {
    docker exec "$NAME" bash -c '
        rm -f /var/log/vallum-ops-calls
        echo "timer:   $(systemctl is-active vallum-trial-vallum0.timer 2>&1)"
        echo "service: $(systemctl is-active vallum-trial-vallum0.service 2>&1)"
        echo "reply:   $(curl -s -m 20 -X POST http://127.0.0.1:7470/api/apply/cancel \
            -H "content-type: application/json" -d "{}")"
        echo "remedy:  $(cat /var/log/vallum-ops-calls 2>/dev/null || echo none)"
    '
}

echo "== nothing armed: refuse, and do not touch the tunnel"
out=$(cancel)
echo "$out" | sed 's/^/   /'
echo "$out" | grep -q '"error"' || fail "cancel ran with no trial armed"
echo "$out" | grep -q 'nothing to cancel' || fail "the refusal does not say why"
echo "$out" | grep -q 'remedy:  none' || fail "the refusal still ran the remedy"
echo "   ok"

echo "== scripts/trial.sh's timer armed: proceed"
docker exec "$NAME" systemd-run --quiet --on-active=600 --unit=vallum-trial-vallum0 /bin/true
out=$(cancel)
echo "$out" | sed 's/^/   /'
echo "$out" | grep -q '"ok":true' || fail "cancel was refused while the timer was armed"
echo "$out" | grep -q 'remedy:  revert' || fail "the remedy did not receive exactly \`revert\`"
echo "   ok"

# Arm a timer that has already fired and left its service running: the window
# where the deadline is spent and the revert is the thing in progress. This is
# the branch a timer-only check would miss.
echo "== timer spent, the revert service still running: proceed"
docker exec "$NAME" bash -c '
    systemctl stop vallum-trial-vallum0.timer
    systemctl reset-failed vallum-trial-vallum0.timer vallum-trial-vallum0.service 2>/dev/null
    systemd-run --quiet --on-active=1 --unit=vallum-trial-vallum0 sleep 120
    for _ in $(seq 1 40); do
        [ "$(systemctl is-active vallum-trial-vallum0.service)" = active ] && break
        sleep 0.25
    done
    systemctl stop vallum-trial-vallum0.timer
'
sleep 1
out=$(cancel)
echo "$out" | sed 's/^/   /'
echo "$out" | grep -q '"ok":true' || fail "cancel was refused while the revert was running"
echo "$out" | grep -q 'remedy:  revert' || fail "the remedy did not run for the service alone"
echo "   ok"

echo "== both gone again: refuse"
docker exec "$NAME" systemctl stop vallum-trial-vallum0.service
out=$(cancel)
echo "$out" | sed 's/^/   /'
echo "$out" | grep -q 'nothing to cancel' || fail "cancel ran with the trial stood down"
echo "$out" | grep -q 'remedy:  none' || fail "the remedy ran after the trial stood down"
echo "   ok"

echo "PASS"
