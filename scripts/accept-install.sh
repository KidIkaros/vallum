#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Acceptance: a machine that is not the author's installs Vallum and joins it.
#
# A machine that is not the operator's: a clean systemd container with its own
# network namespace. It installs from the shipped media, receives a real ticket
# minted on the production server, joins, and proves the tunnel carries.
#
# Reproducibility is the claim under test: nothing here may depend on the
# operator's home directory, their shell history, or a file they happen to have.
set -uo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)


# Everything machine-specific is an override, because a test only the
# author can run does not prove reproducibility.
REPO=$(cd "$(dirname "$0")/.." && pwd)
NAME=${NAME:-vallum-accept}
PEER=${PEER:-accept1}
VPS=${VPS:-wingman-vps}
LOG=${LOG:-$(mktemp -t accept-install.XXXXXX)}

TICKET_DIR=$(mktemp -d -t accept-install.XXXXXX)
say() { echo "[accept] $*"; }
die() { echo "[accept] FAIL: $*" >&2; exit 1; }

cleanup() {
    say "cleanup"
    ssh "$VPS" "sudo -n /usr/bin/vallum peer remove $PEER --config "${CONFIG:-/etc/vallum/vallum0.toml}"; sudo -n /usr/bin/vallum server enroll --disable --config "${CONFIG:-/etc/vallum/vallum0.toml}"" >/dev/null 2>&1
    docker rm -f "$NAME" >/dev/null 2>&1
    rm -rf "$TICKET_DIR"
}
trap 'rc=$?; cleanup; "$REPO/scripts/verdict.sh" accept-install "$([ "$rc" -eq 0 ] && echo passed || echo failed)" "${ASSERTIONS:-0}"' EXIT

say "starting a clean systemd container (own netns, not --network=host)"
docker rm -f "$NAME" >/dev/null 2>&1
# Flags from references/reboot-lab.md: `-v /sys/fs/cgroup:…:ro` exits 255 with no
# log, and the source:dest form is mandatory — `/sys/fs/cgroup:rw` alone is
# rejected outright. The image is the one known to actually boot.
docker run -d --name "$NAME" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
    jrei/systemd-ubuntu:24.04 \
    || die "container would not start"

for _ in $(seq 1 40); do
    state=$(docker exec "$NAME" systemctl is-system-running 2>/dev/null || true)
    [ "$state" = "running" ] || [ "$state" = "degraded" ] && break
    sleep 2
done
say "systemd: $(docker exec "$NAME" systemctl is-system-running 2>/dev/null || echo unknown)"

say "network tools (a missing ip reads exactly like a dead tunnel)"
docker exec "$NAME" bash -c 'apt-get update -qq && apt-get install -y -qq iproute2 curl iputils-ping >/dev/null 2>&1' || true

say "copying install media to /opt/vallum (the layout install.sh expects)"
docker exec "$NAME" mkdir -p /opt/vallum/target/release
for d in scripts packaging; do docker cp "$REPO/$d" "$NAME:/opt/vallum/$d" >/dev/null; done
for b in vallum vallum-quick; do
    docker cp "$REPO/target/release/$b" "$NAME:/opt/vallum/target/release/$b" >/dev/null
done

say "hand command one: install.sh --local --install-only"
docker exec "$NAME" bash -c 'cd /opt/vallum && bash scripts/install.sh --local --install-only' >"$LOG" 2>&1
grep -qE 'installed|complete' "$LOG" || { tail -20 "$LOG"; die "install.sh did not report success"; }
docker exec "$NAME" test -x /usr/bin/vallum || die "no binary after install"
say "installed: $(docker exec "$NAME" /usr/bin/vallum --version 2>&1 | head -1)"

say "no author path may survive the install"
# Any home directory in an installed artifact is a machine-specific path that
# cannot work on another machine. Scan for the shape, not for one author.
if docker exec "$NAME" grep -rlE '/home/[A-Za-z0-9._-]+/' /usr/local/lib/vallum /usr/local/sbin /etc/systemd/system 2>/dev/null | head -3 | grep -q .; then
    docker exec "$NAME" grep -rlE '/home/[A-Za-z0-9._-]+/' /usr/local/lib/vallum /usr/local/sbin /etc/systemd/system 2>/dev/null | head -3
    die "the install carries a machine-specific home directory"
fi
say "author path: none"

say "minting a real ticket on the server"
# Extract locally: nested quoting through ssh mangled the token on the first
# attempt, and a ticket that is silently empty looks like a broken invite path.
ssh "$VPS" "sudo -n /usr/bin/vallum peer remove $PEER --config "${CONFIG:-/etc/vallum/vallum0.toml}"" >/dev/null 2>&1
ssh "$VPS" "sudo -n /usr/bin/vallum peer invite $PEER --config "${CONFIG:-/etc/vallum/vallum0.toml}"" > $TICKET_DIR/invite.txt 2>&1
# The ticket carries `:` (host:port) and `/` (fields); the usage string carries
# `<`, so excluding `<` and space keeps the real token and drops the help text.
# A length floor rejects the truncated fragment the help line still yields.
grep -oE 'vallum1-join:[^ <]+' $TICKET_DIR/invite.txt | awk 'length($0) > 40' | head -1 > $TICKET_DIR/ticket
TICKET=$(cat $TICKET_DIR/ticket)
if [ -z "$TICKET" ]; then tail -5 $TICKET_DIR/invite.txt; die "no ticket minted"; fi
say "ticket minted for $PEER (${#TICKET} bytes)"

say "hand command two: vallum join"
printf '%s' "$TICKET" | base64 -w0 > $TICKET_DIR/ticket.b64
docker cp $TICKET_DIR/ticket.b64 "$NAME:/root/t.b64" >/dev/null
docker exec "$NAME" bash -c 'base64 -d /root/t.b64 > /root/ticket && /usr/bin/vallum join "$(cat /root/ticket)"' >"$LOG" 2>&1
tail -6 "$LOG"

say "units after join"
# The unit instance is the config stem, so it is the peer name - not a literal.
UNITS=$(docker exec "$NAME" systemctl is-active "vallum@$PEER" "vallum-quick@$PEER" 2>&1 | tr '\n' ' ')
echo "   $UNITS"
ASSERTIONS=0
FAILED=""
ASSERTIONS=$((ASSERTIONS + 1))
case "$UNITS" in
    *inactive*|*failed*|*unknown*) FAILED="the join left a unit inactive: $UNITS" ;;
esac

say "does the tunnel carry (ICMP to the server's tunnel address)"
# 51820 is UDP: a /dev/tcp probe there fails by construction and reads as a
# dead tunnel. Ping the tunnel address, which the client's on-link prefix
# routes into the interface.
PING=$(docker exec "$NAME" bash -c 'ping -c3 -W3 10.7.0.1 2>&1 | tail -2')
echo "$PING" | sed 's/^/   /'
ASSERTIONS=$((ASSERTIONS + 1))
echo "$PING" | grep -q ' 0% packet loss' || FAILED="${FAILED:+$FAILED; }the tunnel did not carry (no 0% packet loss)"

say "the server's view of this device"
ssh "$VPS" "sudo -n /usr/bin/vallum show --control /run/vallum/vallum0.sock 2>/dev/null | grep -A3 '$PEER' | head -6"

echo
# The gate returns an exit code. Printing a FAIL line and exiting 0 is how this
# gate passed once with an inactive unit and a dead ping - the reader noticed,
# the script did not (premortem, 2026-11-12).
if [ -n "$FAILED" ]; then
    echo "== FAIL - $FAILED"
    exit 1
fi
echo "== PASS - installed, joined, and the tunnel carries"


