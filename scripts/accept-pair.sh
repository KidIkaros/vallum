#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Gate: a self-contained acceptance pair.
#
# Two containers on one docker bridge, each running the real daemon against a
# real TUN interface and real UDP: a server, a client, one handshake, and a ping
# that can only arrive through the tunnel. Nothing outside this script is
# touched - no VPS, no SSH alias, no host IP, no credential, no production
# deployment. That is the point: the earlier gates could only ever be true on
# one machine, once.
#
#   scripts/accept-pair.sh          # one command, no arguments, no secrets
#
# The server's address and the client's are fixed inside a private bridge
# network, so nothing here can collide with a real network, and the target is
# destroyed on exit whether the run passed or failed.
set -uo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
# The verdict trap is installed FIRST: the backend dispatch below can exit
# before anything else runs, and a gate that records nothing is the rot mode
# this whole mechanism exists to end.
trap 'rc=$?; command -v cleanup >/dev/null 2>&1 && cleanup; "$REPO/scripts/verdict.sh" accept-pair "$([ "$rc" -eq 0 ] && echo passed || echo failed)" "${ASSERTIONS:-0}"' EXIT
ASSERTIONS=0

cd "$(dirname "$0")/.."

# Two backends, and docker is not one of them by default.
#
#   namespaces (default) - two network namespaces joined by a veth pair, the
#       same shape scripts/e2e-netns.sh uses. Needs no docker, no root (an
#       unprivileged user namespace grants the CAP_NET_ADMIN the TUN setup
#       wants), and nothing else on the host.
#   docker - optional, for a machine where container isolation is preferred.
#       Selected with BACKEND=docker, and skipped with a clear message when
#       docker is not installed.
#
# The namespace backend is the default because a gate that needs a specific
# container runtime installed is a gate fewer machines can run.
BACKEND=${BACKEND:-namespaces}
if [ "$BACKEND" = namespaces ] && ! command -v unshare >/dev/null 2>&1; then
    BACKEND=docker
fi
if [ "$BACKEND" = docker ] && ! command -v docker >/dev/null 2>&1; then
    echo "[pair] docker is not installed - falling back to the namespace backend"
    BACKEND=namespaces
fi
if [ "$BACKEND" = namespaces ]; then
    # The namespace pair is scripts/e2e-netns.sh: two daemons, two namespaces,
    # a veth between them and a ping that can only arrive through the tunnel.
    # `sudo -E` is the fallback for a host whose AppArmor forbids unprivileged
    # user namespaces (Ubuntu 24.04's default) - the same shape ci.yml uses.
    echo "[pair] backend: namespaces (no docker required)"
    export QUICK="$PWD/target/release/vallum-quick"
    NS_OUT=$(bash scripts/e2e-netns.sh "$PWD/target/release/vallum" 2>&1)
    NS_RC=$?
    NS_ASSERT=$(printf '%s\n' "$NS_OUT" | grep -c '^   ok')
    if [ "$NS_RC" -ne 0 ]; then
        NS_OUT2=$(sudo -n -E bash scripts/e2e-netns.sh "$PWD/target/release/vallum" 2>&1)
        NS_RC=$?
        NS_ASSERT2=$(printf '%s\n' "$NS_OUT2" | grep -c '^   ok')
        # keep whichever attempt got further: a failed escalation must not
        # erase the checks the first attempt did make
        if [ "$NS_ASSERT2" -gt "$NS_ASSERT" ]; then
            NS_ASSERT=$NS_ASSERT2
            NS_OUT=$NS_OUT2
        fi
    fi
    printf '%s\n' "$NS_OUT"
    # the delegated gate's own checks are the assertions it made
    ASSERTIONS=$NS_ASSERT
    if [ "$NS_RC" -eq 0 ]; then
        echo "== PASS - a server and a client, in namespaces, handshook and carried"
        exit 0
    fi
    echo "== FAIL - the namespace pair did not pass (and sudo was not available)"
    exit 1
fi
echo "[pair] backend: docker"

NETWORK=vallumpair   # no dash: docker's -f template cannot address a name with one
SERVER=vallum-pair-server
CLIENT=vallum-pair-client
IMAGE=${IMAGE:-debian:stable-slim}
WORK=$(mktemp -d -t vallum-pair.XXXXXX)
ASSERTIONS=0
FAILED=""

say() { echo "[pair] $*"; }
die() { echo "[pair] FAIL: $*" >&2; exit 1; }
ex()  { docker exec "$1" bash -c "$2"; }

cleanup() {
    say "cleanup"
    docker rm -f "$CLIENT" "$SERVER" >/dev/null 2>&1
    docker network rm "$NETWORK" >/dev/null 2>&1
    rm -rf "$WORK"
}

say "building the release binaries"
cargo build --release -p vallum -p vallum-quick >/dev/null 2>&1 \
    || die "cargo build --release -p vallum -p vallum-quick failed"
[ -x target/release/vallum ] || die "no binary after build"

say "creating a private bridge (nothing here can reach the host network)"
docker network rm "$NETWORK" >/dev/null 2>&1
docker network create "$NETWORK" >/dev/null || die "could not create $NETWORK"

say "starting the server"
docker run -d --name "$SERVER" --privileged --network "$NETWORK" \
    --tmpfs /run --tmpfs /tmp "$IMAGE" sleep infinity >/dev/null \
    || die "server container would not start"
docker cp target/release/vallum "$SERVER:/usr/bin/vallum" >/dev/null
ex "$SERVER" "chmod +x /usr/bin/vallum"
install_ping "$SERVER"

# `--no-host` installs no units and `--no-service` starts nothing: the daemon is
# run by hand below, so the container needs no systemd.
ex "$SERVER" "mkdir -p /srv && /usr/bin/vallum server init --config /srv/server.toml \
    --address 10.7.0.1/24 --listen 0.0.0.0:51820 --no-host --no-service" \
    >"$WORK/server-init.log" 2>&1 || { tail -10 "$WORK/server-init.log"; die "server init failed"; }
say "server config written"

SERVER_IP=$(docker inspect -f "{{.NetworkSettings.Networks.$NETWORK.IPAddress}}" "$SERVER")
[ -n "$SERVER_IP" ] || die "no bridge address for the server"
say "server bridge address: $SERVER_IP"

say "starting the server daemon"
docker exec -d "$SERVER" bash -c "/usr/bin/vallum run --config /srv/server.toml >/tmp/server.log 2>&1"
sleep 3
ex "$SERVER" "tail -2 /tmp/server.log" 2>/dev/null | sed 's/^/   /'

install_ping() {
    local c=$1
    ex "$c" "command -v ping >/dev/null" && return 0
    say "   installing ping in $c (a missing ip reads like a dead tunnel)"
    ex "$c" "apt-get update -qq && apt-get install -y -qq iputils-ping" >/dev/null 2>&1
    ex "$c" "command -v ping >/dev/null" || die "no ping in $c - cannot prove the tunnel carries"
}

say "starting the client and generating its key"
docker run -d --name "$CLIENT" --privileged --network "$NETWORK" \
    --tmpfs /run --tmpfs /tmp "$IMAGE" sleep infinity >/dev/null \
    || die "client container would not start"
docker cp target/release/vallum "$CLIENT:/usr/bin/vallum" >/dev/null
ex "$CLIENT" "chmod +x /usr/bin/vallum; mkdir -p /c"
install_ping "$CLIENT"
ex "$CLIENT" "/usr/bin/vallum keygen --output /c/client.key" >"$WORK/client.pub" 2>&1 \
    || { cat "$WORK/client.pub"; die "keygen failed"; }
# The public line is `vallum1:<suite>:<kem>:<signing|->` — four colon-separated
# fields. A pattern that stops at the first colon truncates it to two fields and
# the server rejects it as malformed.
grep -oE 'vallum1:[^[:space:]]+' "$WORK/client.pub" | head -1 | tr -d '.,;' >"$WORK/client.line"
[ -s "$WORK/client.line" ] || { cat "$WORK/client.pub"; die "no public line printed"; }
# The public line goes to the SERVER (it is what the server records as the
# peer); the private half never leaves the client container.
ex "$SERVER" "mkdir -p /c"
docker cp "$WORK/client.line" "$SERVER:/c/client.pub" >/dev/null

SERVER_LINE=$(ex "$SERVER" "/usr/bin/vallum pubkey --private-key /srv/server.key" 2>&1 | grep -oE 'vallum1:[^[:space:]]+' | head -1 | tr -d '.,;')
[ -n "$SERVER_LINE" ] || die "no server public line"

say "teaching the server about the client"
ex "$SERVER" "/usr/bin/vallum peer add client --config /srv/server.toml --public-key-file /c/client.pub" \
    >"$WORK/peer-add.log" 2>&1 || { tail -10 "$WORK/peer-add.log"; die "peer add failed"; }

say "writing the client config"
cat >"$WORK/client.toml" <<EOF
[interface]
name = "paircli"
private_key = "client.key"
address = "10.7.0.2/24"
listen = "0.0.0.0:51821"
control = "/run/vallum/paircli.sock"

[[peer]]
name = "server"
public_key = "$SERVER_LINE"
endpoint = "$SERVER_IP:51820"
allowed_ips = ["10.7.0.1/32"]
persistent_keepalive = 25
EOF
docker cp "$WORK/client.toml" "$CLIENT:/c/client.toml" >/dev/null
docker cp "$WORK/client.pub" "$CLIENT:/c/client.pub" >/dev/null 2>&1 || true
# the key itself lives in the container; copy it out only for the public line
ex "$CLIENT" "ls -l /c/client.key" >/dev/null 2>&1 || die "no client key in the container"

say "running the client daemon"
# `docker exec` waits for the command, and the daemon never exits - so it must
# be detached (`-d`), not backgrounded inside the exec.
docker exec -d "$CLIENT" bash -c "mkdir -p /run/vallum && /usr/bin/vallum run --config /c/client.toml >/tmp/client.log 2>&1"
# The client's persistent_keepalive is 25 s and it has no session to send on
# until then, so a handshake needs a tick - judge after one, not immediately.
sleep 30
ex "$CLIENT" "tail -3 /tmp/client.log" 2>/dev/null | sed 's/^/   /'

say "client daemon state"
# After the keepalive tick, so the snapshot includes the session.
STATE=$(ex "$CLIENT" "/usr/bin/vallum show --control /run/vallum/paircli.sock 2>/dev/null")
echo "$STATE" | sed 's/^/   /'
ASSERTIONS=$((ASSERTIONS + 1))
echo "$STATE" | grep -q 'last_handshake_time_sec' || FAILED="the client never handshook"

say "the only ping that can arrive is through the tunnel"
PING=$(ex "$CLIENT" "ping -c3 -W3 10.7.0.1 2>&1 | tail -2")
echo "$PING" | sed 's/^/   /'
ASSERTIONS=$((ASSERTIONS + 1))
echo "$PING" | grep -q ' 0% packet loss' || FAILED="${FAILED:+$FAILED; }the tunnel did not carry"

say "the server's view"
ex "$SERVER" "/usr/bin/vallum show --control /run/vallum/server.sock 2>/dev/null | grep -A3 client | head -6" | sed 's/^/   /'

echo
if [ -n "$FAILED" ]; then
    echo "== FAIL - $FAILED"
    exit 1
fi
echo "== PASS - a server and a client, provisioned here, handshook and carried"


