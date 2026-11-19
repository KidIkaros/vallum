#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Gate: an AGENT enrols a device headless (ADR-0047 account/device flow).
#
# No browser, no operator: the agent gets an ACCOUNT through the desk HTTP API
# (account-only signup), generates its own key, presents the public line to
# POST /api/devices, receives a PINNED single-use ticket, and joins with it.
# The private key never leaves the device; a wrong key is refused. This is the
# "on-demand for agents" claim, exercised with the real binaries end to end.
#
#   scripts/accept-agent-enrol.sh      # one command, no arguments, no secrets
#
# Topology: the e2e-netns / pin-probe rig — a server namespace (daemon + enrol
# responder + the desk) and a client namespace joined by veth. A loopback
# endpoint in one namespace is the client's own address, which the product
# rightly refuses, so the endpoint is the veth address. Host /etc/vallum and
# /run are hidden behind tmpfs: nothing outside the namespaces is touched, no
# VPS, no docker. An unprivileged user namespace grants the caps the TUN, nft
# and tmpfs setup want; `sudo -n` is the AppArmor fallback.
set -uo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
trap 'rc=$?; command -v cleanup >/dev/null 2>&1 && cleanup; "$REPO/scripts/verdict.sh" accept-agent-enrol "$([ "$rc" -eq 0 ] && echo passed || echo failed)" "${ASSERTIONS:-0}" "$0"' EXIT
ASSERTIONS=0

say() { echo "[agent-enrol] $*"; }
die() { echo "[agent-enrol] FAIL: $*" >&2; exit 1; }

say "building the release binary"
cargo build --release -p vallum >/dev/null 2>&1 || die "cargo build --release -p vallum failed"
[ -x "$REPO/target/release/vallum" ] || die "no binary after build"
cd "$REPO"
command -v unshare >/dev/null 2>&1 || die "unshare (util-linux) is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required (the desk + the API client)"

WORK=$(mktemp -d /tmp/vallum-agent-enrol.XXXXXX)
cleanup() { rm -rf -- "$WORK"; }

# The lab body is materialized to a seekable file (the e2e-netns suite documented
# a bash parser bug on non-seekable stdin heredocs above a certain size).
cat > "$WORK/inner.sh" <<'INNER'
set -u
BIN=$1
WORK=$2
REPO=$3
export PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH
FAIL=0
note() { printf '\n── %s\n' "$*"; }
ok()   { printf '   ok    %s\n' "$*"; }
bad()  { printf '   FAIL  %s\n' "$*" >&2; exit 1; }
check() { if [ "$1" = 0 ]; then ok "$2"; else printf '   FAIL  %s\n' "$2" >&2; FAIL=1; fi; }

mount -t tmpfs tmpfs /etc/vallum || exit 90
mount -t tmpfs tmpfs /run || exit 90
mkdir -p /run/vallum
ip link set lo up

LAB=$WORK
V=$BIN
DESK_PORT=8400

cleanup() {
    for f in "$LAB"/*.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null; done
    [ -n "${HOLDER:-}" ] && kill "$HOLDER" 2>/dev/null
    wait 2>/dev/null
    chmod -R a+rwX "$LAB" 2>/dev/null || true
}
trap cleanup EXIT

note "outer network: server (ns1) and client (ns2) joined by veth"
ip link add veth-a type veth peer name veth-b
ip link set veth-a up; ip addr add 10.99.0.1/24 dev veth-a
unshare -n sleep infinity & HOLDER=$!
sleep 0.3
ip link set veth-b netns "$HOLDER"
in_ns() { nsenter -t "$HOLDER" -n -- "$@"; }
in_ns ip link set lo up; in_ns ip link set veth-b up; in_ns ip addr add 10.99.0.2/24 dev veth-b
ping -c1 -W2 -q 10.99.0.2 >/dev/null 2>&1; check $? "outer network crosses (veth)"

note "server init (veth endpoint, enrolment on)"
"$V" server init --config /etc/vallum/srv.toml --address 10.77.0.1/24 \
    --listen 10.99.0.1:51990 --no-host --no-service --enroll > "$LAB/init.log" 2>&1
check $? "server init"
python3 - <<'EOF'
p = '/etc/vallum/srv.toml'
text = open(p).read()
text = text.replace('[interface]', '[interface]\npublic_endpoint = "10.99.0.1:51990"', 1)
open(p, 'w').write(text)
EOF
grep -q 'public_endpoint' /etc/vallum/srv.toml; check $? "public_endpoint set (a device can dial it)"

note "start the daemon + the enrolment responder (ns1)"
setsid "$V" run --config /etc/vallum/srv.toml >> "$LAB/srv.log" 2>&1 & echo $! > "$LAB/srv.pid"
setsid "$V" enroll-serve --config /etc/vallum/srv.toml >> "$LAB/enroll.log" 2>&1 & echo $! > "$LAB/enroll.pid"
sleep 2
"$V" show --config /etc/vallum/srv.toml --json > "$LAB/srv-show.json" 2>&1
check $? "server daemon answers on its control socket"

note "start the desk against the real daemon (ns1, loopback HTTP)"
printf 'agent-code-1\n' > "$LAB/codes.txt"
printf 'test-admin-token\n' > "$LAB/admin-token"
setsid python3 "$REPO/service/vallum-desk" \
    --config /etc/vallum/srv.toml --state "$LAB/desk.sqlite" \
    --codes "$LAB/codes.txt" --admin-token-file "$LAB/admin-token" \
    --bind 127.0.0.1 --port "$DESK_PORT" --cli "$V" \
    --trial-days 14 --trial-bytes 1000000000 --device-cap 5 \
    >> "$LAB/desk.log" 2>&1 & echo $! > "$LAB/desk.pid"
# the desk is ready when /healthz answers
ready=1
for i in $(seq 1 50); do
    if python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:$DESK_PORT/healthz',timeout=2)" 2>/dev/null; then
        ready=0; break
    fi
    sleep 0.2
done
check $ready "desk /healthz answers"
[ $ready -eq 0 ] || { tail -20 "$LAB/desk.log" >&2; bad "the desk never came up"; }

# A POST helper: prints the response body, exits with the HTTP status.
cat > "$LAB/api.py" <<'EOF'
import sys, urllib.request, urllib.error
path, body = sys.argv[1], sys.argv[2]
req = urllib.request.Request("http://127.0.0.1:8400" + path, data=body.encode(),
                             headers={"Content-Type": "application/json"}, method="POST")
try:
    r = urllib.request.urlopen(req, timeout=20)
    sys.stdout.write(r.read().decode()); sys.exit(r.status)
except urllib.error.HTTPError as e:
    sys.stdout.write(e.read().decode()); sys.exit(e.code)
EOF
api() { python3 "$LAB/api.py" "$1" "$2"; }

note "AGENT step 1: account-only signup (no device, no ticket)"
SIGNUP=$(api /api/signup '{"code":"agent-code-1"}'); RC=$?
[ "$RC" = 200 ]; check $? "signup HTTP 200 (rc=$RC)"
TOKEN=$(printf '%s' "$SIGNUP" | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])' 2>/dev/null)
[ -n "$TOKEN" ]; check $? "signup returned an account token"
printf '%s' "$SIGNUP" | python3 -c 'import json,sys;d=json.load(sys.stdin);assert "ticket" not in d and "peer" not in d, d' 2>/dev/null
check $? "signup is account-only (no ticket, no peer in the response)"

note "AGENT step 2: the device generates its own key (ns2; custody)"
in_ns "$V" keygen --key "$LAB/agent.key" > "$LAB/keygen.log" 2>&1; check $? "keygen on the device"
LINE=$(in_ns "$V" pubkey --key "$LAB/agent.key" 2>"$LAB/pubkey.err"); check $? "pubkey on the device"

note "AGENT step 3: present the public line, get a PINNED ticket"
BODY=$(python3 -c 'import json,sys;print(json.dumps({"token":sys.argv[1],"name":"agent1","public_key":sys.argv[2]}))' "$TOKEN" "$LINE")
DEVICES=$(api /api/devices "$BODY"); RC=$?
[ "$RC" = 200 ]; check $? "POST /api/devices HTTP 200 (rc=$RC)"
TICKET=$(printf '%s' "$DEVICES" | python3 -c 'import json,sys;print(json.load(sys.stdin)["ticket"])' 2>/dev/null)
[ -n "$TICKET" ]; check $? "devices returned a join ticket"
printf '%s' "$DEVICES" | python3 -c 'import json,sys;assert json.load(sys.stdin)["pinned"] is True' 2>/dev/null
check $? "the ticket is pinned to the device's key"

note "AGENT step 4: join --key (ns2 — the pinned redemption)"
in_ns bash -c "setsid $V join '$TICKET' --key $LAB/agent.key --name agent > $LAB/join.log 2>&1 & echo \$! > $LAB/join.pid"
for i in $(seq 1 150); do [ -f /etc/vallum/agent.toml ] && break; sleep 0.2; done
[ -f /etc/vallum/agent.toml ]; check $? "join wrote the client config"
if [ -f /etc/vallum/agent.toml ]; then
    in_ns bash -c "setsid $V run --config /etc/vallum/agent.toml >> $LAB/client.log 2>&1 & echo \$! > $LAB/client.pid"
fi
for i in $(seq 1 200); do kill -0 "$(cat "$LAB/join.pid")" 2>/dev/null || break; sleep 0.3; done
grep -q 'enrolled `agent`' "$LAB/join.log"; check $? "join enrolled (log)"
grep -q 'using the key at' "$LAB/join.log"; check $? "join used the named key (not a fresh one)"
grep -q 'ok    handshake with the server' "$LAB/join.log"; check $? "handshake proven by join"
cmp -s "$LAB/agent.key" /etc/vallum/agent.key; check $? "the placed key IS the device's key (custody)"

note "server applied the peer; handshake on both ends"
"$V" show --config /etc/vallum/srv.toml --json > "$LAB/srv-show2.json" 2>&1
python3 - "$LAB" <<'EOF'
import json, sys
lab = sys.argv[1]
doc = json.load(open(f'{lab}/srv-show2.json'))
peers = {p['name']: p for p in doc.get('peers', [])}
assert 'u0001-agent1' in peers, f"peer not applied: {list(peers)}"
hs = peers['u0001-agent1'].get('last_handshake')
assert hs and hs.get('sec'), f"no server-side handshake: {hs}"
EOF
check $? "server has u0001-agent1 with a handshake"

note "data plane: ping the server's tunnel address through the tunnel (ns2)"
in_ns ping -c3 -W2 -I 10.77.0.2 10.77.0.1 > "$LAB/ping.log" 2>&1
check $? "ping 10.77.0.1 from 10.77.0.2 rides the tunnel"

note "NEGATIVE: a pinned ticket refuses a different key"
in_ns "$V" keygen --key "$LAB/other.key" > /dev/null 2>&1
BODY2=$(python3 -c 'import json,sys;print(json.dumps({"token":sys.argv[1],"name":"other","public_key":sys.argv[2]}))' "$TOKEN" "$LINE")
DEVICES2=$(api /api/devices "$BODY2"); RC=$?
[ "$RC" = 200 ]; check $? "a second pinned ticket minted (same pin, other name)"
T2=$(printf '%s' "$DEVICES2" | python3 -c 'import json,sys;print(json.load(sys.stdin)["ticket"])' 2>/dev/null)
in_ns "$V" join "$T2" --key "$LAB/other.key" --name other > "$LAB/join2.log" 2>&1; RC=$?
[ "$RC" -ne 0 ]; check $? "join with the WRONG key refused (rc=$RC)"
grep -qi 'different key' "$LAB/join2.log"; check $? "the refusal names the pin"
[ ! -f /etc/vallum/other.toml ]; check $? "no config written for the refused join"
grep -q 'u0002-other' /etc/vallum/srv.toml; [ $? -ne 0 ]; check $? "the server did not enrol the wrong key"

note "agent enrolment probe FAIL=$FAIL"
exit $FAIL
INNER

say "running the lab in an unprivileged user namespace (no docker, no VPS)"
# -m (mount namespace) is required: the lab hides host /etc/vallum and /run
# behind tmpfs, and a tmpfs mount needs a mount ns owned by the user ns.
LAB_OUT=$(unshare -Urnm bash "$WORK/inner.sh" "$REPO/target/release/vallum" "$WORK" "$REPO" 2>&1)
LAB_RC=$?
if [ "$LAB_RC" -ne 0 ]; then
    say "unprivileged namespaces unavailable - trying sudo -n (AppArmor fallback)"
    LAB_OUT2=$(sudo -n unshare -Urnm bash "$WORK/inner.sh" "$REPO/target/release/vallum" "$WORK" "$REPO" 2>&1)
    LAB_RC=$?
    if [ "$LAB_RC" -eq 0 ]; then LAB_OUT=$LAB_OUT2; else LAB_OUT="$LAB_OUT
$LAB_OUT2"; fi
fi
printf '%s\n' "$LAB_OUT"
ASSERTIONS=$(printf '%s\n' "$LAB_OUT" | grep -c '^   ok')
if [ "$LAB_RC" -ne 0 ]; then
    echo "== FAIL - the agent enrolment lab did not pass (see the FAIL line above)"
    exit 1
fi
echo "== PASS - an agent enrols headless: account-only signup, pinned ticket, join --key, handshake"