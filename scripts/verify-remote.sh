#!/usr/bin/env bash
#
# verify-remote.sh — the two-machine test: a real client, a real server, over
# the real network.
#
# What verify.sh cannot prove and a same-host test cannot either: that a client
# on another machine completes a handshake, reaches the server's tunnel address,
# forwards traffic to the internet through the server's NAT, and resolves DNS
# through the tunnel.
#
#   sudo ./scripts/verify-remote.sh user@vps.example.com
#   sudo ./scripts/verify-remote.sh --product user@vps.example.com
#
# Default is a *scratch* server: binaries and config live in /tmp on the remote,
# no systemd units, no /etc/vallum, nothing installed. The only host changes are
# one UDP port, `net.ipv4.ip_forward`, and an nftables table of its own — all
# removed on exit.
#
# --product instead runs `vallum server init` with every host step on: it
# installs /usr/bin/vallum{,-quick}, /etc/vallum, both units, and the firewall
# rules the product would add. That is the honest test of `server init` on a
# real host, and it needs a disposable one.
#
# The local half needs root for the TUN; the SSH half runs as the invoking user
# so its keys work.

set -u
cd "$(dirname "$0")/.."

VALLUM=${VALLUM:-target/release/vallum}
QUICK=${QUICK:-target/release/vallum-quick}
PORT=${PORT:-51921}
SUBNET=${SUBNET:-10.99.90.0/24}
SRV_IP=${SRV_IP:-10.99.90.1}
CLI_IP=${CLI_IP:-10.99.90.2}
PREFIX=${PREFIX:-24}
REMOTE_DIR=/tmp/vallum-remote-test
LOCAL_DIR=/tmp/vallum-remote-client
CIFACE=vallumrc0
PRODUCT=0
KEEP=0
TARGET=""

say(){ printf '── %s\n' "$*"; }
ok(){ printf '   ok    %s\n' "$*"; }
bad(){ printf '   FAIL  %s\n' "$*"; exit 1; }
note(){ printf '   note  %s\n' "$*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --product) PRODUCT=1 ;;
        --keep) KEEP=1 ;;
        --port) shift; PORT=$1 ;;
        --subnet) shift; SUBNET=$1; PREFIX=${SUBNET#*/}; NET=${SUBNET%/*}; SRV_IP="${NET%.*}.1"; CLI_IP="${NET%.*}.2" ;;
        -h|--help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*) echo "unknown flag: $1" >&2; exit 1 ;;
        *) TARGET=$1 ;;
    esac
    shift
done
[ -n "$TARGET" ] || { echo "usage: $0 [--product] user@host" >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run with sudo: the client needs a TUN"; exit 1; }

# The remote half must run as the invoking user: root's SSH keys are not theirs.
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    OWNER_HOME=$(eval echo "~$SUDO_USER")
    rsh() { sudo -u "$SUDO_USER" env HOME="$OWNER_HOME" ssh -o BatchMode=yes "$TARGET" "$@"; }
    rscp() { sudo -u "$SUDO_USER" env HOME="$OWNER_HOME" scp -q "$@"; }
else
    rsh() { ssh -o BatchMode=yes "$TARGET" "$@"; }
    rscp() { scp -q "$@"; }
fi

SERVER_PID=""
CLIENT_PID=""
REMOTE_STARTED=0
FORWARD_WAS=""

cleanup() {
    set +e
    say "cleanup"
    [ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null
    [ -f "$LOCAL_DIR/client.toml" ] && "$QUICK" detach "$LOCAL_DIR/client.toml" >/dev/null 2>&1
    if [ "$REMOTE_STARTED" = 1 ]; then
        rsh "set +e
            sudo pkill -f '^$REMOTE_DIR/vallum run' 2>/dev/null
            sudo systemctl disable --now vallum-quick@vallumrc vallum@vallumrc >/dev/null 2>&1
            sudo rm -f /etc/systemd/system/vallum@.service /etc/systemd/system/vallum-quick@.service
            sudo systemctl daemon-reload >/dev/null 2>&1
            sudo rm -rf /etc/vallum /etc/sysctl.d/90-vallum.conf
            sudo ufw delete allow $PORT/udp >/dev/null 2>&1
            sudo iptables -D FORWARD -i vallumrc -j ACCEPT 2>/dev/null
            sudo iptables -D FORWARD -o vallumrc -j ACCEPT 2>/dev/null
            sudo iptables -D INPUT -p udp --dport $PORT -j ACCEPT 2>/dev/null
            sudo nft delete table inet vallum 2>/dev/null
            sudo nft delete table inet vallumtest 2>/dev/null
            sudo rm -f /usr/bin/vallum /usr/bin/vallum-quick
            sudo rm -rf $REMOTE_DIR" >/dev/null 2>&1
        if [ -n "$FORWARD_WAS" ]; then
            rsh "sudo sysctl -q -w net.ipv4.ip_forward=$FORWARD_WAS" >/dev/null 2>&1
        fi
    fi
    rm -rf "$LOCAL_DIR"
    ok "both ends restored"
}
[ "$KEEP" = 1 ] || trap cleanup EXIT

[ -x "$VALLUM" ] || bad "build first: cargo build --release -p vallum -p vallum-quick"

say "remote checks ($TARGET)"
rsh "sudo -n true" 2>/dev/null || bad "the remote user needs passwordless sudo"
rsh "test ! -e /etc/vallum" 2>/dev/null || bad "/etc/vallum already exists on the remote; refusing"
FORWARD_WAS=$(rsh "cat /proc/sys/net/ipv4/ip_forward" 2>/dev/null | tr -d '[:space:]')
[ -n "$FORWARD_WAS" ] || bad "cannot read the remote's ip_forward"
ok "passwordless sudo, no existing deployment, ip_forward=$FORWARD_WAS"

# The target may be an ssh alias, so ask ssh what it would connect to.
HOSTNAME=$(ssh -G "$TARGET" 2>/dev/null | awk '/^hostname /{print $2; exit}')
[ -n "$HOSTNAME" ] || HOSTNAME=${TARGET#*@}
PUBLIC=$(getent hosts "$HOSTNAME" 2>/dev/null | awk '{print $1; exit}')
[ -n "$PUBLIC" ] || bad "cannot resolve $HOSTNAME"
ok "the client will dial $PUBLIC:$PORT"

say "copying the binaries"
rsh "mkdir -p $REMOTE_DIR && rm -rf $REMOTE_DIR/*" || bad "mkdir on the remote"
rscp "$VALLUM" "$QUICK" "$TARGET:$REMOTE_DIR/" || bad "scp"
ok "binaries on the remote"

REMOTE_STARTED=1

if [ "$PRODUCT" = 1 ]; then
    say "server init, every host step on (--product)"
    rsh "sudo install -m0755 $REMOTE_DIR/vallum /usr/bin/vallum && \
         sudo install -m0755 $REMOTE_DIR/vallum-quick /usr/bin/vallum-quick && \
         sudo /usr/bin/vallum server init --config /etc/vallum/vallumrc.toml --name vallumrc \
              --address $SRV_IP/$PREFIX --listen 0.0.0.0:$PORT --endpoint $PUBLIC" \
        | tail -6 || bad "server init"
    for unit in vallum@vallumrc vallum-quick@vallumrc; do
        rsh "systemctl is-active $unit" | grep -q '^active$' || bad "$unit is not active"
    done
    ok "both units active"
    SERVER_CMD="sudo /usr/bin/vallum"
    CONFIG=/etc/vallum/vallumrc.toml
else
    say "scratch server (no systemd, no /etc)"
    rsh "sudo $REMOTE_DIR/vallum server init --config $REMOTE_DIR/server.toml --name vallumrc \
            --no-host --no-service --address $SRV_IP/$PREFIX --listen 0.0.0.0:$PORT \
            --endpoint $PUBLIC --control $REMOTE_DIR/server.sock" >/dev/null || bad "server init"
    rsh "sudo sysctl -q -w net.ipv4.ip_forward=1
         sudo ufw allow $PORT/udp >/dev/null 2>&1
         sudo nft add table inet vallumtest 2>/dev/null
         sudo nft 'add chain inet vallumtest postrouting { type nat hook postrouting priority srcnat; }' 2>/dev/null
         sudo nft add rule inet vallumtest postrouting ip saddr $SUBNET masquerade 2>/dev/null
         sudo nohup $REMOTE_DIR/vallum run --config $REMOTE_DIR/server.toml > $REMOTE_DIR/server.log 2>&1 &
         sleep 2" || bad "remote host setup"
    rsh "test -S $REMOTE_DIR/server.sock" || { rsh "sudo tail -5 $REMOTE_DIR/server.log"; bad "the remote daemon did not start"; }
    ok "forwarding, NAT, one UDP port, daemon up"
    SERVER_CMD="sudo $REMOTE_DIR/vallum"
    CONFIG=$REMOTE_DIR/server.toml
fi

say "enrolling a client"
rsh "$SERVER_CMD peer add laptop --config $CONFIG --endpoint $PUBLIC \
        --bundle-out $REMOTE_DIR/bundle --dns 1.1.1.1" >/dev/null || bad "peer add"
rsh "sudo cp $REMOTE_DIR/bundle $REMOTE_DIR/bundle.tmp && sudo chmod 644 $REMOTE_DIR/bundle.tmp" || bad "chmod"
ok "bundle written on the remote"

BUNDLE=/tmp/vallum-remote.bundle
rscp "$TARGET:$REMOTE_DIR/bundle.tmp" "$BUNDLE" || bad "could not fetch the bundle"
rm -rf "$LOCAL_DIR" && mkdir -p "$LOCAL_DIR"
"$VALLUM" import-bundle "$BUNDLE" --output-dir "$LOCAL_DIR" >/dev/null || bad "import-bundle"
CLIENT_CONFIG=$(ls "$LOCAL_DIR"/*.toml | head -1)
# Split tunnel: only the server's tunnel address and one internet address go
# through the tunnel, so the local default route and DNS are untouched.
python3 - "$CLIENT_CONFIG" "$CIFACE" "$SRV_IP" "$LOCAL_DIR" <<'PY'
import re, sys
path, iface, srv, workdir = sys.argv[1:5]
text = open(path).read()
text = re.sub(r'^name = ".*?"', f'name = "{iface}"', text, count=1, flags=re.M)
text = re.sub(r'^control = .*$', f'control = "{workdir}/c.sock"', text, flags=re.M)
text = re.sub(r'allowed_ips = \[.*?\]', f'allowed_ips = ["{srv}/32", "1.1.1.1/32"]', text)
text = re.sub(r'^dns = .*\n', '', text, flags=re.M)
open(path, 'w').write(text)
PY
ok "client config prepared (split tunnel)"

say "client daemon"
"$VALLUM" run --config "$CLIENT_CONFIG" > "$LOCAL_DIR/client.log" 2>&1 &
CLIENT_PID=$!
sleep 2
kill -0 "$CLIENT_PID" 2>/dev/null || { cat "$LOCAL_DIR/client.log"; bad "the client daemon exited"; }
"$QUICK" attach "$CLIENT_CONFIG" > "$LOCAL_DIR/attach.log" 2>&1 || { cat "$LOCAL_DIR/attach.log"; bad "attach"; }

established=0
for _ in $(seq 1 20); do
    ping -c1 -W1 "$SRV_IP" >/dev/null 2>&1
    "$VALLUM" show --control "$LOCAL_DIR/c.sock" 2>/dev/null | grep -q "last_handshake_time_sec=[1-9]" && { established=1; break; }
    sleep 0.5
done
[ "$established" = 1 ] && ok "handshake" || bad "no handshake: is UDP $PORT reachable?"

say "the tunnel"
ping -c2 -W3 "$SRV_IP" > "$LOCAL_DIR/tunnel.log" 2>&1 || { cat "$LOCAL_DIR/tunnel.log"; bad "the tunnel does not ping"; }
ok "tunnel: $(tail -2 "$LOCAL_DIR/tunnel.log" | head -1)"

say "the internet, through the server's NAT"
ping -c3 -W4 1.1.1.1 > "$LOCAL_DIR/egress.log" 2>&1 || { cat "$LOCAL_DIR/egress.log"; bad "no egress through the server"; }
ok "egress: $(tail -2 "$LOCAL_DIR/egress.log" | head -1)"

say "DNS through the tunnel"
if command -v dig >/dev/null 2>&1; then
    dig +time=3 +tries=1 @1.1.1.1 example.com A > "$LOCAL_DIR/dig.log" 2>&1 \
        && grep -q "ANSWER SECTION" "$LOCAL_DIR/dig.log" \
        && ok "DNS: $(grep -E '^example.com' "$LOCAL_DIR/dig.log" | head -1)" \
        || bad "DNS through the tunnel did not answer"
else
    note "dig not installed; skipped"
fi

say "PASS — a real client, a real server, real egress"
