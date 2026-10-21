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
#   sudo ./scripts/verify-remote.sh --transports token user@vps.example.com
#   sudo ./scripts/verify-remote.sh --clean-remote user@vps.example.com
#
# A host that already runs Vallum is refused, because the test installs its own
# deployment and would otherwise delete a working one. `--clean-remote` is the
# explicit override: it removes an existing Vallum deployment (listed below) and
# then proceeds. It removes *Vallum's* files, never anyone else's.
#
# It enrols one client per enrolment transport — bundle, ssh (`setup --remote`),
# token (`peer invite` + `setup --join`) — and proves each carries traffic. A
# pass records the commit in ~/.local/state/vallum/remote-verified, which
# scripts/release.sh requires before it will build a release.
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
cd "$(dirname "$0")/.." || exit 1

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
CLEAN=0
TRANSPORTS="bundle ssh token"
TARGET=""

say(){ printf '── %s\n' "$*"; }
ok(){ printf '   ok    %s\n' "$*"; }
bad(){ printf '   FAIL  %s\n' "$*"; exit 1; }
note(){ printf '   note  %s\n' "$*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --product) PRODUCT=1 ;;
        --keep) KEEP=1 ;;
        --clean-remote) CLEAN=1 ;;
        --transports) shift; TRANSPORTS=$1 ;;
        --port) shift; PORT=$1 ;;
        --subnet) shift; SUBNET=$1; PREFIX=${SUBNET#*/}; NET=${SUBNET%/*}; SRV_IP="${NET%.*}.1"; CLI_IP="${NET%.*}.2" ;;
        -h|--help) sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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
            sudo pkill -f '^$REMOTE_DIR/vallum enroll-serve' 2>/dev/null
            sudo systemctl disable --now vallum-enroll@vallumrc >/dev/null 2>&1
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
# Absolute, because the client half runs with a working directory of its own.
VALLUM=$(cd "$(dirname "$VALLUM")" && pwd)/$(basename "$VALLUM")
QUICK=$(cd "$(dirname "$QUICK")" && pwd)/$(basename "$QUICK")

say "remote checks ($TARGET)"
rsh "sudo -n true" 2>/dev/null || bad "the remote user needs passwordless sudo"
if rsh "test -e /etc/vallum" 2>/dev/null; then
    if [ "$CLEAN" != 1 ]; then
        bad "/etc/vallum already exists on the remote; refusing to delete a live deployment.
   Re-run with --clean-remote to remove it first, or pick a host with no Vallum."
    fi
    say "removing the existing deployment (--clean-remote)"
    echo "   units:      vallum@*, vallum-quick@*, vallum-enroll@*"
    echo "   files:      /etc/vallum, /etc/sysctl.d/90-vallum.conf, /usr/bin/vallum{,-quick}"
    echo "   firewall:   the UDP port rule, the vallum FORWARD rules, table inet vallum"
    rsh "set +e
        sudo systemctl disable --now 'vallum@*' 'vallum-quick@*' 'vallum-enroll@*' >/dev/null 2>&1
        sudo rm -f /etc/systemd/system/vallum@.service /etc/systemd/system/vallum-quick@.service \
                   /etc/systemd/system/vallum-enroll@.service
        sudo systemctl daemon-reload >/dev/null 2>&1
        sudo rm -rf /etc/vallum /run/vallum /etc/sysctl.d/90-vallum.conf
        sudo ufw delete allow $PORT/udp >/dev/null 2>&1
        sudo nft delete table inet vallum >/dev/null 2>&1
        sudo rm -f /usr/bin/vallum /usr/bin/vallum-quick" >/dev/null 2>&1
    rsh "test ! -e /etc/vallum" || bad "could not remove the existing deployment"
    ok "existing deployment removed"
fi
FORWARD_WAS=$(rsh "cat /proc/sys/net/ipv4/ip_forward" 2>/dev/null | tr -d '[:space:]')
[ -n "$FORWARD_WAS" ] || bad "cannot read the remote's ip_forward"
ok "passwordless sudo, no existing deployment, ip_forward=$FORWARD_WAS"

# The target may be an ssh alias, so ask ssh what it would connect to — as the
# invoking user, because `ssh` reads `~/.ssh/config` from the passwd entry and
# root's home has none of their aliases.
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    HOSTNAME=$(sudo -u "$SUDO_USER" env HOME="$OWNER_HOME" ssh -G "$TARGET" 2>/dev/null \
        | awk '/^hostname /{print $2; exit}')
else
    HOSTNAME=$(ssh -G "$TARGET" 2>/dev/null | awk '/^hostname /{print $2; exit}')
fi
[ -n "$HOSTNAME" ] || HOSTNAME=${TARGET#*@}
PUBLIC=$(getent hosts "$HOSTNAME" 2>/dev/null | awk '{print $1; exit}')
if [ -z "$PUBLIC" ]; then
    # `ssh -G` may already have given us an address.
    case "$HOSTNAME" in
        *[0-9].[0-9]*) PUBLIC=$HOSTNAME ;;
    esac
fi
[ -n "$PUBLIC" ] || bad "cannot resolve $HOSTNAME (checked the invoking user's ssh config and DNS)"
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

say "server ready for enrolment"

# ── the three transports ─────────────────────────────────────────────────
# Each one ends with a client config on this machine. What they prove is that
# *provisioning* works three ways; the tunnel that follows is the same for all.

ENROLL_READY=0
ensure_enroll() {
    [ "$ENROLL_READY" = 1 ] && return 0
    if [ "$PRODUCT" = 1 ]; then
        rsh "sudo /usr/bin/vallum server enroll --config $CONFIG --enable" >/dev/null || bad "server enroll --enable"
    else
        rsh "sudo sh -c 'grep -q \"^\\[enroll\\]\" $CONFIG || printf \"\\n[enroll]\\nenabled = true\\nport = $((PORT+1))\\n\" >> $CONFIG'"
        rsh "sudo ufw allow $((PORT+1))/udp >/dev/null 2>&1
             sudo nohup $REMOTE_DIR/vallum enroll-serve --config $CONFIG >> $REMOTE_DIR/enroll.log 2>&1 &
             sleep 1"
    fi
    ENROLL_READY=1
}

# Run a command as the invoking user, in a directory, so `setup` writes there
# instead of /etc/vallum.
as_owner() {
    local dir=$1
    shift
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
        sudo -u "$SUDO_USER" env HOME="$OWNER_HOME" sh -c "cd '$dir' && $*"
    else
        sh -c "cd '$dir' && $*"
    fi
}

enrol_bundle() {
    local name=$1 dir=$2
    rsh "$SERVER_CMD peer add $name --config $CONFIG --endpoint $PUBLIC \
            --ship-key --bundle-out $REMOTE_DIR/$name.bundle" >/dev/null || bad "peer add ($name)"
    rsh "sudo chmod 644 $REMOTE_DIR/$name.bundle" || bad "chmod bundle"
    rscp "$TARGET:$REMOTE_DIR/$name.bundle" "$dir/$name.vallum-bundle" || bad "fetch bundle"
    "$VALLUM" import-bundle "$dir/$name.vallum-bundle" --output-dir "$dir" >/dev/null || bad "import-bundle"
}

enrol_ssh() {
    local name=$1 dir=$2
    # `setup --remote` runs `sudo vallum peer enroll` over there, so the binary
    # must be installed. Cleanup removes it again.
    if [ "$PRODUCT" != 1 ]; then
        rsh "sudo install -m0755 $REMOTE_DIR/vallum /usr/bin/vallum" || bad "install vallum on the remote"
        note "installed vallum to /usr/bin on the remote for the ssh transport"
    fi
    as_owner "$dir" "$VALLUM setup --remote $TARGET --name $name" > "$dir/setup.log" 2>&1 \
        || { cat "$dir/setup.log"; bad "setup --remote ($name)"; }
}

enrol_token() {
    local name=$1 dir=$2
    ensure_enroll
    local invite id token fingerprint
    invite=$(rsh "$SERVER_CMD peer invite $name --config $CONFIG --json") || bad "peer invite ($name)"
    id=$(printf '%s' "$invite" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
    token=$(printf '%s' "$invite" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
    fingerprint=$(printf '%s' "$invite" | python3 -c 'import json,sys; print(json.load(sys.stdin)["fingerprint"])')
    as_owner "$dir" "$VALLUM setup --join $PUBLIC:$((PORT+1)) --name $name \
            --invite-id $id --token $token --expect $fingerprint" > "$dir/setup.log" 2>&1 \
        || { cat "$dir/setup.log"; bad "setup --join ($name)"; }
    grep -q "server fingerprint $fingerprint" "$dir/setup.log" || bad "the fingerprint was not verified"
}

# A client config from any transport, rewritten to a split tunnel so this
# machine's default route and resolver are never touched, then run and proved.
prove_client() {
    local name=$1 dir=$2 config iface=$CIFACE
    config=$(ls "$dir"/*.toml | head -1)
    [ -n "$config" ] || bad "$name: no client config was produced"

    # Before rewriting it into a split tunnel, check the config as the server
    # produced it: `attach --dry-run` prints the plan and refuses a config it
    # could not install (a full tunnel without a fwmark, for instance).
    "$QUICK" attach "$config" --dry-run > "$dir/attach-dry.log" 2>&1 \
        || { cat "$dir/attach-dry.log"; bad "$name: the config as produced cannot be attached"; }
    python3 - "$config" "$iface" "$SRV_IP" "$dir" <<'PY'
import re, sys
path, iface, srv, workdir = sys.argv[1:5]
text = open(path).read()
text = re.sub(r'^name = ".*?"', f'name = "{iface}"', text, count=1, flags=re.M)
text = re.sub(r'^control = .*$', f'control = "{workdir}/c.sock"', text, flags=re.M)
text = re.sub(r'allowed_ips = \[.*?\]', f'allowed_ips = ["{srv}/32", "1.1.1.1/32"]', text)
text = re.sub(r'^dns = .*\n', '', text, flags=re.M)
open(path, 'w').write(text)
PY

    "$VALLUM" run --config "$config" > "$dir/client.log" 2>&1 &
    CLIENT_PID=$!
    sleep 2
    kill -0 "$CLIENT_PID" 2>/dev/null || { cat "$dir/client.log"; bad "$name: the client daemon exited"; }
    "$QUICK" attach "$config" > "$dir/attach.log" 2>&1 || { cat "$dir/attach.log"; bad "$name: attach"; }

    local established=0
    for _ in $(seq 1 20); do
        # Traffic drives the handshake — the daemon does not dial an idle peer
        # on its own, exactly as WireGuard does not. The ping is what starts it.
        ping -c1 -W1 "$SRV_IP" >/dev/null 2>&1
        "$VALLUM" show --control "$dir/c.sock" 2>/dev/null | grep -q "last_handshake_time_sec=[1-9]" && { established=1; break; }
        sleep 0.5
    done
    [ "$established" = 1 ] || bad "$name: no handshake (is UDP $PORT reachable?)"

    ping -c2 -W3 "$SRV_IP" > "$dir/tunnel.log" 2>&1 || { cat "$dir/tunnel.log"; bad "$name: the tunnel does not ping"; }
    ping -c3 -W4 1.1.1.1 > "$dir/egress.log" 2>&1 || { cat "$dir/egress.log"; bad "$name: no egress through the server"; }
    if command -v dig >/dev/null 2>&1; then
        dig +time=3 +tries=1 @1.1.1.1 example.com A > "$dir/dig.log" 2>&1
        grep -q "ANSWER SECTION" "$dir/dig.log" || bad "$name: DNS through the tunnel did not answer"
    fi
    ok "$name: handshake, tunnel, egress$(command -v dig >/dev/null 2>&1 && printf ', DNS')"

    kill "$CLIENT_PID" 2>/dev/null; wait "$CLIENT_PID" 2>/dev/null
    CLIENT_PID=""
    "$QUICK" detach "$config" >/dev/null 2>&1
    # The next transport reuses this interface name; wait for the kernel to
    # release it rather than failing on "device exists".
    for _ in $(seq 1 25); do
        ip link show "$iface" >/dev/null 2>&1 || break
        sleep 0.2
    done
}

for kind in $TRANSPORTS; do
    name="laptop-$kind"
    dir="$LOCAL_DIR/$kind"
    rm -rf "$dir" && mkdir -p "$dir"
    # The client half runs as the invoking user (their SSH keys, and `setup`
    # writes here instead of /etc/vallum), so the directory must be theirs.
    chown "${SUDO_USER:-root}" "$LOCAL_DIR" "$dir" 2>/dev/null
    say "transport: $kind"
    case "$kind" in
        bundle) enrol_bundle "$name" "$dir" ;;
        ssh)    enrol_ssh "$name" "$dir" ;;
        token)  enrol_token "$name" "$dir" ;;
        *) bad "unknown transport: $kind (bundle, ssh, token)" ;;
    esac
    ok "$kind: client config on this machine"
    prove_client "$name" "$dir"
done

say "PASS — a real client, a real server, real egress, three enrolment transports"

# The stamp scripts/release.sh requires. It lives outside the repository and
# names the commit it proved, so an old pass cannot vouch for a new tree.
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    OWNER_STATE=$(sudo -u "$SUDO_USER" sh -c 'printf %s "${XDG_STATE_HOME:-$HOME/.local/state}"')
else
    OWNER_STATE="${XDG_STATE_HOME:-$HOME/.local/state}"
fi
mkdir -p "$OWNER_STATE/vallum"
printf '%s\n' "$(git rev-parse HEAD)" > "$OWNER_STATE/vallum/remote-verified"
chown -R "${SUDO_USER:-root}" "$OWNER_STATE/vallum" 2>/dev/null
say "recorded $(git rev-parse --short HEAD) as verified on two hosts"
