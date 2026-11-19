#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Gate: opt-in client isolation (ADR-0047 service tenancy).
#
# One server and TWO clients in network namespaces, plus a fourth "wan"
# namespace that stands in for the internet. With `[interface]
# client_isolation` off (the personal default) the two peers reach each
# other; with it on they must NOT reach each other, while BOTH still reach
# the wan and the server itself. The toggle is exercised the way an operator
# does it: edit the config, re-run `vallum server init`, and the host plan
# converges — including back to flat.
#
#   scripts/accept-isolation.sh        # one command, no arguments, no secrets
#
# Nothing outside the namespaces is touched: no host routes, no host
# firewall, no VPS. The default backend needs no container runtime — an
# unprivileged user namespace grants the CAP_NET_ADMIN the TUN and nft
# setup want. `sudo -n` is tried only as a fallback for a host whose
# AppArmor forbids unprivileged user namespaces.
set -uo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
trap 'rc=$?; command -v cleanup >/dev/null 2>&1 && cleanup; "$REPO/scripts/verdict.sh" accept-isolation "$([ "$rc" -eq 0 ] && echo passed || echo failed)" "${ASSERTIONS:-0}" "$0"' EXIT
ASSERTIONS=0

say() { echo "[isolation] $*"; }
die() { echo "[isolation] FAIL: $*" >&2; exit 1; }

say "building the release binary"
cargo build --release -p vallum >/dev/null 2>&1 \
    || die "cargo build --release -p vallum failed"
[ -x "$REPO/target/release/vallum" ] || die "no binary after build"
cd "$REPO"

command -v unshare >/dev/null 2>&1 || die "unshare (util-linux) is required"

WORK=$(mktemp -d /tmp/vallum-isolation.XXXXXX)
cleanup() { rm -rf -- "$WORK"; }

# The lab body is materialized to a file, not piped through bash -s: the
# e2e-netns suite documented a bash parser bug on non-seekable stdin heredocs
# above a certain size, and a seekable file is independently lintable.
cat > "$WORK/inner.sh" <<'INNER'
set -euo pipefail
BIN=$1
WORK=$2
export PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH

# The lab runs inside `unshare -Urn`: this shell IS the server namespace.
SRV_OUT_B=10.99.0.1   # server end of the veth to client B
SRV_OUT_C=10.99.1.1   # server end of the veth to client C
SRV_OUT_W=10.99.2.1   # server end of the veth to the wan
B_OUT=10.99.0.2
C_OUT=10.99.1.2
W_OUT=10.99.2.2       # the "internet" address both clients must keep reaching
INNER_SRV=10.7.0.1
INNER_B=10.7.0.2
INNER_C=10.7.0.3
PORT=51820

SRV_LOG=$WORK/srv.log
B_LOG=$WORK/devb.log
C_LOG=$WORK/devc.log
SRV_PIDFILE=$WORK/srv.pid
B_PIDFILE=$WORK/devb.pid
C_PIDFILE=$WORK/devc.pid
B_HOLDER=$WORK/b.holder
C_HOLDER=$WORK/c.holder
W_HOLDER=$WORK/w.holder

say()  { printf '\n── %s\n' "$*"; }
ok()   { printf '   ok    %s\n' "$*"; }
bad()  { printf '   FAIL  %s\n' "$*" >&2; exit 1; }

kill_pidfile() {
    [ -f "$1" ] || return 0
    kill ${2:--TERM} "$(cat "$1")" 2>/dev/null || true
}
stop_all() {
    kill_pidfile "$SRV_PIDFILE"; kill_pidfile "$B_PIDFILE"; kill_pidfile "$C_PIDFILE"
    kill_pidfile "$SRV_PIDFILE" -KILL; kill_pidfile "$B_PIDFILE" -KILL; kill_pidfile "$C_PIDFILE" -KILL
    kill_pidfile "$B_HOLDER" -KILL; kill_pidfile "$C_HOLDER" -KILL; kill_pidfile "$W_HOLDER" -KILL
    wait 2>/dev/null || true
    # An escalated (real-root) run leaves root-owned files in the user's
    # scratch dir; hand them back so the outer cleanup can remove them.
    chmod -R a+rwX "$WORK" 2>/dev/null || true
}
trap stop_all EXIT

in_b() { nsenter -t "$(cat "$B_HOLDER")" -n -- "$@"; }
in_c() { nsenter -t "$(cat "$C_HOLDER")" -n -- "$@"; }
in_w() { nsenter -t "$(cat "$W_HOLDER")" -n -- "$@"; }

# Retry a crossing until a reply arrives: one lost datagram is not a failure.
crosses() { # $1 seconds, $2 namespace-runner (empty = here), rest: ping args
    local wait=$1 runner=$2; shift 2
    local deadline=$((SECONDS + wait))
    until $runner ping -c1 -W2 -q "$@" >/dev/null 2>&1; do
        [ "$SECONDS" -ge "$deadline" ] && return 1
        sleep 0.2
    done
}
# The negative check: the crossing must fail for the WHOLE window, not once.
silent() { # $1 seconds, $2 runner, rest: ping args
    local wait=$1 runner=$2; shift 2
    local deadline=$((SECONDS + wait))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if $runner ping -c1 -W1 -q "$@" >/dev/null 2>&1; then return 1; fi
        sleep 0.2
    done
    return 0
}

dump_state() { # $1 label — what the lab looked like when a check failed
    {
        printf '\n── %s: server config\n' "$1"; cat "$WORK/srv.toml" 2>/dev/null || true
        printf '\n── %s: nft table inet vallum\n' "$1"; nft list table inet vallum 2>&1 || true
        printf '\n── %s: last 15 lines of each daemon log\n' "$1"
        for log in "$SRV_LOG" "$B_LOG" "$C_LOG"; do
            printf '── %s\n' "$log"; tail -n 15 "$log" 2>/dev/null || true
        done
    } >&2
}

say "building the outer network: server star with three veths (B, C, wan)"
ip link set lo up
mkdir -p "$WORK/rt"

unshare -n sleep infinity & echo $! > "$B_HOLDER"
unshare -n sleep infinity & echo $! > "$C_HOLDER"
unshare -n sleep infinity & echo $! > "$W_HOLDER"
sleep 0.3

ip link add veth-b1 type veth peer name veth-b2
ip link add veth-c1 type veth peer name veth-c2
ip link add veth-w1 type veth peer name veth-w2
ip link set veth-b1 up; ip addr add "$SRV_OUT_B/24" dev veth-b1
ip link set veth-c1 up; ip addr add "$SRV_OUT_C/24" dev veth-c1
ip link set veth-w1 up; ip addr add "$SRV_OUT_W/24" dev veth-w1
ip link set veth-b2 netns "$(cat "$B_HOLDER")"
ip link set veth-c2 netns "$(cat "$C_HOLDER")"
ip link set veth-w2 netns "$(cat "$W_HOLDER")"
in_b ip link set lo up; in_b ip link set veth-b2 up; in_b ip addr add "$B_OUT/24" dev veth-b2
in_c ip link set lo up; in_c ip link set veth-c2 up; in_c ip addr add "$C_OUT/24" dev veth-c2
in_w ip link set lo up; in_w ip link set veth-w2 up; in_w ip addr add "$W_OUT/24" dev veth-w2

ping -c1 -W3 -q "$B_OUT" >/dev/null || bad "outer link to B is not up"
ping -c1 -W3 -q "$C_OUT" >/dev/null || bad "outer link to C is not up"
ping -c1 -W3 -q "$W_OUT" >/dev/null || bad "outer link to the wan is not up"
ok "outer network is up: server reaches B, C and the wan"

# The rig enables forwarding itself: `server init --no-forward` skips the
# product's /etc/sysctl.d write, which a user namespace cannot do (the host
# /etc is not writable here). The sysctl is per-netns, so this touches only
# the lab. The NAT/isolation plan below IS the product's own.
echo 1 > /proc/sys/net/ipv4/ip_forward

INIT_ARGS=(--config "$WORK/srv.toml" --name vallum0 --address "$INNER_SRV/24"
    --listen "0.0.0.0:$PORT" --endpoint "$SRV_OUT_B:$PORT"
    --control "$WORK/rt/srv.sock" --no-service --no-forward --no-firewall)

say "server init (flat personal default), then the daemon"
"$BIN" server init "${INIT_ARGS[@]}" > "$WORK/srv-init.log" 2>&1 \
    || { cat "$WORK/srv-init.log" >&2; bad "server init failed"; }
if grep -q 'client_isolation' "$WORK/srv.toml"; then
    bad "the flat default wrote a client_isolation key"
fi
ok "server init wrote a flat config (no client_isolation key)"

"$BIN" run --config "$WORK/srv.toml" > "$SRV_LOG" 2>&1 &
echo $! > "$SRV_PIDFILE"
sleep 1
kill -0 "$(cat "$SRV_PIDFILE")" 2>/dev/null || { tail -20 "$SRV_LOG" >&2; bad "server daemon died"; }

say "provisioning two devices through the real peer add path"
for dev in devb devc; do
    "$BIN" keygen --output "$WORK/$dev.key" > "$WORK/$dev.pub" 2>"$WORK/$dev.keygen.log" \
        || { cat "$WORK/$dev.keygen.log" >&2; bad "keygen $dev failed"; }
done
"$BIN" peer add devb --config "$WORK/srv.toml" --public-key-file "$WORK/devb.pub" \
    --endpoint "$SRV_OUT_B:$PORT" --client-config-out "$WORK/devb.toml" \
    > "$WORK/add-b.log" 2>&1 || { cat "$WORK/add-b.log" >&2; bad "peer add devb failed"; }
"$BIN" peer add devc --config "$WORK/srv.toml" --public-key-file "$WORK/devc.pub" \
    --endpoint "$SRV_OUT_C:$PORT" --client-config-out "$WORK/devc.toml" \
    > "$WORK/add-c.log" 2>&1 || { cat "$WORK/add-c.log" >&2; bad "peer add devc failed"; }
ok "two peers provisioned; the server wrote both client configs"

# The product-written client config names /run/vallum for its socket; the
# lab's runtime dir is in $WORK (the host /run is not writable here). Only
# that path is adapted — the config is otherwise the server's own artifact.
B_IF=$(grep -m1 '^name' "$WORK/devb.toml" | cut -d'"' -f2)
C_IF=$(grep -m1 '^name' "$WORK/devc.toml" | cut -d'"' -f2)
[ -n "$B_IF" ] && [ -n "$C_IF" ] || bad "client configs name no interface"
sed -i "s|^control = .*|control = \"$WORK/rt/$B_IF.sock\"|" "$WORK/devb.toml"
sed -i "s|^control = .*|control = \"$WORK/rt/$C_IF.sock\"|" "$WORK/devc.toml"

in_b "$BIN" run --config "$WORK/devb.toml" > "$B_LOG" 2>&1 &
echo $! > "$B_PIDFILE"
in_c "$BIN" run --config "$WORK/devc.toml" > "$C_LOG" 2>&1 &
echo $! > "$C_PIDFILE"
sleep 1

# Full-tunnel routes by hand (the lab has no vallum-quick/systemd): the
# default goes into the tunnel; the daemon's own UDP still leaves via the
# connected veth route, which is more specific than the default.
in_b ip route add default via "$INNER_SRV" dev "$B_IF"
in_c ip route add default via "$INNER_SRV" dev "$C_IF"

say "waiting for both clients to handshake (a ping triggers the dial)"
handshook() { # $1 control socket
    "$BIN" show --control "$1" 2>/dev/null | grep -q 'last_handshake_time_sec'
}
deadline=$((SECONDS + 45))
until handshook "$WORK/rt/$B_IF.sock" && handshook "$WORK/rt/$C_IF.sock"; do
    [ "$SECONDS" -ge "$deadline" ] && { dump_state "handshake timeout"; bad "a client never handshook"; }
    in_b ping -c1 -W1 -q "$INNER_SRV" >/dev/null 2>&1 || true
    in_c ping -c1 -W1 -q "$INNER_SRV" >/dev/null 2>&1 || true
    sleep 2
done
ok "both clients handshook with the server"

say "flat default: the two peers reach each other and the internet"
crosses 10 in_b "$INNER_C" || { dump_state "flat B->C"; bad "flat default: B cannot reach C"; }
ok "flat: B reaches C through the tunnel"
crosses 10 in_c "$INNER_B" || { dump_state "flat C->B"; bad "flat default: C cannot reach B"; }
ok "flat: C reaches B through the tunnel"
crosses 10 in_b "$W_OUT" || { dump_state "flat B->wan"; bad "flat: B cannot reach the wan"; }
crosses 10 in_c "$W_OUT" || { dump_state "flat C->wan"; bad "flat: C cannot reach the wan"; }
ok "flat: both clients reach the wan (forward + masquerade)"

say "the flag against a preserved flat config is refused, not silent"
if "$BIN" server init "${INIT_ARGS[@]}" --client-isolation > "$WORK/refuse.log" 2>&1; then
    bad "init --client-isolation against a flat config should refuse"
fi
grep -q 'client_isolation' "$WORK/refuse.log" \
    || { cat "$WORK/refuse.log" >&2; bad "the refusal does not name client_isolation"; }
ok "re-init with the flag against a flat config refuses and names the key"

say "operator toggle: client_isolation = true in the config, re-run init"
sed -i '/^forward = true/a client_isolation = true' "$WORK/srv.toml"
grep -q '^client_isolation = true' "$WORK/srv.toml" || bad "the toggle did not land in [interface]"
"$BIN" server init "${INIT_ARGS[@]}" > "$WORK/srv-init-iso.log" 2>&1 \
    || { cat "$WORK/srv-init-iso.log" >&2; bad "re-init with isolation failed"; }
grep -q '^client_isolation = true' "$WORK/srv.toml" \
    || bad "re-init rewrote the preserved config"
nft list chain inet vallum forward 2>/dev/null | grep -q 'iifname "vallum0" oifname "vallum0" drop' \
    || { nft list table inet vallum >&2; bad "the isolation drop chain is not installed"; }
ok "re-init converged: the drop chain is in Vallum's own table, config preserved"

say "isolated: peers must NOT reach each other; the wan and server must stay"
silent 6 in_b "$INNER_C" || { dump_state "isolated B->C"; bad "isolation ON but B still reaches C"; }
ok "isolated: B cannot reach C (sustained over the whole window)"
silent 6 in_c "$INNER_B" || { dump_state "isolated C->B"; bad "isolation ON but C still reaches B"; }
ok "isolated: C cannot reach B (sustained over the whole window)"
crosses 10 in_b "$W_OUT" || { dump_state "isolated B->wan"; bad "isolation broke B's internet path"; }
crosses 10 in_c "$W_OUT" || { dump_state "isolated C->wan"; bad "isolation broke C's internet path"; }
ok "isolated: both clients STILL reach the wan"
crosses 10 in_b "$INNER_SRV" || { dump_state "isolated B->srv"; bad "isolation broke the client->server path"; }
ok "isolated: the server's own tunnel address still answers (input, not forward)"

say "toggle back off: the host converges to flat again"
sed -i '/^client_isolation = true/d' "$WORK/srv.toml"
"$BIN" server init "${INIT_ARGS[@]}" > "$WORK/srv-init-flat.log" 2>&1 \
    || { cat "$WORK/srv-init-flat.log" >&2; bad "re-init back to flat failed"; }
if nft list chain inet vallum forward >/dev/null 2>&1; then
    bad "the forward chain survived the toggle back to flat"
fi
crosses 10 in_b "$INNER_C" || { dump_state "reflat B->C"; bad "toggle off did not restore peer reachability"; }
ok "toggle off removed the drop chain and B reaches C again"

say "creation flag: --client-isolation persists and reports"
mkdir -p "$WORK/fresh"
"$BIN" server init --config "$WORK/fresh/s.toml" --name vallum0 \
    --address "$INNER_SRV/24" --listen "0.0.0.0:$PORT" --endpoint "$SRV_OUT_B:$PORT" \
    --no-host --no-service --dry-run --client-isolation > "$WORK/fresh.log" 2>&1 \
    || { cat "$WORK/fresh.log" >&2; bad "dry-run init --client-isolation failed"; }
grep -q 'client_isolation = true' "$WORK/fresh.log" \
    || { cat "$WORK/fresh.log" >&2; bad "the created config would not carry client_isolation"; }
"$BIN" server init --config "$WORK/fresh/s.toml" --name vallum0 \
    --address "$INNER_SRV/24" --listen "0.0.0.0:$PORT" --endpoint "$SRV_OUT_B:$PORT" \
    --no-host --no-service --dry-run --json --client-isolation > "$WORK/fresh.json" 2>&1 \
    || { cat "$WORK/fresh.json" >&2; bad "json dry-run init failed"; }
grep -q '"client_isolation": true' "$WORK/fresh.json" \
    || { cat "$WORK/fresh.json" >&2; bad "the json report does not carry client_isolation"; }
ok "--client-isolation persists at creation and shows in the report"

printf '\n== PASS - isolation blocks peer-to-peer, keeps the internet, and converges both ways\n'
INNER

say "running the lab in an unprivileged user namespace (no docker required)"
LAB_OUT=$(unshare -Urn bash "$WORK/inner.sh" "$REPO/target/release/vallum" "$WORK" 2>&1)
LAB_RC=$?
if [ "$LAB_RC" -ne 0 ]; then
    say "unprivileged namespaces unavailable - trying sudo -n (AppArmor fallback)"
    LAB_OUT2=$(sudo -n unshare -Urn bash "$WORK/inner.sh" "$REPO/target/release/vallum" "$WORK" 2>&1)
    LAB_RC=$?
    if [ "$LAB_RC" -eq 0 ]; then LAB_OUT=$LAB_OUT2; else LAB_OUT="$LAB_OUT
$LAB_OUT2"; fi
fi
printf '%s\n' "$LAB_OUT"
ASSERTIONS=$(printf '%s\n' "$LAB_OUT" | grep -c '^   ok')
if [ "$LAB_RC" -ne 0 ]; then
    echo "== FAIL - the isolation lab did not pass (see the FAIL line above)"
    exit 1
fi
echo "== PASS - opt-in client isolation verified end to end"
