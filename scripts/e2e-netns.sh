#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Two `vallum run` daemons, two real TUN interfaces, real UDP, real kernel
# routing — end to end.
#
# `crates/vallum/tests/gate.rs` substitutes the interface, the socket and the
# clock, so it can prove the daemon's logic but not that the logic meets a
# kernel. This script closes that gap: it starts the actual binary against
# `/dev/net/tun` and a real `UdpSocket`, in two network namespaces joined by a
# veth pair, and then pings across the tunnel. A successful ping means the
# packet was routed into `vallum0`, read by daemon A, sealed, sent as UDP,
# accepted by daemon B, opened, written to B's `vallum0`, answered by B's
# kernel, and came all the way back. Nothing else can deliver it: the inner
# addresses exist only on the two TUN interfaces.
#
#   ns1 (this shell)                     ns2
#   ┌────────────────────────┐           ┌────────────────────────┐
#   │ vallum0 10.7.0.1/24    │           │ vallum0 10.7.0.2/24    │
#   │   ⇅ daemon A           │           │   ⇅ daemon B           │
#   │ veth-a 10.99.0.1/24 ───┼───veth────┼── 10.99.0.2/24 veth-b  │
#   └────────────────────────┘           └────────────────────────┘
#        UDP 10.99.0.1:51820                 UDP 10.99.0.2:51820
#
# No root: an unprivileged user namespace grants CAP_NET_ADMIN over a network
# namespace it owns, so `TUNSETIFF` succeeds and no host interface is touched.
#
# The second namespace is made with a nested `unshare -n` rather than
# `ip netns add`, because the latter wants to bind-mount into `/run/netns` and
# that directory belongs to the host's root, which this user namespace cannot
# map. A process parked in the new namespace holds it open, and
# `nsenter -t <pid> -n` runs commands in it.
#
# Usage:
#   scripts/e2e-netns.sh [path/to/vallum]
#
# Set KEEP=1 to leave the scratch directory (keys, configs and both daemons' logs)
# behind instead of deleting it — the fastest way to read what a failure saw.
#
# Exit status 0 means every check passed. Requires: Linux with unprivileged user
# namespaces, `ip`, `nsenter`, and `ping`.

set -euo pipefail

BIN=${1:-$(dirname -- "$0")/../target/debug/vallum}
BIN=$(readlink -f -- "$BIN")
if [ ! -x "$BIN" ]; then
    echo "no vallum binary at $BIN" >&2
    echo "build it first: cargo build -p vallum" >&2
    exit 2
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/vallum-e2e.XXXXXX")
if [ -n "${KEEP:-}" ]; then
    trap 'echo "kept: $WORK"' EXIT
else
    trap 'rm -rf -- "$WORK"' EXIT
fi

# `-U` user, `-r` map to root inside it, `-n` network. The inner script is passed
# the binary and the scratch directory as $1 and $2.
unshare -Urn --map-root-user bash -s -- "$BIN" "$WORK" <<'INNER'
set -euo pipefail

BIN=$1
WORK=$2

OUTER_A=10.99.0.1
OUTER_B=10.99.0.2
INNER_A=10.7.0.1
INNER_B=10.7.0.2
PORT=51820

A_LOG=$WORK/a.log
B_LOG=$WORK/b.log
A_PIDFILE=$WORK/a.pid
B_PIDFILE=$WORK/b.pid
HOLDER_PIDFILE=$WORK/holder.pid

say()  { printf '\n── %s\n' "$*"; }
ok()   { printf '   ok    %s\n' "$*"; }
bad()  { printf '   FAIL  %s\n' "$*" >&2; exit 1; }

kill_pidfile() {
    [ -f "$1" ] || return 0
    kill ${2:--TERM} "$(cat "$1")" 2>/dev/null || true
}

# Wait for a pid to disappear, but never forever: a daemon stuck in a read would
# otherwise hang the script instead of failing it.
wait_gone() { # $1 pidfile  $2 seconds
    local pid
    pid=$(cat "$1" 2>/dev/null) || return 0
    for _ in $(seq 1 "$(( ${2%.*} * 10 + 1 ))"); do
        kill -0 "$pid" 2>/dev/null || return 0
        sleep 0.1
    done
    return 1
}

stop_all() {
    kill_pidfile "$A_PIDFILE"
    kill_pidfile "$B_PIDFILE"
    wait_gone "$A_PIDFILE" 1 || true
    wait_gone "$B_PIDFILE" 1 || true
    kill_pidfile "$A_PIDFILE" -KILL
    kill_pidfile "$B_PIDFILE" -KILL
    # The wrapper jobs: for B this is `nsenter`, which does not die on its own
    # until its child does. Each kill is `|| true`: these pids are usually gone
    # by now, and a failing `kill` inside an EXIT trap would become the script's
    # exit status.
    if [ -n "${A_JOB:-}" ]; then kill -KILL "$A_JOB" 2>/dev/null || true; fi
    if [ -n "${B_JOB:-}" ]; then kill -KILL "$B_JOB" 2>/dev/null || true; fi
    kill_pidfile "$HOLDER_PIDFILE" -KILL
    wait 2>/dev/null || true
}
trap stop_all EXIT

# Sum a counter from /proc/net/snmp, matched by name so a kernel that reorders
# the fields does not silently break the measurement.
snmp_sum() { # $1 = counter name, reads the snmp text on stdin
    awk -v want="$1" '
        NR % 2 == 1 { col = 0; for (i = 1; i <= NF; i++) if ($i == want) col = i; next }
        col { total += $col }
        END { print total + 0 }
    '
}
snmp_here() { snmp_sum "$1" < /proc/net/snmp; }
snmp_ns2()  { in_ns cat /proc/net/snmp | snmp_sum "$1"; }

# ── the outer network ────────────────────────────────────────────────

say "building the outer network: veth $OUTER_A <-> $OUTER_B, second end in its own namespace"
ip link set lo up
ip link add veth-a type veth peer name veth-b
ip link set veth-a up
ip addr add "$OUTER_A/24" dev veth-a

# Park a process in a fresh network namespace. `sleep infinity` holds it open
# for as long as this script runs, and `nsenter` is how we reach inside.
unshare -n sleep infinity &
echo $! > "$HOLDER_PIDFILE"
sleep 0.2

in_ns() { nsenter -t "$(cat "$HOLDER_PIDFILE")" -n -- "$@"; }

in_ns ip link set lo up
ip link set veth-b netns "$(cat "$HOLDER_PIDFILE")"
in_ns ip link set veth-b up
in_ns ip addr add "$OUTER_B/24" dev veth-b

ping -c1 -W3 -q "$OUTER_B" >/dev/null || bad "the outer network is not up"
ok "outer network is up"

# ── keys and configs ─────────────────────────────────────────────────

say "generating two keys with the CLI"
"$BIN" keygen --output "$WORK/a.key" --suite 3 > "$WORK/a.pub"
"$BIN" keygen --output "$WORK/b.key" --suite 3 > "$WORK/b.pub"
PUB_A=$(cat "$WORK/a.pub")
PUB_B=$(cat "$WORK/b.pub")
[ "$PUB_A" != "$PUB_B" ] || bad "keygen produced the same key twice"
ok "two distinct tri-hybrid keys ($(wc -c < "$WORK/a.pub") bytes of public line each)"

# A config names its key file *relatively*, and each daemon below is started from
# a different working directory: this also exercises config-relative resolution.
write_config() { # $1 name  $2 inner addr  $3 listen  $4 peer endpoint  $5 peer allowed  $6 peer public
    local name=$1 addr=$2 listen=$3 endpoint=$4 allowed=$5 peer_public=$6
    {
        printf '[interface]\n'
        printf 'name = "vallum0"\n'
        printf 'private_key = "%s.key"\n' "$name"
        printf 'address = "%s/24"\n' "$addr"
        printf 'listen = "%s"\n' "$listen"
        printf '\n[log]\nlevel = "info"\n'
        printf '\n[[peer]]\nname = "peer"\n'
        printf 'public_key = "%s"\n' "$peer_public"
        if [ -n "$endpoint" ]; then
            printf 'endpoint = "%s"\n' "$endpoint"
        fi
        printf 'allowed_ips = ["%s/32"]\n' "$allowed"
    } > "$WORK/$name.toml"
}

# A dials B. B is told nothing about where A is: it must learn A's address from
# the authenticated handshake, which is the roaming path.
write_config a "$INNER_A" "$OUTER_A:$PORT" "$OUTER_B:$PORT" "$INNER_B" "$PUB_B"
write_config b "$INNER_B" "$OUTER_B:$PORT" ""                 "$INNER_A" "$PUB_A"

# ── start the two daemons ────────────────────────────────────────────

FRAG_A_BEFORE=$(snmp_here FragCreates)
FRAG_B_BEFORE=$(snmp_ns2 FragCreates)
REASM_A_BEFORE=$(snmp_here ReasmReqds)
REASM_B_BEFORE=$(snmp_ns2 ReasmReqds)

say "starting daemon B in the second namespace, then daemon A here"
# `exec` so the recorded pid *is* the daemon, not a wrapper shell.
in_ns bash -c 'echo $$ > "$2"; exec "$1" run --config "$3"' \
    _ "$BIN" "$B_PIDFILE" "$WORK/b.toml" > "$B_LOG" 2>&1 &
B_JOB=$!
sleep 0.4

# Started from `/`, because the config names its key file relatively: if the
# daemon resolved that against the working directory instead of the config, this
# would fail here rather than in a unit test.
bash -c 'echo $$ > "$1"; cd /; exec "$2" run --config "$3"' \
    _ "$A_PIDFILE" "$BIN" "$WORK/a.toml" > "$A_LOG" 2>&1 &
A_JOB=$!
sleep 0.4

for pidfile in "$A_PIDFILE" "$B_PIDFILE"; do
    kill -0 "$(cat "$pidfile")" 2>/dev/null || bad "$(basename "$pidfile" .pid) exited at startup; see $WORK"
done
ok "both daemons are running"

# ── establishment ────────────────────────────────────────────────────

say "carrying traffic: ping -c 3 $INNER_B"
if ping -c3 -W5 -i0.3 -q "$INNER_B"; then
    ok "an inner packet completed a round trip through the tunnel"
else
    bad "ping across the tunnel failed; see $A_LOG and $B_LOG"
fi

grep -q "established at epoch" "$A_LOG" || bad "A never logged an establishment"
grep -q "established at epoch" "$B_LOG" || bad "B never logged an establishment"
grep -q "as Initiator" "$A_LOG" || bad "A did not take the initiator role"
grep -q "as Responder" "$B_LOG" || bad "B did not take the responder role"
ok "A established as Initiator, B as Responder"

# B was never configured with A's address. If B answers pings on the session, it
# learned the address from traffic that proved A's key — nothing else could have.
if grep -q "endpoint" "$WORK/b.toml"; then
    bad "B's config has an endpoint; the roaming check proves nothing"
fi
ok "B learned A's address from the handshake (no endpoint in B's config)"

# ── the other direction, over the session A started ──────────────────

say "carrying traffic the other way: from the second namespace"
if in_ns ping -c2 -W5 -i0.3 -q "$INNER_A"; then
    ok "B -> A completed a round trip on A's session"
else
    bad "the reverse direction failed"
fi

# ── a large payload ──────────────────────────────────────────────────

say "carrying a large payload: ping -s 1200 (1228 B on the wire)"
if ping -c2 -W5 -i0.3 -q -s 1200 "$INNER_B"; then
    ok "a 1228-byte inner packet fit the 1380-byte inner MTU"
else
    bad "a large inner packet did not cross"
fi

# ── what the outer network actually saw ──────────────────────────────

FRAG_A_AFTER=$(snmp_here FragCreates)
FRAG_B_AFTER=$(snmp_ns2 FragCreates)
REASM_A_AFTER=$(snmp_here ReasmReqds)
REASM_B_AFTER=$(snmp_ns2 ReasmReqds)

say "outer IP behaviour during establishment and the checks above"
printf '   ns1, daemon A:  FragCreates +%s   ReasmReqds +%s\n' \
    "$((FRAG_A_AFTER - FRAG_A_BEFORE))" "$((REASM_A_AFTER - REASM_A_BEFORE))"
printf '   ns2, daemon B:  FragCreates +%s   ReasmReqds +%s\n' \
    "$((FRAG_B_AFTER - FRAG_B_BEFORE))" "$((REASM_B_AFTER - REASM_B_BEFORE))"
printf '   veth MTU:       1500\n'
if [ "$((FRAG_A_AFTER - FRAG_A_BEFORE))" -gt 0 ] || [ "$((FRAG_B_AFTER - FRAG_B_BEFORE))" -gt 0 ]; then
    printf '   note   the handshake exceeded the outer MTU and was fragmented.\n'
    printf '          Frozen sizes (crates/vallum-core/tests/interop.rs): the\n'
    printf '          tri-hybrid InitHello is 4609 B plus 32 B of mac1 = 4641 B, and\n'
    printf '          the RespHello is 4378 B plus 32 B = 4410 B. At 1480 B of IPv4\n'
    printf '          payload per fragment that is 4 and 3 fragments: ceil(4641/1480)\n'
    printf '          and ceil(4410/1480). The counters above should match those two\n'
    printf '          numbers.\n'
    printf '          This is the limitation docs/proof/daemon.md records: there is no\n'
    printf '          application-layer segmentation, so the handshake depends on IP\n'
    printf '          fragmentation, and a middlebox that drops fragments drops the\n'
    printf '          tunnel.\n'
else
    printf '   note   no outer fragmentation was observed here.\n'
fi

# ── shut down ────────────────────────────────────────────────────────

say "shutting the daemons down with SIGTERM"
kill_pidfile "$A_PIDFILE"
kill_pidfile "$B_PIDFILE"
wait_gone "$A_PIDFILE" 5 || bad "A ignored SIGTERM"
wait_gone "$B_PIDFILE" 5 || bad "B ignored SIGTERM"
ok "both daemons exited on SIGTERM"

grep -q "tunnel down:" "$A_LOG" || bad "A did not shut down cleanly"
grep -q "tunnel down:" "$B_LOG" || bad "B did not shut down cleanly"
ok "both daemons logged their counters as they stopped"

printf '\n== PASS\n'
INNER
