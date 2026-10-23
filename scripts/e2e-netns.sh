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
# namespaces, `ip`, `nsenter`, `ping`, and `python3` (the adversary in the last
# phase uses it to capture one real handshake and to send raw datagrams).

set -euo pipefail

BIN=${1:-$(dirname -- "$0")/../target/debug/vallum}
BIN=$(readlink -f -- "$BIN")
if [ ! -x "$BIN" ]; then
    echo "no vallum binary at $BIN" >&2
    echo "build it first: cargo build -p vallum" >&2
    exit 2
fi

WORK=$(mktemp -d /tmp/vallum-e2e.XXXXXX)
# Deliberately not $TMPDIR: the lab runs inside `unshare -Urn`, where this user's
# uid is unmapped, so a path under the home directory — where $TMPDIR points on
# this machine — is not traversable and every exec fails with EACCES.

# The binary is normally under the home directory for the same reason, so stage
# a copy where the namespace can reach it.
install -m 0755 -- "$BIN" "$WORK/vallum"
BIN="$WORK/vallum"
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
OUTER6_A=fd00:99::1
OUTER6_B=fd00:99::2
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
    if [ -n "${SNIFF_PID:-}" ]; then kill -KILL "$SNIFF_PID" 2>/dev/null || true; fi
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
ip -6 addr add "$OUTER6_A/64" dev veth-a nodad

# Park a process in a fresh network namespace. `sleep infinity` holds it open
# for as long as this script runs, and `nsenter` is how we reach inside.
unshare -n sleep infinity &
echo $! > "$HOLDER_PIDFILE"
sleep 0.2

in_ns() { nsenter -t "$(cat "$HOLDER_PIDFILE")" -n -- "$@"; }

# Retry a crossing until a reply arrives. A lossy path drops individual packets,
# and one lost ping is not the tunnel failing — a user's browser retries too.
# `$1` is how many seconds to keep trying; the rest is passed to `ping`.
crosses() {
    local wait=$1; shift
    local deadline=$((SECONDS + wait))
    until ping -c1 -W2 -q "$@" >/dev/null 2>&1; do
        [ "$SECONDS" -ge "$deadline" ] && return 1
        sleep 0.2
    done
}
crosses_in_ns() {
    local wait=$1; shift
    local deadline=$((SECONDS + wait))
    until in_ns ping -c1 -W2 -q "$@" >/dev/null 2>&1; do
        [ "$SECONDS" -ge "$deadline" ] && return 1
        sleep 0.2
    done
}

in_ns ip link set lo up
ip link set veth-b netns "$(cat "$HOLDER_PIDFILE")"
in_ns ip link set veth-b up
in_ns ip addr add "$OUTER_B/24" dev veth-b
in_ns ip -6 addr add "$OUTER6_B/64" dev veth-b nodad

ping -c1 -W3 -q "$OUTER_B" >/dev/null || bad "the outer network is not up"
ping -6 -c1 -W3 -q "$OUTER6_B" >/dev/null || bad "the outer IPv6 network is not up"
ok "outer network is up, over IPv4 and IPv6"

# ── fault injection ──
# FAULT degrades the outer link *before* the tunnel is built, so every later
# assertion runs under it. This is how the behaviour data gets produced without
# users: a clean veth proves the tunnel works, and a degraded one shows what it
# does when the link does not. Values: mtu1492 mtu1400 mtu1280 loss<N>
# delay<N> reorder<N>.
case "${FAULT:-none}" in
    none) ;;
    mtu*)
        mtu=${FAULT#mtu}
        case "$mtu" in 1492|1400|1280) ;; *) bad "FAULT=$FAULT: unsupported MTU";; esac
        ip link set veth-a mtu "$mtu"
        in_ns ip link set veth-b mtu "$mtu"
        ok "fault: outer MTU clamped to $mtu (PPPoE/DS-Lite shaped)" ;;
    loss*|delay*|reorder*)
        command -v tc >/dev/null 2>&1 || bad "FAULT=$FAULT needs tc (iproute2)"
        arg=${FAULT#loss}; kind=loss
        case "$FAULT" in delay*)   arg=${FAULT#delay};   kind=delay ;;
                          reorder*) arg=${FAULT#reorder}; kind=reorder ;; esac
        case "$arg" in ''|*[!0-9]*) bad "FAULT=$FAULT: expected a number";; esac
        case "$kind" in
            loss)    tc qdisc add dev veth-a root netem loss "${arg}%" ;;
            delay)   tc qdisc add dev veth-a root netem delay "${arg}ms" ;;
            reorder) tc qdisc add dev veth-a root netem delay 10ms reorder 25% "${arg}%" ;;
        esac
        ok "fault: ${kind} ${arg} on the outer link" ;;
    *) bad "unknown FAULT=$FAULT" ;;
esac

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
write_config() { # $1 name  $2 inner CIDR  $3 listen  $4 peer endpoint  $5 peer allowed  $6 peer public  $7 keepalive
    local name=$1 addr=$2 listen=$3 endpoint=$4 allowed=$5 peer_public=$6 keepalive=$7
    {
        printf '[interface]\n'
        printf 'name = "vallum0"\n'
        printf 'private_key = "%s.key"\n' "$name"
        printf 'address = "%s"\n' "$addr"
        printf 'listen = "%s"\n' "$listen"
        printf '\n[log]\nlevel = "info"\n'
        printf '\n[[peer]]\nname = "peer"\n'
        printf 'public_key = "%s"\n' "$peer_public"
        if [ -n "$endpoint" ]; then
            printf 'endpoint = "%s"\n' "$endpoint"
        fi
        printf 'allowed_ips = ["%s"]\n' "$allowed"
        if [ -n "$keepalive" ]; then
            printf 'persistent_keepalive = %s\n' "$keepalive"
        fi
    } > "$WORK/$name.toml"
}

# A dials B. B is told nothing about where A is: it must learn A's address from
# the authenticated handshake, which is the roaming path. B is the end told to
# keep the path warm, because B is the end a NAT would forget: it never speaks
# until spoken to. A one-second cadence makes the keepalive observable inside the
# few seconds this script runs for.
# A binds port 0: the kernel picks one, and the control plane must report the
# real port rather than the configured `0`.
write_config a "$INNER_A/24" "$OUTER_A:0" "$OUTER_B:$PORT" "$INNER_B/32" "$PUB_B" ""
write_config b "$INNER_B/24" "$OUTER_B:$PORT" ""                 "$INNER_A/32" "$PUB_A" 1
# The fail-closed guard only applies when the config asks for it: a split
# tunnel defaults to `auto`, which leaves egress alone by design. Stated
# explicitly so the policy phase tests the guard rather than the default.
sed -i '/^\[log\]/i [quick]\npolicy = "on"\n' "$WORK/a.toml"

# G2: A serves the control UAPI on a socket beside its config.
sed -i '/^listen = /a control = "control.sock"' "$WORK/a.toml"
# G3: a socket mark, applied before the privilege drop.
sed -i '/^listen = /a fwmark = 4660' "$WORK/a.toml"

# G1: a configured PSK on both ends. Every lifecycle below inherits it, so the
# whole gate runs with a PSK rather than one special case.
PSK=$("$BIN" genpsk)
[ "${#PSK}" -eq 64 ] || bad "genpsk produced ${#PSK} characters, expected 64"
sed -i "/^public_key = /a preshared_key = \"$PSK\"" "$WORK/a.toml" "$WORK/b.toml"
grep -q "^preshared_key = \"$PSK\"$" "$WORK/a.toml" || bad "A's config lost the PSK"
grep -q "^preshared_key = \"$PSK\"$" "$WORK/b.toml" || bad "B's config lost the PSK"
ok "a shared preshared key is configured on both ends"

# ── arm the adversary's capture ──────────────────────────────────────
#
# The adversary lives in ns2, but the `InitHello` it will replay is captured on
# veth-a, where it leaves ns1. Capturing on the sending side keeps the recorded
# pid a plain `python3` (created with `exec` below), so the EXIT trap can kill it
# without an `nsenter` wrapper in between.
#
# P6.7 means the handshake arrives as whole UDP datagrams instead of IP
# fragments, so the capture reassembles the *Vallum* envelope — and records the
# two quantities the gate is about: how many datagrams the InitHello took, and
# the largest UDP payload that crossed, which is what decides whether the kernel
# has anything to fragment at all.
say "arming the capture on veth-a"
python3 - "$WORK/inithello.bin" "$WORK/segments.txt" <<'PY' > "$WORK/sniff.log" 2>&1 &
import socket, sys, time

out, report = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind(("veth-a", 0))
s.settimeout(0.5)
deadline = time.time() + 15
pieces = {}
largest = 0
seen = 0
fragments = 0


def assemble(parts, total):
    """The message, if the fragments form a contiguous run covering it."""
    if 0 not in parts:
        return None
    data = b""
    offset = 0
    while offset < total:
        if offset not in parts:
            return None
        chunk = parts[offset]
        data += chunk
        offset += len(chunk)
    return data


def write(message, count):
    with open(out, "wb") as handle:
        handle.write(message)
    with open(report, "w") as handle:
        handle.write(f"{count} {largest} {seen}\n")


while time.time() < deadline:
    try:
        frame, _ = s.recvfrom(65535)
    except socket.timeout:
        continue
    if frame[12:14] != b"\x08\x00":
        continue
    ip = frame[14:]
    ihl = (ip[0] & 0xF) * 4
    if ip[9] != 17:  # UDP
        continue
    payload = ip[ihl + 8:]
    seen += 1
    largest = max(largest, len(payload))
    if payload[:2] == b"\x01\x07":
        # Version 1, the segment envelope: message_id, offset, total, then data.
        message_id = int.from_bytes(payload[2:6], "big")
        offset = int.from_bytes(payload[6:8], "big")
        total = int.from_bytes(payload[8:10], "big")
        parts = pieces.setdefault(message_id, {})
        if offset not in parts:
            fragments += 1
        parts[offset] = payload[10:]
        whole = assemble(parts, total)
        # `01 01` is version 1, message type `InitHello`.
        if whole is not None and whole[:2] == b"\x01\x01":
            write(whole, fragments)
            break
    elif payload[:2] == b"\x01\x01":
        # Unfragmented: the message fits one datagram after all.
        write(payload, 1)
        break
else:
    sys.exit("no complete InitHello appeared on veth-a")
PY
SNIFF_PID=$!

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

# Started from `/`, because the config names its key file relatively: if the
# daemon resolved that against the working directory instead of the config, this
# would fail here rather than in a unit test.
bash -c 'echo $$ > "$1"; cd /; exec "$2" run --config "$3"' \
    _ "$A_PIDFILE" "$BIN" "$WORK/a.toml" > "$A_LOG" 2>&1 &
A_JOB=$!

# Wait for both interfaces rather than sleeping a fixed time. The daemon prints
# `tunnel up` after `TUNSETIFF` and `Configuration::up()`, so the line means the
# interface exists *and* its connected route does — which is exactly what `ping`
# needs and exactly what it does not have yet while the daemon is starting.
#
# A fixed sleep here is a race, and it fails in the worst possible way: `ping`
# then answers `Network is unreachable`, which reads like a broken tunnel when
# nothing is broken, only slow. On a quiet host 0.4 s was enough; on this one
# under load the daemon takes about 0.75 s, so the gate failed on a busy machine
# and passed on an idle one, for a reason unconnected to what it tests.
DEADLINE=$((SECONDS + 10))
while :; do
    if grep -q "tunnel up on interface" "$A_LOG" && grep -q "tunnel up on interface" "$B_LOG"; then
        break
    fi
    # A pidfile that is not written yet is a daemon still starting, not a
    # failure; a pid that was written and is gone is a daemon that died.
    for pidfile in "$A_PIDFILE" "$B_PIDFILE"; do
        [ -s "$pidfile" ] || continue
        kill -0 "$(cat "$pidfile")" 2>/dev/null \
            || bad "$(basename "$pidfile" .pid) exited at startup; see $WORK"
    done
    if [ "$SECONDS" -ge "$DEADLINE" ]; then
        bad "an interface did not come up within 10 s; see $A_LOG and $B_LOG"
    fi
    sleep 0.1
done
ok "both daemons are running with their interfaces up"

# ── establishment ────────────────────────────────────────────────────

say "carrying traffic: ping $INNER_B"
if crosses 20 "$INNER_B"; then
    ok "an inner packet completed a round trip through the tunnel"
else
    bad "ping across the tunnel failed; see $A_LOG and $B_LOG"
fi

grep -q "established at epoch" "$A_LOG" || bad "A never logged an establishment"
grep -q "established at epoch" "$B_LOG" || bad "B never logged an establishment"
grep -q "as Initiator" "$A_LOG" || bad "A did not take the initiator role"
grep -q "as Responder" "$B_LOG" || bad "B did not take the responder role"
ok "A established as Initiator, B as Responder"

# ── the control plane ────────────────────────────────────────────────
say "querying the control socket"
[ -S "$WORK/control.sock" ] || bad "A did not create the control socket"
"$BIN" show --control "$WORK/control.sock" --dump > "$WORK/show.dump" 2>&1 \
    || bad "show --dump failed"
grep -q '^errno=0$' "$WORK/show.dump" || bad "show did not end with errno=0"
"$BIN" show --control "$WORK/control.sock" > "$WORK/show.txt" 2>&1 \
    || bad "show failed"
grep -q '^interface ' "$WORK/show.txt" || bad "show did not report the interface"
grep -q '^peer ' "$WORK/show.txt" || bad "show did not report the peer"
grep -q 'allowed_ip=' "$WORK/show.dump" || bad "show did not report allowed IPs"
grep -q '^fwmark=4660$' "$WORK/show.dump" || bad "show did not report the fwmark"
grep -q '^vallum_can_set_listen_port=true$' "$WORK/show.dump" \
    || bad "the capability line does not advertise a runtime rebind"
grep -q '^vallum_batching=true$' "$WORK/show.dump" \
    || bad "the daemon does not report batched sends"
grep -q '^private_key=' "$WORK/show.dump" || bad "show --dump lost the private key"
grep -q '^  private_key=' "$WORK/show.txt" && bad "the default show printed the private key"
grep -q '^  preshared_key=' "$WORK/show.txt" && bad "the default show printed the PSK"
awk '/^interface / { print length($2) }' "$WORK/show.txt" | grep -qx 16 \
    || bad "the interface label is not a 16-hex fingerprint"
PORT_NOW=$(sed -n 's/^listen_port=//p' "$WORK/show.dump")
[ -n "$PORT_NOW" ] && [ "$PORT_NOW" -ne 0 ] \
    || bad "listen_port is $PORT_NOW, not the bound port"
ok "the control socket reports the device and its peer"
ok "the bound port ($PORT_NOW) is reported, not the configured 0"
ok "the socket mark is reported"
ok "the default view hides secrets and uses short identifiers"

"$BIN" showconf --config "$WORK/a.toml" > "$WORK/showconf.toml" 2>&1 \
    || bad "showconf failed"
grep -q '^\[interface\]$' "$WORK/showconf.toml" || bad "showconf has no interface"
grep -q '^\[\[peer\]\]$' "$WORK/showconf.toml" || bad "showconf has no peer"
grep -q 'public_key = "vallum1:0003:' "$WORK/showconf.toml" \
    || bad "showconf did not use the public line"
grep -q 'private_key = "private.key"' "$WORK/showconf.toml" \
    || bad "showconf did not use a private-key placeholder"
ok "showconf exports a usable config without secrets"

say "querying the JSON, TUI, and doctor surfaces"
"$BIN" show --control "$WORK/control.sock" --json > "$WORK/show.json" 2>&1 \
    || bad "show --json failed"
grep -q '"interface": "vallum0"' "$WORK/show.json" || bad "show --json has no interface"
grep -q '"peers"' "$WORK/show.json" || bad "show --json has no peers"
grep -q '"private_key":' "$WORK/show.json" && bad "show --json leaked the private key"
ok "show --json is secret-free"

"$BIN" tui --control "$WORK/control.sock" --snapshot --width 120 --height 36 \
    > "$WORK/tui.txt" 2>&1 || bad "tui --snapshot failed"
grep -q 'Vallum' "$WORK/tui.txt" || bad "the TUI snapshot has no header"
grep -q 'Peers' "$WORK/tui.txt" || bad "the TUI snapshot has no peer table"
grep -q 'listen' "$WORK/tui.txt" || bad "the TUI snapshot has no device state"
ok "the TUI renders the live device and peer table headlessly"

"$BIN" doctor --control "$WORK/control.sock" > "$WORK/doctor.txt" 2>&1 \
    || bad "doctor reported a failure"
grep -q 'PASS  control' "$WORK/doctor.txt" || bad "doctor did not pass the control check"
ok "doctor checks the control socket"


"$BIN" syncconf "$WORK/a.toml" || bad "syncconf failed on an unchanged config"
ok "syncconf applied an unchanged config idempotently"

# B was never configured with A's address. If B answers pings on the session, it
# learned the address from traffic that proved A's key — nothing else could have.
if grep -q "endpoint" "$WORK/b.toml"; then
    bad "B's config has an endpoint; the roaming check proves nothing"
fi
ok "B learned A's address from the handshake (no endpoint in B's config)"

# ── the handshake the adversary will replay ──────────────────────────

say "collecting the captured InitHello"
wait "$SNIFF_PID" 2>/dev/null || true
SNIFF_PID=""
[ -s "$WORK/inithello.bin" ] || bad "the capture saw no complete InitHello; see $WORK/sniff.log"
CAPTURED=$(wc -c < "$WORK/inithello.bin" | tr -d ' ')
# 4609 B of message (the frozen `init_hello_len`, hint included) plus a 20 B
# `mac1` field: a 16 B MAC under a 4 B tag and length. Pinning the number here is
# what turns the size table in docs/proof/daemon.md into a live check.
[ "$CAPTURED" = 4665 ] || bad "captured $CAPTURED bytes of InitHello, expected 4665"
read -r SEGMENTS LARGEST SEEN < "$WORK/segments.txt"
printf '   captured %s bytes after reassembly: 4609 B message + 20 B mac1 field\n' "$CAPTURED"
printf '   it crossed as %s Vallum fragments, the largest UDP payload being %s B\n' \
    "$SEGMENTS" "$LARGEST"
# One `InitHello` datagram would mean the envelope never engaged, and the rest of
# this gate would be measuring nothing.
[ "$SEGMENTS" -gt 1 ] \
    || bad "the InitHello crossed in one datagram; the segmentation envelope never engaged"
[ "$SEGMENTS" -eq 4 ] \
    || printf '   note   %s fragments for 4665 B at a 1442 B payload (ceil(4665/1442) = 4)\n' "$SEGMENTS"
ok "the InitHello crossed as whole UDP datagrams and reassembled byte for byte"

# ── the other direction, over the session A started ──────────────────

say "carrying traffic the other way: from the second namespace"
if crosses_in_ns 20 "$INNER_A"; then
    ok "B -> A completed a round trip on A's session"
else
    bad "the reverse direction failed"
fi

# ── a large payload ──────────────────────────────────────────────────

say "carrying a large payload: ping -s 1200 (1228 B on the wire)"
if crosses 20 -s 1200 "$INNER_B"; then
    ok "a 1228-byte inner packet fit the 1380-byte inner MTU"
else
    bad "a large inner packet did not cross"
fi

# ── fail-closed egress ───────────────────────────────────────────────
# The killswitch shipped in items 2 and 3 had never been exercised against a
# kernel by any harness. It runs here, in ns2, because ns2 is a real disposable
# namespace: this script's *primary* namespace is the invoking host's, and
# applying the policy there would block the machine running the test.
say "fail-closed egress: policy on must block, policy off must not"

# Resolved here, not inside the namespace: `nft` is not on PATH under nsenter.
NFT=$(command -v nft || echo /usr/sbin/nft)

# B reaches A's outer address over the veth, outside any tunnel. That is the
# leak path — what a browser would use if the tunnel died.
crosses_in_ns 5 "$OUTER_A" || bad "ns2 cannot reach the outer network before any policy is applied"
ok "ns2 reaches the outer network with no policy applied"

in_ns "$BIN" policy on --config "$WORK/a.toml" > "$WORK/policy-on.log" 2>&1 \
    || { cat "$WORK/policy-on.log"; bad "policy on failed inside ns2"; }
# A declining guard also exits 0, so the applied case must be identified from
# the ruleset rather than from the exit status.
in_ns "$NFT" list ruleset 2>/dev/null | grep -q 'table inet vallum_policy' \
    || { cat "$WORK/policy-on.log"; bad "policy on exited 0 but installed no ruleset"; }
if in_ns ping -c1 -W2 -q "$OUTER_A" >/dev/null 2>&1; then
    bad "egress escaped with the policy on: the killswitch did not block"
fi
ok "policy on blocks egress outside the tunnel"

in_ns "$BIN" policy off --config "$WORK/a.toml" > "$WORK/policy-off.log" 2>&1 \
    || { cat "$WORK/policy-off.log"; bad "policy off failed inside ns2"; }
# The control. Without it, "blocked" could just as well mean the harness broke.
crosses_in_ns 5 "$OUTER_A" || bad "egress stayed blocked after policy off: the block was not the policy"
ok "policy off restores egress (control)"

# ── what the outer network actually saw ──────────────────────────────

FRAG_A=$(snmp_here FragCreates)
FRAG_B=$(snmp_ns2 FragCreates)
REASM_A=$(snmp_here ReasmReqds)
REASM_B=$(snmp_ns2 ReasmReqds)

say "outer IP behaviour during establishment and the checks above"
printf '   ns1, daemon A:  FragCreates +%s   ReasmReqds +%s\n' \
    "$((FRAG_A - FRAG_A_BEFORE))" "$((REASM_A - REASM_A_BEFORE))"
printf '   ns2, daemon B:  FragCreates +%s   ReasmReqds +%s\n' \
    "$((FRAG_B - FRAG_B_BEFORE))" "$((REASM_B - REASM_B_BEFORE))"
printf '   veth MTU:       1500   largest UDP payload our capture saw: %s\n' "${LARGEST:-?}"
# The point of P6.7, stated as the kernel sees it. Every UDP payload Vallum emits
# is at most 1452 B, so with 28 B of IPv4+UDP headers no datagram exceeds the
# 1500-byte veth MTU and the kernel has nothing to fragment. This is an
# independent proof of the same statement the capture's `largest` measures: one
# counts fragments, the other measures lengths.
if [ "$((FRAG_A - FRAG_A_BEFORE))" -ne 0 ] || [ "$((FRAG_B - FRAG_B_BEFORE))" -ne 0 ]; then
    bad "the kernel fragmented our handshake; the envelope did not cover it"
fi
if [ "$((REASM_A - REASM_A_BEFORE))" -ne 0 ] || [ "$((REASM_B - REASM_B_BEFORE))" -ne 0 ]; then
    bad "the kernel reassembled IP fragments; nothing should have arrived in pieces"
fi
LARGEST=${LARGEST:-0}
[ "$LARGEST" -le 1452 ] \
    || bad "a $LARGEST-byte UDP payload crossed veth-a; the envelope budget is 1452 B"
ok "no IP fragment was created or reassembled, and no datagram exceeded the budget"

# ── the idle peer keeps the path warm ────────────────────────────────
#
# B was told `persistent_keepalive = 1` and has nothing of its own to send: no
# ping runs during this window. Every datagram B produces here is the policy
# keepalive, which also makes this the only place the daemon's periodic tick is
# observable before the 120 s rekey would exercise it — and the keepalive itself
# is what makes a NAT-bound peer reachable when it has nothing to say.
#
# A keepalive is a single datagram, so it never fragments; the fragment counters
# read just above are unaffected by it.
say "listening on veth-a for 2.5 s with no traffic, watching B keep the path warm"
KEEPALIVES=$(python3 - "$OUTER_A" "${PORT_NOW:-$PORT}" <<'PY'
import socket, sys, time

a_address, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind(("veth-a", 0))
s.settimeout(0.2)
deadline = time.time() + 2.5
count = 0
while time.time() < deadline:
    try:
        frame, _ = s.recvfrom(65535)
    except socket.timeout:
        continue
    if frame[12:14] != b"\x08\x00":
        continue
    ip = frame[14:]
    ihl = (ip[0] & 0xF) * 4
    if ip[9] != 17:  # UDP
        continue
    flags = int.from_bytes(ip[6:8], "big")
    if (flags & 0x1FFF) or (flags & 0x2000):
        continue  # a fragment; a keepalive is one whole datagram
    if socket.inet_ntoa(ip[16:20]) != a_address:
        continue
    if int.from_bytes(ip[ihl + 2 : ihl + 4], "big") != port:
        continue
    count += 1
print(count)
PY
) || bad "the keepalive counter failed to run"

grep -q "persistent_keepalive" "$WORK/b.toml" || bad "B's config lost its keepalive field"
[ "$KEEPALIVES" -ge 2 ] \
    || bad "idle B sent $KEEPALIVES keepalives in 2.5 s, expected at least 2 at a 1 s cadence"
printf '   B sent %s keepalives in 2.5 idle seconds with no traffic to send\n' "$KEEPALIVES"
ok "the idle peer kept its NAT binding warm on its own"

# ── the adversary ────────────────────────────────────────────────────
#
# An attacker co-located with B, on B's outer link: the position a compromised
# peer, or anything else in the same broadcast domain, actually occupies. It can
# send any datagram to either daemon and it holds one genuine `InitHello` it
# captured. Everything it can do with those two things is tried here:
#
#   * junk of every size (0, 1, 1 KiB, 16 KiB, 65 507 bytes), to both daemons,
#   * a well-formed header with no `mac1` (the cheapest forgery),
#   * the real handshake, replayed from a different address.
#
# The invariant is one sentence: **an unauthenticated datagram never draws a
# reply**, so there is nothing to amplify and nothing to bounce. A daemon that
# answered any of these would print a reply count here and fail.
say "adversary in ns2: junk, oversized datagrams, and a replayed handshake"

ATTACK=$(in_ns python3 - "$WORK/inithello.bin" "$OUTER_A" "$OUTER_B" "$PORT" "${PORT_NOW:-$PORT}" <<'PY'
import os
import socket
import sys
import time

capture, a_address, b_address = sys.argv[1], sys.argv[2], sys.argv[3]
port, a_port = int(sys.argv[4]), int(sys.argv[5])
with open(capture, "rb") as handle:
    init_hello = handle.read()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 0))


def drain(window):
    """Count and measure every reply that arrives for `window` seconds."""
    replies = []
    deadline = time.time() + window
    while True:
        left = deadline - time.time()
        if left <= 0:
            return replies
        sock.settimeout(left)
        try:
            data, _ = sock.recvfrom(70000)
        except socket.timeout:
            return replies
        replies.append(len(data))


def probe(destination, payload, window):
    """Send one datagram, then watch for replies."""
    sock.sendto(payload, (destination, port))
    return drain(window)


junk = []
for payload in (b"", b"\x00", os.urandom(1024), os.urandom(16384), os.urandom(65507)):
    junk += probe(b_address, payload, 0.25)
for payload in (os.urandom(2048), os.urandom(65507)):
    # A listens on the port the kernel picked, not the configured 0.
    sock.sendto(payload, (a_address, a_port))
    junk += drain(0.25)

# Version 1, `InitHello`, suite 3, a plausible index, then noise. No `mac1`, so
# the admission gate refuses it before any KEM work.
forged = probe(b_address, b"\x01\x01\x00\x03" + os.urandom(4600), 0.25)


def fragment(message_id, offset, total, data=b""):
    """The segment envelope: version 1, code 0x07, id, offset, total, data."""
    return (
        b"\x01\x07"
        + message_id.to_bytes(4, "big")
        + offset.to_bytes(2, "big")
        + total.to_bytes(2, "big")
        + data
    )


# The surface P6.7 added, and the same rule applies to it: a fragment is
# unauthenticated input of exactly the standing a whole datagram has, so none of
# this may draw a reply. A lone first fragment, an envelope claiming a message
# larger than the 16 KiB cap, one claiming an offset past the end of its own
# message, and a flood of first fragments under random message ids — each of
# which is a candidate slot in the 16-entry reassembly table, which is the thing
# this probe is really measuring: whether a flood can exhaust it or draw an
# answer.
fragments = probe(b_address, fragment(1, 0, 4665, os.urandom(1442)), 0.25)
fragments += probe(b_address, fragment(2, 0, 65535, os.urandom(64)), 0.25)
fragments += probe(b_address, fragment(3, 9000, 4665, os.urandom(64)), 0.25)
for _ in range(64):
    ident = int.from_bytes(os.urandom(4), "big")
    sock.sendto(fragment(ident, 0, 4665, os.urandom(1442)), (b_address, port))
fragments += drain(0.5)

# The genuine article, from a different source address.
replay = probe(b_address, init_hello, 1.0)

print(f"junk={len(junk)}")
print(f"forged={len(forged)}")
print(f"fragments={len(fragments)}")
print(f"replay={len(replay)}")
print(f"replay_bytes={sum(replay)}")
PY
) || bad "the attacker script itself failed"

field() { printf '%s\n' "$ATTACK" | awk -F= -v key="$1" '$1 == key { print $2 }'; }

junk_replies=$(field junk)
forged_replies=$(field forged)
fragment_replies=$(field fragments)
replay_replies=$(field replay)
replay_bytes=$(field replay_bytes)

[ "$junk_replies" = 0 ] || bad "junk drew $junk_replies reply datagrams"
ok "empty, 1-byte, 1 KiB, 16 KiB and 65 507-byte datagrams drew no reply"
[ "$forged_replies" = 0 ] || bad "a header with no mac1 drew $forged_replies replies"
ok "a well-formed header with no mac1 drew no reply"
[ "$fragment_replies" = 0 ] || bad "fragments drew $fragment_replies reply datagrams"
ok "68 fragments, including a 64-deep flood under random ids, drew no reply"
[ "$replay_replies" = 0 ] || bad "a replayed InitHello drew $replay_replies replies ($replay_bytes bytes)"
ok "a replayed InitHello drew no reply"

for pidfile in "$A_PIDFILE" "$B_PIDFILE"; do
    kill -0 "$(cat "$pidfile")" 2>/dev/null || bad "$(basename "$pidfile" .pid) died under attack"
done
if crosses 20 "$INNER_B"; then
    ok "the tunnel still carries traffic after the attack"
else
    bad "the tunnel stopped carrying traffic after the attack"
fi

# ── runtime rebind ───────────────────────────────────────────────────
#
# The last functional limit: a listen-port change used to be EOPNOTSUPP. The
# socket is swappable now, so the control plane applies it and the reader picks
# up the new socket after its read timeout.
say "rebinding A's listen port at runtime"
cp "$WORK/a.toml" "$WORK/a.rebind.toml"
sed -i 's/^listen = .*/listen = "10.99.0.1:51999"/' "$WORK/a.rebind.toml"
"$BIN" syncconf "$WORK/a.rebind.toml" || bad "runtime rebind failed"
"$BIN" show --control "$WORK/control.sock" --dump > "$WORK/rebind.dump" 2>&1 \
    || bad "show after the rebind failed"
grep -q '^listen_port=51999$' "$WORK/rebind.dump" \
    || bad "the daemon did not rebind to 51999"
if crosses 20 "$INNER_B"; then
    ok "the tunnel survived a runtime listen-port change"
else
    bad "the tunnel did not survive the rebind"
fi
ok "the bound port is now 51999, as the control plane reports"

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

# ── a narrow outer path ──────────────────────────────────────────────
#
# Everything above ran at the default 1500-byte assumption. This restates the
# same two daemons on a 1000-byte path (PPPoE-sized) and proves the kernel still
# sees no fragment and the tunnel still carries a packet. The budget is a
# startup property, so this is a second lifecycle rather than a live change.

say "restarting on a 1000-byte outer path (outer_mtu = 1000)"
sed -i '/^listen = /a outer_mtu = 1000' "$WORK/a.toml" "$WORK/b.toml"
grep -q '^outer_mtu = 1000$' "$WORK/a.toml" || bad "the narrow config was not written"

FRAG_A_NARROW_BEFORE=$(snmp_here FragCreates)
FRAG_B_NARROW_BEFORE=$(snmp_ns2 FragCreates)
# The pidfiles still hold the previous lifecycle's pids; the wait loop below
# would read them as a daemon that died before the new one writes its own.
: > "$A_PIDFILE"
: > "$B_PIDFILE"

in_ns bash -c 'echo $$ > "$2"; exec "$1" run --config "$3"' \
    _ "$BIN" "$B_PIDFILE" "$WORK/b.toml" > "$B_LOG" 2>&1 &
B_JOB=$!
bash -c 'echo $$ > "$1"; cd /; exec "$2" run --config "$3"' \
    _ "$A_PIDFILE" "$BIN" "$WORK/a.toml" > "$A_LOG" 2>&1 &
A_JOB=$!

DEADLINE=$((SECONDS + 10))
while :; do
    if grep -q "tunnel up on interface" "$A_LOG" && grep -q "tunnel up on interface" "$B_LOG"; then
        break
    fi
    for pidfile in "$A_PIDFILE" "$B_PIDFILE"; do
        [ -s "$pidfile" ] || continue
        kill -0 "$(cat "$pidfile")" 2>/dev/null \
            || bad "$(basename "$pidfile" .pid) exited on the narrow path; see $WORK"
    done
    if [ "$SECONDS" -ge "$DEADLINE" ]; then
        bad "an interface did not come up within 10 s on the narrow path"
    fi
    sleep 0.1
done

if crosses 20 -s 700 "$INNER_B"; then
    ok "a 728-byte inner packet crossed a 972-byte v4 budget"
else
    bad "the narrow path did not carry traffic"
fi

FRAG_A_NARROW=$(snmp_here FragCreates)
FRAG_B_NARROW=$(snmp_ns2 FragCreates)
if [ "$((FRAG_A_NARROW - FRAG_A_NARROW_BEFORE))" -ne 0 ] \
    || [ "$((FRAG_B_NARROW - FRAG_B_NARROW_BEFORE))" -ne 0 ]; then
    bad "the kernel fragmented on the narrow path"
fi
ok "no IP fragment was created on the narrow path either"

say "shutting the narrow-path daemons down"
kill_pidfile "$A_PIDFILE"
kill_pidfile "$B_PIDFILE"
wait_gone "$A_PIDFILE" 5 || bad "A ignored SIGTERM on the narrow path"
wait_gone "$B_PIDFILE" 5 || bad "B ignored SIGTERM on the narrow path"
ok "the narrow-path daemons exited on SIGTERM"

# ── IPv6 interface addresses ─────────────────────────────────────────
#
# The daemon assigns a v6 address itself, over netlink: `tun2`'s configuration
# path is an `AF_INET` ioctl and cannot express one. The outer path stays IPv4;
# only the inner addressing changes, so a ping6 crossing proves the address was
# assigned and the kernel installed its connected route.

say "restarting with IPv6 inner addresses"
: > "$A_PIDFILE"
: > "$B_PIDFILE"
sed -i 's|^address = .*|address = "fd00:7::1/64"|; s|^allowed_ips = .*|allowed_ips = ["fd00:7::2/128"]|' "$WORK/a.toml"
sed -i 's|^address = .*|address = "fd00:7::2/64"|; s|^allowed_ips = .*|allowed_ips = ["fd00:7::1/128"]|' "$WORK/b.toml"

in_ns bash -c 'echo $$ > "$2"; exec "$1" run --config "$3"' \
    _ "$BIN" "$B_PIDFILE" "$WORK/b.toml" > "$B_LOG" 2>&1 &
B_JOB=$!
bash -c 'echo $$ > "$1"; cd /; exec "$2" run --config "$3"' \
    _ "$A_PIDFILE" "$BIN" "$WORK/a.toml" > "$A_LOG" 2>&1 &
A_JOB=$!

DEADLINE=$((SECONDS + 10))
while :; do
    if grep -q "tunnel up on interface" "$A_LOG" && grep -q "tunnel up on interface" "$B_LOG"; then
        break
    fi
    for pidfile in "$A_PIDFILE" "$B_PIDFILE"; do
        [ -s "$pidfile" ] || continue
        kill -0 "$(cat "$pidfile")" 2>/dev/null \
            || bad "$(basename "$pidfile" .pid) exited on the v6 path; see $WORK"
    done
    if [ "$SECONDS" -ge "$DEADLINE" ]; then
        bad "an interface did not come up within 10 s on the v6 path"
    fi
    sleep 0.1
done

in_ns ip -6 addr show dev vallum0 | grep -q 'fd00:7::2/64' \
    || bad "B's interface has no fd00:7::2/64; see $B_LOG"
ok "the daemon assigned its IPv6 address and the kernel installed the route"



# From A, for the same reason the IPv4 phase starts there: A has an endpoint to
# dial, and B learns A's address from the authenticated handshake. A ping from B
# first would queue forever — B has nothing to dial.
# A lossy path can lose the first handshake, so give it the patience a user
# would: retry until a reply comes back rather than failing on one attempt.
DEADLINE=$((SECONDS + 20))
until ping -6 -c1 -W2 -q fd00:7::2 >/dev/null 2>&1; do
    if [ "$SECONDS" -ge "$DEADLINE" ]; then
        bad "IPv6 traffic did not cross the tunnel"
    fi
    sleep 0.2
done
ok "ping6 crossed the tunnel (fd00:7::1 -> fd00:7::2)"

# ...and the other way, over the session A started.
DEADLINE=$((SECONDS + 20))
until in_ns ping -6 -c1 -W2 -q fd00:7::1 >/dev/null 2>&1; do
    if [ "$SECONDS" -ge "$DEADLINE" ]; then
        bad "the IPv6 reverse direction failed"
    fi
    sleep 0.2
done
ok "ping6 crossed back (fd00:7::2 -> fd00:7::1)"

say "shutting the IPv6-path daemons down"
kill_pidfile "$A_PIDFILE"
kill_pidfile "$B_PIDFILE"
wait_gone "$A_PIDFILE" 5 || bad "A ignored SIGTERM on the v6 path"
wait_gone "$B_PIDFILE" 5 || bad "B ignored SIGTERM on the v6 path"
ok "the IPv6-path daemons exited on SIGTERM"

# ── IPv6 outer path, dual-stack /32 inner ────────────────────────────
#
# Two gaps in one lifecycle: the transport binds a v6 socket and dials a v6
# endpoint (so `IPV6_DONTFRAG` and the v6 cookie encoding are exercised), and the
# interface carries one address of each family as a /32 and a /128. With no
# connected route for either, the operator installs the host routes — which is
# also what the daemon's config warning tells them to do.

say "restarting with a v6 outer path and dual-stack /32 inner addresses"
: > "$A_PIDFILE"
: > "$B_PIDFILE"

sed -i -e 's|^address = .*|addresses = ["10.8.0.1/32", "fd00:8::1/128"]|' \
       -e 's|^listen = .*|listen = "[fd00:99::1]:51820"|' \
       -e 's|^endpoint = .*|endpoint = "[fd00:99::2]:51820"|' \
       -e 's|^allowed_ips = .*|allowed_ips = ["10.8.0.2/32", "fd00:8::2/128"]|' \
       "$WORK/a.toml"
sed -i -e 's|^address = .*|addresses = ["10.8.0.2/32", "fd00:8::2/128"]|' \
       -e 's|^listen = .*|listen = "[fd00:99::2]:51820"|' \
       -e 's|^allowed_ips = .*|allowed_ips = ["10.8.0.1/32", "fd00:8::1/128"]|' \
       "$WORK/b.toml"
grep -q '^addresses = ' "$WORK/a.toml" || bad "the dual-stack config was not written"

in_ns bash -c 'echo $$ > "$2"; exec "$1" run --config "$3"' \
    _ "$BIN" "$B_PIDFILE" "$WORK/b.toml" > "$B_LOG" 2>&1 &
B_JOB=$!
bash -c 'echo $$ > "$1"; cd /; exec "$2" run --config "$3"' \
    _ "$A_PIDFILE" "$BIN" "$WORK/a.toml" > "$A_LOG" 2>&1 &
A_JOB=$!

DEADLINE=$((SECONDS + 10))
while :; do
    if grep -q "tunnel up on interface" "$A_LOG" && grep -q "tunnel up on interface" "$B_LOG"; then
        break
    fi
    for pidfile in "$A_PIDFILE" "$B_PIDFILE"; do
        [ -s "$pidfile" ] || continue
        kill -0 "$(cat "$pidfile")" 2>/dev/null \
            || bad "$(basename "$pidfile" .pid) exited on the dual-stack path; see $WORK"
    done
    if [ "$SECONDS" -ge "$DEADLINE" ]; then
        bad "an interface did not come up within 10 s on the dual-stack path"
    fi
    sleep 0.1
done

# Both addresses, both families, assigned by the daemon over netlink.
ip addr show dev vallum0 | grep -q '10.8.0.1/32' \
    || bad "A has no v4 /32 address; see $A_LOG"
ip -6 addr show dev vallum0 | grep -q 'fd00:8::1/128' \
    || bad "A has no v6 /128 address; see $A_LOG"
in_ns ip addr show dev vallum0 | grep -q '10.8.0.2/32' \
    || bad "B has no v4 /32 address; see $B_LOG"
in_ns ip -6 addr show dev vallum0 | grep -q 'fd00:8::2/128' \
    || bad "B has no v6 /128 address; see $B_LOG"
ok "one interface carries both families, assigned by the daemon"

# A /32 and a /128 install no connected route; the operator adds host routes,
# exactly as the config warning says.
ip route add 10.8.0.2/32 dev vallum0
ip -6 route add fd00:8::2/128 dev vallum0
in_ns ip route add 10.8.0.1/32 dev vallum0
in_ns ip -6 route add fd00:8::1/128 dev vallum0

if crosses 20 10.8.0.2; then
    ok "IPv4 crossed a dual-stack tunnel over a v6 outer path"
else
    bad "IPv4 did not cross the dual-stack tunnel"
fi
if crosses 20 -6 fd00:8::2; then
    ok "IPv6 crossed the same tunnel"
else
    bad "IPv6 did not cross the dual-stack tunnel"
fi
if crosses_in_ns 20 10.8.0.1 && crosses_in_ns 20 -6 "fd00:8::1"; then
    ok "both families crossed back"
else
    bad "the reverse direction failed for at least one family"
fi

say "shutting the dual-stack daemons down"
kill_pidfile "$A_PIDFILE"
kill_pidfile "$B_PIDFILE"
wait_gone "$A_PIDFILE" 5 || bad "A ignored SIGTERM on the dual-stack path"
wait_gone "$B_PIDFILE" 5 || bad "B ignored SIGTERM on the dual-stack path"
ok "the dual-stack daemons exited on SIGTERM"

# ── IPv4 DF: a path that narrows under a running tunnel ──────────────
#
# `IP_MTU_DISCOVER = DO` makes the kernel report EMSGSIZE instead of
# fragmenting, so nothing is ever silently split. The daemons start on a wide
# path and discover it; the link is then narrowed underneath them, which is the
# case startup discovery cannot cover. The daemon must ask the kernel what the
# path now carries, narrow its datagrams, and carry the handshake anyway.
# Without DF the kernel would fragment silently and the misconfiguration would
# look like a slow path.

: > "$A_PIDFILE"
: > "$B_PIDFILE"

# A single v4 inner address with a connected route, and a v4 outer path.
sed -i -e 's|^addresses = .*|address = "10.9.0.1/24"|' \
       -e 's|^listen = .*|listen = "10.99.0.1:51820"|' \
       -e 's|^endpoint = .*|endpoint = "10.99.0.2:51820"|' \
       -e 's|^allowed_ips = .*|allowed_ips = ["10.9.0.2/32"]|' \
       -e '/^outer_mtu/d' "$WORK/a.toml"
sed -i -e 's|^addresses = .*|address = "10.9.0.2/24"|' \
       -e 's|^listen = .*|listen = "10.99.0.2:51820"|' \
       -e 's|^allowed_ips = .*|allowed_ips = ["10.9.0.1/32"]|' \
       -e '/^outer_mtu/d' "$WORK/b.toml"

FRAG_A_DF_BEFORE=$(snmp_here FragCreates)
FRAG_B_DF_BEFORE=$(snmp_ns2 FragCreates)

in_ns bash -c 'echo $$ > "$2"; exec "$1" run --config "$3"' \
    _ "$BIN" "$B_PIDFILE" "$WORK/b.toml" > "$B_LOG" 2>&1 &
B_JOB=$!
bash -c 'echo $$ > "$1"; cd /; exec "$2" run --config "$3"' \
    _ "$A_PIDFILE" "$BIN" "$WORK/a.toml" > "$A_LOG" 2>&1 &
A_JOB=$!

DEADLINE=$((SECONDS + 10))
while :; do
    if grep -q "tunnel up on interface" "$A_LOG" && grep -q "tunnel up on interface" "$B_LOG"; then
        break
    fi
    for pidfile in "$A_PIDFILE" "$B_PIDFILE"; do
        [ -s "$pidfile" ] || continue
        kill -0 "$(cat "$pidfile")" 2>/dev/null \
            || bad "$(basename "$pidfile" .pid) exited on the DF path; see $WORK"
    done
    if [ "$SECONDS" -ge "$DEADLINE" ]; then
        bad "an interface did not come up within 10 s on the DF path"
    fi
    sleep 0.1
done

# A packet from A starts the handshake on a wide path, and gives the daemon a
# destination to measure — this is where the pre-send probe runs.
ping -c1 -W2 -q 10.9.0.2 >/dev/null 2>&1 || true
DEADLINE=$((SECONDS + 10))
until ping -c1 -W1 -q 10.9.0.2 >/dev/null 2>&1; do
    if [ "$SECONDS" -ge "$DEADLINE" ]; then
        bad "the tunnel did not come up on the wide path; see $WORK"
    fi
    sleep 0.2
done

# Now narrow it underneath an already-measured destination. The probe will not
# run again, so this is the case the kernel must report as EMSGSIZE rather than
# fragment, and the daemon must react to.
say "narrowing the outer path to 1200 bytes while the daemons are running"
ip link set veth-a mtu 1200
in_ns ip link set veth-b mtu 1200

# A payload that no longer fits the path, to provoke the report.
ping -c1 -W2 -s 1200 -q 10.9.0.2 >/dev/null 2>&1 || true

DEADLINE=$((SECONDS + 8))
while :; do
    if grep -q "exceeded the path MTU" "$A_LOG"; then
        break
    fi
    for pidfile in "$A_PIDFILE" "$B_PIDFILE"; do
        [ -s "$pidfile" ] || continue
        kill -0 "$(cat "$pidfile")" 2>/dev/null \
            || bad "$(basename "$pidfile" .pid) exited on the DF path; see $WORK"
    done
    if [ "$SECONDS" -ge "$DEADLINE" ]; then
        bad "no EMSGSIZE warning after 8 s on a 1200-byte path"
    fi
    sleep 0.1
done
ok "the kernel reported the oversize datagram instead of fragmenting it"

FRAG_A_DF=$(snmp_here FragCreates)
FRAG_B_DF=$(snmp_ns2 FragCreates)
if [ "$((FRAG_A_DF - FRAG_A_DF_BEFORE))" -ne 0 ] \
    || [ "$((FRAG_B_DF - FRAG_B_DF_BEFORE))" -ne 0 ]; then
    bad "the kernel fragmented a datagram despite IP_MTU_DISCOVER=DO"
fi
ok "nothing was fragmented"

# The path narrowed under a running tunnel. The daemon must narrow its datagrams
# and carry the handshake anyway, rather than dropping every datagram after it.
# The window is generous because a post-quantum handshake is many fragments: at
# 5% loss each attempt has a real chance of losing one, so recovery takes several
# retries rather than one.
DEADLINE=$((SECONDS + 25))
while :; do
    if ping -c1 -W1 -q 10.9.0.2 >/dev/null 2>&1; then
        break
    fi
    if [ "$SECONDS" -ge "$DEADLINE" ]; then
        bad "the tunnel did not recover after the path narrowed to 1200 bytes; see $WORK"
    fi
    sleep 0.2
done
ok "the tunnel recovered and carried traffic on the narrower path"

kill_pidfile "$A_PIDFILE"
kill_pidfile "$B_PIDFILE"
wait_gone "$A_PIDFILE" 5 || bad "A ignored SIGTERM on the DF path"
wait_gone "$B_PIDFILE" 5 || bad "B ignored SIGTERM on the DF path"

say "naming the real MTU (outer_mtu = 1200) makes the same path work"
sed -i '/^listen = /a outer_mtu = 1200' "$WORK/a.toml" "$WORK/b.toml"
: > "$A_PIDFILE"
: > "$B_PIDFILE"

in_ns bash -c 'echo $$ > "$2"; exec "$1" run --config "$3"' \
    _ "$BIN" "$B_PIDFILE" "$WORK/b.toml" > "$B_LOG" 2>&1 &
B_JOB=$!
bash -c 'echo $$ > "$1"; cd /; exec "$2" run --config "$3"' \
    _ "$A_PIDFILE" "$BIN" "$WORK/a.toml" > "$A_LOG" 2>&1 &
A_JOB=$!

DEADLINE=$((SECONDS + 10))
while :; do
    if grep -q "tunnel up on interface" "$A_LOG" && grep -q "tunnel up on interface" "$B_LOG"; then
        break
    fi
    for pidfile in "$A_PIDFILE" "$B_PIDFILE"; do
        [ -s "$pidfile" ] || continue
        kill -0 "$(cat "$pidfile")" 2>/dev/null \
            || bad "$(basename "$pidfile" .pid) exited on the corrected path; see $WORK"
    done
    if [ "$SECONDS" -ge "$DEADLINE" ]; then
        bad "an interface did not come up within 10 s on the corrected path"
    fi
    sleep 0.1
done

if crosses 20 10.9.0.2; then
    ok "a 1200-byte path with outer_mtu = 1200 carries traffic"
else
    bad "the corrected path did not carry traffic"
fi
if grep -q "exceeded the path MTU" "$A_LOG"; then
    bad "the corrected path still reported an oversize datagram"
fi
ok "and no oversize datagram was reported"

say "shutting the DF-path daemons down"
kill_pidfile "$A_PIDFILE"
kill_pidfile "$B_PIDFILE"
wait_gone "$A_PIDFILE" 5 || bad "A ignored SIGTERM on the corrected path"
wait_gone "$B_PIDFILE" 5 || bad "B ignored SIGTERM on the corrected path"
ok "the DF-path daemons exited on SIGTERM"


# ── the provisioning path ────────────────────────────────────────────
#
# Everything above writes its configs by hand. This lifecycle uses the product
# path instead: `vallum server init` on each end, then `vallum peer add` to enrol
# the other, with addresses allocated rather than chosen. A ping here means the
# commands a person follows actually produce a working tunnel.
say "provisioning both ends through the CLI"

PROV=$WORK/prov
mkdir -p "$PROV/a" "$PROV/b"

# The DF-path lifecycle above narrowed the veth to 1200 bytes and did not widen
# it again. A freshly provisioned config assumes a 1500-byte path, so restore it
# rather than making the provisioning test depend on the previous test's damage.
ip link set veth-a mtu 1500
in_ns ip link set veth-b mtu 1500

"$BIN" server init --config "$PROV/a/vallum0.toml" --address "$INNER_A/24" \
    --listen "$OUTER_A:$PORT" --endpoint "$OUTER_B:$PORT" \
    --control "$PROV/a/control.sock" --no-host --no-service \
    > "$WORK/prov-a-init.log" 2>&1 || bad "A's server init failed; see $WORK/prov-a-init.log"
"$BIN" server init --config "$PROV/b/vallum0.toml" --address "$INNER_B/24" \
    --listen "$OUTER_B:$PORT" \
    --control "$PROV/b/control.sock" --no-host --no-service \
    > "$WORK/prov-b-init.log" 2>&1 || bad "B's server init failed; see $WORK/prov-b-init.log"
ok "server init wrote both configs and keys"

[ "$(stat -c %a "$PROV/a/server.key")" = "600" ] || bad "the generated key is not 0600"
[ "$(stat -c %a "$PROV/a/vallum0.toml")" = "600" ] || bad "the generated config is not 0600"
ok "the generated key and config are 0600"

"$BIN" pubkey --private-key "$PROV/a/server.key" > "$PROV/a.pub"
"$BIN" pubkey --private-key "$PROV/b/server.key" > "$PROV/b.pub"
"$BIN" peer add b --config "$PROV/a/vallum0.toml" --public-key-file "$PROV/b.pub" \
    --endpoint "$OUTER_B:$PORT" --no-apply > "$WORK/prov-a-peer.log" 2>&1 \
    || bad "A's peer add failed; see $WORK/prov-a-peer.log"
"$BIN" peer add a --config "$PROV/b/vallum0.toml" --public-key-file "$PROV/a.pub" \
    --no-apply > "$WORK/prov-b-peer.log" 2>&1 \
    || bad "B's peer add failed; see $WORK/prov-b-peer.log"
grep -q "allowed_ips = \[\"$INNER_B/32\"\]" "$PROV/a/vallum0.toml" \
    || bad "A's peer did not get $INNER_B/32"
grep -q "allowed_ips = \[\"$INNER_A/32\"\]" "$PROV/b/vallum0.toml" \
    || bad "B's peer did not get $INNER_A/32"
ok "peer add allocated $INNER_B and $INNER_A and wrote both peers"

# A duplicate name is refused rather than silently duplicated.
if "$BIN" peer add b --config "$PROV/a/vallum0.toml" --public-key-file "$PROV/b.pub" \
    --no-apply > /dev/null 2>&1; then
    bad "a duplicate peer name was accepted"
fi
ok "a duplicate peer name is refused"

start_prov() {
    : > "$WORK/prov-b.pid"
    in_ns bash -c 'echo $$ > "$2"; exec "$1" run --config "$3"' \
        _ "$BIN" "$WORK/prov-b.pid" "$PROV/b/vallum0.toml" > "$WORK/prov-b.log" 2>&1 &
    : > "$WORK/prov-a.pid"
    bash -c 'echo $$ > "$1"; cd /; exec "$2" run --config "$3"' \
        _ "$WORK/prov-a.pid" "$BIN" "$PROV/a/vallum0.toml" > "$WORK/prov-a.log" 2>&1 &

    local deadline=$((SECONDS + 10))
    while :; do
        if ip link show vallum0 >/dev/null 2>&1 \
            && in_ns ip link show vallum0 >/dev/null 2>&1; then
            return 0
        fi
        for pidfile in "$WORK/prov-a.pid" "$WORK/prov-b.pid"; do
            [ -s "$pidfile" ] || continue
            kill -0 "$(cat "$pidfile")" 2>/dev/null \
                || bad "$(basename "$pidfile" .pid) exited; see $WORK/prov-a.log or prov-b.log"
        done
        if [ "$SECONDS" -ge "$deadline" ]; then
            bad "a provisioned interface did not come up within 10 s"
        fi
        sleep 0.1
    done
}

stop_prov() {
    kill_pidfile "$WORK/prov-a.pid"
    kill_pidfile "$WORK/prov-b.pid"
    wait_gone "$WORK/prov-a.pid" 5 || bad "provisioned A ignored SIGTERM"
    wait_gone "$WORK/prov-b.pid" 5 || bad "provisioned B ignored SIGTERM"
}

start_prov
ok "both provisioned daemons brought their interfaces up"

if crosses 20 "$INNER_B"; then
    ok "the provisioned tunnel carries traffic"
else
    bad "the provisioned tunnel did not carry traffic; see $WORK/prov-a.log"
fi

stop_prov
ok "the provisioned daemons exited on SIGTERM"

# ── rotation ─────────────────────────────────────────────────────────
#
# A is the initiator, so its key is the one that rotates: B accepts A's old key
# as the previous identity while A switches. That is the direction that has to
# work — a responder accepts a previous key, an initiator dials with its current
# one.
say "rotating A's key with no outage"

cp "$PROV/a/server.key" "$PROV/a-old.key"
"$BIN" keygen --output "$PROV/a-new.key" --suite 3 > "$PROV/a-new.pub" 2>/dev/null
"$BIN" peer rotate a --config "$PROV/b/vallum0.toml" \
    --public-key-file "$PROV/a-new.pub" --no-apply > "$WORK/prov-rotate.log" 2>&1 \
    || bad "peer rotate failed; see $WORK/prov-rotate.log"
grep -q '^previous_public_key = ' "$PROV/b/vallum0.toml" \
    || bad "peer rotate did not keep the old key as previous_public_key"
ok "peer rotate kept the old key as the previous identity"

start_prov
if crosses 20 "$INNER_B"; then
    ok "the old key still works while the rotation is open"
else
    bad "the old key stopped working during a rotation; see $WORK/prov-a.log"
fi
stop_prov

cp "$PROV/a-new.key" "$PROV/a/server.key"
start_prov
if crosses 20 "$INNER_B"; then
    ok "the new key works once the device has it"
else
    bad "the new key did not work; see $WORK/prov-a.log"
fi
stop_prov

"$BIN" peer finalize a --config "$PROV/b/vallum0.toml" --no-apply \
    > "$WORK/prov-finalize.log" 2>&1 || bad "peer finalize failed"
grep -q '^previous_public_key = ' "$PROV/b/vallum0.toml" \
    && bad "peer finalize left the previous key behind"
start_prov
# A rotation forces a new handshake; on a lossy path that takes more than one
# attempt, so retry rather than failing on the first.
DEADLINE=$((SECONDS + 25))
until ping -c1 -W2 -q "$INNER_B" >/dev/null 2>&1; do
    if [ "$SECONDS" -ge "$DEADLINE" ]; then
        bad "the tunnel stopped working after finalize; see $WORK/prov-a.log"
    fi
    sleep 0.2
done
ok "the tunnel still works after finalize"
stop_prov

# The retired key must be refused, or finalize is only cosmetic.
cp "$PROV/a-old.key" "$PROV/a/server.key"
start_prov
if ping -c1 -W2 -q "$INNER_B" >/dev/null 2>&1; then
    bad "the retired key still completed a handshake"
fi
ok "the retired key is refused"
stop_prov
cp "$PROV/a-new.key" "$PROV/a/server.key"

"$BIN" peer remove b --config "$PROV/a/vallum0.toml" --no-apply > /dev/null 2>&1 \
    || bad "peer remove failed"
grep -q 'name = "b"' "$PROV/a/vallum0.toml" && bad "peer remove left the peer behind"
ok "peer remove took the peer out of the config"

printf '\n== PASS\n'
INNER
