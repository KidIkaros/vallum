#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Does the daemon make any syscall its own filter does not name?
#
# ADR-0028 step 4. The allow-list in `crates/vallum/src/sandbox.rs` is derived
# from a trace, so it goes stale the moment a code path starts calling something
# new — and the failure mode is a daemon that dies in production in `enforce`
# mode, months later, on a path nobody ran. This script is the check that makes
# the list self-maintaining: it runs the same exercise the list was derived from
# and fails when the set of syscalls the daemon actually made is not a subset of
# the set the binary installs.
#
# The list is read back from the binary (`vallum sandbox --names`) rather than
# from the source, because a guard with its own copy of the list cannot fail when
# the two copies disagree.
#
#   ns (one network namespace, one user namespace)
#   ┌────────────────────────────────────────────────────────┐
#   │ vallum0 10.99.0.1/24        vallum0 10.99.0.2/24       │
#   │   ⇅ daemon A                  ⇅ daemon B               │
#   │ 127.0.0.1:51820       ⇄       127.0.0.2:51820          │
#   ├────────────────────────────────────────────────────────┤
#   │ vallum2 10.98.0.1/24        vallum3 10.98.0.2/24       │
#   │   ⇅ daemon A′                 ⇅ daemon B′              │
#   │ 127.0.0.3:51821 (tcp) ⇄       127.0.0.4:51821 (tcp)    │
#   └────────────────────────────────────────────────────────┘
#
# The exercise runs twice, once per carrier. The UDP leg is the default and the
# path the list was first derived from; the TCP leg (ADR-0026) is the code that
# dials, waits in `poll`, and shuts a stream down, none of which the default
# carrier does. Both are the daemon's syscall surface, so both are traced and the
# guard diffs the union.
#
# strace attaches to daemon A only after the tunnel is up, so the trace is the
# running daemon's syscall surface: the startup phase (`ip` calls, `openat`,
# `setuid`) happens before the drop and is deliberately not in the list.
#
# What this cannot see: syscalls made by threads that already existed when the
# trace attached (thread creation, `set_robust_list`, `rseq`). `docs/proof/seccomp.md`
# §3 says which entries rest on reading the code instead of on a trace.
#
# The traced daemon runs without `interface.user`, because the question is what
# the daemon asks for, not whether the filter installs — and an unprivileged user
# namespace cannot call `setgroups`, which the privilege drop does. The live
# enforce run is `scripts/seccomp-enforce.sh`, which needs real root.
#
# Usage:
#   scripts/seccomp-trace.sh [path/to/vallum]
#
# Set KEEP=1 to leave the scratch directory (configs, keys, both logs and the raw
# traces) behind instead of deleting it.
#
# Exit status 0 means every syscall in either trace is on the allow-list. Requires
# Linux with user namespaces (or root), `ip`, `ping`, and `strace`.

set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BIN=${1:-$ROOT/target/debug/vallum}

die() {
    echo "seccomp-trace: $*" >&2
    exit 1
}

[ -x "$BIN" ] || die "no daemon at '$BIN'; build it with \`cargo build -p vallum\`"
for tool in ip ping strace; do
    command -v "$tool" > /dev/null 2>&1 || die "missing '$tool' (apt install strace iputils-ping)"
done

W=$(mktemp -d /tmp/vallum-seccomp.XXXXXX) || die "cannot create a scratch directory"
cleanup() {
    if [ "${KEEP:-0}" = 1 ]; then
        echo "seccomp-trace: kept $W" >&2
    else
        rm -rf "$W"
    fi
}
trap cleanup EXIT

# The home directory a CI runner checks out into is not always traversable from
# inside the user namespace, so the binary is copied into the scratch directory.
cp "$BIN" "$W/vallum" || die "cannot copy the binary into $W"

cat > "$W/inner.sh" << 'INNER'
#!/usr/bin/env bash
# Runs inside the namespace: keys, two carriers, four daemons, two traces.
set -euo pipefail
cd "$W"

ip link set lo up

"$W/vallum" keygen --output "$W/a.key" --suite 3 > "$W/a.pub"
"$W/vallum" keygen --output "$W/b.key" --suite 3 > "$W/b.pub"
pub_a=$(cat "$W/a.pub")
pub_b=$(cat "$W/b.pub")

# The control socket can appear before the interface has an address, so this is
# retried rather than attempted once: a silent failure here would leave the ping
# to fail with a misleading message.
add_route() {
    local destination=$1 device=$2 tag=$3 attempt
    for attempt in $(seq 1 50); do
        if ip route add "$destination" dev "$device" 2> "$W/route-$tag.err"; then return 0; fi
        sleep 0.1
    done
    echo "cannot route $destination into $device after 5s: $(cat "$W/route-$tag.err")" >&2
    return 1
}

# One exercise: two daemons, a real TUN each, the handshake, three pings each
# way, a control request, and a shutdown — with strace on A from the moment the
# tunnel is up. The carrier is the only thing the two calls differ in.
#
#   leg TAG CARRIER IF_A IF_B TUN_A TUN_B OUTER_A OUTER_B
leg() {
    local tag=$1 carrier=$2 if_a=$3 if_b=$4 tun_a=$5 tun_b=$6 outer_a=$7 outer_b=$8
    local pid_a pid_b tracer

    cat > "$W/$tag-a.toml" <<EOF
[interface]
name = "$if_a"
private_key = "$W/a.key"
address = "$tun_a/24"
listen = "$outer_a"
control = "$W/ctl-$tag.sock"
carrier = "$carrier"

[log]
level = "info"

[[peer]]
name = "b"
public_key = "$pub_b"
endpoint = "$outer_b"
allowed_ips = ["$tun_b/32"]
persistent_keepalive = 1
EOF

    cat > "$W/$tag-b.toml" <<EOF
[interface]
name = "$if_b"
private_key = "$W/b.key"
address = "$tun_b/24"
listen = "$outer_b"
carrier = "$carrier"

[log]
level = "info"

[[peer]]
name = "a"
public_key = "$pub_a"
allowed_ips = ["$tun_a/32"]
EOF

    "$W/vallum" run --config "$W/$tag-b.toml" --allow-insecure-key-permissions > "$W/$tag-b.log" 2>&1 &
    pid_b=$!
    "$W/vallum" run --config "$W/$tag-a.toml" --allow-insecure-key-permissions > "$W/$tag-a.log" 2>&1 &
    pid_a=$!

    # The control socket is published only once the daemon is serving, so it is a
    # better readiness signal than a sleep.
    for _ in $(seq 1 100); do
        [ -S "$W/ctl-$tag.sock" ] && break
        sleep 0.1
    done
    [ -S "$W/ctl-$tag.sock" ] || {
        echo "$tag: daemon A did not start: $(tail -3 "$W/$tag-a.log")" >&2
        exit 1
    }

    add_route "$tun_b/32" "$if_a" "$tag"
    add_route "$tun_a/32" "$if_b" "$tag"

    strace -f -p "$pid_a" -o "$W/trace-$tag.txt" 2> /dev/null &
    tracer=$!
    sleep 0.5

    # Both directions: each reader and each writer path is exercised once. The
    # source address of a ping into the tunnel is the interface's, so this is the
    # daemon's own send path and not the host's.
    ping -c 3 -W 1 "$tun_b" > "$W/ping-$tag-a.log" 2>&1 || {
        echo "$tag: A to B did not carry traffic: $(tail -3 "$W/ping-$tag-a.log")" >&2
        exit 1
    }
    ping -c 3 -W 1 "$tun_a" > "$W/ping-$tag-b.log" 2>&1 || {
        echo "$tag: B to A did not carry traffic: $(tail -3 "$W/ping-$tag-b.log")" >&2
        exit 1
    }

    # The control plane is a thread of the daemon, so a request through it is part
    # of the surface that has to stay covered. `vallum show` is the client the
    # product ships, and it fails loudly rather than hanging.
    timeout 5 "$W/vallum" show --control "$W/ctl-$tag.sock" > /dev/null || {
        echo "$tag: the control socket did not answer" >&2
        exit 1
    }

    kill -TERM "$pid_a"
    sleep 1
    # strace exits with the daemon it traced, so it is usually gone by now.
    kill "$tracer" 2> /dev/null || true
    wait "$pid_a" 2> /dev/null || true
    kill -TERM "$pid_b" 2> /dev/null || true
    wait "$pid_b" 2> /dev/null || true

    # strace prefixes each line with `[pid N]` when it follows threads and a bare
    # number when it does not; both are stripped before the call name is taken. An
    # empty result is checked by the caller, so a `grep` that finds nothing must
    # not abort the script here.
    sed -E 's/^\[pid +[0-9]+\] +//; s/^[0-9]+ +//' "$W/trace-$tag.txt" \
        | grep -oE '^[a-z_0-9]+\(' | tr -d '(' | sort -u > "$W/traced-$tag.txt" || true
}

leg udp udp vallum0 vallum1 10.99.0.1 10.99.0.2 127.0.0.1:51820 127.0.0.2:51820
leg tcp tcp vallum2 vallum3 10.98.0.1 10.98.0.2 127.0.0.3:51821 127.0.0.4:51821

cat "$W/traced-udp.txt" "$W/traced-tcp.txt" | sort -u > "$W/traced.txt"
INNER

if unshare -Urn true 2> /dev/null; then
    NS=(unshare -Urn)
else
    [ "$(id -u)" = 0 ] || die "this host forbids unprivileged user namespaces; run it under sudo"
    NS=(unshare -n)
fi

if ! W="$W" "${NS[@]}" bash "$W/inner.sh" 2> "$W/inner.err"; then
    echo "seccomp-trace: the exercise failed" >&2
    cat "$W/inner.err" >&2
    for leg in udp tcp; do
        [ -s "$W/$leg-a.log" ] && tail -5 "$W/$leg-a.log" >&2
    done
    exit 1
fi

"$W/vallum" sandbox --names | sort -u > "$W/allowed.txt"
[ -s "$W/traced.txt" ] || die "the trace is empty; strace did not attach"
traced=$(wc -l < "$W/traced.txt")
# A trace that saw only `exit` means it attached to a dying process, which would
# pass the diff below for the wrong reason.
[ "$traced" -ge 8 ] || die "the trace saw only $traced distinct syscalls; strace attached too late or the daemon died"
comm -23 "$W/traced.txt" "$W/allowed.txt" > "$W/unknown.txt"

echo "== udp leg: $(wc -l < "$W/traced-udp.txt") syscalls; tcp leg: $(wc -l < "$W/traced-tcp.txt")"
echo "== union: $traced distinct syscalls after startup"
if [ -s "$W/unknown.txt" ]; then
    echo "== FAIL: the allow-list does not name:" >&2
    sed 's/^/     /' "$W/unknown.txt" >&2
    echo "   Add them to ALLOWED in crates/vallum/src/sandbox.rs, or stop making the call." >&2
    KEEP=1
    exit 1
fi
echo "== all of them are on the allow-list ($(wc -l < "$W/allowed.txt") entries)"
