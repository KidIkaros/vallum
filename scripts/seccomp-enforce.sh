#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Does the filter hold on a live, dropped daemon in enforce mode?
#
# `docs/proof/seccomp.md` §5.2 records the gap this closes: enforce mode had never
# run against a live daemon, because the filter is installed by the privilege drop
# and the drop calls `setgroups`, which an unprivileged user namespace answers
# with `EPERM`. Under real root it succeeds, so this runs where root is available.
#
# What it asserts, in the order it asserts it:
#
#   1. the daemon says it installed the filter, and in enforce mode;
#   2. the kernel agrees — `/proc/<pid>/status` reports `Seccomp: 2` (filter, not
#      disabled) and `NoNewPrivs: 1`;
#   3. the drop happened — the effective uid is the configured one, not root;
#   4. every thread the daemon created **after** the install inherited the filter,
#      which is the one claim the insertion point exists to buy;
#   5. it still works while filtered: a ping crosses the tunnel, and the control
#      plane answers;
#   6. a `SIGTERM` still shuts it down cleanly, so the filter does not block the
#      shutdown path.
#
# What it does not assert: that a syscall off the list kills the daemon. There is
# no way to ask a live daemon to take that path without a debugger inside it, and
# a debugger inside it is not a test. The kill is proven by the self-test in
# `crates/vallum/src/sandbox.rs`, which re-executes itself, installs the same
# filter in enforce mode, and asserts the child dies on `SIGSYS` when it calls
# `execve`.
#
# If a daemon dies during startup the report replays it under `strace` and prints
# the syscall that killed it, because `SIGSYS` names no syscall and the guard's
# trace attaches after startup. The first live run of this leg is how `linkat` was
# found on the control-socket path; see `docs/proof/seccomp.md` §3.
#
# This needs real root. Run it as:
#
#   bash scripts/seccomp-enforce.sh || sudo -E bash scripts/seccomp-enforce.sh
#
# Set KEEP=1 to leave the scratch directory (configs, keys, logs) behind.

set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BIN=${1:-$ROOT/target/debug/vallum}
USER_NAME=${SECCOMP_ENFORCE_USER:-nobody}

die() {
    echo "seccomp-enforce: $*" >&2
    exit 1
}

[ "$(id -u)" = 0 ] || die "needs real root: the privilege drop calls setgroups, which an unprivileged user namespace denies (run it under sudo)"
[ -x "$BIN" ] || die "no daemon at '$BIN'; build it with \`cargo build -p vallum\`"
for tool in ip ping; do
    command -v "$tool" > /dev/null 2>&1 || die "missing '$tool' (apt install iputils-ping)"
done
id "$USER_NAME" > /dev/null 2>&1 || die "no user '$USER_NAME' to drop to; set SECCOMP_ENFORCE_USER"

W=$(mktemp -d /tmp/vallum-enforce.XXXXXX) || die "cannot create a scratch directory"
cleanup() {
    if [ "${KEEP:-0}" = 1 ]; then
        echo "seccomp-enforce: kept $W" >&2
    else
        rm -rf "$W"
    fi
}
trap cleanup EXIT

cp "$BIN" "$W/vallum" || die "cannot copy the binary into $W"
# The daemon publishes its control socket after the drop, as the configured user.
chmod 0777 "$W" || die "cannot open $W to the user the daemon drops to"

cat > "$W/inner.sh" << 'INNER'
#!/usr/bin/env bash
# Runs inside the network namespace: two daemons in enforce mode, four assertions
# about one of them, and traffic through both.
set -euo pipefail
cd "$W"

ok=0
pid_a=
pid_b=
stop() {
    for pid in ${pid_a:-} ${pid_b:-}; do
        kill "$pid" 2> /dev/null || true
    done
}
trap stop EXIT
pass() {
    ok=$((ok + 1))
    printf '  ok    %s\n' "$*"
}
fail() {
    printf '  FAIL  %s\n' "$*" >&2
    exit 1
}

status_field() { # pid, field
    sed -n "s/^$2:[[:space:]]*//p" "/proc/$1/status"
}

# A daemon killed by its own filter exits with "Bad system call" and nothing
# else: `SIGSYS` does not say which syscall. strace does, so a startup death is
# replayed under it and the killing call is printed — otherwise the first live
# run of this leg costs an investigation instead of a fix. That is how `linkat`
# was found: publishing the control socket hard-links a chmodded socket into
# place, and the list had `unlinkat` but not `linkat`, because the guarded trace
# attaches after startup.
name_the_kill() { # config, tag
    local config=$1 tag=$2
    command -v strace > /dev/null 2>&1 || {
        echo '     (no strace here: the killing syscall is not named)' >&2
        return 0
    }
    # The dead daemon leaves its socket name behind and a second publication
    # refuses an occupied path, so the name is cleared before the replay.
    rm -f "$W/ctl-$tag.sock"
    timeout 15 strace -f -o "$W/$tag.kill.trace" -- "$W/vallum" run --config "$config" \
        --allow-insecure-key-permissions > "$W/$tag.kill.log" 2>&1 || true
    # A path that is timing-dependent may survive the replay; do not leave that
    # daemon running inside the namespace.
    pkill -TERM -f "$config" 2> /dev/null || true
    if grep -q 'SIGSYS' "$W/$tag.kill.trace" 2> /dev/null; then
        echo '     the killing syscall:' >&2
        grep -B2 -m1 'SIGSYS' "$W/$tag.kill.trace" | sed 's/^/       /' >&2
    else
        echo "     the replay did not die; see $W/$tag.kill.log" >&2
    fi
    return 0
}

die_at_startup() {
    if grep -q 'syscall filter installed in enforce mode' "$W/a.log" 2> /dev/null; then
        echo '  FAIL  the filter killed the daemon after it installed: a syscall on the startup path is not on the allow-list' >&2
    else
        echo '  FAIL  the daemon exited before installing the filter: it could not drop, or could not install' >&2
    fi
    cat "$W/a.log" >&2
    name_the_kill "$W/a.toml" a
    exit 1
}

ip link set lo up

"$W/vallum" keygen --output "$W/a.key" --suite 3 > "$W/a.pub"
"$W/vallum" keygen --output "$W/b.key" --suite 3 > "$W/b.pub"
pub_a=$(cat "$W/a.pub")
pub_b=$(cat "$W/b.pub")

group=$(id -gn "$USER_NAME")

# Both sides drop and both sides enforce: the responder is the side whose
# shutdown and teardown paths a one-sided run would never reach.
cat > "$W/a.toml" <<EOF
[interface]
name = "vallum0"
private_key = "$W/a.key"
address = "10.97.0.1/24"
listen = "127.0.0.1:51830"
control = "$W/ctl-a.sock"
user = "$USER_NAME"
group = "$group"
seccomp = "enforce"

[log]
level = "info"

[[peer]]
name = "b"
public_key = "$pub_b"
endpoint = "127.0.0.2:51830"
allowed_ips = ["10.97.0.2/32"]
persistent_keepalive = 1
EOF

cat > "$W/b.toml" <<EOF
[interface]
name = "vallum1"
private_key = "$W/b.key"
address = "10.97.0.2/24"
listen = "127.0.0.2:51830"
user = "$USER_NAME"
group = "$group"
seccomp = "enforce"

[log]
level = "info"

[[peer]]
name = "a"
public_key = "$pub_a"
allowed_ips = ["10.97.0.1/32"]
EOF
chmod 0600 "$W/a.toml" "$W/b.toml"

"$W/vallum" run --config "$W/b.toml" --allow-insecure-key-permissions > "$W/b.log" 2>&1 &
pid_b=$!
"$W/vallum" run --config "$W/a.toml" --allow-insecure-key-permissions > "$W/a.log" 2>&1 &
pid_a=$!

for _ in $(seq 1 100); do
    [ -S "$W/ctl-a.sock" ] && break
    kill -0 "$pid_a" 2> /dev/null || break
    sleep 0.1
done
kill -0 "$pid_a" 2> /dev/null || die_at_startup
[ -S "$W/ctl-a.sock" ] || fail "daemon A never published its control socket"

# 1. What the daemon says.
grep -q 'syscall filter installed in enforce mode' "$W/a.log" \
    || fail "the startup log does not say the filter was installed in enforce mode"
pass "the daemon reported 'syscall filter installed in enforce mode'"

# 2. What the kernel says. SECCOMP_MODE_FILTER is 2; 0 would mean no filter at all
# and 1 means strict mode, which this is not.
seccomp=$(status_field "$pid_a" Seccomp)
[ "$seccomp" = 2 ] || fail "the kernel reports Seccomp: ${seccomp:-<missing>} for the daemon, not 2 (filter)"
pass "the kernel reports Seccomp: 2 (filter) for the daemon"
nopriv=$(status_field "$pid_a" NoNewPrivs)
[ "$nopriv" = 1 ] || fail "the kernel reports NoNewPrivs: ${nopriv:-<missing>}, not 1"
pass "the kernel reports NoNewPrivs: 1"

# 3. The drop happened. `Uid:` is real, effective, saved, fs — all four, because a
# daemon that kept root as its saved id could take it back.
uid_wanted=$(id -u "$USER_NAME")
uids=$(status_field "$pid_a" Uid)
for uid_field in $uids; do
    [ "$uid_field" = "$uid_wanted" ] || fail "the daemon runs with uid $uids, not all $uid_wanted ('$USER_NAME')"
done
pass "the daemon runs as uid $uid_wanted ('$USER_NAME'): real, effective, saved and fs"

# 4. Every thread inherited the filter. This is the claim the insertion point is
# for: the filter is installed before any thread exists, so there is no
# per-thread case. A thread count of one would make this assertion vacuous.
threads=0
for task in "/proc/$pid_a/task"/*; do
    threads=$((threads + 1))
    thread_seccomp=$(sed -n 's/^Seccomp:[[:space:]]*//p' "$task/status")
    [ "$thread_seccomp" = 2 ] || fail "thread $(basename "$task") reports Seccomp: ${thread_seccomp:-<missing>}, not 2"
done
[ "$threads" -ge 3 ] || fail "the daemon has $threads thread(s); the inheritance claim needs the threads it starts after the install"
pass "all $threads threads report Seccomp: 2 — the filter was inherited, not installed per thread"

# 5. It still works while filtered.
ip route add 10.97.0.2/32 dev vallum0 || fail "cannot route the peer into vallum0"
ip route add 10.97.0.1/32 dev vallum1 || fail "cannot route the peer into vallum1"
ping -c 3 -W 1 10.97.0.2 > "$W/ping.log" 2>&1 || {
    cat "$W/ping.log" >&2
    fail "the tunnel did not carry traffic in enforce mode"
}
pass "three pings crossed the tunnel in enforce mode"
timeout 5 "$W/vallum" show --control "$W/ctl-a.sock" > /dev/null \
    || fail "the control plane did not answer in enforce mode"
pass "the control plane answered in enforce mode"

# 6. Shutdown is a normal path, not a kill: the exit status has to be 0.
kill -TERM "$pid_a"
sleep 1
kill "$pid_b" 2> /dev/null || true
wait "$pid_a" || fail "the daemon did not exit cleanly on SIGTERM (shutdown path blocked by the filter?)"
pass "SIGTERM shut the daemon down cleanly (exit 0)"
wait "$pid_b" 2> /dev/null || true

printf '== %d checks passed in enforce mode\n' "$ok"
INNER

if unshare -n true 2> /dev/null; then
    run_inner=(unshare -n bash "$W/inner.sh")
else
    echo "seccomp-enforce: cannot create a network namespace; running in this one" >&2
    run_inner=(bash "$W/inner.sh")
fi

if ! W="$W" USER_NAME="$USER_NAME" "${run_inner[@]}" 2> "$W/inner.err"; then
    echo "seccomp-enforce: the enforce-mode exercise failed" >&2
    cat "$W/inner.err" >&2
    [ -s "$W/a.log" ] && tail -5 "$W/a.log" >&2
    [ -s "$W/b.log" ] && tail -5 "$W/b.log" >&2
    KEEP=1
    exit 1
fi
