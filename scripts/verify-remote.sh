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
#   ./scripts/verify-remote.sh user@vps.example.com            # client in a remote namespace (default)
#   ./scripts/verify-remote.sh --host-direct user@vps.example.com   # client on this machine (needs local root)
#   ./scripts/verify-remote.sh --product --keep user@vps.example.com
#   ./scripts/verify-remote.sh --upgrade user@vps.example.com
#   ./scripts/verify-remote.sh --transports token user@vps.example.com
#   ./scripts/verify-remote.sh --app-class user@vps.example.com
#   ./scripts/verify-remote.sh --clean-remote user@vps.example.com
#
# **A host that already runs Vallum can run this test.** Scratch mode (the
# default) keeps its state entirely apart from a deployment: its own directory
# under /tmp, its own config, its own nftables table `inet vallumtest`, its own
# interface `vallumrc`, its own network namespace, and its own UDP port and
# subnet. What it cannot do is share a port or a tunnel subnet with the live
# deployment, so those are checked up front and the run refuses with the exact
# override if they collide:
#
#   PORT=51931 SUBNET=10.99.91.0/24 ./scripts/verify-remote.sh host
#
# At the end it asserts the live deployment is still there (/etc/vallum and
# table `inet vallum`), and revokes the stamp if it is not. Before that check
# existed, the teardown deleted /etc/vallum, /run/vallum, `inet vallum` and
# /usr/bin/vallum{,-quick} unconditionally — which is why the release gate
# needed a host of its own, and why the gate that proves the product could
# destroy it.
#
# `--product` DOES install the real thing (units, /etc/vallum, /usr/bin/…) and
# so still refuses a host that already runs Vallum. `--clean-remote` is the
# explicit override for it: it first copies the deployment — /etc/vallum,
# /var/lib/vallum and the units — with scripts/backup-deployment.sh,
# **verifies that copy**, and refuses to remove anything if it could not be
# made; then it removes that deployment (listed below) and proceeds. It removes
# *Vallum's* files, never anyone else's. The archive path is printed at the end
# and recorded in the verdict, so the restore never depends on someone having
# prepared a tarball.
#
# Two modes, by where the client half runs:
#
#   --namespaced (the default) runs the client daemon inside a network
#     namespace on the *SSH target*: a veth pair bridges the namespace to the
#     host's own routing, so the client dials the server's public endpoint the
#     same way a laptop would. Nothing on the invoking machine is touched —
#     no local TUN, no local routes, no local sudo — which is what makes this
#     a contract any contributor can reproduce against any disposable root
#     Linux host they can SSH into, rather than the maintainer's laptop.
#
#   --host-direct runs the client daemon on the invoking machine against its
#     real interfaces, which exercises a true second host but rewrites this
#     machine's routing for the run and needs local root. Keep it for a
#     release-day pass after protocol-affecting changes; never let it become
#     the only way the tree can be proved.
#
# The remote half runs as root over SSH (the invoking user's key is used),
# so the local half needs only the built binaries:
#
#   ./scripts/verify-remote.sh user@vps.example.com
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
# Everything is removed on exit, pass or fail, unless --keep is given. Use it
# when the point of the run is a deployment to dogfood rather than a gate to
# record: without it a --product run proves `server init` and then uninstalls
# what it just proved, leaving a host with no Vallum and no keys.
#
# --app-class adds the per-app launch path (ADR-0023) after the transports:
# the bundle client is rebuilt as a full tunnel, the product's own attach moves
# the device into a member namespace, and a launched member must route, resolve
# and carry traffic through the tunnel while the client keeps its own path and
# resolver. It is opt-in because it moves a device and starts a holder process
# on the target, and it needs `unshare`/`nsenter` there. Namespaced mode only.
# No cgroup, mark or nft rule is involved: the namespace is the boundary.
#
# Every namespaced run also stops the *server* once and waits it out
# (--no-outage to skip): about four minutes of wall clock, because the client's
# verdict may not be trusted as not-`up` until its last handshake is older than
# the 180 s reject window, and the recovery that follows must come without
# touching the client. That leg is the only place `always-on` is asserted on a
# real link instead of in-process.
#
# --keep skips cleanup entirely, so it keeps whatever the run left running. In
# the default scratch mode that is a test daemon still listening on the port,
# with its config in /tmp — not a deployment. The script says what it kept on
# exit; on a host that does anything else, stop it when you are done.
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
# A live deployment's masquerade table is not this script's to destroy. It is
# removed by the clean path below so the test starts from nothing, and that took
# a working full-tunnel server's NAT with it: clients stopped carrying while the
# tunnel still read `active` and handshakes still succeeded (2026-11-12). Save it
# first, restore it on the way out.
NAT_SAVE=$(mktemp -t vallum-nat.XXXXXX)
LOCAL_DIR=/tmp/vallum-remote-client
CIFACE=vallumrc0
# The remote client namespace (--namespaced) and its host-side veth.
CLI_NS=vallum-cli
CLI_VETH=vallum-cli-h
# Every client-side action happens on the target, inside the namespace.
# Arguments are joined because they are all literals this script controls.
cli_put(){ rsh "sudo ip netns exec $CLI_NS $*"; }

# Why a large download failed, from what curl actually reported.
#
# The assertion used to print "<n> of 1000000 bytes — path MTU blackhole", which
# states a cause it never measured: size_download is 0 for a refused connection,
# a silently dropped packet, an unresolvable name and a stalled TLS handshake
# alike. A run that failed on an SSH hiccup therefore read as an MTU fault, and
# the next run — identical code, same host — passed. A gate whose failure text
# names the wrong layer is worse than one that says nothing, because it sends
# the reader to the wrong file.
#
# The discriminator is curl's exit status plus the two timers:
#   time_connect 0 + no appconnect   TCP never established
#   time_connect set + no appconnect TCP is fine, TLS is not — THE blackhole shape
#   appconnect set                  TLS completed, so the fault is after it
# A timer of 0.000000 means the phase never happened; 0.041 means it took 41 ms.
# `${x%%.*}` cannot tell those apart — it reads 0.041 as "0" — so the comparison
# is numeric. (This was written the wrong way first, and the classifier then
# called a 41 ms connect "TCP never established": the same mis-attribution the
# whole change exists to remove.)
is_zero() { awk -v v="${1:-0}" 'BEGIN { exit !(v + 0 == 0) }'; }

describe_download_failure() { # $1=exit $2=size $3=connect $4=appconnect $5=http_code
    local rc=$1 size=$2 connect=$3 appconnect=$4 code=$5 what
    case "$rc" in
        255) what="the SSH transport to the target failed, so curl never ran — this is not a tunnel fault" ;;
        0)   what="curl succeeded but returned $size bytes (HTTP $code)" ;;
        6)   what="the name did not resolve inside the namespace — a DNS fault, not MTU" ;;
        7)   what="connection refused — something answered, so the path is fine" ;;
        28)  if is_zero "$connect"; then
                 what="timed out before TCP connected — packets are being dropped or the route is wrong"
             elif is_zero "$appconnect"; then
                 what="TCP connected (${connect}s) but TLS never completed — the path-MTU blackhole signature"
             else
                 what="TLS completed (${appconnect}s) and the transfer stalled — loss, not MTU"
             fi ;;
        35|60) what="TLS handshake failed (exit $rc) with TCP connected — certificate or MTU, check the pair" ;;
        *)   what="curl exited $rc" ;;
    esac
    printf '%s' "$what"
}
PRODUCT=0
KEEP=0
CLEAN=0
# Set when a live deployment is copied before being removed; the path is
# printed in the summary and recorded in the verdict, so the evidence names the
# artefact that can put the host back.
BACKUP_ARCHIVE=""
# Set when this run deleted the host's own `inet vallum` table, so the restore
# step knows whether there is anything to put back. Scratch mode never deletes
# it, and re-applying a table that still exists fails ("File exists") — which
# would have failed the run after a perfectly clean pass.
NAT_DELETED=0
# Set when the host had a live deployment at start-up; the run then asserts, at
# the end, that it still does. That assertion is the point of the whole change.
LIVE_DEPLOYMENT=0
# Prior state of the host's enrolment responder, captured before the run touches
# anything and restored in cleanup. The daemon restart in cleanup does not touch
# this separate unit, so without this a gate run could leave the live desk unable
# to accept joins (found 2026-11-20: responder down, [enroll] enabled=false).
ENROLL_WAS_ACTIVE=0
ENROLL_WAS_ENABLED=""
# Set when enrol_ssh moved a host's own /usr/bin/vallum aside; cleanup puts it
# back. Without this a gate run replaces production binaries with the tree's.
BINARY_RESTORE=0
# Set when cleanup could not restore the host's own binaries (the mv failed or the
# restored binary does not run) or its daemon did not come back. Revokes the stamp —
# a host left running the gate's build is not a verified host (premortem 2026-11-19, mode 3).
BINARY_RESTORE_FAILED=0
# Set only when this run actually installed a binary at /usr/bin/vallum. Cleanup
# removes that binary, and ONLY that one — see the note at the removal.
BINARY_INSTALLED=0
UPGRADE=0
APP_CLASS=0
# The outage leg runs once per run, not once per transport: it costs minutes and
# proves a property of the client, not of the enrolment path that produced it.
OUTAGE_DONE=0
OUTAGE=1
OUTAGE_PINGS=1300
# The protocol's own reject window, in seconds (`REJECT_AFTER_TIME_MS`). Copied
# rather than read from the crate because this script has no cargo; the daemon
# is the authority, and the leg fails loudly if the two ever disagree.
REJECT_WINDOW=180
# How long the client is given to carry again once the server has returned. It
# is one number in two places on purpose: the `VallumClientStale` alert
# (`packaging/vallum-alerts.yml`) waits exactly this long before paging, so a
# client is never paged for taking the time this gate allows it. Change both or
# neither.
RECOVERY_BUDGET=150
NAMESPACED=1
TRANSPORTS="bundle ssh token"
TARGET=""

say(){ printf '── %s\n' "$*"; }
ok(){ ASSERTIONS=$((ASSERTIONS+1)); printf '   ok    %s\n' "$*"; }
ASSERTIONS=0
fail(){ printf '   FAIL  %s\n' "$*"; }
# A failed assertion is a product claim that did not hold; a harness failure is
# the run not happening. They exit differently (1 vs 2) so the scheduled wrapper
# can alert on the first and merely note the second — an SSH timeout must never
# page as "Vallum is broken".
bad(){
    printf '   FAIL  %s\n' "$*"
    if [ "${HARNESS_FAILED:-0}" = 1 ]; then
        printf '   note  the harness could not run; this run does not speak to the tunnel\n'
        exit 2
    fi
    exit 1
}
note(){ printf '   note  %s\n' "$*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --product) PRODUCT=1 ;;
        # An upgrade is the product install plus a swap: previous release in,
        # client enrolled and proved, new binaries+units over the top, tunnel
        # proved again. Only the bundle transport runs — it is the one stable
        # across every release's CLI.
        --upgrade) UPGRADE=1; PRODUCT=1; TRANSPORTS="bundle" ;;
        --keep) KEEP=1 ;;
        # The per-app launch path (ADR-0023), on the real link: a full tunnel,
        # the product's own attach moving the device into a member namespace,
        # and one launched member that routes, resolves and carries traffic
        # through the tunnel. Off by default because it moves a device on the
        # target and starts a holder process.
        --app-class) APP_CLASS=1 ;;
        # Skip the server-outage leg: for a host whose provider rate-limits a
        # restart, or a quick pass where the recovery claim is not what changed.
        --no-outage) OUTAGE=0 ;;
        # Where the client half runs. Default is a remote namespace (no local
        # root, no local routes touched); --host-direct keeps the old behaviour
        # of installing the client on the invoking machine.
        --namespaced) NAMESPACED=1 ;;
        --host-direct) NAMESPACED=0 ;;
        --clean-remote) CLEAN=1 ;;
        --transports) shift; TRANSPORTS=$1 ;;
        --port) shift; PORT=$1 ;;
        --subnet) shift; SUBNET=$1; PREFIX=${SUBNET#*/}; NET=${SUBNET%/*}; SRV_IP="${NET%.*}.1"; CLI_IP="${NET%.*}.2" ;;
        -h|--help)
            # The header block itself: a line range here silently truncated the
            # help whenever the block grew.
            awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
            exit 0
            ;;
        -*) echo "unknown flag: $1" >&2; exit 1 ;;
        *) TARGET=$1 ;;
    esac
    shift
done
[ -n "$TARGET" ] || { echo "usage: $0 [--product] user@host" >&2; exit 1; }
# Namespaced mode touches nothing on this machine: the client daemon runs on
# the SSH target inside a network namespace, so no local TUN is needed.
# --host-direct installs the client on this machine, which needs root.
if [ "$NAMESPACED" != 1 ] && [ "$(id -u)" != 0 ]; then
    echo "run with sudo: --host-direct runs the client on this machine and needs a TUN" >&2
    exit 1
fi

# The remote half must run as the invoking user: root's SSH keys are not theirs.
# `rsh "<script>"` hands ssh a *double-quoted* string, so everything in it
# expands here before it is sent. A backtick in a remote comment is a local
# command substitution whose output becomes remote script lines — a comment
# reading `ufw allow` ran ufw on this machine and sent its usage text to the
# target's shell. No backticks inside an rsh argument: quote words with ' or ".
# One TCP connection carries every call: the run makes well over a hundred
# short SSH invocations, and the burst pattern is exactly what a remote
# rate-limiter (sshd MaxStartups, a host-side firewall, a provider edge)
# turns into intermittent "Connection timed out" mid-run. The master is
# opened once below and cleaned up in cleanup(); rsh/rscp only ride it.
SSH_MUX_DIR=$(mktemp -d -t vallum-verify-mux.XXXXXX)
SSH_MUX="$SSH_MUX_DIR/sock"
# `ServerAlive*` is the one that matters: without it a silently dead path is
# not noticed until the next write, which can be minutes later and looks like a
# hung run. `ConnectTimeout` bounds the other end of the same problem — a failed
# attempt that otherwise waits out the kernel's SYN retry budget (~2 min).
SSH_KEEP=(-o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o ConnectTimeout=10)
SSH_OPTS=(-o BatchMode=yes "${SSH_KEEP[@]}" -o "ControlPath=$SSH_MUX" -o ControlMaster=no)

# Whether the harness itself could not run, as opposed to an assertion failing.
# The distinction is the whole point of this block: a dropped SSH connection and
# a broken tunnel are unrelated failures, and a run that reports the first as
# the second sends the reader to the wrong file. `bad` exits 2 when this is set,
# and scripts/verify-scheduled.sh turns that into "the gate could not run".
HARNESS_FAILED=0

_ssh_reopen() {
    # The master is gone — a path change, a provider idle timeout, a rate
    # limiter. Re-open it rather than let every later call fall back to its own
    # connection: ssh does that silently when ControlPath points at nothing, and
    # 144 fresh handshakes is the burst that provokes the rate limiter.
    ssh_mux_close >/dev/null 2>&1
    sleep 1
    ssh_mux_open >/dev/null 2>&1
}

# Run one SSH operation, retrying once through a fresh master.
#
# Only a transport failure is retried (ssh's own 255). A remote command that
# exits nonzero is a result, not a fault — `test -e /etc/vallum` returning 1 is
# how this script asks a question — so its status is passed through untouched.
_ssh_call() { # $1 = "ssh"|"scp" (for the message), rest = argv
    shift
    local rc
    "$@" && return 0
    rc=$?
    [ "$rc" -eq 255 ] || return "$rc"
    note "transport failed (ssh exit 255); re-opening the connection and retrying once"
    _ssh_reopen
    "$@" && return 0
    rc=$?
    if [ "$rc" -eq 255 ]; then
        HARNESS_FAILED=1
        note "the SSH transport to $TARGET failed twice — this is the harness, not the tunnel"
    fi
    return "$rc"
}

if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    OWNER_HOME=$(eval echo "~$SUDO_USER")
    # The control socket lives where the invoking user can write it.
    chown "$SUDO_USER" "$SSH_MUX_DIR"
    rsh() { _ssh_call ssh sudo -u "$SUDO_USER" env HOME="$OWNER_HOME" ssh "${SSH_OPTS[@]}" "$TARGET" "$@"; }
    # `-q` was here and is gone: a copy that fails prints its reason to stderr,
    # and the reason is the whole diagnostic. A run that died on
    # `bad "scp laptop-bundle.key"` left nothing behind to explain it — no ssh
    # error, no exit status — so the only conclusion available was a guess.
    rscp() { _ssh_call scp sudo -u "$SUDO_USER" env HOME="$OWNER_HOME" scp "${SSH_KEEP[@]}" -o "ControlPath=$SSH_MUX" -o ControlMaster=no "$@"; }
else
    rsh() { _ssh_call ssh ssh "${SSH_OPTS[@]}" "$TARGET" "$@"; }
    rscp() { _ssh_call scp scp "${SSH_KEEP[@]}" -o "ControlPath=$SSH_MUX" -o ControlMaster=no "$@"; }
fi

# The persistent connection all rsh/rscp calls multiplex onto. Opened after
# the sudo check proves the keys work; ControlPersist keeps it warm through
# the quiet stretches so the outage leg never pays a reconnect.
ssh_mux_open() {
    local -a open_opts=(-o BatchMode=yes "${SSH_KEEP[@]}" -o ControlMaster=yes
        -o "ControlPath=$SSH_MUX" -o ControlPersist=yes -MNf)
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
        sudo -u "$SUDO_USER" env HOME="$OWNER_HOME" ssh "${open_opts[@]}" "$TARGET"
    else
        ssh "${open_opts[@]}" "$TARGET"
    fi
}

ssh_mux_close() {
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
        sudo -u "$SUDO_USER" env HOME="$OWNER_HOME" \
            ssh -o "ControlPath=$SSH_MUX" -O exit "$TARGET" >/dev/null 2>&1
    else
        ssh -o "ControlPath=$SSH_MUX" -O exit "$TARGET" >/dev/null 2>&1
    fi
    rm -rf "$SSH_MUX_DIR"
}

CLIENT_PID=""
REMOTE_STARTED=0
FORWARD_WAS=""
# How the server half is stopped and started again for the outage leg: the unit
# in --product mode, the process in scratch mode. One of the two is set by the
# server setup below; `server_stop`/`server_start` pick by $PRODUCT.
SERVER_UNIT=""
SERVER_PATTERN=""

NAT_RESTORE_FAILED=0
restore_nat() {
    [ "$NAT_DELETED" = 1 ] || return 0
    [ -s "$NAT_SAVE" ] || return 0
    if rsh "sudo nft -f -" <"$NAT_SAVE" >/dev/null 2>&1; then
        ok "the host's own \`inet vallum\` NAT table was restored"
        return 0
    fi
    # A silent failure here was the worst of it: the run still reported PASS
    # and still stamped the commit as verified, with the host's NAT gone.
    fail "the host's \`inet vallum\` NAT table could NOT be restored from $NAT_SAVE"
    fail "   the host's tunnel egress is broken until that table is put back:"
    fail "   sudo nft -f $NAT_SAVE"
    NAT_RESTORE_FAILED=1
    return 1
}

# Where the 'this commit passed the two-host gate' stamp lives.
verified_stamp() {
    if [ -n "${SUDO_USER:-}" ]; then
        printf '%s/vallum/remote-verified' \
            "$(sudo -u "$SUDO_USER" sh -c 'printf %s "${XDG_STATE_HOME:-$HOME/.local/state}"')"
    else
        printf '%s/vallum/remote-verified' "${XDG_STATE_HOME:-$HOME/.local/state}"
    fi
}

cleanup() {
    set +e
    say "cleanup"
    [ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null
    [ -f "$LOCAL_DIR/client.toml" ] && "$QUICK" detach "$LOCAL_DIR/client.toml" >/dev/null 2>&1
    if [ "$REMOTE_STARTED" = 1 ]; then
        # The teardown removes what THIS RUN created, not every Vallum artefact
        # on the machine. It used to delete /etc/vallum, /run/vallum, table
        # `inet vallum` and /usr/bin/vallum{,-quick} unconditionally — which is
        # why the script had to refuse any host that already ran Vallum, and why
        # the release gate needed a second host of its own. Scratch mode installs
        # none of those: it runs from $REMOTE_DIR with `--no-host --no-service`,
        # its own config, its own table `inet vallumtest` and its own interface
        # `vallumrc`. So on a host with a live deployment, an unconditional
        # teardown is the whole problem, not a safety measure.
        if [ "$PRODUCT" = 1 ]; then
            # --product / --upgrade DID install the real thing: units, /etc/vallum,
            # /usr/bin/vallum{,-quick}, the live firewall state. Same teardown.
            rsh "set +e
                sudo pkill -f '^$REMOTE_DIR/vallum run' 2>/dev/null
                sudo pkill -f '^$REMOTE_DIR/vallum enroll-serve' 2>/dev/null
                sudo systemctl disable --now vallum-enroll@vallumrc >/dev/null 2>&1
                sudo systemctl disable --now vallum-quick@vallumrc vallum@vallumrc >/dev/null 2>&1
                sudo rm -f /etc/systemd/system/vallum@.service /etc/systemd/system/vallum-quick@.service \
                           /etc/systemd/system/vallum-quick-watch@.service \
                           /etc/systemd/system/vallum-enroll@.service
                sudo systemctl daemon-reload >/dev/null 2>&1
                sudo rm -rf /etc/vallum /run/vallum /etc/sysctl.d/90-vallum.conf
                sudo ufw delete allow $PORT/udp >/dev/null 2>&1
                sudo ufw delete allow $((PORT+1))/udp >/dev/null 2>&1
                sudo iptables -D FORWARD -i vallumrc -j ACCEPT 2>/dev/null
                sudo iptables -D FORWARD -o vallumrc -j ACCEPT 2>/dev/null
                sudo iptables -D INPUT -p udp --dport $PORT -j ACCEPT 2>/dev/null
                sudo nft delete table inet vallum 2>/dev/null
                sudo nft delete table inet vallumtest 2>/dev/null
                sudo rm -f /usr/bin/vallum /usr/bin/vallum-quick
                sudo rm -rf $REMOTE_DIR
                # The client namespace (--namespaced) and its veth. The veth is
                # deleted by name on the host first: deleting the namespace alone
                # would orphan the host-side peer.
                sudo ip netns pids $CLI_NS 2>/dev/null | xargs -r kill 2>/dev/null
                sudo ip netns del $CLI_NS 2>/dev/null
                sudo ip link del $CLI_VETH 2>/dev/null" >/dev/null 2>&1
        else
            # Scratch mode. Only what this run made: the test table, the test
            # daemon and its directory, the interface it created, the port rule
            # it added, and the namespace. `/etc/vallum`, `/run/vallum`,
            # `inet vallum` and `/usr/bin/vallum*` belong to whoever was here
            # first and are not this script's to remove.
            rsh "set +e
                sudo pkill -f '^$REMOTE_DIR/vallum run' 2>/dev/null
                sudo pkill -f '^$REMOTE_DIR/vallum enroll-serve' 2>/dev/null
                sudo ufw delete allow $PORT/udp >/dev/null 2>&1
                sudo ufw delete allow $((PORT+1))/udp >/dev/null 2>&1
                # One rule per interface family this run could have added; -D
                # removes a single matching rule and fails harmlessly if absent.
                sudo iptables -D FORWARD -i vallumrc -j ACCEPT 2>/dev/null
                sudo iptables -D FORWARD -o vallumrc -j ACCEPT 2>/dev/null
                sudo iptables -D INPUT -p udp --dport $PORT -j ACCEPT 2>/dev/null
                sudo nft delete table inet vallumtest 2>/dev/null
                sudo ip netns pids $CLI_NS 2>/dev/null | xargs -r kill 2>/dev/null
                sudo ip netns del $CLI_NS 2>/dev/null
                sudo ip link del $CLI_VETH 2>/dev/null
                sudo rm -rf $REMOTE_DIR" >/dev/null 2>&1
            # The scratch daemon creates interface `vallumrc`; the live
            # deployment's is a different name, and this only removes the one
            # this run made.
            rsh "sudo ip link del vallumrc 2>/dev/null" >/dev/null 2>&1
            # Put the host's own binaries back, and remove a test build ONLY if
            # this run is what put it there.
            #
            # This deleted /usr/bin/vallum and vallum-quick unconditionally, and
            # on 2026-11-17 that took a live server's binaries away: the run
            # failed at the bundle transport *before* enrol_ssh, so nothing had
            # been installed, BINARY_RESTORE was never set — and cleanup removed
            # the deployment's binaries anyway. `vallum@` then failed to start,
            # because its ExecStart is that path. Two independent guards now, and
            # both are needed: one restores what was moved aside, the other
            # refuses to delete what was never installed.
            if [ "$BINARY_RESTORE" = 1 ]; then
                # Verify the restore, don't assume it: the mv must succeed AND the
                # restored binary must run. Copying files back is not restoring a
                # service (premortem 2026-11-19, mode 3) — the old `set +e; mv -f`
                # discarded errors under an unconditional "restored" note, so a failed
                # restore left the host on the gate's build, stamped PASS.
                if rsh "sudo mv -f /usr/bin/vallum.pre-verify-remote /usr/bin/vallum && \
                        sudo mv -f /usr/bin/vallum-quick.pre-verify-remote /usr/bin/vallum-quick && \
                        /usr/bin/vallum --version >/dev/null 2>&1"; then
                    ok "restored the host's own /usr/bin/vallum{,-quick} — the restored binary runs"
                    # The running daemon still holds the gate's build in memory until it
                    # restarts; load the restored production binary and prove it is up.
                    if [ "$LIVE_DEPLOYMENT" = 1 ]; then
                        if rsh "sudo systemctl restart vallum@vallum0 && sleep 3 && systemctl is-active vallum@vallum0 >/dev/null 2>&1"; then
                            ok "the host's daemon is active on the restored binary"
                        else
                            BINARY_RESTORE_FAILED=1
                            fail "the host's daemon did not come back active on the restored binary"
                        fi
                    fi
                else
                    BINARY_RESTORE_FAILED=1
                    fail "the host's own /usr/bin/vallum{,-quick} could NOT be restored — the host may run the gate's build or none"
                fi
            elif [ "$BINARY_INSTALLED" = 1 ]; then
                rsh "sudo rm -f /usr/bin/vallum /usr/bin/vallum-quick" >/dev/null 2>&1
            else
                note "left /usr/bin/vallum{,-quick} alone — this run installed neither"
            fi
        fi
        # The enrolment responder is a separate unit the daemon restart above does
        # not touch. Restore it to its captured prior state so a gate run never
        # leaves the live desk unable to accept joins.
        if [ "$LIVE_DEPLOYMENT" = 1 ]; then
            enroll_now=$(rsh "sudo sed -n '/^\[enroll\]/,/^\[/p' /etc/vallum/vallum0.toml | sed -n 's/^enabled *= *//p' | head -1" 2>/dev/null | tr -d '[:space:]')
            if [ -n "$ENROLL_WAS_ENABLED" ] && [ "$ENROLL_WAS_ENABLED" != "$enroll_now" ]; then
                rsh "sudo sed -i '/^\[enroll\]/,/^\[/s/^enabled *= *.*/enabled = $ENROLL_WAS_ENABLED/' /etc/vallum/vallum0.toml" >/dev/null 2>&1
                note "restored [enroll] enabled=$ENROLL_WAS_ENABLED in the host's config"
            fi
            if [ "$ENROLL_WAS_ACTIVE" = 1 ]; then
                if rsh "sudo systemctl reset-failed vallum-enroll@vallum0 2>/dev/null; sudo systemctl start vallum-enroll@vallum0 && sleep 1 && systemctl is-active vallum-enroll@vallum0 >/dev/null 2>&1"; then
                    ok "the host's enrolment responder is active again (prior state restored)"
                else
                    fail "the host's enrolment responder did not come back — re-arm: sudo vallum server enroll --enable --config /etc/vallum/vallum0.toml && sudo systemctl start vallum-enroll@vallum0"
                fi
            fi
        fi
        if [ -n "$FORWARD_WAS" ]; then
            rsh "sudo sysctl -q -w net.ipv4.ip_forward=$FORWARD_WAS" >/dev/null 2>&1
        fi
    fi
    rm -rf "$LOCAL_DIR"
    # LAST, after every `nft delete` above has run. Restoring first — as this
    # did — put the table back and then deleted it again, so the fix was a no-op
    # that read like a fix (found by the premortem, 2026-11-12).
    restore_nat
    # The host had a deployment when this run started and was not asked to
    # remove it: prove it is still there. Asserted rather than assumed because
    # the whole reason scratch mode used to need a dedicated host was a teardown
    # that took production with it, and a future edit could put that back
    # silently. This check is what makes the regression loud.
    if [ "$LIVE_DEPLOYMENT" = 1 ] && [ "$PRODUCT" != 1 ]; then
        if rsh "test -e /etc/vallum && sudo nft list table inet vallum >/dev/null 2>&1"; then
            ok "the host's live deployment is intact (/etc/vallum and table inet vallum)"
        else
            rm -f "$(verified_stamp)" 2>/dev/null
            fail "the host's live deployment is GONE — this run destroyed a deployment it was not asked to touch"
            fail "   restore it: the archive from backup-deployment.sh, or /root on $TARGET"
            exit 1
        fi
    fi
    if [ "$NAT_RESTORE_FAILED" = 1 ]; then
        # The stamp says this commit passed the gate. If the host was left
        # broken, that stamp is a lie - revoke it and fail the run.
        rm -f "$(verified_stamp)" 2>/dev/null
        fail "the commit was NOT recorded as verified: the host was left unrestored"
        exit 1
    fi
    if [ "$BINARY_RESTORE_FAILED" = 1 ]; then
        # Same lie, different artefact: the host's binaries or daemon were left
        # unrestored, so the stamp must not vouch for this commit (mode 3).
        rm -f "$(verified_stamp)" 2>/dev/null
        fail "the commit was NOT recorded as verified: the host's binaries/daemon were left unrestored"
        fail "   restore /usr/bin/vallum{,-quick} from the .pre-verify-remote backups or backup-deployment.sh on $TARGET"
        exit 1
    fi
    ssh_mux_close
    ok "both ends restored"
}
kept() {
    ssh_mux_close
    say "kept (--keep) — nothing was cleaned up"
    echo "   remote daemon   $TARGET, UDP $PORT, config $REMOTE_DIR/server.toml"
    echo "   remote files    $REMOTE_DIR and /usr/bin/vallum{,-quick}"
    echo "   stop it         ssh $TARGET \"sudo pkill -f '^$REMOTE_DIR/vallum run'\""
    echo "   local client    $LOCAL_DIR"
    echo "   remote client   still inside ns $CLI_NS — ssh $TARGET \"sudo ip netns del $CLI_NS; sudo ip link del $CLI_VETH\" when done"
}
[ "$KEEP" = 1 ] && trap kept EXIT || trap cleanup EXIT

[ -x "$VALLUM" ] || bad "build first: cargo build --release -p vallum -p vallum-quick"
# Absolute, because the client half runs with a working directory of its own.
VALLUM=$(cd "$(dirname "$VALLUM")" && pwd)/$(basename "$VALLUM")
QUICK=$(cd "$(dirname "$QUICK")" && pwd)/$(basename "$QUICK")

say "remote checks ($TARGET)"
# The multiplexed control connection — one handshake for the whole run,
# so the hundred-plus rsh calls below never trip a remote rate limit.
ssh_mux_open || { HARNESS_FAILED=1; bad "cannot open an SSH control connection to $TARGET — the harness could not run"; }
rsh "sudo -n true" 2>/dev/null || bad "the remote user needs passwordless sudo"
# The difference between "the host has no such table" and "we could not read it"
# matters: the cleanup deletes `inet vallum`, so a table we failed to save is a
# table we destroy and cannot put back - and the restore, seeing an empty save
# file, would report success. So the second case refuses to run at all.
if rsh "sudo nft list table inet vallum" >"$NAT_SAVE" 2>/dev/null; then
    note "saved the host's existing \`inet vallum\` table to restore after the run"
elif rsh "sudo nft list tables inet 2>/dev/null | grep -q '^inet vallum$'"; then
    fail "the host HAS an \`inet vallum\` table but it could not be read"
    fail "   refusing to run: the cleanup would delete a table we cannot restore"
    exit 1
else
    note "the host has no \`inet vallum\` table to preserve"
fi
if rsh "test -e /etc/vallum" 2>/dev/null; then
    LIVE_DEPLOYMENT=1
    # Capture the production responder's prior state so cleanup can restore it.
    if rsh "systemctl is-active vallum-enroll@vallum0 >/dev/null 2>&1"; then
        ENROLL_WAS_ACTIVE=1
    fi
    ENROLL_WAS_ENABLED=$(rsh "sudo sed -n '/^\[enroll\]/,/^\[/p' /etc/vallum/vallum0.toml | sed -n 's/^enabled *= *//p' | head -1" 2>/dev/null | tr -d '[:space:]')
    if [ "$CLEAN" != 1 ] && [ "$PRODUCT" = 1 ]; then
        # --product installs the real thing over /etc/vallum and the real units,
        # so on a host that already has a deployment it would overwrite one.
        bad "/etc/vallum already exists on the remote and --product would install over it.
   Re-run with --clean-remote to remove the existing deployment first, or pick a
   host with no Vallum."
    fi
    if [ "$CLEAN" != 1 ]; then
        # Scratch mode touches none of the existing deployment's state: its own
        # directory, its own config, its own table `inet vallumtest`, its own
        # interface `vallumrc`, its own namespace. What it CAN collide with is
        # the host's UDP port and tunnel subnet, and that collision would be
        # silent — two daemons on one port, or two interfaces claiming one /24 —
        # so it is checked here rather than discovered as a mystery handshake
        # failure later.
        live=$(rsh "sudo cat /etc/vallum/*.toml 2>/dev/null \
            | sed -n -e 's/^[[:space:]]*listen[[:space:]]*=[[:space:]]*\"[^\"]*:\([0-9]*\)\"/port \1/p' \
                     -e 's/^[[:space:]]*address[[:space:]]*=[[:space:]]*\"\([0-9.]*\)\/[0-9]*\"/addr \1/p'" 2>/dev/null)
        live_port=$(printf '%s\n' "$live" | sed -n 's/^port \(.*\)/\1/p' | sort -u)
        live_addr=$(printf '%s\n' "$live" | sed -n 's/^addr \(.*\)/\1/p' | sort -u)
        live_prefix=${SUBNET%.*.*}
        for p in $live_port; do
            [ "$p" = "$PORT" ] || continue
            bad "the host already listens on UDP $PORT (an existing deployment's config).
   Scratch mode would bind the same port. Pick another:
     PORT=$((PORT + 10)) SUBNET=10.99.91.0/24 $0 $TARGET"
        done
        for a in $live_addr; do
            case "$a" in
                "$live_prefix".*) : ;;
                *) continue ;;
            esac
            bad "the host already uses the subnet $SUBNET (an existing deployment's config).
   Two daemons on one /24 would route each other's addresses. Pick another:
     SUBNET=10.99.91.0/24 $0 $TARGET"
        done
        note "the host has a live deployment; scratch mode leaves it alone"
        note "   its state:  /etc/vallum, /run/vallum, table inet vallum, /usr/bin/vallum*"
        note "   this run:   $REMOTE_DIR, table inet vallumtest, iface vallumrc, UDP $PORT, $SUBNET"
    fi
fi
# Only --clean-remote removes a deployment. Scratch mode above proved it can run
# beside one; this branch is the destructive one and it is opt-in.
if [ "$CLEAN" = 1 ] && rsh "test -e /etc/vallum" 2>/dev/null; then
    # The restore used to be a tarball built by hand from a paragraph in a
    # document — so the gate that proves the product could destroy it whenever
    # nobody read that far. It is now the script's own first step, and a failure
    # here refuses the run before anything is touched.
    say "copying the existing deployment before removing it"
    rsh "sudo tee /root/vallum-backup-deployment.sh >/dev/null" < "$(dirname "$0")/backup-deployment.sh" \
        || bad "could not place scripts/backup-deployment.sh on $TARGET"
    rsh "sudo chmod 700 /root/vallum-backup-deployment.sh" || bad "could not make the backup script executable"
    backup_out=$(rsh "sudo /root/vallum-backup-deployment.sh --label pre-verify-remote") \
        || bad "the pre-run backup failed — refusing to delete a deployment that could not be copied.
   Nothing has been removed. The backup script's own message says what it could not verify."
    printf '%s\n' "$backup_out" | sed 's/^/   /'
    BACKUP_ARCHIVE=$(printf '%s\n' "$backup_out" | sed -n 's/^backup-deployment: \([^ ]*\) (.*/\1/p' | head -1)
    [ -n "$BACKUP_ARCHIVE" ] || bad "the backup reported success but did not name an archive"
    ok "deployment copied to $BACKUP_ARCHIVE"

    say "removing the existing deployment (--clean-remote)"
    echo "   units:      vallum@*, vallum-quick@*, vallum-enroll@*"
    echo "   files:      /etc/vallum, /etc/sysctl.d/90-vallum.conf, /usr/bin/vallum{,-quick}"
    echo "   firewall:   the UDP port rule, the vallum FORWARD rules, table inet vallum"
    rsh "set +e
        sudo systemctl stop 'vallum@*' 'vallum-quick@*' 'vallum-enroll@*' >/dev/null 2>&1
        sudo rm -rf /etc/systemd/system/multi-user.target.wants/vallum*@*
        sudo rm -f /etc/systemd/system/vallum@.service /etc/systemd/system/vallum-quick@.service \
                   /etc/systemd/system/vallum-quick-watch@.service \
                   /etc/systemd/system/vallum-enroll@.service
        sudo systemctl daemon-reload >/dev/null 2>&1
        sudo rm -rf /etc/vallum /run/vallum /etc/sysctl.d/90-vallum.conf
        sudo ufw delete allow $PORT/udp >/dev/null 2>&1
        sudo nft delete table inet vallum >/dev/null 2>&1
        sudo rm -f /usr/bin/vallum /usr/bin/vallum-quick" >/dev/null 2>&1
    NAT_DELETED=1
    rsh "test ! -e /etc/vallum" || bad "could not remove the existing deployment"
    ok "existing deployment removed"
fi
# The old single block ended here; the `fi` above closes the --clean-remote
# branch, and the block it replaced closed the outer `/etc/vallum` test.
FORWARD_WAS=$(rsh "cat /proc/sys/net/ipv4/ip_forward" 2>/dev/null | tr -d '[:space:]')
[ -n "$FORWARD_WAS" ] || bad "cannot read the remote's ip_forward"
if [ "$LIVE_DEPLOYMENT" = 1 ] && [ "$CLEAN" != 1 ]; then
    ok "passwordless sudo, ip_forward=$FORWARD_WAS, running beside the host's live deployment"
else
    ok "passwordless sudo, no existing deployment, ip_forward=$FORWARD_WAS"
fi

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
rsh "sudo rm -rf $REMOTE_DIR && mkdir -p $REMOTE_DIR" || bad "mkdir on the remote"
rscp "$VALLUM" "$QUICK" "$TARGET:$REMOTE_DIR/" || bad "scp"
ok "binaries on the remote"

if [ "$NAMESPACED" = 1 ]; then
    say "client namespace on the target (nothing changes on this machine)"
    # A stale namespace from a previous killed run would poison every later
    # `ip netns exec`, so remove it first — its veth is deleted with it.
    rsh "sudo ip netns del $CLI_NS 2>/dev/null; sudo ip link del $CLI_VETH 2>/dev/null; true"
    rsh "sudo ip netns add $CLI_NS" || bad "cannot create netns $CLI_NS on the target"
    rsh "set -e
         sudo ip link add $CLI_VETH type veth peer name vallum-cli-n
         sudo ip link set vallum-cli-n netns $CLI_NS
         sudo ip addr add 10.99.91.1/24 dev $CLI_VETH
         sudo ip link set $CLI_VETH up
         sudo ip netns exec $CLI_NS ip link set lo up
         sudo ip netns exec $CLI_NS ip link set vallum-cli-n up
         sudo ip netns exec $CLI_NS ip addr add 10.99.91.2/24 dev vallum-cli-n
         sudo ip netns exec $CLI_NS ip route add default via 10.99.91.1" \
        || bad "the veth bridge into $CLI_NS did not come up"
    # Prove the namespace can reach the host's public endpoint before anything
    # depends on it: a veth misconfigured here would surface as 'no handshake'
    # minutes from now, pointing at the tunnel instead of the bridge.
    rsh "sudo ip netns exec $CLI_NS ping -c1 -W2 $PUBLIC" >/dev/null 2>&1 \
        || bad "$CLI_NS cannot reach $PUBLIC — the veth bridge is wrong"
    ok "$CLI_NS bridges to the host and can reach $PUBLIC:$PORT"
fi

REMOTE_STARTED=1

if [ "$UPGRADE" = 1 ]; then
    # Install the previous *release* first: the point of this mode is that a
    # daemon written by an older tree must be upgraded by this one, with the
    # config and peers it wrote still valid.
    say "installing the previous release on the remote"
    # This script runs as root for the local TUN, but `gh` credentials live
    # with the invoking user — run it as them, which also makes drafts
    # (which have assets but no public API entry) usable as the base. Fall
    # back to the public API when gh is absent or unauthenticated.
    gh_as_user() {
        if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
            sudo -u "$SUDO_USER" gh "$@"
        else
            gh "$@"
        fi
    }
    prev=""
    if command -v gh >/dev/null 2>&1 && gh_as_user auth status >/dev/null 2>&1; then
        prev=$(gh_as_user release list --repo KidIkaros/vallum --limit 20 \
            --json tagName --jq '.[0].tagName' 2>/dev/null)
    fi
    if [ -z "$prev" ]; then
        prev=$(curl -fsSL "https://api.github.com/repos/KidIkaros/vallum/releases" 2>/dev/null \
            | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
    fi
    [ -n "$prev" ] || bad "cannot list releases — no published releases, and gh is not authenticated"
    asset="vallum-$prev-x86_64-linux.tar.gz"
    mkdir -p "$LOCAL_DIR"
    # gh runs as the invoking user, so the download dir must be writable by
    # them — the script itself is root and `mkdir` made it root's.
    chown "${SUDO_USER:-root}" "$LOCAL_DIR" 2>/dev/null || true
    if ! curl -fsSL "https://github.com/KidIkaros/vallum/releases/download/$prev/$asset" \
        -o "$LOCAL_DIR/$asset" 2>/dev/null; then
        # A draft has no public download URL; gh reaches it with auth.
        gh_as_user release download "$prev" --repo KidIkaros/vallum \
            --pattern "$asset" --dir "$LOCAL_DIR" --clobber \
            || bad "cannot download $prev"
    fi
    rscp "$LOCAL_DIR/$asset" "$TARGET:$REMOTE_DIR/" || bad "scp previous release"
    rsh "cd $REMOTE_DIR && tar -xzf $asset && \
         sudo install -m0755 vallum-$prev-x86_64-linux/vallum /usr/bin/vallum && \
         sudo install -m0755 vallum-$prev-x86_64-linux/vallum-quick /usr/bin/vallum-quick && \
         for u in vallum@.service vallum-quick@.service vallum-enroll@.service; do \
             sudo install -m0644 vallum-$prev-x86_64-linux/\$u /etc/systemd/system/\$u; \
         done && sudo systemctl daemon-reload" || bad "install previous release"
    ok "previous release $prev installed"
    rscp packaging/vallum@.service packaging/vallum-quick@.service \
        packaging/vallum-quick-watch@.service \
        packaging/vallum-enroll@.service "$TARGET:$REMOTE_DIR/" || bad "scp new units"
fi

if [ "$PRODUCT" = 1 ]; then
    say "server init, every host step on (--product)"
    if [ "$UPGRADE" = 1 ]; then
        rsh "sudo /usr/bin/vallum server init --config /etc/vallum/vallumrc.toml --name vallumrc \
             --address $SRV_IP/$PREFIX --listen 0.0.0.0:$PORT --endpoint $PUBLIC" \
            | tail -6 || bad "server init (previous release)"
    else
        rsh "sudo install -m0755 $REMOTE_DIR/vallum /usr/bin/vallum && \
         sudo install -m0755 $REMOTE_DIR/vallum-quick /usr/bin/vallum-quick && \
         sudo /usr/bin/vallum server init --config /etc/vallum/vallumrc.toml --name vallumrc \
              --address $SRV_IP/$PREFIX --listen 0.0.0.0:$PORT --endpoint $PUBLIC" \
            | tail -6 || bad "server init"
    fi
    for unit in vallum@vallumrc vallum-quick@vallumrc; do
        rsh "systemctl is-active $unit" | grep -q '^active$' || bad "$unit is not active"
    done
    ok "both units active"
    SERVER_CMD="sudo /usr/bin/vallum"
    CONFIG=/etc/vallum/vallumrc.toml
    SERVER_UNIT=vallum@vallumrc
else
    say "scratch server (no systemd, no /etc)"
    rsh "sudo $REMOTE_DIR/vallum server init --config $REMOTE_DIR/server.toml --name vallumrc \
            --no-host --no-service --address $SRV_IP/$PREFIX --listen 0.0.0.0:$PORT \
            --endpoint $PUBLIC --control $REMOTE_DIR/server.sock" >/dev/null || bad "server init"
    # Every host step fails loudly. These were once run with 2>/dev/null and a
    # final `sleep 2`, so one killed step — the masquerade rule, say — still
    # printed `ok`, and the lost symptom showed up minutes later as a
    # 100%-loss egress ping that points at the wrong layer.
    rsh "set -e
         sudo nft delete table inet vallumtest 2>/dev/null || true
         sudo sysctl -q -w net.ipv4.ip_forward=1
         # Only an *active* ufw filters anything, and only then is an allow rule
         # needed. A host with ufw installed but inactive (the default on many
         # images) made 'ufw allow' fail — 'ERROR: Invalid syntax' — and took the
         # whole setup down over a rule that would have changed nothing. The
         # check is the status line, not the binary's presence.
         if sudo ufw status 2>/dev/null | grep -q '^Status: active'; then
             sudo ufw allow $PORT/udp >/dev/null
         else
             echo 'note: ufw is not active on the target; no allow rule is needed'
         fi
         # Forwarding acceptance is not optional. ufw's before-forward chain
         # accepts ICMP echo, so a tunnel with no FORWARD rule pings happily
         # and drops every TCP and UDP packet — the trap in
         # docs/deployment/troubleshooting.md, found here the first time this
         # script ran a DNS query through the tunnel.
         sudo iptables -I FORWARD 1 -i vallumrc -j ACCEPT
         sudo iptables -I FORWARD 1 -o vallumrc -j ACCEPT
         sudo nft add table inet vallumtest
         sudo nft 'add chain inet vallumtest postrouting { type nat hook postrouting priority srcnat; }'
         sudo nft add rule inet vallumtest postrouting ip saddr $SUBNET masquerade
         sudo nohup $REMOTE_DIR/vallum run --config $REMOTE_DIR/server.toml > $REMOTE_DIR/server.log 2>&1 &
         sleep 2" || bad "remote host setup"
    # Assert the forwarding plane took the state, not just that no step
    # reported an error: a masquerade table with zero rules or an nft binary
    # that silently dropped the rule would pass the block above.
    rsh "sudo nft list table inet vallumtest | grep -q masquerade &&
         sudo iptables -C FORWARD -i vallumrc -j ACCEPT &&
         sudo iptables -C FORWARD -o vallumrc -j ACCEPT" \
        || bad "the forwarding-plane rules did not take"
    rsh "test -S $REMOTE_DIR/server.sock" || { rsh "sudo tail -5 $REMOTE_DIR/server.log"; bad "the remote daemon did not start"; }
    ok "forwarding, NAT, one UDP port, daemon up"
    SERVER_CMD="sudo $REMOTE_DIR/vallum"
    CONFIG=$REMOTE_DIR/server.toml
    # The config, not just the binary: the client daemon is started from the
    # same directory and its command line begins identically, so `^<dir>/vallum
    # run` stopped both. The outage leg measured a client that had been killed
    # along with its server, and the verdict read `down` for the wrong reason.
    SERVER_PATTERN="^$REMOTE_DIR/vallum run --config $REMOTE_DIR/server.toml"
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
    # No --endpoint here: this is the SERVER-side peer entry, whose connect
    # address must be learned from datagrams, like any responder side. The
    # server's own public_endpoint only names where the CLIENT dials (it is
    # baked into the bundle below); passing it as the peer's endpoint made
    # rotation's passive re-initiation dial the server itself.
    rsh "$SERVER_CMD peer add $name --config $CONFIG \
            --ship-key --bundle-out $REMOTE_DIR/$name.bundle" >/dev/null || bad "peer add ($name)"
    rsh "sudo chmod 644 $REMOTE_DIR/$name.bundle" || bad "chmod bundle"
    rscp "$TARGET:$REMOTE_DIR/$name.bundle" "$dir/$name.vallum-bundle" || bad "fetch bundle"
    # A shipped-key bundle is refused by default (ADR: the key existed on
    # another machine first, so the file's holder holds the key). Pin the
    # refusal, then import with the explicit override.
    if "$VALLUM" import-bundle "$dir/$name.vallum-bundle" --output-dir "$dir" >/dev/null 2>&1; then
        bad "import-bundle: a shipped-key bundle was accepted WITHOUT --allow-shipped-key"
    else
        ok "import-bundle refuses a shipped-key bundle by default"
    fi
    "$VALLUM" import-bundle "$dir/$name.vallum-bundle" --output-dir "$dir" \
        --allow-shipped-key >/dev/null || bad "import-bundle (--allow-shipped-key)"
}

enrol_ssh() {
    local name=$1 dir=$2
    # `setup --remote` runs `sudo vallum peer enroll` over there, so the binary
    # must be installed.
    #
    # On a host that already has a deployment this installs OVER production
    # binaries — a gate run would leave the tree's build at /usr/bin/vallum,
    # which the next `systemctl restart` would then run. So an existing binary is
    # moved aside first and put back by cleanup, and the run says so. Scratch
    # mode used to delete /usr/bin/vallum outright on the way out, which was
    # worse in a different direction (it removed a deployment's binary); this is
    # the version that neither keeps nor destroys what was there.
    if [ "$PRODUCT" != 1 ]; then
        if rsh "sudo test -e /usr/bin/vallum" 2>/dev/null; then
            # A leftover .pre-verify-remote means a previous run was interrupted before
            # it restored: /usr/bin/vallum may be that run's gate build, not production.
            # Copying it aside as "production" would launder the gate's binary into the
            # backup (premortem 2026-11-19, mode 3). Refuse instead of poisoning it.
            if rsh "sudo test -e /usr/bin/vallum.pre-verify-remote" 2>/dev/null; then
                bad "a previous verify-remote run left /usr/bin/vallum.pre-verify-remote on $TARGET — the host may run that run's gate build; restore /usr/bin/vallum{,-quick} from those backups manually, then re-run"
            fi
            rsh "sudo cp -p /usr/bin/vallum /usr/bin/vallum.pre-verify-remote \
                 && sudo cp -p /usr/bin/vallum-quick /usr/bin/vallum-quick.pre-verify-remote" 2>/dev/null \
                || bad "could not set the host's own binaries aside"
            BINARY_RESTORE=1
            note "the host already has /usr/bin/vallum — set aside, restored by cleanup"
        fi
        rsh "sudo install -m0755 $REMOTE_DIR/vallum /usr/bin/vallum" || bad "install vallum on the remote"
        BINARY_INSTALLED=1
        note "installed vallum to /usr/bin on the remote for the ssh transport"
    fi
    as_owner "$dir" "$VALLUM setup --remote $TARGET --remote-config $CONFIG --name $name" > "$dir/setup.log" 2>&1 \
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
# A client config from any transport, proved in whichever mode the run uses:
# prove_client_ns consumes the config on the SSH target inside $CLI_NS;
# prove_client_host consumes it on this machine. What they prove is the same
# set of assertions; only the address space differs.
prove_client() {
    if [ "$NAMESPACED" = 1 ]; then prove_client_ns "$@"; else prove_client_host "$@"; fi
}

# ── stopping and starting the server ─────────────────────────────────────
# By unit in --product mode, by process in scratch mode. `stop` rather than
# kill in the product case on purpose: the shipped unit is `Restart=always`, so
# a killed process would come straight back and there would be no outage.
server_stop() {
    if [ "$PRODUCT" = 1 ]; then
        rsh "sudo systemctl stop $SERVER_UNIT" || return 1
        for _ in $(seq 1 20); do
            rsh "sudo systemctl is-active $SERVER_UNIT" 2>/dev/null | grep -q '^inactive$' && return 0
            sleep 0.5
        done
        return 1
    fi
    rsh "sudo pkill -f '$SERVER_PATTERN'" || return 1
    # The process, not the socket: a killed daemon can leave its socket file
    # behind, and waiting on the file would report a stop that did not happen.
    for _ in $(seq 1 20); do
        rsh "sudo pgrep -f '$SERVER_PATTERN' >/dev/null" 2>/dev/null || return 0
        sleep 0.5
    done
    return 1
}

server_start() {
    if [ "$PRODUCT" = 1 ]; then
        rsh "sudo systemctl start $SERVER_UNIT" || return 1
        for _ in $(seq 1 30); do
            rsh "sudo test -S /run/vallum/vallumrc.sock" 2>/dev/null && return 0
            sleep 0.5
        done
        return 1
    fi
    rsh "sudo nohup $REMOTE_DIR/vallum run --config $REMOTE_DIR/server.toml \
         >> $REMOTE_DIR/server.log 2>&1 &" || return 1
    for _ in $(seq 1 30); do
        rsh "test -S $REMOTE_DIR/server.sock" 2>/dev/null && return 0
        sleep 0.5
    done
    return 1
}

# ── the outage, and recovery without a human ─────────────────────────────
# Roadmap item 5's last piece. Recovery is pinned in-process by protocol tests
# and in the namespace lab, but nowhere on the real link: this stops the server
# while the client stays attached and untouched, and requires four things.
#
#   1. The client's verdict stops saying `up` while it is dead — including past
#      the reject window, which is the case an idle laptop sat in for hours.
#   2. Nothing crosses. The route into the tunnel is still there (so this is not
#      fail-open) and every datagram sent dies in it.
#   3. The tunnel returns with nobody touching the client.
#   4. It does not hammer once it is back.
#
# A ping stream, not a single ping, keeps the delivery window full for the whole
# outage: the verdict is only allowed to judge 100 datagrams in the window, and
# an idle window would let `up` be explained away. It is also what a user with a
# dead browser actually does.
prove_outage_recovery() {
    local name=$1 dir=$2 rdir=$3 iface=$CIFACE
    local vallum_r="$REMOTE_DIR/vallum"
    local word="" deadline sent took e0 e1

    [ "$OUTAGE" = 1 ] || { note "--no-outage: the server-outage leg was skipped"; return 0; }
    [ "$OUTAGE_DONE" = 1 ] && return 0
    OUTAGE_DONE=1

    say "outage: the server goes away, and the client must not lie, leak or need a hand"

    # The baseline, so a later `stale` cannot be a client that was already dead.
    cli_put "ping -c2 -W3 1.1.1.1" > /dev/null 2>&1 \
        || bad "$name: the tunnel did not carry before the outage"
    cli_put "$vallum_r status --config $rdir/client.toml --json" > "$dir/status-before.json" 2>&1
    grep -q '"verdict": "up"' "$dir/status-before.json" \
        || { cat "$dir/status-before.json"; bad "$name: the verdict was not up before the outage"; }
    ok "$name: carrying and reported up before the outage"

    server_stop || { rsh "sudo tail -5 $REMOTE_DIR/server.log" >&2; bad "$name: the server could not be stopped, so nothing was measured"; }
    # Only the *server* stopped. A pattern that also matched the client's daemon
    # would make every later assertion about a client that is not running, and
    # `down` would look like an outage verdict instead of a dead process.
    cli_put "$vallum_r show --control $rdir/c.sock" > /dev/null 2>&1 \
        || { rsh "sudo tail -5 $rdir/client.log" >&2; bad "$name: the client daemon stopped too — the server-stop pattern matches it"; }
    cli_put "nohup ping -c $OUTAGE_PINGS -i 0.2 -W 1 1.1.1.1 > $rdir/outage-ping.log 2>&1 &"

    # 1a. The delivery verdict stops saying up. With the stream running the
    # window is full within seconds, so a bounded poll cannot be excused by a
    # sample that is still too small.
    for _ in $(seq 1 30); do
        cli_put "$vallum_r status --config $rdir/client.toml --json" > "$dir/status-outage.json" 2>&1
        word=$(sed -n 's/.*"verdict": "\([^"]*\)".*/\1/p' "$dir/status-outage.json" | head -1)
        case "$word" in up|"") sleep 2 ;; *) break ;; esac
    done
    case "$word" in
        up|"") cat "$dir/status-outage.json"; bad "$name: the verdict still said up with the server stopped" ;;
    esac
    ok "$name: a dead server reads as $word, not up"

    # 1b. Past the reject window the daemon itself has declared the session
    # dead, and the verdict must say so rather than falling back to `up` when
    # the delivery window drains.
    deadline=$(( $(date +%s) + REJECT_WINDOW + 80 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        cli_put "$vallum_r status --config $rdir/client.toml --json" > "$dir/status-stale.json" 2>&1
        word=$(sed -n 's/.*"verdict": "\([^"]*\)".*/\1/p' "$dir/status-stale.json" | head -1)
        [ "$word" = stale ] && break
        sleep 5
    done
    [ "$word" = stale ] \
        || { cat "$dir/status-stale.json"; bad "$name: the verdict never reached stale past the ${REJECT_WINDOW} s reject window (last read: ${word:-none})"; }
    ok "$name: past ${REJECT_WINDOW} s the verdict is stale — the daemon answers, the session is dead"

    # 2. Nothing crossed, and the reason is that the tunnel held rather than
    # that the route quietly reverted to the physical link.
    local dev
    dev=$(cli_put "ip route get 1.1.1.1" 2>/dev/null | sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -1)
    case "$dev" in
        vallum*) : ;;
        *) bad "$name: during the outage egress to 1.1.1.1 went via ${dev:-no device}, not the tunnel — that is fail-open" ;;
    esac

    # The bracket keeps pkill from matching the shell that runs it: its own
    # command line contains the pattern, and killing itself would never reach
    # ping — the same trap `[v]allum` breaks everywhere else in this script.
    rsh "sudo pkill -INT -f '[p]ing -c $OUTAGE_PINGS' >/dev/null 2>&1; true"
    sleep 2
    rsh "cat $rdir/outage-ping.log" > "$dir/outage-ping.log" 2>/dev/null
    if grep -qE '[0-9]+ packets transmitted, [1-9][0-9]* (packets )?received' "$dir/outage-ping.log"; then
        cat "$dir/outage-ping.log"
        bad "$name: traffic crossed while the server was stopped"
    fi
    sent=$(sed -n 's/^\([0-9]*\) packets transmitted.*/\1/p' "$dir/outage-ping.log" | tail -1)
    [ "${sent:-0}" -ge 100 ] \
        || { cat "$dir/outage-ping.log"; bad "$name: the outage probe sent ${sent:-0} datagrams, too few for the window to judge anything"; }
    ok "$name: $sent datagrams into a dead tunnel, none answered, and the route still pointed at it"

    # 3. Recovery, with every client-side process left exactly as it was: what
    # is restarted here is the server, and nothing else.
    say "recovery: the server returns; the client is not touched"
    took=$(date +%s)
    server_start || { rsh "sudo tail -10 $REMOTE_DIR/server.log" >&2; bad "$name: the server did not come back"; }
    # Carrying again is the recovery claim, and it is measured separately from
    # the verdict: the verdict cannot say `up` until the 60 s delivery window
    # has drained of the outage's failed datagrams, which is the window's own
    # latency and not the tunnel's. Reporting one number for both would credit
    # the window drain to the protocol.
    local carried=0
    deadline=$(( $(date +%s) + RECOVERY_BUDGET ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        # Traffic is what makes recovery observable: neither side dials an idle
        # peer, and the re-initiation needs a stale datagram to be triggered by.
        cli_put "ping -c1 -W1 1.1.1.1" > /dev/null 2>&1 && { carried=1; break; }
        sleep 2
    done
    [ "$carried" = 1 ] \
        || { rsh "sudo tail -20 $rdir/client.log" >&2; bad "$name: traffic did not cross again within ${RECOVERY_BUDGET} s of the server returning"; }
    took=$(( $(date +%s) - took ))
    ok "$name: carried again ${took}s after the server returned, with the client daemon untouched"

    word=""
    deadline=$(( $(date +%s) + 120 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        cli_put "$vallum_r status --config $rdir/client.toml --json" > "$dir/status-recovered.json" 2>&1
        word=$(sed -n 's/.*"verdict": "\([^"]*\)".*/\1/p' "$dir/status-recovered.json" | head -1)
        [ "$word" = up ] && break
        cli_put "ping -c2 -W3 1.1.1.1" > /dev/null 2>&1
        sleep 3
    done
    [ "$word" = up ] \
        || { cat "$dir/status-recovered.json"; bad "$name: the tunnel carried again but the verdict stayed ${word:-unknown} for 120 s"; }
    cli_put "ping -c2 -W3 1.1.1.1" > "$dir/recovered-ping.log" 2>&1 \
        || { cat "$dir/recovered-ping.log"; bad "$name: the verdict said up but traffic still did not cross"; }
    ok "$name: the verdict is back to up once the delivery window drained"

    # 4. Recovering once is not the same as recovering stably: a client that
    # handshakes in a loop looks healthy in any single reading.
    e0=$(_established "$vallum_r" "$rdir")
    sleep 30
    cli_put "ping -c2 -W3 1.1.1.1" > /dev/null 2>&1
    e1=$(_established "$vallum_r" "$rdir")
    [ $((e1 - e0)) -le 2 ] \
        || bad "$name: $((e1 - e0)) handshakes in 30 s of steady traffic — recovery is looping, not settling"
    ok "$name: $((e1 - e0)) handshake(s) in 30 s of steady traffic — the recovered tunnel is not thrashing"
}

# `vallum_loop_handshakes_established_total`, or 0 when the scrape cannot say.
_established() {
    local vallum_r=$1 rdir=$2 value
    value=$(cli_put "$vallum_r metrics --config $rdir/client.toml" 2>/dev/null \
        | awk '/^vallum_loop_handshakes_established_total/ { print $2; exit }')
    case "$value" in ''|*[!0-9]*) echo 0 ;; *) echo "$value" ;; esac
}

# ── the namespaced proof ─────────────────────────────────────────────────
# The caller's machine is never touched: the config is rewritten for the
# remote directory while it is still here, then scp'd over, and the daemon,
# vallum-quick and every assertion run inside the namespace via `ip netns
# exec`. Egress is still real: the namespace's veth hangs off the host's own
# routing, so the client dials the server's public endpoint exactly as a
# laptop would.
prove_client_ns() {
    local name=$1 dir=$2 iface=$CIFACE rdir="$REMOTE_DIR/cli/$1" config
    local vallum_r="$REMOTE_DIR/vallum" quick_r="$REMOTE_DIR/vallum-quick"

    config=$(ls "$dir"/*.toml | head -1)
    [ -n "$config" ] || bad "$name: no client config was produced"

    # Same split-tunnel rewrite as --host-direct — but "control" already points
    # at the remote directory, because the config is consumed over there.
    # The large-response target must not need to be resolved inside the
    # namespace, which has no working resolver — and pinning it also keeps
    # the flow tunnel-carried in --host-direct, where an unpinned name would
    # silently ride the physical link instead of proving the tunnel works.
    # Resolved here, on the invoking machine, over its ordinary DNS, before
    # anything is touched; empty means the size check below is skipped.
    local edge
    edge=$(getent ahostsv4 speed.cloudflare.com 2>/dev/null | awk '{print $1; exit}')
    python3 - "$config" "$iface" "$SRV_IP" "$rdir" "$edge" <<'PY'
import re, sys
path, iface, srv, workdir, edge = sys.argv[1:6]
text = open(path).read()
text = re.sub(r'^name = ".*?"', f'name = "{iface}"', text, count=1, flags=re.M)
text = re.sub(r'^control = .*$', f'control = "{workdir}/c.sock"', text, flags=re.M)
allowed = [f'"{srv}/32"', '"1.1.1.1/32"']
if edge:
    allowed.append(f'"{edge}/32"')  # pin the large-response target so the flow is tunnel-carried
text = re.sub(r'allowed_ips = \[.*?\]', 'allowed_ips = [' + ', '.join(allowed) + ']', text)
text = re.sub(r'^dns = .*\n', '', text, flags=re.M)
open(path, 'w').write(text)
PY

    # Fresh dir, not `mkdir -p`: a dir left behind by a sudo-run step (the
    # server's bundle-out, for instance) is root-owned, and `mkdir -p` would
    # silently keep it — then the scp below fails on an open it cannot own.
    rsh "sudo rm -rf $rdir && mkdir -p $rdir" || bad "$name: no scratch dir on the target"
    rscp "$config" "$TARGET:$rdir/client.toml" || bad "$name: scp the config"
    # The config references its private key by relative name (the daemon
    # resolves it against the config's directory), and every transport bundles
    # a key with the config — on the local dir it sat next to the .toml and the
    # reference just worked; over here it has to travel too or the daemon dies
    # with a No such file on its key.
    for key in "$dir"/*.key; do
        [ -e "$key" ] || continue
        rscp "$key" "$TARGET:$rdir/" \
            || bad "$name: scp $(basename "$key") failed — the message above is ssh's own.
        If it says 'Connection timed out' the transport died, not the tunnel: the host
        drops new connections under load (sshd MaxStartups) and this gate opens a
        lot of them. Re-run; a failure that repeats at the same step is the gate, one
        that moves around is the transport."
    done

    # Before running it, check the config as the server produced it:
    # `attach --dry-run` prints the plan and refuses a config it could not
    # install — the same gate --host-direct runs, but inside the namespace
    # where it will actually attach.
    cli_put "$quick_r attach $rdir/client.toml --dry-run" > "$dir/attach-dry.log" 2>&1 \
        || { cat "$dir/attach-dry.log"; bad "$name: the config as produced cannot be attached"; }

    # The daemon lives in the namespace for the whole proof; `nohup` keeps it
    # past the ssh session, and the pkill below reaps it per transport.
    # Start the daemon within this session and verify it by *effect*: the TUN
    # appearing inside the namespace, not by pgrep. pgrep -f matches any
    # process whose command line contains the pattern — and the remote shell
    # running this very command contains it too, so a plain spelling matches
    # that shell, not the daemon, and a dead daemon sails under a green check
    # straight into attach's timeout. `[v]allum` breaks the literal match.
    cli_put "nohup $vallum_r run --config $rdir/client.toml > $rdir/client.log 2>&1 &"
    local iface_up=0
    for _ in $(seq 1 20); do
        cli_put "ip link show $iface" >/dev/null 2>&1 && { iface_up=1; break; }
        sleep 0.5
    done
    if [ "$iface_up" != 1 ]; then
        rsh "cat $rdir/client.log 2>/dev/null" >&2
        bad "$name: the client daemon did not create $iface"
    fi
    cli_put "$quick_r attach $rdir/client.toml" > "$dir/attach.log" 2>&1 \
        || { cat "$dir/attach.log"; rsh "cat $rdir/client.log 2>/dev/null" >&2; bad "$name: attach"; }

    local established=0
    for _ in $(seq 1 20); do
        # Traffic drives the handshake — the daemon does not dial an idle peer
        # on its own, exactly as WireGuard does not. The ping is what starts it.
        cli_put "ping -c1 -W1 $SRV_IP" >/dev/null 2>&1
        cli_put "$vallum_r show --control $rdir/c.sock" 2>/dev/null | grep -q "last_handshake_time_sec=[1-9]" && { established=1; break; }
        sleep 0.5
    done
    [ "$established" = 1 ] || bad "$name: no handshake (is UDP $PORT reachable?)"

    cli_put "ping -c2 -W3 $SRV_IP" > "$dir/tunnel.log" 2>&1 || { cat "$dir/tunnel.log"; bad "$name: the tunnel does not ping"; }
    cli_put "ping -c3 -W4 1.1.1.1" > "$dir/egress.log" 2>&1 || {
        cat "$dir/egress.log"
        say "server forwarding state at the moment of the egress failure"
        rsh "sudo iptables -L FORWARD -n -v | head -8
             sudo nft list table inet vallumtest 2>/dev/null
             sudo tail -n 8 $REMOTE_DIR/server.log" || true
        bad "$name: no egress through the server"
    }
    local dig_r curl_r
    dig_r=$(rsh "command -v dig >/dev/null 2>&1 && echo 1")
    if [ "${dig_r:-0}" = 1 ]; then
        cli_put "dig +time=3 +tries=1 @1.1.1.1 example.com A" > "$dir/dig.log" 2>&1
        if ! grep -q "ANSWER SECTION" "$dir/dig.log"; then
            cat "$dir/dig.log"
            note "ICMP crossed but UDP did not, which is the signature of a"
            note "FORWARD policy that drops everything except echo — see"
            note "docs/deployment/troubleshooting.md, \"ping works, nothing else\""
            bad "$name: DNS through the tunnel did not answer"
        fi
    fi
    ok "$name: handshake, tunnel, egress$([ "${dig_r:-0}" = 1 ] && printf ', DNS')"

    # A 1 MiB HTTPS response exercises the path MTU end to end, as in
    # --host-direct: a wrong MTU is reported by users as "the VPN is up but
    # some sites hang", so the size that arrived matters.
    curl_r=$(rsh "command -v curl >/dev/null 2>&1 && echo 1")
    if [ "${curl_r:-0}" = 1 ] && [ -n "$edge" ]; then
        local out rc size connect appconnect code
        out=$(cli_put "curl -s --max-time 25 -o /dev/null \
            -w '%{size_download} %{time_connect} %{time_appconnect} %{http_code}' \
            --resolve speed.cloudflare.com:443:$edge \
            'https://speed.cloudflare.com/__down?bytes=1000000'" 2>"$dir/curl.log")
        rc=$?
        # ssh returns the remote command's status, so curl's own exit code
        # survives; 255 means the SSH hop itself failed and curl never ran.
        read -r size connect appconnect code <<<"$out"
        if [ "${size:-0}" -ge 900000 ]; then
            ok "$name: a 1 MiB HTTPS response arrives intact"
        else
            [ -s "$dir/curl.log" ] && cat "$dir/curl.log"
            why=$(describe_download_failure "$rc" "${size:-0}" "$connect" "$appconnect" "$code")
            # Pay for a measurement only when the shape says MTU could be it:
            # the server is the hop that NATs this download, so its path to the
            # edge is the one that would black-hole it. `vallum doctor
            # --probe-mtu` already exists and bisects with `ping -M do`; the
            # assertion above used to *name* this cause without ever asking it.
            measured=""
            case "$why" in
                *blackhole*|*"TLS handshake failed"*)
                    measured=$(rsh "sudo $SERVER_CMD doctor --config $CONFIG --probe-mtu $edge 2>&1 | sed -n 's/^[A-Z]* *path-mtu *//p'" | head -1)
                    [ -n "$measured" ] && measured="
   measured: path-mtu $measured"
                    ;;
            esac
            bad "$name: a large HTTPS response did not arrive (${size:-0} of 1000000 bytes, curl exit $rc, connect ${connect:-none}s, tls ${appconnect:-none}s)
   $why$measured"
        fi
    else
        note "curl absent on the target, or the edge could not be resolved over ordinary DNS: the large-response check was skipped"
    fi

    # A leak is a routing decision, and inside the namespace it is readable the
    # same way: the lookup for an outside address must land on the tunnel.
    local v4dev
    v4dev=$(cli_put "ip route get 1.1.1.1" 2>/dev/null | sed -n 's/.*dev \\([^ ]*\\).*/\\1/p' | head -1)
    case "$v4dev" in
        vallum*) ok "$name: IPv4 egress routes into the tunnel ($v4dev)" ;;
        "")      note "could not determine the IPv4 route" ;;
        *)       bad "$name: IPv4 egress escapes via $v4dev, not the tunnel" ;;
    esac

    # The namespace is IPv4-only by construction: it has no global v6 address
    # (the veth carries no v6), so the strict v6 assertion cannot apply — same
    # decide-not-assert rule as --host-direct, stated for the same reason.
    note "$name: this client is IPv4-only, so the IPv6 route assertion does not apply"
    note "   on a dual-stack host a v4-only split tunnel leaves IPv6 on the physical"
    note "   link — that is split-tunnel semantics. For a full-tunnel posture the"
    note "   fail-closed guard blocks it: vallum policy on (see ADR-0018/ADR-0020)"

    # ── no foreign source may enter the tunnel ──
    # Both directions as in --host-direct: nothing foreign during normal
    # traffic, then a foreign source attempted on purpose, which must be
    # refused and named. Link-local traffic is excluded — a link-local source
    # means nothing across a link boundary.
    refusals() {
        rsh "grep 'does not own that address' $rdir/client.log 2>/dev/null" | grep -v 'from fe80:'
    }
    if [ -n "$(refusals | head -1)" ]; then
        refusals | head -3
        bad "$name: ordinary traffic was refused for a routable foreign source"
    else
        ok "$name: no routable foreign source during normal traffic"
    fi

    # The positive control, inside the namespace: an address the config does
    # not declare is added to the tunnel interface and a packet is sourced from
    # it; the daemon must refuse it.
    local foreign=192.0.2.99
    if cli_put "ip addr add $foreign/32 dev $iface" 2>/dev/null; then
        cli_put "ping -I $foreign -c1 -W1 $SRV_IP" >/dev/null 2>&1
        sleep 1
        if rsh "grep 'does not own that address' $rdir/client.log 2>/dev/null" | grep -q "from $foreign"; then
            ok "$name: a foreign source is refused locally and named"
        else
            bad "$name: a packet sourced from $foreign was sealed, not refused"
        fi
        cli_put "ip addr del $foreign/32 dev $iface" 2>/dev/null
    else
        note "could not add $foreign to $iface: foreign-source control skipped"
    fi

    # The server-outage leg (roadmap item 5 / ADR-0019), on the real link and
    # with the client left exactly as it is. Runs once per invocation: it costs
    # minutes and proves a property of the client, not of the transport.
    prove_outage_recovery "$name" "$dir" "$rdir"

    if [ "$kind" = "bundle" ]; then
        say "rotation live across the network"
        local new_key="$dir/new.key" new_pub="$dir/new.pub"
        "$VALLUM" keygen --output "$new_key" --suite 3 > "$new_pub" || bad "$name: keygen for rotation"
        # The CLI reads a public-line file, not a `-` alias for stdin — see the
        # note in prove_client_host.
        rsh "$SERVER_CMD peer rotate $name --config $CONFIG --public-key-file /dev/stdin" < "$new_pub" \
            || bad "$name: remote peer rotate"
        cli_put "ping -c2 -W3 1.1.1.1" >/dev/null 2>&1 || bad "$name: rotation broke active tunnel egress"
        ok "$name: tunnel survives rotation across the network"
        rsh "$SERVER_CMD peer finalize $name --config $CONFIG" || bad "$name: remote peer finalize"
        ok "$name: rotated and finalized on remote server"

        # Finalize retires the old key on the server. The live session carries
        # on, which is all the assertion above sees — but the client's config
        # still names the retired key, so the *next* handshake is refused, and
        # nothing in the log says why. (The per-app case below restarts the
        # daemon, and a restarted daemon must handshake: that is how this was
        # found.) Adopt the rotated key and prove a fresh handshake with it, so
        # the run does not end on a deployment that only works until the next
        # rekey.
        rsh "sudo pkill -f '[v]allum run --config $rdir/client.toml'" >/dev/null 2>&1
        for _ in $(seq 1 25); do cli_put "ip link show $iface" >/dev/null 2>&1 || break; sleep 0.2; done
        rscp "$new_key" "$TARGET:$rdir/client.key" || bad "$name: scp the rotated key"
        rsh "sudo python3 - $rdir/client.toml <<'PY'
import re, sys
path = sys.argv[1]
text = open(path).read()
text = re.sub(r'^private_key = .*$', 'private_key = \"client.key\"', text, count=1, flags=re.M)
open(path, 'w').write(text)
PY" || bad "$name: pointing the config at the rotated key failed"
        cli_put "nohup $vallum_r run --config $rdir/client.toml > $rdir/client.log 2>&1 &"
        local fresh=0
        # The restart took the routes attach had installed with the old device,
        # and the attach that puts them back is the caller's next step — so put
        # the one route this probe needs back by hand. Without it the ping has no
        # route to the server, nothing enters the TUN, and the failure looks
        # like a rejected key.
        for _ in $(seq 1 20); do cli_put "ip link show $iface" >/dev/null 2>&1 && break; sleep 0.5; done
        cli_put "ip route replace $SRV_IP/32 dev $iface" >/dev/null 2>&1 || true
        for _ in $(seq 1 20); do
            cli_put "ping -4 -c1 -W1 -I $CLI_IP $SRV_IP" >/dev/null 2>&1
            cli_put "$vallum_r show --control $rdir/c.sock" 2>/dev/null | grep -q "last_handshake_time_sec=[1-9]" && { fresh=1; break; }
            sleep 0.5
        done
        cli_put "ip route del $SRV_IP/32 dev $iface" >/dev/null 2>&1 || true
        if [ "$fresh" != 1 ]; then
            rsh "sudo tail -5 $rdir/client.log" >&2
            bad "$name: the rotated key did not handshake"
        fi
        ok "$name: the rotated key handshakes a fresh session"

        cli_put "$quick_r leak-check --json $rdir/client.toml" > "$dir/leak-check.json" 2>&1 \
            || { cat "$dir/leak-check.json"; bad "$name: remote leak-check failed"; }
        grep -qE '"status":"(clean|skipped)"' "$dir/leak-check.json" \
            || { cat "$dir/leak-check.json"; bad "$name: unexpected leak-check verdict"; }
        ok "$name: remote vallum-quick leak-check verified"

        cli_put "$quick_r dns-proxy --dry-run $rdir/client.toml" > "$dir/dns-proxy-plan.txt" 2>&1 \
            || { cat "$dir/dns-proxy-plan.txt"; bad "$name: remote dns-proxy --dry-run failed"; }
        ok "$name: remote vallum-quick dns-proxy plan verified"
    fi

    # ── the client verdict, on the real link ──
    # What pages must be what was tested: the same three endings the netns
    # gate (e2e-netns.sh) proves, here against a daemon on the real live
    # network over the server's real NAT. The scrape runs inside the namespace
    # the way a real exporter would see it, and the dead endings are proven
    # against the namespace's own guard tables — which is why this leg sits
    # inside prove_client_ns and not prove_client_host: the script never
    # installs or removes a guard on the invoking machine's tables.
    say "client verdict: the scrape carries the status verdict"
    cli_put "$vallum_r metrics --config $rdir/client.toml > $rdir/metrics-live.txt 2>&1" \
        || { rsh "cat $rdir/metrics-live.txt"; bad "$name: the scrape failed while the daemon lived"; }
    rsh "cat $rdir/metrics-live.txt" > "$dir/metrics-live.txt"
    grep -q '^# TYPE vallum_client_verdict gauge$' "$dir/metrics-live.txt" \
        || bad "$name: the scrape has no client-verdict family"
    grep -q "client_verdict{interface=\"$iface\",verdict=\"up\"} 1" "$dir/metrics-live.txt" \
        || { cat "$dir/metrics-live.txt"; bad "$name: the live scrape did not read verdict=up"; }
    grep -q '^vallum_up 1$' "$dir/metrics-live.txt" \
        || bad "$name: the live scrape did not report up=1"
    ok "$name: the live scrape carries the verdict the status verb would print"

    # The endings that page. The transported config runs as a deliberate
    # split tunnel — where a dead daemon without a guard is `down` by design,
    # not a leak — so the leaked ending needs the config to state a full
    # -tunnel posture. The provisioning writer already ships a `[quick]`
    # section (`table = "auto"`, optional `dns`), so the policy is set inside
    # it, in place — the same thing the netns gate writes for its own config
    # before the same ending. The final state is asserted, and anything else
    # fails loudly rather than faking the alert.
    rsh "if grep -q '^policy = ' $rdir/client.toml; then
             sed -i 's/^policy\\(\s*=\\).*$/policy = \"on\"/' $rdir/client.toml
         else
             sed -i '/^\\[quick\\]/a policy = \"on\"' $rdir/client.toml
         fi
         grep -q '^policy = \"on\"$' $rdir/client.toml" \
        || bad "$name: the config did not end with policy = on; the verdict leg's rewrite broke in that config shape"

    rsh "sudo pkill -f '[v]allum run --config $rdir/client.toml'" >/dev/null 2>&1
    for _ in $(seq 1 25); do
        cli_put "ip link show $iface" >/dev/null 2>&1 || break
        sleep 0.2
    done
    cli_put "rm -f $rdir/c.sock"
    # `ip netns exec` execs binaries, not a shell, so a `command -v` builtin is
    # a "no such file" here — the check must go through a shell.
    cli_put "sh -c 'command -v nft'" >/dev/null 2>&1 \
        || bad "$name: the target has no nft; the verdict leg cannot read the guard state"

    cli_put "$vallum_r policy on --config $rdir/client.toml" > "$dir/policy-dead-on.log" 2>&1 \
        || { cat "$dir/policy-dead-on.log"; bad "$name: policy on failed with the daemon dead"; }
    grep -q 'is blocked' "$dir/policy-dead-on.log" \
        || { cat "$dir/policy-dead-on.log"; bad "$name: dead-daemon policy on did not report a guard"; }
    # The dead scrape must exit nonzero — scripts gate on that — yet still
    # write the file: silence would hide the state instead of naming it.
    if cli_put "$vallum_r metrics --config $rdir/client.toml --output $rdir/metrics-blocked.prom" \
        >/dev/null 2>&1; then
        bad "$name: the scrape exited 0 while the daemon was dead"
    fi
    rsh "cat $rdir/metrics-blocked.prom" > "$dir/metrics-blocked.prom" 2>/dev/null
    grep -q 'verdict="blocked"' "$dir/metrics-blocked.prom" \
        || { cat "$dir/metrics-blocked.prom" 2>/dev/null; bad "$name: a dead daemon under a guard did not read blocked"; }
    grep -q '^vallum_up 0$' "$dir/metrics-blocked.prom" \
        || bad "$name: the dead-daemon scrape did not report up=0"
    ok "$name: a dead daemon under an installed guard scrapes as blocked, the scrape failing"

    cli_put "$vallum_r policy off --config $rdir/client.toml" > "$dir/policy-dead-off.log" 2>&1 \
        || { cat "$dir/policy-dead-off.log"; bad "$name: policy off failed with the daemon dead"; }
    if cli_put "$vallum_r metrics --config $rdir/client.toml --output $rdir/metrics-leaking.prom" \
        >/dev/null 2>&1; then
        bad "$name: the scrape exited 0 with a dead daemon and no guard"
    fi
    rsh "cat $rdir/metrics-leaking.prom" > "$dir/metrics-leaking.prom" 2>/dev/null
    grep -q 'verdict="LEAKING"' "$dir/metrics-leaking.prom" \
        || { cat "$dir/metrics-leaking.prom" 2>/dev/null; bad "$name: a dead daemon with no guard did not read LEAKING"; }
    ok "$name: a dead daemon with no guard scrapes as LEAKING — the state the pager names"

    # Teardown for the next transport: detach, then reap the daemon whose
    # command line names this transport's config directory.
    cli_put "$quick_r detach $rdir/client.toml" >/dev/null 2>&1
    # Same literal-match trap as above, mirrored for the kill: the parent
    # shell of this pkill contains the pattern, so it must not match itself.
    rsh "sudo pkill -f '[v]allum run --config $rdir/client.toml'" >/dev/null 2>&1
    for _ in $(seq 1 25); do
        cli_put "ip link show $iface" >/dev/null 2>&1 || break
        sleep 0.2
    done
}

# ── the host-direct proof ────────────────────────────────────────────────
# The old behaviour, kept deliberately: the client runs on the invoking
# machine against its real interfaces, which is the closest a test gets to a
# real second laptop. It rewrites this machine's routes for the run and needs
# local root, which is why it is opt-in rather than the default.
prove_client_host() {
    local name=$1 dir=$2 config iface=$CIFACE
    config=$(ls "$dir"/*.toml | head -1)
    # The outage leg is namespaced-only: it stops the real server and waits out
    # the reject window, which is fine against a client in a namespace and is
    # not something to do while this machine's own routes are rewritten. Stated
    # rather than silently skipped, because it is the one production claim a
    # --host-direct run does not cover.
    note "$name: the server-outage leg runs in namespaced mode only (see --namespaced)"
    [ -n "$config" ] || bad "$name: no client config was produced"

    # Before rewriting it into a split tunnel, check the config as the server
    # produced it: `attach --dry-run` prints the plan and refuses a config it
    # could not install (a full tunnel without a fwmark, for instance).
    "$QUICK" attach "$config" --dry-run > "$dir/attach-dry.log" 2>&1 \
        || { cat "$dir/attach-dry.log"; bad "$name: the config as produced cannot be attached"; }
    # The large-response target is resolved here and pinned two ways: into
    # this config's allowed set, so the flow is carried by the tunnel instead
    # of the physical link (an unpinned name would silently travel outside
    # the interface and make the size pass vacuously), and with --resolve on
    # the curl below. Empty means the size check is skipped, not ignored.
    local edge
    edge=$(getent ahostsv4 speed.cloudflare.com 2>/dev/null | awk '{print $1; exit}')
    python3 - "$config" "$iface" "$SRV_IP" "$dir" "$edge" <<'PY'
import re, sys
path, iface, srv, workdir, edge = sys.argv[1:6]
text = open(path).read()
text = re.sub(r'^name = ".*?"', f'name = "{iface}"', text, count=1, flags=re.M)
text = re.sub(r'^control = .*$', f'control = "{workdir}/c.sock"', text, flags=re.M)
allowed = [f'"{srv}/32"', '"1.1.1.1/32"']
if edge:
    allowed.append(f'"{edge}/32"')  # pin the large-response target so the flow is tunnel-carried
text = re.sub(r'allowed_ips = \[.*?\]', 'allowed_ips = [' + ', '.join(allowed) + ']', text)
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
    ping -c3 -W4 1.1.1.1 > "$dir/egress.log" 2>&1 || {
        cat "$dir/egress.log"
        say "server forwarding state at the moment of the egress failure"
        rsh "sudo iptables -L FORWARD -n -v | head -8
             sudo nft list table inet vallumtest 2>/dev/null
             sudo tail -n 8 $REMOTE_DIR/server.log" || true
        bad "$name: no egress through the server"
    }
    if command -v dig >/dev/null 2>&1; then
        dig +time=3 +tries=1 @1.1.1.1 example.com A > "$dir/dig.log" 2>&1
        if ! grep -q "ANSWER SECTION" "$dir/dig.log"; then
            cat "$dir/dig.log"
            note "ICMP crossed but UDP did not, which is the signature of a"
            note "FORWARD policy that drops everything except echo — see"
            note "docs/deployment/troubleshooting.md, \"ping works, nothing else\""
            bad "$name: DNS through the tunnel did not answer"
        fi
    fi
    ok "$name: handshake, tunnel, egress$(command -v dig >/dev/null 2>&1 && printf ', DNS')"

    # ── what a browser would notice ──
    # A 1 MiB HTTPS response exercises the path MTU end to end. A wrong MTU is
    # reported by users as "the VPN is up but some sites hang", so the size that
    # arrived matters more than the fact that something did.
    if command -v curl >/dev/null 2>&1 && [ -n "$edge" ]; then
        local out rc size connect appconnect code
        out=$(curl -s --max-time 25 -o /dev/null \
            -w '%{size_download} %{time_connect} %{time_appconnect} %{http_code}' \
            --resolve speed.cloudflare.com:443:$edge \
            "https://speed.cloudflare.com/__down?bytes=1000000" 2>"$dir/curl.log")
        rc=$?
        read -r size connect appconnect code <<<"$out"
        if [ "${size:-0}" -ge 900000 ]; then
            ok "$name: a 1 MiB HTTPS response arrives intact"
        else
            [ -s "$dir/curl.log" ] && cat "$dir/curl.log"
            why=$(describe_download_failure "$rc" "${size:-0}" "$connect" "$appconnect" "$code")
            # Pay for a measurement only when the shape says MTU could be it:
            # the server is the hop that NATs this download, so its path to the
            # edge is the one that would black-hole it. `vallum doctor
            # --probe-mtu` already exists and bisects with `ping -M do`; the
            # assertion above used to *name* this cause without ever asking it.
            measured=""
            case "$why" in
                *blackhole*|*"TLS handshake failed"*)
                    measured=$(rsh "sudo $SERVER_CMD doctor --config $CONFIG --probe-mtu $edge 2>&1 | sed -n 's/^[A-Z]* *path-mtu *//p'" | head -1)
                    [ -n "$measured" ] && measured="
   measured: path-mtu $measured"
                    ;;
            esac
            bad "$name: a large HTTPS response did not arrive (${size:-0} of 1000000 bytes, curl exit $rc, connect ${connect:-none}s, tls ${appconnect:-none}s)
   $why$measured"
        fi
    else
        note "curl absent, or the edge could not be resolved over ordinary DNS: the large-response check was skipped"
    fi

    # A leak is a routing decision: with a full tunnel attached, the lookup for
    # an outside address must land on the tunnel, not on the physical link.
    local v4dev
    v4dev=$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -1)
    case "$v4dev" in
        vallum*) ok "$name: IPv4 egress routes into the tunnel ($v4dev)" ;;
        "")      note "could not determine the IPv4 route" ;;
        *)       bad "$name: IPv4 egress escapes via $v4dev, not the tunnel" ;;
    esac

    if ip -6 addr show scope global 2>/dev/null | grep -q 'inet6'; then
        # The strict assertion is about a tunnel that carries IPv6. A config
        # rewritten to a split tunnel around $SRV_IP is IPv4-only by
        # construction, so a dual-stack host would fail `not wlp0s20f3`
        # every run by construction too. Decide instead of asserting: for a
        # config that carries v6, egress must route into the tunnel; for one
        # that does not, v6 staying on the physical link is split-tunnel
        # semantics, and the fail-closed guard (ADR-0018) is the control for
        # a full-tunnel posture. This gate never installs that guard on the
        # invoking machine — it would block every other v4 destination's
        # browsing for the run's duration.
        local allowed_line
        allowed_line=$(grep '^allowed_ips' "$config" 2>/dev/null || true)
        case "$allowed_line" in
            *:*)
                local v6dev
                v6dev=$(ip -6 route get 2606:4700:4700::1111 2>/dev/null \
                    | sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -1)
                case "$v6dev" in
                    vallum*) ok "$name: IPv6 egress routes into the tunnel ($v6dev)" ;;
                    "")      note "could not determine the IPv6 route" ;;
                    *)       bad "$name: IPv6 egress escapes via $v6dev, not the tunnel" ;;
                esac
                ;;
            *)
                note "$name: this client is IPv4-only, so the IPv6 route assertion does not apply"
                note "   on a dual-stack host a v4-only split tunnel leaves IPv6 on the physical"
                note "   link — that is split-tunnel semantics. For a full-tunnel posture the"
                note "   fail-closed guard blocks it: vallum policy on (see ADR-0018/ADR-0020)"
                ;;
        esac
    else
        note "no global IPv6 on this host: the IPv6 leak check does not apply"
    fi
    # ── no foreign source may enter the tunnel ──
    # The peer refuses an inner source outside its allowed_ips, and it is right
    # to: that check is what stops one peer claiming another's address. The
    # consequence is that a packet with a foreign source is not misrouted, it is
    # *unacceptable*, so the sender must decline it where the cause is visible
    # rather than seal it and lose it at the far end. Both directions are
    # asserted: nothing foreign during normal traffic, then a foreign source
    # attempted on purpose, which must be refused and named.
    # Link-local traffic reaches the tunnel at startup on every host — MLD and
    # neighbour discovery for the interface's own addresses — and refusing it is
    # correct, since a link-local source means nothing across a link boundary.
    # So the clean-run assertion is about *routable* foreign sources only; a
    # check that failed on the expected case would be red on every run and
    # ignored within a week.
    refusals() {
        grep "does not own that address" "$dir/client.log" 2>/dev/null | grep -v 'from fe80:'
    }

    if [ -n "$(refusals | head -1)" ]; then
        refusals | head -3
        bad "$name: ordinary traffic was refused for a routable foreign source"
    else
        ok "$name: no routable foreign source during normal traffic"
    fi

    # The positive control. An address the config does not declare is added to
    # the interface and a packet is sourced from it; the daemon must refuse it.
    # Without this the assertion above could never be shown to be capable of
    # failing, which is how a suite that only passes gets mistaken for coverage.
    local foreign=192.0.2.99
    if ip addr add "$foreign/32" dev "$iface" 2>/dev/null; then
        ping -I "$foreign" -c1 -W1 "$SRV_IP" >/dev/null 2>&1
        sleep 1
        if grep -q "does not own that address" "$dir/client.log" &&
            grep "does not own that address" "$dir/client.log" | grep -q "from $foreign"; then
            ok "$name: a foreign source is refused locally and named"
        else
            bad "$name: a packet sourced from $foreign was sealed, not refused"
        fi
        ip addr del "$foreign/32" dev "$iface" 2>/dev/null
    else
        note "could not add $foreign to $iface: foreign-source control skipped"
    fi

    # DNS "nowhere else" is the remaining half, and it cannot be asserted yet:
    # resolution outside the tunnel only leaks once the tunnel is *down*, which
    # is what the fail-closed policy changes. See docs/roadmap.md items 2 and 3.

    if [ "$kind" = "bundle" ]; then
        say "rotation live across the network"
        local new_key="$dir/new.key" new_pub="$dir/new.pub"
        "$VALLUM" keygen --output "$new_key" --suite 3 > "$new_pub" || bad "$name: keygen for rotation"
        # The CLI reads a public-line file, not a `-` alias for stdin: `-` is
        # stdin for --token only (`setup.rs read_token_arg`), and the product's
        # own convention for piped keys is the literal /dev/stdin — the same
        # path `setup --remote` offers for `peer enroll`. A literal `-` here
        # failed with "No such file or directory" and stopped the run.
        rsh "$SERVER_CMD peer rotate $name --config $CONFIG --public-key-file /dev/stdin" < "$new_pub" \
            || bad "$name: remote peer rotate"
        ping -c2 -W3 1.1.1.1 >/dev/null 2>&1 || bad "$name: rotation broke active tunnel egress"
        ok "$name: tunnel survives rotation across the network"
        rsh "$SERVER_CMD peer finalize $name --config $CONFIG" || bad "$name: remote peer finalize"
        ok "$name: rotated and finalized on remote server"
    fi

    # ── the client verdict, live ending only ──
    # The same series the netns gate and the namespaced leg assert. Only the
    # live ending proves here: the dead endings are guard manipulations, and
    # this script never installs or removes a guard on the invoking machine
    # (the same rule that keeps --host-direct from applying the egress
    # policy). The namespace leg owns the dead endings.
    say "client verdict: the live scrape carries the status verdict"
    "$VALLUM" metrics --config "$config" > "$dir/metrics-live.txt" 2>&1 \
        || { cat "$dir/metrics-live.txt"; bad "$name: the scrape failed while the daemon lived"; }
    grep -q '^# TYPE vallum_client_verdict gauge$' "$dir/metrics-live.txt" \
        || bad "$name: the scrape has no client-verdict family"
    grep -q "client_verdict{interface=\"$iface\",verdict=\"up\"} 1" "$dir/metrics-live.txt" \
        || { cat "$dir/metrics-live.txt"; bad "$name: the live scrape did not read verdict=up"; }
    grep -q '^vallum_up 1$' "$dir/metrics-live.txt" \
        || bad "$name: the live scrape did not report up=1"
    ok "$name: the live scrape carries the verdict the status verb would print"

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

# ── the per-app launch path, on the real link (ADR-0023) ─────────────────
# Opt-in (--app-class), and namespaced mode only: it rebuilds the bundle
# transport's client as a *full* tunnel with `app_class`, attaches, and checks
# what the namespace alone makes possible — the client keeps its own path, the
# device leaves its namespace, and a launched member routes, resolves and
# carries traffic from inside the tunnel's while the client's own resolver is
# untouched. State lives under the scratch dir.
prove_app_class_ns() {
    local name=$1 dir="$LOCAL_DIR/bundle" config rdir
    rdir="$REMOTE_DIR/cli/$1"
    config="$rdir/client.toml"
    local quick_r="$REMOTE_DIR/vallum-quick" vallum_r="$REMOTE_DIR/vallum"
    local iface=$CIFACE

    [ "$NAMESPACED" = 1 ] || { note "--app-class needs the namespaced client: skipped"; return 0; }
    # The local config keeps the name the bundle gave it (the interface), while
    # `prove_client_ns` copies it over as `client.toml` — so the local half is
    # "any .toml" and the remote half is that fixed name. Testing for
    # `client.toml` locally skipped this whole case on every run.
    [ -n "$(ls "$dir"/*.toml 2>/dev/null | head -1)" ] \
        || { note "the bundle transport did not run: the per-app case is skipped"; return 0; }
    rsh "test -f $config" 2>/dev/null || { note "no remote bundle config: the per-app case is skipped"; return 0; }
    cli_put "sh -c 'command -v unshare && command -v nsenter'" >/dev/null 2>&1 \
        || { note "the target has no unshare/nsenter: the per-app case is skipped"; return 0; }

    say "per-app: a member rides the tunnel; the client keeps its own path"
    # The transport proof left a split tunnel with host routes. The per-app path
    # installs none — the member namespace decides — so the config is rewritten
    # and the daemon restarted to read it.
    rsh "sudo pkill -f '[v]allum run --config $config'" >/dev/null 2>&1
    for _ in $(seq 1 25); do cli_put "ip link show $iface" >/dev/null 2>&1 || break; sleep 0.2; done

    rsh "sudo python3 - $config <<'PY'
import re, sys
path = sys.argv[1]
text = open(path).read()
text = re.sub(r'^allowed_ips = .*$', 'allowed_ips = [\"0.0.0.0/0\"]', text, flags=re.M)
if re.search(r'^\\[quick\\]', text, flags=re.M):
    text = re.sub(r'^\\[quick\\]$', '[quick]\\napp_class = true', text, count=1, flags=re.M)
else:
    text += '\\n[quick]\\napp_class = true\\n'
open(path, 'w').write(text)
PY" || bad "$name: rewriting the class config failed"

    local resolv_before
    resolv_before=$(cli_put "sha256sum /etc/resolv.conf 2>/dev/null | cut -d' ' -f1" 2>/dev/null || true)

    cli_put "nohup $vallum_r run --config $config > $rdir/app-class.log 2>&1 &"
    local up=0
    for _ in $(seq 1 20); do
        cli_put "ip link show $iface" >/dev/null 2>&1 && { up=1; break; }
        sleep 0.5
    done
    if [ "$up" != 1 ]; then
        rsh "cat $rdir/app-class.log 2>/dev/null" >&2
        bad "$name: the class daemon did not create $iface"
    fi

    cli_put "env VALLUM_STATE_DIR=$rdir/state $quick_r attach $config" \
        > "$dir/app-class-attach.log" 2>&1 \
        || { cat "$dir/app-class-attach.log"; bad "$name: class attach failed"; }

    rsh "sudo test -f $rdir/state/$iface.quick-ns" \
        || bad "$name: attach reported success but wrote no member-namespace record"

    # The device left the client's namespace, and the client kept its own path:
    # the split this mechanism exists for, asserted directly.
    if cli_put "ip link show $iface" >/dev/null 2>&1; then
        bad "$name: attach left $iface in the client's namespace"
    fi
    if cli_put "ip route get 1.1.1.1" 2>/dev/null | grep -q "dev $iface"; then
        bad "$name: the client's own traffic was routed into the tunnel"
    fi
    ok "$name: the device left the client's namespace; the client kept its own path"

    # A launcher with no member: the namespace must be reachable and must not
    # borrow the client's route table.
    cli_put "env VALLUM_STATE_DIR=$rdir/state $quick_r app $config lookup -- sh -c 'ip route get 1.1.1.1; cat /etc/resolv.conf'" \
        > "$dir/app-lookup.log" 2>&1 \
        || { cat "$dir/app-lookup.log"; bad "$name: the launched member's lookup failed"; }
    grep -q "dev $iface" "$dir/app-lookup.log" \
        || { cat "$dir/app-lookup.log"; bad "$name: the launched member did not route through $iface"; }

    # Traffic through the member's path: the server's outer address is inside
    # the full tunnel's allowed_ips, so this ping leaves from the tunnel address
    # and is also the traffic that finishes the handshake.
    local established=0
    for _ in $(seq 1 20); do
        cli_put "env VALLUM_STATE_DIR=$rdir/state $quick_r app $config gateway -- ping -c1 -W1 $SRV_IP" \
            > "$dir/app-gateway.log" 2>&1 || true
        cli_put "$vallum_r show --control $rdir/c.sock" 2>/dev/null | grep -q "last_handshake_time_sec=[1-9]" && { established=1; break; }
        sleep 0.5
    done
    # A silent member proves nothing: the launcher's own output and the daemon's
    # log are the only record of why a packet did not reach the tunnel.
    [ "$established" = 1 ] || {
        cat "$dir/app-gateway.log"
        rsh "sudo tail -20 $rdir/app-class.log 2>/dev/null" >&2
        cli_put "$vallum_r show --control $rdir/c.sock" 2>&1 >&2 || true
        bad "$name: the member's traffic did not establish the tunnel"
    }
    ok "$name: a launched member's traffic carried the tunnel"

    local resolv_after
    resolv_after=$(cli_put "sha256sum /etc/resolv.conf 2>/dev/null | cut -d' ' -f1" 2>/dev/null || true)
    [ "$resolv_before" = "$resolv_after" ] \
        || bad "$name: attach rewrote the client's /etc/resolv.conf"
    ok "$name: the client's resolver is untouched"

    # Detach returns the device and refuses further launches: a member started
    # after detach would run outside the tunnel, which is the leak the verb
    # exists to prevent.
    cli_put "env VALLUM_STATE_DIR=$rdir/state $quick_r detach $config" >/dev/null 2>&1 || true
    for _ in $(seq 1 25); do cli_put "ip link show $iface" >/dev/null 2>&1 && break; sleep 0.2; done
    cli_put "ip link show $iface" >/dev/null 2>&1 \
        || bad "$name: detach did not return $iface to the client namespace"
    if cli_put "env VALLUM_STATE_DIR=$rdir/state $quick_r app $config late -- true" \
        > "$dir/app-late.log" 2>&1; then
        bad "$name: app launched after detach"
    fi
    ok "$name: detach returned the device and the verb refuses to launch"

    # The daemon is left stopped on purpose: the next transport starts its own,
    # and a live one would hold the device this case moved around.
    rsh "sudo pkill -f '[v]allum run --config $config'" >/dev/null 2>&1
    for _ in $(seq 1 25); do cli_put "ip link show $iface" >/dev/null 2>&1 || break; sleep 0.2; done
}

for kind in $TRANSPORTS; do
    name="laptop-$kind"
    dir="$LOCAL_DIR/$kind"
    rm -rf "$dir" && mkdir -p "$dir"
    # The enrolment half runs as the invoking user (their SSH keys, and `setup`
    # writes here instead of /etc/vallum). Only needed when the script itself
    # was invoked under sudo; without sudo the directories are already theirs.
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
        chown "$SUDO_USER" "$LOCAL_DIR" "$dir"
    fi
    say "transport: $kind"
    case "$kind" in
        bundle) enrol_bundle "$name" "$dir" ;;
        ssh)    enrol_ssh "$name" "$dir" ;;
        token)  enrol_token "$name" "$dir" ;;
        *) bad "unknown transport: $kind (bundle, ssh, token)" ;;
    esac
    ok "$kind: client config produced"
    prove_client "$name" "$dir"
done

if [ "$UPGRADE" = 1 ]; then
    name="laptop-bundle"
    dir="$LOCAL_DIR/bundle"
    say "upgrading the remote to this tree"
    rsh "sudo install -m0755 $REMOTE_DIR/vallum /usr/bin/vallum && \
         sudo install -m0755 $REMOTE_DIR/vallum-quick /usr/bin/vallum-quick && \
         for u in vallum@.service vallum-quick@.service vallum-quick-watch@.service vallum-enroll@.service; do \
             sudo install -m0644 $REMOTE_DIR/\$u /etc/systemd/system/\$u; \
         done && sudo systemctl daemon-reload && \
         sudo systemctl restart vallum@vallumrc vallum-quick@vallumrc vallum-quick-watch@vallumrc" || bad "binary+unit upgrade"
    # /run/vallum is 0750 root:root — an unprivileged stat never sees the
    # socket even when the daemon is healthy. Probe as root, and on failure
    # show the journal rather than a bare FAIL.
    for _ in $(seq 1 20); do
        rsh "sudo test -S /run/vallum/vallumrc.sock" 2>/dev/null && break
        sleep 0.5
    done
    rsh "sudo test -S /run/vallum/vallumrc.sock" \
        || { rsh "sudo journalctl -u vallum@vallumrc -u vallum-quick@vallumrc --since '-3min' --no-pager | tail -20"
             bad "the upgraded daemon did not come up over the old config"; }
    rsh "sudo /usr/bin/vallum peer list --config $CONFIG" | grep -q "$name" \
        || bad "peer state lost in the upgrade"
    ok "new binaries run the old config; peers intact"
    say "proving the tunnel again on the upgraded daemon"
    prove_client "$name" "$dir"
    ok "the tunnel survives an in-place upgrade"
fi

if [ "$APP_CLASS" = 1 ]; then
    prove_app_class_ns "laptop-bundle"
fi

if [ "$NAMESPACED" = 1 ]; then
    say "PASS — a real server, real egress, a client proved inside a remote namespace, three enrolment transports"
else
    say "PASS — a real client, a real server, real egress, three enrolment transports"
fi

# The stamp scripts/release.sh requires. It lives outside the repository and
# names the commit it proved, so an old pass cannot vouch for a new tree. The
# record is structured rather than a bare hash: it names the remote host, the
# time, the operator and a hash of this script, because a two-host claim the
# artefact does not encode is a claim the artefact cannot back.
STAMP=$(verified_stamp)
mkdir -p "$(dirname "$STAMP")"
cat > "$STAMP" <<EOF
{
  "commit": "$(git rev-parse HEAD)",
  "remote_host": "$TARGET",
  "namespaced": $([ "$NAMESPACED" = 1 ] && echo true || echo false),
  "assertions": $ASSERTIONS,
  "invoked_by": "$(id -un 2>/dev/null || echo unknown)@$(hostname 2>/dev/null || echo unknown)",
  "script_sha256": "$(sha256sum "$0" 2>/dev/null | cut -d' ' -f1)",
  "backup_archive": "${BACKUP_ARCHIVE:-none}",
  "recorded_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
chown -R "${SUDO_USER:-root}" "$(dirname "$STAMP")" 2>/dev/null
# The note names the archive a `--clean-remote` run destroyed the host to
# prove: whoever reads this record later can see whether a deployment had to be
# restored, and from what.
if [ -n "$BACKUP_ARCHIVE" ]; then
    VERDICT_NOTE="pre-run deployment copied to $BACKUP_ARCHIVE" \
        VERDICT_TARGET="$TARGET" "$(dirname "$0")/verdict.sh" verify-remote passed "$ASSERTIONS" "$0"
else
    VERDICT_TARGET="$TARGET" "$(dirname "$0")/verdict.sh" verify-remote passed "$ASSERTIONS" "$0"
fi
if [ "$NAMESPACED" = 1 ]; then
    say "recorded $(git rev-parse --short HEAD) as verified against $TARGET (namespaced, $ASSERTIONS assertions)"
else
    say "recorded $(git rev-parse --short HEAD) as verified on two hosts ($ASSERTIONS assertions)"
fi
if [ -n "$BACKUP_ARCHIVE" ]; then
    note "this run removed the host's deployment; it is at $BACKUP_ARCHIVE on $TARGET"
    note "restore with: ssh $TARGET sudo tar -xzpf $BACKUP_ARCHIVE -C / && sudo systemctl daemon-reload"
fi
