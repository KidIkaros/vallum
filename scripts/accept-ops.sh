#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Gate: the dispatcher's decisions, exercised where they cannot hurt anyone.
#
# packaging/vallum-ops is the one NOPASSWD grant the consoles hold. Its job is
# to turn a name the operator typed into the unit or config that name means —
# and the bugs it has already had were all in that mapping: a config-less name
# once fell back onto the live tunnel, and a refusal inside $(...) once kept
# running anyway. Those were verified by hand on a production server. This gate
# makes them repeatable: the helpers sourced directly, then the verbs through
# the dispatcher, inside a clean systemd container where a mistake costs
# nothing.
#
#   scripts/accept-ops.sh          # no arguments, no production, no secrets
#
set -uo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
trap 'rc=$?; command -v cleanup >/dev/null 2>&1 && cleanup; "$REPO/scripts/verdict.sh" accept-ops "$([ "$rc" -eq 0 ] && echo passed || echo failed)" "${ASSERTIONS:-0}" "$0"' EXIT
ASSERTIONS=0

say() { echo "[ops] $*"; }
die() { echo "[ops] FAIL: $*" >&2; exit 1; }
ok()  { ASSERTIONS=$((ASSERTIONS+1)); printf '   ok    %s\n' "$*"; }

NAME=vallum-ops-test
WORK=$(mktemp -d -t vallum-ops.XXXXXX)

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1
    rm -rf "$WORK"
}

say "starting a clean systemd container (same image as accept-install)"
docker rm -f "$NAME" >/dev/null 2>&1
docker run -d --name "$NAME" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
    jrei/systemd-ubuntu:24.04 \
    || die "container would not start"

for _ in $(seq 1 40); do
    state=$(docker exec "$NAME" systemctl is-system-running 2>/dev/null || true)
    [ "$state" = "running" ] || [ "$state" = "degraded" ] && break
    sleep 2
done
say "systemd: $(docker exec "$NAME" systemctl is-system-running 2>/dev/null || echo unknown)"

say "installing the dispatcher, the unit templates, and two config fixtures"
# vallum-ops only checks that a config exists (-f), so an empty file is a
# fixture; the unit templates are what `enable`/`disable` aim at.
docker exec "$NAME" mkdir -p /etc/vallum /etc/systemd/system
docker exec "$NAME" bash -c 'touch /etc/vallum/vallum0.toml /etc/vallum/second.toml'
docker cp "$REPO/packaging/vallum-ops" "$NAME:/usr/local/sbin/vallum-ops" >/dev/null
docker exec "$NAME" chmod 755 /usr/local/sbin/vallum-ops
for u in vallum@.service vallum-quick@.service vallum-quick-watch@.service \
    vallum-guard@.service vallum-enroll@.service; do
    docker cp "$REPO/packaging/$u" "$NAME:/etc/systemd/system/$u" >/dev/null
done
docker exec "$NAME" systemctl daemon-reload

# The helper layer, sourced. Everything before the `case` is assignments and
# function definitions, so the preamble can be sourced without dispatching.
cat > "$WORK/helpers.sh" <<'EOF'
source <(awk '/^case /{exit} {print}' /usr/local/sbin/vallum-ops)

# require_iface answers with `exit 2`, so a negative check must run it in a
# subshell — the same reason conf_or_fail had to stop using exit inside $(...).
refuses2() { ( "$@" ) >/dev/null 2>&1; [ $? -eq 2 ]; }

require_iface vallum0               || { echo "require_iface refused a good name"; exit 1; }
refuses2 require_iface 'bad;name'   || { echo "require_iface took a metachar"; exit 1; }
refuses2 require_iface 'this-name-is-far-too-long' || { echo "require_iface took >15"; exit 1; }
refuses2 require_iface '-x'         || { echo "require_iface took a flag"; exit 1; }

[ "$(resolve_conf second)" = "/etc/vallum/second.toml" ]        || { echo "resolve_conf missed an exact match"; exit 1; }
[ "$(resolve_conf vallum-second)" = "/etc/vallum/second.toml" ] || { echo "resolve_conf missed the vallum- prefix strip"; exit 1; }
[ "$(resolve_conf ghost)" = "/etc/vallum/second.toml" ]         || { echo "resolve_conf lost its documented first-config fallback"; exit 1; }

[ "$(stem_or_self ghost)" = "ghost" ]     || { echo "stem_or_self did not keep a config-less name verbatim"; exit 1; }
[ "$(stem_or_self second)" = "second" ]   || { echo "stem_or_self mis-resolved a configured name"; exit 1; }

# The refusal must be silent on stdout: callers run this in $(...) and would
# use whatever a stray path printed.
out=$(conf_or_fail ghost 2>/dev/null) && { echo "conf_or_fail resolved a config-less name"; exit 1; }
[ -z "$out" ] || { echo "conf_or_fail printed a path while refusing"; exit 1; }
[ "$(conf_or_fail vallum0)" = "/etc/vallum/vallum0.toml" ] || { echo "conf_or_fail refused the default name"; exit 1; }
echo "helpers: PASS"
EOF
docker cp "$WORK/helpers.sh" "$NAME:/root/helpers.sh" >/dev/null
docker exec "$NAME" bash /root/helpers.sh | grep -q 'helpers: PASS' \
    || die "helper assertions failed inside the container"
ok "the name→stem→config helpers: refusal, verbatim stems, prefix strip, documented fallback"

say "dispatcher: a config-less name must refuse, never retarget"
out=$(docker exec "$NAME" vallum-ops enable ghost 2>&1); rc=$?
[ "$rc" -eq 1 ] && printf '%s' "$out" | grep -q "no config for 'ghost'" \
    || die "enable ghost: rc=$rc out=$out"
ok "enable ghost refuses (rc=1) and names the missing config"
docker exec "$NAME" bash -c 'ls /etc/systemd/system/*.wants/vallum@ghost.service 2>/dev/null' && \
    die "enable ghost still created a symlink" || \
    ok "enable ghost created no unit symlink"

say "dispatcher: the happy path enables the lifecycle trio"
docker exec "$NAME" vallum-ops enable vallum0 >/dev/null \
    || die "enable vallum0 failed"
for u in vallum vallum-quick vallum-quick-watch; do
    docker exec "$NAME" bash -c "ls /etc/systemd/system/*.wants/$u@vallum0.service >/dev/null 2>&1" \
        || die "enable vallum0 did not link $u@vallum0"
done
ok "enable vallum0 linked vallum@, vallum-quick@ and vallum-quick-watch@"

say "dispatcher: retiring a leftover unit must not touch the live tunnel"
# The regression this gate exists for: pre-fix, `disable ghost` resolved
# ghost → vallum0 and stripped the live tunnel's boot links.
docker exec "$NAME" vallum-ops disable ghost >/dev/null \
    || die "disable ghost failed"
docker exec "$NAME" bash -c 'ls /etc/systemd/system/*.wants/vallum@vallum0.service >/dev/null 2>&1' \
    || die "disable ghost stripped vallum@vallum0 — the resolve_conf footgun is back"
docker exec "$NAME" bash -c 'ls /etc/systemd/system/*.wants/vallum-quick@vallum0.service >/dev/null 2>&1' \
    || die "disable ghost stripped vallum-quick@vallum0"
ok "disable ghost left every vallum0 boot link in place"

say "dispatcher: a second config resolves to its own stem"
docker exec "$NAME" vallum-ops enable second >/dev/null \
    || die "enable second failed"
docker exec "$NAME" bash -c 'ls /etc/systemd/system/*.wants/vallum@second.service >/dev/null 2>&1' \
    || die "enable second linked the wrong stem"
ok "enable second linked vallum@second, not vallum@vallum0"

say "dispatcher: service aims at the verbatim stem, not the fallback"
# No /usr/bin/vallum exists in this container, so any start fails — what
# matters is WHICH unit record systemd creates. The unit auto-restarts, so
# `is-failed` races the retry loop; poll until the burst settles to failed.
docker exec "$NAME" vallum-ops service start ghost >/dev/null 2>&1 || true
settled=""
for _ in $(seq 1 15); do
    [ "$(docker exec "$NAME" systemctl is-failed vallum@ghost 2>/dev/null)" = "failed" ] \
        && { settled=yes; break; }
    sleep 1
done
[ -n "$settled" ] \
    || die "service start ghost left no vallum@ghost failure — it aimed elsewhere"
[ -z "$(docker exec "$NAME" systemctl show vallum@vallum0.service -p ActiveEnterTimestamp --value 2>/dev/null)" ] \
    || die "service start ghost started vallum@vallum0 — retargeted the live tunnel"
ok "service start ghost failed against vallum@ghost and never touched vallum@vallum0"
docker exec "$NAME" systemctl reset-failed vallum@ghost >/dev/null 2>&1 || true

say "dispatcher: config-verbs refuse a config-less name through every door"
out=$(docker exec "$NAME" vallum-ops invite peer1 60 ghost 2>&1); rc=$?
[ "$rc" -eq 1 ] && printf '%s' "$out" | grep -q "no config for 'ghost'" \
    || die "invite on ghost: rc=$rc out=$out"
ok "invite ... ghost refuses before minting anything"
out=$(docker exec "$NAME" vallum-ops revert ghost 2>&1); rc=$?
[ "$rc" -eq 1 ] && printf '%s' "$out" | grep -q "no config for 'ghost'" \
    || die "revert ghost: rc=$rc out=$out"
ok "revert ghost refuses before any panic/restore"

say "dispatcher: name validation reaches the front door"
docker exec "$NAME" vallum-ops status 'bad;name' >/dev/null 2>&1
[ $? -eq 2 ] || die "status accepted a metacharacter name"
ok "a metacharacter interface name exits 2 at the dispatcher"

say "cleanup"
printf '== PASS - the dispatcher resolves names the way its comments claim\n'
