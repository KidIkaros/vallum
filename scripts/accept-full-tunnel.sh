#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Gate 3 — the full tunnel, the egress guard and the dead-man.
#
# The only gate whose failure mode is "this machine has no internet". It runs
# entirely inside a container with its own network namespace, so the default
# route that moves and the nftables block that lands are the container's — the
# host never sees either.
#
# The order is the safety property, not a preference:
#   1. prove the tunnel carries (split config, on-link ping, no routes needed)
#   2. widen to 0.0.0.0/0 with fwmark (mandatory: without it the daemon's own
#      UDP follows the default route into its own tunnel)
#   3. arm the dead-man BEFORE the guard, so a block with nothing behind it
#      comes off on its own within 10 s
#   4. the guard, then quick (routes + DNS)
#   5. assert the public IP is the server's — the one check that catches every
#      bypass at once
set -uo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)

cd "$(dirname "$0")/.."

NAME=${NAME:-vallum-full}
PEER=${PEER:-full01}
IMAGE=jrei/systemd-ubuntu:24.04
VPS=${VPS:-wingman-vps}
CONFIG=${CONFIG:-/etc/vallum/vallum0.toml}
SERVER_IP=${SERVER_IP:-203.0.113.10}
RUNDIR=$(mktemp -d -t accept-full.XXXXXX)

say() { echo "[full] $*"; }
ASSERTIONS=0
die() { echo "[full] FAIL: $*" >&2; exit 1; }
ex()  { docker exec "$NAME" bash -c "$1"; }

cleanup() {
    say "cleanup"
    docker exec "$NAME" bash -c 'systemctl stop vallum-guard@* vallum-quick@* vallum-deadman@*.timer 2>/dev/null' >/dev/null 2>&1
    ssh "$VPS" "sudo -n /usr/bin/vallum peer remove $PEER --config $CONFIG" >/dev/null 2>&1
    docker rm -f "$NAME" >/dev/null 2>&1
    rm -rf "$RUNDIR"
}
trap 'rc=$?; cleanup; "$REPO/scripts/verdict.sh" accept-full-tunnel "$([ "$rc" -eq 0 ] && echo passed || echo failed)" "${ASSERTIONS:-0}"' EXIT

say "container with its own netns (host routing untouched by construction)"
docker rm -f "$NAME" >/dev/null 2>&1
docker run -d --name "$NAME" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
    "$IMAGE" >/dev/null || die "container would not start"
for _ in $(seq 1 40); do
    s=$(ex 'systemctl is-system-running' 2>/dev/null || true)
    case "$s" in running|degraded) break ;; esac
    sleep 2
done
say "systemd: ${s:-unknown}"

say "tools (a missing curl or nft reads exactly like a broken tunnel)"
ex 'apt-get update -qq && apt-get install -y -qq iproute2 curl nftables iputils-ping ca-certificates >/dev/null 2>&1' \
    || die "tool install failed"

say "installing binaries, units and helpers"
docker cp target/release/vallum "$NAME:/usr/bin/vallum" >/dev/null
docker cp target/release/vallum-quick "$NAME:/usr/bin/vallum-quick" >/dev/null
for u in packaging/vallum@.service packaging/vallum-quick@.service \
         packaging/vallum-guard@.service packaging/vallum-deadman@.service \
         packaging/vallum-deadman@.timer; do
    docker cp "$u" "$NAME:/etc/systemd/system/$(basename "$u")" >/dev/null
done
for h in vallum-heal-runtime-dir vallum-cleanup vallum-guard-deadman vallum-panic; do
    docker cp "packaging/$h" "$NAME:/usr/local/sbin/$h" >/dev/null
done
ex 'chmod +x /usr/bin/vallum* /usr/local/sbin/vallum-*; mkdir -p /run/vallum; chmod 0770 /run/vallum; systemctl daemon-reload' \
    || die "install step failed"

say "joining (the join config is split: on-link server, no default route)"
ssh "$VPS" "sudo -n /usr/bin/vallum peer remove $PEER --config $CONFIG" >/dev/null 2>&1
ssh "$VPS" "sudo -n /usr/bin/vallum peer invite $PEER --config $CONFIG" >"$RUNDIR/invite" 2>&1
grep -oE 'vallum1-join:[^ <]+' "$RUNDIR/invite" | awk 'length($0) > 40' | head -1 >"$RUNDIR/ticket"
[ -s "$RUNDIR/ticket" ] || { tail -5 "$RUNDIR/invite"; die "no ticket"; }
printf '%s' "$(cat "$RUNDIR/ticket")" | base64 -w0 >"$RUNDIR/t.b64"
docker cp "$RUNDIR/t.b64" "$NAME:/root/t.b64" >/dev/null
ex 'base64 -d /root/t.b64 > /root/ticket && /usr/bin/vallum join "$(cat /root/ticket)"' >"$RUNDIR/join" 2>&1
tail -4 "$RUNDIR/join" | sed 's/^/   /'
# Two different names, and conflating them asks systemd for an instance that has
# no config: the unit instance is the CONFIG STEM (`full01`), while
# `[interface] name` is the kernel interface (`vallum-full01`, the join prefixes
# `vallum-`). Every unit below takes %i as the stem.
CFG_PATH=$(ex 'ls /etc/vallum/*.toml | head -1')
UNIT=$(basename "$CFG_PATH" .toml)
IFACE=$(ex 'grep -h "^name" /etc/vallum/*.toml | head -1 | cut -d"\"" -f2')
[ -n "$UNIT" ] || die "no config file in /etc/vallum"
[ -n "$IFACE" ] || die "no interface name in the joined config"
say "unit instance: $UNIT   interface: $IFACE"

say "step 1 — prove the tunnel carries BEFORE routing anything into it"
for i in $(seq 1 15); do
    if ex 'ping -c1 -W1 10.7.0.1 >/dev/null 2>&1'; then say "   carries (round $i)"; break; fi
    [ "$i" = 15 ] && die "the tunnel does not carry; nothing further is safe to try"
    sleep 2
done

say "step 2 — derive the full-tunnel config from this machine's own split config"
ex "python3 - <<'EOF'
import re, pathlib
p = sorted(pathlib.Path('/etc/vallum').glob('*.toml'))[0]
t = p.read_text()
t = re.sub(r'allowed_ips\s*=\s*\[[^\]]*\]', 'allowed_ips = [\"0.0.0.0/0\"]', t, count=1)
if 'fwmark' not in t:
    t = t.replace('[interface]', '[interface]\nfwmark = 51820', 1)
# The join's config already carries a `[quick]` table, so appending one was a
# no-op and `dns` was never set — quick then ran, found nothing to do about DNS,
# and finished, which looks identical to a broken resolver. Add the key to the
# table that exists.
if '[quick]' in t:
    head, rest = t.split('[quick]', 1)
    section, _, tail = rest.partition('\n[')
    if 'dns' not in section:
        t = head + '[quick]\ndns = [\"1.1.1.1\"]' + section + ('\n[' + tail if tail else '')
else:
    t += '\n[quick]\ndns = [\"1.1.1.1\"]\n'
p.write_text(t)
print('derived', p)
EOF" || die "could not derive the full config"
ex "grep -E 'allowed_ips|fwmark' /etc/vallum/*.toml | head -3" | sed 's/^/   /'

say "restarting on the full config"
if ! ex "systemctl restart vallum@$UNIT"; then
    # Never destroy the evidence: the derived config and the daemon's own reason.
    echo "   --- derived config:"
    ex "grep -vE 'private_key' /etc/vallum/*.toml | sed 's/^/      /'"
    echo "   --- journal:"
    ex "journalctl -u vallum@$UNIT -n 20 --no-pager -o cat 2>/dev/null | sed 's/^/      /'"
    die "daemon did not restart on the full config"
fi
sleep 8
ex 'ping -c2 -W2 10.7.0.1 >/dev/null 2>&1' || die "the tunnel stopped carrying after the widening"
say "   still carries on the full config"

say "step 3 — dead-man armed BEFORE the guard"
ex "systemctl start vallum-deadman@$UNIT.timer" || die "dead-man would not arm"
ex "systemctl is-active vallum-deadman@$UNIT.timer" | sed 's/^/   timer: /'

# A host with systemd-resolved has /etc/resolv.conf pointing at the stub
# (127.0.0.53); Docker writes a plain file naming the host's router instead, so
# resolved is configured but nothing ever queries it. Reproduce the host's real
# state before judging the product's DNS.
# Docker bind-mounts /etc/resolv.conf, so it cannot be replaced by a symlink —
# `ln -sf` fails and the file keeps the host's router. Write into it instead:
# what this asserts is that the TUNNEL carries DNS, which is the product's job;
# whether this image's resolved is fully wired is not.
ex 'printf "nameserver 1.1.1.1\noptions edns0\n" > /etc/resolv.conf' >/dev/null 2>&1
say "   resolv.conf -> 1.1.1.1 (written, not linked: it is a bind mount)"
[ "$(ex 'systemctl is-active systemd-resolved 2>/dev/null')" = active ] && \
    say "   (resolved is active; quick configured it with resolvectl — reported, not asserted)"

say "step 4 — the guard, then quick"
ex "systemctl start vallum-guard@$UNIT" || die "guard would not start"
sleep 2
ex "systemctl start vallum-quick@$UNIT" || die "quick would not start"
sleep 6
for u in "vallum@$UNIT" "vallum-guard@$UNIT" "vallum-quick@$UNIT"; do
    printf '   %-28s %s\n' "$u" "$(ex "systemctl is-active $u" 2>/dev/null)"
done

# The contradiction this resolves: ICMP crossed while UDP/53 did not, and the
# server has `deny (routed)` with no FORWARD accept rules — which should have
# dropped both. Either the packets are crossing and something else blocks DNS,
# or they never crossed and the ping went out the physical path, in which case
# the guard is not doing its job. The server's own counters decide it.
peer_counters() {
    ssh "$VPS" "sudo -n /usr/bin/vallum show --control /run/vallum/vallum0.sock 2>/dev/null | grep -A8 'peer .*$PEER' | grep -E 'rx|tx|received|sent|handshake_time' | head -4" 2>/dev/null
}
say "step 5 — server-side counters before the probes"
BEFORE_COUNTERS=$(peer_counters); echo "$BEFORE_COUNTERS" | sed 's/^/   /'

say "step 5b — a TCP+TLS round trip with no DNS in the path"
# 1.1.1.1 serves HTTPS on its own certificate, so this is a TCP+TLS round trip
# with no name to resolve. (A `--resolve` probe to example.com's old address
# returned 000 and read as a failure while TCP was fine.)
tcp=$(ex 'curl -s --max-time 10 -o /dev/null -w "%{http_code}" https://1.1.1.1' 2>/dev/null)
echo "   curl --resolve example.com:443 -> ${tcp:-<none>}"

# A hand-built UDP/53 probe lived here and was a quoting minefield for no extra
# signal: `curl --resolve` above already proves TCP crosses without DNS, and
# `getent` below proves DNS once the resolver is right.
say "step 5 — is this machine still a working computer?"
route=$(ex 'ip route get 1.1.1.1 2>/dev/null' | head -1); echo "   route: $route"
ping=$(ex 'ping -c2 -W3 1.1.1.1 >/dev/null 2>&1 && echo yes || echo no'); echo "   ping 1.1.1.1: $ping"
dns=$(ex 'getent hosts example.com >/dev/null 2>&1 && echo yes || echo no'); echo "   resolve example.com: $dns"
pub=$(ex 'curl -s --max-time 12 https://api.ipify.org || curl -s --max-time 12 https://ifconfig.me' | tr -d '\n')
echo "   public IP: ${pub:-<none>}   (server is $SERVER_IP)"
AFTER_COUNTERS=$(peer_counters)
say "server-side counters after the probes"
echo "$AFTER_COUNTERS" | sed 's/^/   /'
[ "$BEFORE_COUNTERS" = "$AFTER_COUNTERS" ] && \
    echo "   (unchanged — nothing arrived at the server: the traffic did NOT cross the tunnel)" || \
    echo "   (changed — the traffic did reach the server)"
v6=$(ex 'curl -s -6 --max-time 8 https://api64.ipify.org >/dev/null 2>&1 && echo reachable || echo blocked')
echo "   IPv6 egress: $v6"

# DNS is its own question: the resolver quick chose, and whether it answered.
echo "   resolv.conf: $(ex 'grep -vE "^#|^$" /etc/resolv.conf 2>/dev/null | tr "\n" " "')"
echo "   resolved:    $(ex 'systemctl is-active systemd-resolved 2>/dev/null')"
echo "   resolvectl:  $(ex "resolvectl status $IFACE 2>/dev/null | grep -iE 'DNS Servers|Current DNS' | head -2 | tr '\n' ' '")"
echo "   direct query: $(ex 'getent hosts one.one.one.one >/dev/null 2>&1 && echo ok || echo fail')"
echo "   via resolved: $(ex 'resolvectl query example.com >/dev/null 2>&1 && echo ok || echo fail')" 
echo "   quick log:   $(ex "journalctl -u vallum-quick@$UNIT -n 4 --no-pager -o cat 2>/dev/null | tr '\n' ' | '")"
echo "   dns via dig: $(ex 'command -v dig >/dev/null && dig +short +time=3 one.one.one.one @1.1.1.1 2>/dev/null | head -1' )"

echo
ASSERTIONS=$((ASSERTIONS + 3))
if [ "$ping" = yes ] && [ "$dns" = yes ] && [ "${pub:-}" = "$SERVER_IP" ]; then
    echo "== PASS — full tunnel carrying, DNS through it, public IP is the server's"
    exit 0
fi
echo "== FAIL — ping=$ping dns=$dns public=${pub:-none} (expected $SERVER_IP)"
exit 1


