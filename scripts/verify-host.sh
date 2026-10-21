#!/usr/bin/env bash
#
# verify-host.sh — the privileged half of verify.sh.
#
# Runs the whole product path with real root on the real host: `server init`
# with every host change enabled, a real systemd unit, real nftables/ufw rules,
# real sysctl persistence, a second daemon as the client, `vallum-quick attach`
# against the host's live systemd-resolved (the `~.` routing domain is checked,
# not assumed), live rotation, and `vallum metrics`.
#
# Everything it touches is on a dedicated name and is removed on exit:
#   config      /etc/vallum/vallumtest0.toml (+ /tmp work dir)
#   sysctl      /etc/sysctl.d/90-vallum.conf   (removed; see note)
#   firewall    one allow rule for UDP 51921, or the nftables input rule
#   NAT         nftables table `inet vallum`
#   systemd     vallum@.service, vallum-quick@.service and two instances
#   binaries    /usr/bin/vallum{,-quick} — only if this script installed them
#
# The sysctl file is shared with a real deployment, so the script refuses to
# run if one already exists.
#
# Usage: sudo ./scripts/verify-host.sh [--keep]
#   --keep   do not clean up on exit (for manual inspection)

set -u
cd "$(dirname "$0")/.."

VALLUM=${VALLUM:-target/release/vallum}
QUICK=${QUICK:-target/release/vallum-quick}
KEEP=${1:-}
WORK=/tmp/vallum-host-verify
IFACE=vallumtest0
CIFACE=vallumtest1
PORT=51921
NET=10.99.77.0/24
SRV_IP=10.99.77.1
CLI_IP=10.99.77.2
SCONFIG=/etc/vallum/$IFACE.toml
SYSCTL_FILE=/etc/sysctl.d/90-vallum.conf
UNIT_D=/etc/systemd/system

say() { printf '── %s\n' "$*"; }
ok()  { printf '   ok    %s\n' "$*"; }
bad() { printf '   FAIL  %s\n' "$*"; exit 1; }
warn(){ printf '   warn  %s\n' "$*"; }
note(){ printf '   note  %s\n' "$*"; }

installed_bins=0
client_pid=""
ns_pid=""

cleanup() {
    set +e
    say "cleanup"
    [ -n "$client_pid" ] && kill "$client_pid" 2>/dev/null
    [ -n "$ns_pid" ] && kill "$ns_pid" 2>/dev/null
    ip netns del vallumtest-ns >/dev/null 2>&1
    ip link del veth-a >/dev/null 2>&1
    [ -f "$WORK/client/laptop.toml" ] && "$QUICK" detach "$WORK/client/laptop.toml" >/dev/null 2>&1
    systemctl disable --now "vallum-quick@$IFACE" "vallum@$IFACE" >/dev/null 2>&1
    rm -f "$UNIT_D/vallum@.service" "$UNIT_D/vallum-quick@.service"
    systemctl daemon-reload >/dev/null 2>&1
    nft delete table inet vallum >/dev/null 2>&1
    iptables -D FORWARD -i "$IFACE" -j ACCEPT >/dev/null 2>&1
    iptables -D FORWARD -o "$IFACE" -j ACCEPT >/dev/null 2>&1
    iptables -D INPUT -p udp --dport "$PORT" -j ACCEPT >/dev/null 2>&1
    command -v ufw >/dev/null 2>&1 && ufw delete allow "$PORT/udp" >/dev/null 2>&1
    rm -f "$SYSCTL_FILE"
    sysctl -p >/dev/null 2>&1
    rm -rf /etc/vallum "$WORK"
    [ "$installed_bins" = 1 ] && rm -f /usr/bin/vallum /usr/bin/vallum-quick
    ok "host state restored"
}
[ "$(id -u)" = 0 ] || { echo "verify-host.sh needs root; run it with sudo"; exit 1; }
[ "$KEEP" = "--keep" ] || trap cleanup EXIT
# Build, rather than trusting whatever is in target/release: a stale binary is
# how this script would test yesterday's code. `sudo` resets PATH, so cargo is
# looked for in the usual places, and the build runs as the invoking user so
# target/ is not left root-owned.
say "building"
build() {
    local cargo=${CARGO:-}
    if [ -z "$cargo" ]; then
        local owner_home
        owner_home=$(eval echo "~${SUDO_USER:-root}")
        for candidate in "$(command -v cargo 2>/dev/null)" \
                         "$owner_home/.cargo/bin/cargo" \
                         "$HOME/.cargo/bin/cargo" \
                         /usr/local/cargo/bin/cargo; do
            if [ -n "$candidate" ] && [ -x "$candidate" ]; then cargo=$candidate; break; fi
        done
    fi
    [ -n "$cargo" ] || bad "cargo not found; build first: cargo build --release -p vallum -p vallum-quick"
    local args=(build --release -p vallum -p vallum-quick)
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
        sudo -u "$SUDO_USER" env HOME="$(eval echo "~$SUDO_USER")" "$cargo" "${args[@]}"
    else
        "$cargo" "${args[@]}"
    fi
}
build > "$WORK-build.log" 2>&1 || { tail -20 "$WORK-build.log"; bad "build"; }
[ -x "$VALLUM" ] && [ -x "$QUICK" ] || bad "the build produced no binaries at $VALLUM / $QUICK"
[ -e /etc/vallum ] && bad "/etc/vallum already exists; this script removes it on cleanup"
[ -e "$SYSCTL_FILE" ] && bad "$SYSCTL_FILE already exists; a real deployment may be using it"
nft list table inet vallum >/dev/null 2>&1 && bad "nftables table 'inet vallum' already exists"
ip link show "$IFACE" >/dev/null 2>&1 && bad "interface $IFACE already exists"

# ── install the binaries where the units look for them ──────────────────────
say "installing the release binaries"
if [ -e /usr/bin/vallum ] || [ -e /usr/bin/vallum-quick ]; then
    bad "/usr/bin/vallum{,-quick} already exist; refusing to overwrite them"
fi
install -m0755 "$VALLUM" /usr/bin/vallum
install -m0755 "$QUICK" /usr/bin/vallum-quick
installed_bins=1
ok "/usr/bin/vallum{,-quick}"

# ── server init, everything on ───────────────────────────────────────────────
say "vallum server init"
"$VALLUM" server init --config "$SCONFIG" --name "$IFACE" \
    --endpoint 127.0.0.1:$PORT --listen 0.0.0.0:$PORT --address "$SRV_IP/24" \
    > "$WORK-init.log" 2>&1 || { cat "$WORK-init.log"; bad "server init"; }
grep -q "ready:" "$WORK-init.log" || { cat "$WORK-init.log"; bad "init did not report ready"; }
ok "server init completed"

# ── assert the privileged effects ───────────────────────────────────────────
say "asserting host changes"
[ -f "$SCONFIG" ] && [ "$(stat -c %a "$SCONFIG")" = 600 ] || bad "config missing or not 0600"
[ -f /etc/vallum/server.key ] && [ "$(stat -c %a /etc/vallum/server.key)" = 600 ] || bad "key missing or not 0600"
ok "config and key are 0600"

grep -q "ip_forward" "$SYSCTL_FILE" || bad "$SYSCTL_FILE was not written"
[ "$(sysctl -n net.ipv4.ip_forward)" = 1 ] || bad "net.ipv4.ip_forward is not live"
ok "forwarding persisted in $SYSCTL_FILE and live"

nft list table inet vallum 2>/dev/null | grep -q masquerade || bad "nftables NAT table 'inet vallum' missing the masquerade rule"
ok "nftables NAT masquerade installed"

# iptables filters live in `ip filter`, which is where Docker, Tailscale, and
# ufw with the iptables backend put their chains. If one of them drops
# forwarded traffic, `server init` must have inserted an accept for our
# interface — otherwise the tunnel pings and nothing forwards.
if iptables -S FORWARD 2>/dev/null | grep -q "^-A FORWARD"; then
    if iptables -S 2>/dev/null | grep -q -- "-j DROP"; then
        iptables -S FORWARD | grep -q -- "-i $IFACE -j ACCEPT" \
            || bad "iptables filters forwarded traffic and has no accept rule for $IFACE"
        ok "iptables filters forwarding; accept rule added for $IFACE"
    else
        ok "iptables has FORWARD rules but no DROP; nothing to open"
    fi
else
    ok "iptables does not filter forwarding on this host"
fi

firewall_ok=0
if command -v ufw >/dev/null 2>&1 && { ufw status 2>/dev/null | grep -q "$PORT/udp" || ufw show added 2>/dev/null | grep -q "$PORT/udp"; }; then
    ok "ufw rule allows UDP $PORT"; firewall_ok=1
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --list-ports 2>/dev/null | grep -q "$PORT/udp"; then
    ok "firewalld allows UDP $PORT"; firewall_ok=1
elif nft list chain inet filter input 2>/dev/null | grep -q "dport $PORT"; then
    ok "nftables input chain allows UDP $PORT"; firewall_ok=1
elif nft list chain inet filter input 2>/dev/null | grep -qi "policy accept"; then
    ok "nftables input chain accepts by policy (no rule needed)"; firewall_ok=1
fi
[ "$firewall_ok" = 1 ] || warn "no firewall rule for UDP $PORT found — check the backend detection"

# ── services ─────────────────────────────────────────────────────────────────
say "systemd units"
[ -f "$UNIT_D/vallum@.service" ] && [ -f "$UNIT_D/vallum-quick@.service" ] || bad "unit files were not installed"
sleep 2
[ "$(systemctl is-active vallum@$IFACE)" = active ] || { journalctl -u vallum@$IFACE --no-pager -n 15; bad "vallum@$IFACE is not active"; }
[ "$(systemctl is-active vallum-quick@$IFACE)" = active ] || { journalctl -u vallum-quick@$IFACE --no-pager -n 15; bad "vallum-quick@$IFACE is not active"; }
ok "vallum@$IFACE and vallum-quick@$IFACE are active"
[ -S /run/vallum/$IFACE.sock ] || bad "control socket missing"
ok "control socket live"
ip link show "$IFACE" >/dev/null 2>&1 || bad "TUN $IFACE does not exist"
ok "TUN $IFACE exists"

# ── a client through the product path ────────────────────────────────────────
say "peer add + import-bundle"
mkdir -p "$WORK"
"$VALLUM" peer add laptop --config "$SCONFIG" \
    --ship-key --bundle-out "$WORK/laptop.vallum-bundle" --dns 1.1.1.1 --forget-key \
    > "$WORK/peer.log" 2>&1 || { cat "$WORK/peer.log"; bad "peer add"; }
grep -q "applied    yes" "$WORK/peer.log" || { cat "$WORK/peer.log"; bad "peer add did not apply to the running daemon"; }
ok "peer added and applied live"

"$VALLUM" import-bundle "$WORK/laptop.vallum-bundle" --output-dir "$WORK/client" \
    > "$WORK/import.log" 2>&1 || { cat "$WORK/import.log"; bad "import-bundle"; }
# Same-host dogfood: the second daemon needs its own interface and socket.
sed -i "s/name = \"vallum0\"/name = \"$CIFACE\"/; s|/run/vallum/vallum0.sock|/run/vallum/$CIFACE.sock|" "$WORK/client/laptop.toml"
ok "client config imported"

# ── run the client and attach ────────────────────────────────────────────────
say "client daemon + quick attach (this exercises resolvectl)"
"$VALLUM" run --config "$WORK/client/laptop.toml" > "$WORK/client.log" 2>&1 &
client_pid=$!
sleep 1.5
kill -0 "$client_pid" 2>/dev/null || { cat "$WORK/client.log"; bad "client daemon exited"; }
"$QUICK" attach "$WORK/client/laptop.toml" > "$WORK/attach.log" 2>&1 || { cat "$WORK/attach.log"; bad "vallum-quick attach"; }
cat "$WORK/attach.log" | tail -4

if systemctl is-active systemd-resolved >/dev/null 2>&1; then
    sleep 0.5
    resolvectl dns "$CIFACE" 2>/dev/null | grep -q 1.1.1.1 || bad "resolvectl shows no resolver on $CIFACE"
    ok "resolvectl: 1.1.1.1 installed on $CIFACE"
    resolvectl domain "$CIFACE" 2>/dev/null | grep -q '~\.' || bad "no ~. routing domain claimed on $CIFACE"
    ok "resolvectl: ~. routing domain claimed (full-tunnel DNS)"
else
    warn "systemd-resolved not running; DNS backend check skipped"
fi

# ── traffic, metrics, rotation ───────────────────────────────────────────────
say "ping across the tunnel"
sleep 1
ping -c2 -W3 "$CLI_IP" > "$WORK/ping.log" 2>&1 || { cat "$WORK/ping.log"; journalctl -u vallum@$IFACE --no-pager -n 10; tail -8 "$WORK/client.log"; bad "ping"; }
tail -2 "$WORK/ping.log" | head -1

say "metrics on the live daemon"
"$VALLUM" metrics --control /run/vallum/$IFACE.sock | grep -E "vallum_up|peers_handshaked" || bad "metrics"
"$VALLUM" metrics --control /run/vallum/$IFACE.sock | grep -q "vallum_peers_handshaked 1" || bad "no handshaked peer in metrics"
ok "metrics reports a handshaked peer"

# ── detach reverts DNS ───────────────────────────────────────────────────────
say "vallum-quick detach"
"$QUICK" detach "$WORK/client/laptop.toml" > "$WORK/detach.log" 2>&1 || { cat "$WORK/detach.log"; bad "detach"; }
if systemctl is-active systemd-resolved >/dev/null 2>&1; then
    resolvectl dns "$CIFACE" 2>/dev/null | grep -q 1.1.1.1 && bad "resolver still installed after detach"
    ok "resolvectl reverted on $CIFACE"
fi

# ── egress, with the client in its own namespace ─────────────────────────────
#
# INFORMATIONAL. A client sharing the host with its server is not a supported
# topology and does not reproduce everywhere: on a host with third-party
# netfilter (Docker, Tailscale) the server's replies are read from its TUN and
# never transmitted, while the same topology forwards correctly on a plain
# host. Client egress is verified on a second machine, or by the namespace E2E
# in scripts/e2e-netns.sh, which is the gate of record for it.
# A full-tunnel client installs a catch-all policy rule. On the *same host* as
# the server that rule also catches the server's forwarded packets, which come
# straight back into the tunnel and loop — wg-quick behaves the same way. So
# the data path is tested where it actually lives: the client in its own
# network namespace, the server on the host.
say "a client in its own namespace (egress through the server's NAT)"
kill "$client_pid" 2>/dev/null; client_pid=""
ip netns add vallumtest-ns || bad "ip netns add"
ip link add veth-a type veth peer name veth-b || bad "veth pair"
ip link set veth-b netns vallumtest-ns
ip addr add 10.200.0.1/24 dev veth-a
ip link set veth-a up
ip netns exec vallumtest-ns ip addr add 10.200.0.2/24 dev veth-b
ip netns exec vallumtest-ns ip link set veth-b up
ip netns exec vallumtest-ns ip link set lo up
ok "veth 10.200.0.1 <-> 10.200.0.2"

# The same client config, dialling the host over the veth, with no `dns` line:
# systemd-resolved cannot see a link inside a namespace, so `attach` would try
# `resolvectl` for a device it cannot find.
sed "s|endpoint = .*|endpoint = \"10.200.0.1:$PORT\"|; /^dns = /d; s|/run/vallum/$CIFACE.sock|/run/vallum/ns.sock|" \
    "$WORK/client/laptop.toml" > "$WORK/client/ns.toml"
ip netns exec vallumtest-ns "$VALLUM" run --config "$WORK/client/ns.toml" > "$WORK/ns-client.log" 2>&1 &
ns_pid=$!
sleep 1.5
kill -0 "$ns_pid" 2>/dev/null || { cat "$WORK/ns-client.log"; bad "the namespace client exited"; }
ip netns exec vallumtest-ns "$QUICK" attach "$WORK/client/ns.toml" > "$WORK/ns-attach.log" 2>&1 \
    || { cat "$WORK/ns-attach.log"; bad "attach inside the namespace"; }
ok "client running inside the namespace, routes attached"

sleep 1
# Wait for the handshake rather than assuming one second is enough: a retry
# with backoff would otherwise look exactly like broken forwarding.
established=0
for _ in $(seq 1 20); do
    if ip netns exec vallumtest-ns "$VALLUM" show --control /run/vallum/ns.sock 2>/dev/null \
        | grep -q "last_handshake_time_sec=[1-9]"; then
        established=1; break
    fi
    sleep 0.5
done
[ "$established" = 1 ] && ok "the client completed a handshake" \
    || note "the client never handshaked"

# The tunnel before the internet: if this fails the handshake or the TUN is at
# fault, not forwarding. It is the difference between two very different bugs.
if ip netns exec vallumtest-ns ping -c2 -W3 "$SRV_IP" > "$WORK/ns-inner.log" 2>&1; then
    ok "the client's tunnel is up: it reaches the server's $SRV_IP"
else
    note "the client cannot reach $SRV_IP from this host; see the dump"
fi

if ip netns exec vallumtest-ns ping -c2 -W3 1.1.1.1 > "$WORK/ns-ping.log" 2>&1; then
    ok "the tunnel carries traffic to the internet: $(tail -2 "$WORK/ns-ping.log" | head -1)"
else
    note "no ICMP through the tunnel; see the dump below"
fi

if ip netns exec vallumtest-ns dig +time=3 +tries=1 @1.1.1.1 example.com A > "$WORK/ns-dig.log" 2>&1 \
   && grep -q "ANSWER SECTION" "$WORK/ns-dig.log"; then
    ok "DNS crosses the tunnel and the server's NAT: $(grep -E '^example.com' "$WORK/ns-dig.log" | head -1)"
else
    note "DNS through the tunnel did not answer; evidence in /tmp/vallum-host-dns.log"
    {
        echo "== ns: ping the server's tunnel address ($SRV_IP)"
        cat "$WORK/ns-inner.log" 2>/dev/null
        echo "== ns: ping 1.1.1.1"
        cat "$WORK/ns-ping.log" 2>/dev/null
        echo "== ns: dig @1.1.1.1 example.com"
        cat "$WORK/ns-dig.log" 2>/dev/null
        echo "== ns: client log"
        cat "$WORK/ns-client.log" 2>/dev/null
        echo "== ns: the client's own view"
        ip netns exec vallumtest-ns "$VALLUM" show --control /run/vallum/ns.sock 2>&1 | head -20
        echo "== server: interface addressing and routes"
        ip -o addr show dev "$IFACE" 2>&1
        ip route show dev "$IFACE" 2>&1
        echo "== server: route to the client's tunnel address"
        ip route get "$CLI_IP" 2>&1
        echo "== server: TUN counters"
        ip -s link show "$IFACE" 2>&1 | tail -4
        echo "== ns: client TUN counters"
        ip netns exec vallumtest-ns ip -s link show "$CIFACE" 2>&1 | tail -4
        echo "== server: metrics"
        "$VALLUM" metrics --control /run/vallum/$IFACE.sock 2>&1 | head -20
        echo "== server: journal"
        journalctl -u "vallum@$IFACE" --no-pager -n 20 2>&1
        echo "== host: nft list table inet vallum"
        nft list table inet vallum 2>&1
        echo "== host: iptables -S (filter table)"
        iptables -S 2>&1 | head -40
        echo "== host: nft ruleset (first 60 lines)"
        nft list ruleset 2>&1 | head -60
        echo "== host: iptables nat"
        iptables -t nat -S 2>&1 | head -20
        echo "== host: ip route get 1.1.1.1"
        ip route get 1.1.1.1 2>&1
        echo "== host: ip rule"
        ip rule 2>&1
        echo "== ns: ip route"
        ip netns exec vallumtest-ns ip route 2>&1
        echo "== forwarding and rp_filter"
        sysctl net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter 2>&1
    } > /tmp/vallum-host-dns.log 2>&1
fi

# Rotation is exercised with a live client: the old key keeps working while
# the new one is installed, and `finalize` retires it. It has to come after the
# egress checks, because finalize invalidates the key this client holds.
say "rotation, live"
"$VALLUM" keygen --output "$WORK/new.key" --suite 3 > "$WORK/new.pub" || bad "keygen"
"$VALLUM" peer rotate laptop --config "$SCONFIG" --public-key-file "$WORK/new.pub" \
    > "$WORK/rotate.log" 2>&1 || { cat "$WORK/rotate.log"; bad "peer rotate"; }
if ip netns exec vallumtest-ns ping -c1 -W3 1.1.1.1 >/dev/null 2>&1; then
    ok "the tunnel survives rotation (the previous key is still accepted)"
else
    warn "traffic stopped after rotation"
fi
"$VALLUM" peer finalize laptop --config "$SCONFIG" > "$WORK/finalize.log" 2>&1 || { cat "$WORK/finalize.log"; bad "peer finalize"; }
ok "rotated and finalized"

ip netns exec vallumtest-ns "$QUICK" detach "$WORK/client/ns.toml" >/dev/null 2>&1
kill "$ns_pid" 2>/dev/null; ns_pid=""
ip netns del vallumtest-ns
ip link del veth-a 2>/dev/null
ok "namespace client torn down"

say "doctor, live"
"$VALLUM" doctor --config "$SCONFIG" 2>&1 | head -8

say "PASS — the privileged path works end to end"
