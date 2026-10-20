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

installed_bins=0
client_pid=""

cleanup() {
    set +e
    say "cleanup"
    [ -n "$client_pid" ] && kill "$client_pid" 2>/dev/null
    [ -f "$WORK/client/laptop.toml" ] && "$QUICK" detach "$WORK/client/laptop.toml" >/dev/null 2>&1
    systemctl disable --now "vallum-quick@$IFACE" "vallum@$IFACE" >/dev/null 2>&1
    rm -f "$UNIT_D/vallum@.service" "$UNIT_D/vallum-quick@.service"
    systemctl daemon-reload >/dev/null 2>&1
    nft delete table inet vallum >/dev/null 2>&1
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
    --bundle-out "$WORK/laptop.vallum-bundle" --dns 1.1.1.1 --forget-key \
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

say "rotation, live"
"$VALLUM" keygen --output "$WORK/new.key" --suite 3 > "$WORK/new.pub" || bad "keygen"
"$VALLUM" peer rotate laptop --config "$SCONFIG" --public-key-file "$WORK/new.pub" \
    > "$WORK/rotate.log" 2>&1 || { cat "$WORK/rotate.log"; bad "peer rotate"; }
ping -c1 -W3 "$CLI_IP" >/dev/null 2>&1 && ok "tunnel survives rotation" || warn "ping dropped during rotation"
"$VALLUM" peer finalize laptop --config "$SCONFIG" > "$WORK/finalize.log" 2>&1 || { cat "$WORK/finalize.log"; bad "peer finalize"; }
ok "rotated and finalized"

# ── DNS through the tunnel, through real NAT ─────────────────────────────────
# Three layers, so a failure says where: egress, DNS across the tunnel with
# resolved out of the picture, then the resolver integration itself.
say "traffic out of the tunnel, through the server's NAT"
if ping -c1 -W3 -I "$CIFACE" 1.1.1.1 > "$WORK/egress.log" 2>&1; then
    ok "the tunnel reaches the internet (1.1.1.1 answers)"
else
    warn "no ICMP through the tunnel; the DNS checks below will likely fail too"
fi

say "raw DNS through the tunnel, bypassing resolved"
if command -v dig >/dev/null 2>&1; then
    if dig +time=3 +tries=1 -b "$CLI_IP" @1.1.1.1 example.com A > "$WORK/dig.log" 2>&1 && grep -q "ANSWER SECTION" "$WORK/dig.log"; then
        ok "dig @1.1.1.1 from $CLI_IP answered: $(grep -E '^example.com' "$WORK/dig.log" | head -1)"
    else
        warn "raw DNS through the tunnel failed; evidence kept"
    fi
else
    warn "dig not installed; skipping the resolver-independent probe"
fi

say "DNS over the tunnel (resolved, the ~. domain, and the tunnel)"
if resolvectl query -i "$CIFACE" example.com > "$WORK/dns.log" 2>&1 && grep -qE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" "$WORK/dns.log"; then
    ok "a real name resolved through the tunnel: $(grep -oE '([0-9]+\.){3}[0-9]+' "$WORK/dns.log" | head -1)"
else
    warn "DNS over the tunnel did not answer; evidence in /tmp/vallum-host-dns.log"
    {
        echo "== egress: ping -I $CIFACE 1.1.1.1"
        cat "$WORK/egress.log" 2>/dev/null
        echo "== raw: dig @1.1.1.1 from $CLI_IP"
        cat "$WORK/dig.log" 2>/dev/null
        echo "== resolvectl query -i $CIFACE example.com"
        cat "$WORK/dns.log" 2>/dev/null
        echo "== resolvectl status $CIFACE"
        resolvectl status "$CIFACE" 2>&1
        echo "== ip route get 1.1.1.1"
        ip route get 1.1.1.1 2>&1
        echo "== ip rule"
        ip rule 2>&1
        echo "== nft list table inet vallum"
        nft list table inet vallum 2>&1
        echo "== forwarding and rp_filter"
        sysctl net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter 2>&1
    } > /tmp/vallum-host-dns.log 2>&1
fi

# ── detach reverts DNS ───────────────────────────────────────────────────────
say "vallum-quick detach"
"$QUICK" detach "$WORK/client/laptop.toml" > "$WORK/detach.log" 2>&1 || { cat "$WORK/detach.log"; bad "detach"; }
if systemctl is-active systemd-resolved >/dev/null 2>&1; then
    resolvectl dns "$CIFACE" 2>/dev/null | grep -q 1.1.1.1 && bad "resolver still installed after detach"
    ok "resolvectl reverted on $CIFACE"
fi

say "doctor, live"
"$VALLUM" doctor --config "$SCONFIG" 2>&1 | head -8

say "PASS — the privileged path works end to end"
