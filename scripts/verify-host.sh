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
    systemctl disable --now "vallum-quick-watch@$IFACE" "vallum-quick@$IFACE" "vallum@$IFACE" >/dev/null 2>&1
    rm -f "$UNIT_D/vallum@.service" "$UNIT_D/vallum-quick@.service" "$UNIT_D/vallum-quick-watch@.service"
    systemctl daemon-reload >/dev/null 2>&1
    nft delete table inet vallum >/dev/null 2>&1
    iptables -D FORWARD -i "$IFACE" -j ACCEPT >/dev/null 2>&1
    iptables -D FORWARD -o "$IFACE" -j ACCEPT >/dev/null 2>&1
    iptables -D INPUT -p udp --dport "$PORT" -j ACCEPT >/dev/null 2>&1
    command -v ufw >/dev/null 2>&1 && ufw delete allow "$PORT/udp" >/dev/null 2>&1
    rm -f "$SYSCTL_FILE"
    sysctl -p >/dev/null 2>&1
    rm -f /etc/tmpfiles.d/vallum-tmpfiles.conf
    rmdir /run/vallum 2>/dev/null
    rm -rf /etc/vallum "$WORK"
    [ "$installed_bins" = 1 ] && rm -f /usr/bin/vallum /usr/bin/vallum-quick
    ok "host state restored"
}
[ "$(id -u)" = 0 ] || { echo "verify-host.sh needs root; run it with sudo"; exit 1; }
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
[ -e /etc/vallum ] && bad "/etc/vallum already exists; refusing to run against a live deployment"
[ -e "$SYSCTL_FILE" ] && bad "$SYSCTL_FILE already exists; a real deployment may be using it"
nft list table inet vallum >/dev/null 2>&1 && bad "nftables table 'inet vallum' already exists"
ip link show "$IFACE" >/dev/null 2>&1 && bad "interface $IFACE already exists"

# ── install the binaries where the units look for them ──────────────────────
say "installing the release binaries"
if [ -e /usr/bin/vallum ] || [ -e /usr/bin/vallum-quick ]; then
    bad "/usr/bin/vallum{,-quick} already exist; refusing to overwrite them"
fi
# Arm cleanup only now. Every check above is read-only, and cleanup removes
# /etc/vallum, the units, the nft table and the sysctl drop-in unconditionally —
# so arming it earlier meant a refusal tore down the very deployment it had just
# refused to touch.
[ "$KEEP" = "--keep" ] || trap cleanup EXIT
install -m0755 "$VALLUM" /usr/bin/vallum
install -m0755 "$QUICK" /usr/bin/vallum-quick
installed_bins=1
ok "/usr/bin/vallum{,-quick}"

# The unit binds ReadWritePaths=/run/vallum, so the directory has to exist
# before it starts — a missing path is 226/NAMESPACE. The package creates it
# from a tmpfiles.d entry in its post-install hook, so the gate does the same
# instead of depending on a reboot to have run it.
say "runtime directory"
install -D -m0644 packaging/vallum-tmpfiles.conf /etc/tmpfiles.d/vallum-tmpfiles.conf
systemd-tmpfiles --create /etc/tmpfiles.d/vallum-tmpfiles.conf
[ -d /run/vallum ] || bad "tmpfiles did not create /run/vallum"
ok "/run/vallum exists"

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
[ -f "$UNIT_D/vallum@.service" ] && [ -f "$UNIT_D/vallum-quick@.service" ] \
    && [ -f "$UNIT_D/vallum-quick-watch@.service" ] || bad "unit files were not installed"
sleep 2
[ "$(systemctl is-active vallum@$IFACE)" = active ] || { journalctl -u vallum@$IFACE --no-pager -n 15; bad "vallum@$IFACE is not active"; }
[ "$(systemctl is-active vallum-quick@$IFACE)" = active ] || { journalctl -u vallum-quick@$IFACE --no-pager -n 15; bad "vallum-quick@$IFACE is not active"; }
[ "$(systemctl is-active vallum-quick-watch@$IFACE)" = active ] || { journalctl -u vallum-quick-watch@$IFACE --no-pager -n 15; bad "vallum-quick-watch@$IFACE is not active"; }
ok "vallum@$IFACE, vallum-quick@$IFACE and vallum-quick-watch@$IFACE are active"
# `is-active` turns true the moment systemd has forked the unit; the socket and
# the TUN appear a moment later. Sampling once here fails intermittently on a
# loaded machine, so poll for both.
sock=0
for _ in $(seq 1 40); do
    [ -S /run/vallum/$IFACE.sock ] && { sock=1; break; }
    sleep 0.25
done
[ "$sock" = 1 ] || { journalctl -u vallum@$IFACE --no-pager -n 15; bad "control socket never appeared"; }
ok "control socket live"
tun=0
for _ in $(seq 1 40); do
    ip link show "$IFACE" >/dev/null 2>&1 && { tun=1; break; }
    sleep 0.25
done
[ "$tun" = 1 ] || bad "TUN $IFACE never appeared"
ok "TUN $IFACE exists"

# ── a client through the product path ────────────────────────────────────────
say "peer add + import-bundle"
# Clear it first: a previous --keep run leaves client keys here, and
# import-bundle refuses to overwrite them, which looks like a product failure.
rm -rf "$WORK"
mkdir -p "$WORK"
"$VALLUM" peer add laptop --config "$SCONFIG" \
    --ship-key --bundle-out "$WORK/laptop.vallum-bundle" --dns 1.1.1.1 --forget-key \
    > "$WORK/peer.log" 2>&1 || { cat "$WORK/peer.log"; bad "peer add"; }
grep -q "applied    yes" "$WORK/peer.log" || { cat "$WORK/peer.log"; bad "peer add did not apply to the running daemon"; }
ok "peer added and applied live"

"$VALLUM" import-bundle "$WORK/laptop.vallum-bundle" --output-dir "$WORK/client" \
    > "$WORK/import.log" 2>&1 || { cat "$WORK/import.log"; bad "import-bundle"; }
# Same-host dogfood: the second daemon needs its own interface and socket.
# Client configs are named after their peer now, so match whatever it is.
sed -i "0,/^name = \".*\"/s//name = \"$CIFACE\"/; s|/run/vallum/[^/]*\.sock|/run/vallum/$CIFACE.sock|" "$WORK/client/laptop.toml"
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

# ── rotation, live ───────────────────────────────────────────────────────────
# Rotation is exercised with a live client: the old key keeps working while
# the new one is installed, and `finalize` retires it.
say "rotation, live"
"$VALLUM" keygen --output "$WORK/new.key" --suite 3 > "$WORK/new.pub" || bad "keygen"
"$VALLUM" peer rotate laptop --config "$SCONFIG" --public-key-file "$WORK/new.pub" \
    > "$WORK/rotate.log" 2>&1 || { cat "$WORK/rotate.log"; bad "peer rotate"; }
ping -c2 -W3 "$CLI_IP" >/dev/null 2>&1 || bad "the tunnel failed during rotation with pending key"
ok "the tunnel survives rotation (the previous key is still accepted)"
"$VALLUM" peer finalize laptop --config "$SCONFIG" > "$WORK/finalize.log" 2>&1 || { cat "$WORK/finalize.log"; bad "peer finalize"; }
ok "rotated and finalized"

# ── detach reverts DNS ───────────────────────────────────────────────────────
say "vallum-quick detach"
"$QUICK" detach "$WORK/client/laptop.toml" > "$WORK/detach.log" 2>&1 || { cat "$WORK/detach.log"; bad "detach"; }
if systemctl is-active systemd-resolved >/dev/null 2>&1; then
    resolvectl dns "$CIFACE" 2>/dev/null | grep -q 1.1.1.1 && bad "resolver still installed after detach"
    ok "resolvectl reverted on $CIFACE"
fi
kill "$client_pid" 2>/dev/null; client_pid=""

say "doctor, live"
"$VALLUM" doctor --config "$SCONFIG" 2>&1 | head -8

say "PASS — the privileged path is installed, the control plane works, and the tunnel carries traffic"
say "     remote client egress and multi-machine traffic are verified by scripts/verify-remote.sh and scripts/e2e-netns.sh"
