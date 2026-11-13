#!/usr/bin/env bash
#
# Full tunnel by trial: the deploy script install.sh ships to every machine.
# Lives in /usr/local/lib/vallum/ (shipped by install.sh, updated by
# vallum-ops sync from the repo on a dev machine). The full-tunnel config is
# not shipped — it is derived at apply time from THIS machine's own split
# config, so there are no per-machine staging files and no author paths.
#
#   vallum-ops full-tunnel     (the supported entry point)
#
# Sequence: save split config → derive full config from it → restart the
# daemon (handshake within 45 s) → arm the dead-man → trial with a 90 s
# deadline (revert timer armed before the routes move) → verify route, DNS,
# and that the public IP is the tunnel exit.
#
# Any failure ends with the split config restored and the unit running.
set -uo pipefail

# The guard's table is named per interface: `vallum_policy_<interface>`, with
# anything that is not a letter or a digit replaced by an underscore, because
# nft identifiers are [A-Za-z_][A-Za-z0-9_]* (ADR-0037).
vallum_guard_table() {
    printf 'vallum_policy_%s' "$(printf '%s' "$1" | tr -c '[:alnum:]' '_')"
}
CHANGED=0

LIB=${VALLUM_LIB:-/usr/local/lib/vallum}
CONF=${VALLUM_CONF:-/etc/vallum/vallum0.toml}
IFACE=${VALLUM_IFACE:-vallum0}
UNIT=vallum@$IFACE
# The tunnel exit this client must present to the internet. Overridable for
# lab or alternate servers.
EXPECTED_IP=${VALLUM_EXIT_IP:-203.0.113.10}

say() { printf '\n=== %s\n' "$*"; }
fail() {
    echo "FAILED: $*" >&2
    echo "reverting to the split tunnel..." >&2
    # Panic first (guard off, routes back, DNS restored), then the split config
    # goes back and the unit is left RUNNING — a rollback must end in a working
    # machine, not a stopped one.
    /usr/local/sbin/vallum-panic 2>/dev/null || \
        { nft delete table inet "$(vallum_guard_table "$IFACE")" 2>/dev/null; \
          nft delete table inet vallum_policy 2>/dev/null; \
          ip route del default dev "$IFACE" 2>/dev/null; }
    [ -f /etc/vallum/vallum0.split.bak ] && \
        install -m 600 -o root -g root /etc/vallum/vallum0.split.bak "$CONF" 2>/dev/null
    systemctl reset-failed "$UNIT" 2>/dev/null || true
    systemctl restart "$UNIT" 2>/dev/null || true
    local net=DOWN
    for _ in 1 2 3; do
        ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1 && { net=ok; break; }
        sleep 2
    done
    echo "split tunnel restored (unit: $(systemctl is-active "$UNIT")); internet: $net" >&2
    exit 1
}
trap 'if [ "$CHANGED" = 1 ]; then fail "unexpected error at line $LINENO"; else echo "FAILED: unexpected error at line $LINENO (nothing changed yet)" >&2; exit 1; fi' ERR

say "0/6 preflight"
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
[ -f "$LIB/trial.sh" ] || { echo "trial.sh missing from $LIB" >&2; exit 1; }
for tool in vallum-panic vallum-guard-deadman; do
    [ -f "/usr/local/sbin/$tool" ] || { echo "$tool missing from /usr/local/sbin" >&2; exit 1; }
done
for u in vallum-quick@.service vallum-guard@.service vallum-deadman@.service vallum-deadman@.timer vallum-cleanup.service; do
    [ -f "/etc/systemd/system/$u" ] || { echo "unit $u not installed — run install.sh or vallum-ops sync" >&2; exit 1; }
done
[ "${NEEDS_RELOAD:-0}" = 1 ] && systemctl daemon-reload

# The script owns getting the host into the state it needs: if a previous
# rollback stopped the unit, start it.
systemctl is-active --quiet "$UNIT" || {
    systemctl reset-failed "$UNIT" 2>/dev/null || true
    echo "  unit not running — starting it"
    systemctl start "$UNIT" || { echo "cannot start $UNIT" >&2; exit 1; }
    for _ in $(seq 1 40); do
        ping -c 1 -W 1 10.7.0.1 >/dev/null 2>&1 && break
        sleep 1
    done
}
grep -q 'allowed_ips = \["10.7.0.1/32"\]\|allowed_ips = \["0.0.0.0/0"\]' "$CONF" || \
    echo "  note: peer allowlist is neither the known split nor full form — continuing"
carry=no
for _ in $(seq 1 30); do
    ping -c 1 -W 1 10.7.0.1 >/dev/null 2>&1 && { carry=yes; break; }
    sleep 1
done
[ "$carry" = yes ] || fail "the tunnel is not carrying right now"
echo "  units and tools present; trial script present; tunnel carrying"

say "1/6 saving the split config"
cp "$CONF" /etc/vallum/vallum0.split.bak && chmod 600 /etc/vallum/vallum0.split.bak

say "2/6 deriving the full-tunnel config from this machine's own config"
cp "$CONF" "${CONF}.work"
# Widen the peer allowlist; the peer is the server, so 0.0.0.0/0 means
# "everything rides the tunnel".
sed -i 's/^allowed_ips = .*/allowed_ips = ["0.0.0.0\/0"]/' "${CONF}.work"
# fwmark is mandatory for 0.0.0.0/0: the daemon's own UDP must escape the
# policy routing that quick will install.
if grep -q '^fwmark' "${CONF}.work"; then
    sed -i 's/^fwmark.*/fwmark = 51820/' "${CONF}.work"
else
    # Peers are [[peer]] array-of-tables, so anchor on [interface] instead:
    # fwmark belongs in that table and the header always exists.
    sed -i '0,/^\[interface\]/s//[interface]\nfwmark = 51820/' "${CONF}.work"
fi
# DNS rides the tunnel: quick attaches the resolver to the tunnel link.
grep -q '^\[quick\]' "${CONF}.work" || printf '\n[quick]\ndns = ["1.1.1.1"]\n' >> "${CONF}.work"
grep -q 'allowed_ips = \["0.0.0.0/0"\]' "${CONF}.work" || fail "derived config lost the wide allowlist"
grep -q 'fwmark' "${CONF}.work" || fail "derived config lost the fwmark"
install -m 600 -o root -g root "${CONF}.work" "$CONF"
rm -f "${CONF}.work"
CHANGED=1

say "3/6 restarting the daemon; handshake must return within 45s"
echo "  (the daemon initiates on its keepalive tick — ~25s is normal)"
systemctl reset-failed "$UNIT" 2>/dev/null || true
systemctl restart "$UNIT" || fail "the daemon did not restart on the new config"
up=no
for i in $(seq 1 45); do
    ping -c 1 -W 1 10.7.0.1 >/dev/null 2>&1 && { up=yes; echo "  handshake + echo at ${i}s"; break; }
    sleep 1
done
[ "$up" = yes ] || fail "no echo over the full tunnel in 45s"

say "4/6 arming the dead-man timer (checks every 10s from here on)"
out=$(systemctl enable --now "vallum-deadman@$IFACE.timer" 2>&1) || \
    echo "  warning: dead-man timer did not start: $out — the trial still has its own deadline"

say "5/6 the trial: 90s deadline armed before the routes move"
"$LIB/trial.sh" --config "$CONF" --trial 90 || fail "the trial failed and reverted itself"

say "6/6 proving browsing rides the tunnel"
PUBLIC=$(curl -s --max-time 10 https://ifconfig.me 2>/dev/null || echo unknown)
echo "  public IP as the internet sees it: $PUBLIC"
[ "$PUBLIC" = "$EXPECTED_IP" ] || fail "the public IP is $PUBLIC, not $EXPECTED_IP — traffic is still bypassing the tunnel"
DNS=$(grep -m1 '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' || true)
[ -n "$DNS" ] || fail "no resolver after the switch"

say "FULL TUNNEL ACTIVE"
echo "  route:  $(ip route get 1.1.1.1 | head -1)"
echo "  dns:    $DNS"
echo "  guard:  $(systemctl is-active vallum-guard@$IFACE)"
echo "  dead-man: $(systemctl is-active vallum-deadman@$IFACE.timer)"
echo
echo "to go back to the split tunnel:"
echo "  sudo vallum-ops revert"
echo
echo "NOTE: this is a session-level trial. After a reboot the tunnel is OFF (safe),"
echo "not full-tunnel. Making it survive reboot is a separate, explicit step."
