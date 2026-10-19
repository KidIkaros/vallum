#!/usr/bin/env bash
#
# Vallum installer for Debian/Ubuntu and Fedora/RHEL.
#
# This is the host-level tool, not the daemon: it installs the binaries, writes a
# server config, sets up NAT, and adds/removes clients. It never asks the daemon
# to run a shell.
#
#   scripts/install.sh                 # install, or add a client if installed
#   scripts/install.sh --add-client N  # add a client and print its QR
#   scripts/install.sh --remove-client N
#   scripts/install.sh --uninstall
#   scripts/install.sh --dry-run ...
#
set -euo pipefail

DRY=0
UNINSTALL=0
ADD_CLIENT=""
REMOVE_CLIENT=""
PORT=51820
SUBNET=10.7.0
SERVER_ADDR=$SUBNET.1

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY=1 ;;
        --uninstall) UNINSTALL=1 ;;
        --add-client) shift; ADD_CLIENT=${1:-} ;;
        --remove-client) shift; REMOVE_CLIENT=${1:-} ;;
        --port) shift; PORT=${1:-51820} ;;
        --subnet) shift; SUBNET=${1:-10.7.0}; SERVER_ADDR=$SUBNET.1 ;;
        -h|--help)
            sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
    shift
done

say() { printf '\n== %s\n' "$*"; }
run() {
    if [ "$DRY" -eq 1 ]; then
        printf '   would run: %s\n' "$*"
    else
        "$@"
    fi
}
need_root() {
    if [ "$DRY" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
        echo "this installer must run as root (or use --dry-run)" >&2
        exit 1
    fi
}
detect_os() {
    if [ -r /etc/debian_version ]; then
        OS=debian
    elif [ -r /etc/fedora-release ] || [ -r /etc/redhat-release ]; then
        OS=rhel
    else
        echo "unsupported distribution: Debian/Ubuntu or Fedora/RHEL only" >&2
        exit 1
    fi
}
install_deps() {
    case "$OS" in
        debian) run apt-get update; run apt-get install -y qrencode nftables ;;
        rhel) run dnf install -y qrencode nftables ;;
    esac
}
bin_src() {
    for candidate in target/release/vallum target/debug/vallum; do
        [ -x "$candidate" ] && { echo "$candidate"; return; }
    done
    echo "build first: cargo build --release -p vallum -p vallum-quick" >&2
    exit 1
}
install_binaries() {
    local src
    src=$(bin_src)
    run install -m 0755 "$src" /usr/local/bin/vallum
    run install -m 0755 "${src%vallum}vallum-quick" /usr/local/bin/vallum-quick
}
install_config() {
    run install -d -m 0755 /etc/vallum /run/vallum
    if [ -f /etc/vallum/server.key ]; then
        return
    fi
    say "generating the server key"
    run /usr/local/bin/vallum keygen --output /etc/vallum/server.key --suite 3
    run /usr/local/bin/vallum pubkey --private-key /etc/vallum/server.key \
        > /etc/vallum/server.pub
    cat > /etc/vallum/vallum0.toml <<TOML
[interface]
name = "vallum0"
private_key = "server.key"
address = "$SERVER_ADDR/24"
listen = "0.0.0.0:$PORT"
control = "/run/vallum/vallum0.sock"
fwmark = 4660

[log]
level = "info"

[quick]
dns = ["1.1.1.1"]
table = "auto"
TOML
    if [ "$DRY" -eq 0 ]; then
        chmod 0600 /etc/vallum/server.key
    fi
}
install_service() {
    run install -m 0644 packaging/vallum@.service /etc/systemd/system/vallum@.service
    run systemctl daemon-reload
    run systemctl enable --now vallum@vallum0
}
install_nat() {
    say "installing NAT for $SUBNET.0/24"
    if [ "$DRY" -eq 1 ]; then
        echo "   would run: nft add table inet vallum"
        echo "   would run: nft add chain inet vallum post { type nat hook postrouting priority 100; }"
        echo "   would run: nft add rule inet vallum post ip saddr $SUBNET.0/24 masquerade"
        return
    fi
    nft list table inet vallum >/dev/null 2>&1 || nft add table inet vallum
    nft list chain inet vallum post >/dev/null 2>&1 || \
        nft add chain inet vallum post '{ type nat hook postrouting priority 100; }'
    nft add rule inet vallum post ip saddr "$SUBNET.0/24" masquerade 2>/dev/null || true
}
next_client_ip() {
    local n=2
    while grep -q "$SUBNET.$n/32" /etc/vallum/vallum0.toml 2>/dev/null; do
        n=$((n + 1))
    done
    echo "$SUBNET.$n"
}
add_client() {
    local name=$1 ip
    [ -n "$name" ] || { echo "--add-client needs a name" >&2; exit 1; }
    ip=$(next_client_ip)
    say "adding client $name at $ip"
    run install -d -m 0755 /etc/vallum/clients
    run /usr/local/bin/vallum keygen --output "/etc/vallum/clients/$name.key" --suite 3
    run /usr/local/bin/vallum pubkey --private-key "/etc/vallum/clients/$name.key" \
        > "/etc/vallum/clients/$name.pub"
    {
        printf '\n[[peer]]\nname = "%s"\n' "$name"
        printf 'public_key = "%s"\n' "$(cat "/etc/vallum/clients/$name.pub")"
        printf 'allowed_ips = ["%s/32"]\n' "$ip"
    } >> /etc/vallum/vallum0.toml
    run /usr/local/bin/vallum syncconf /etc/vallum/vallum0.toml

    cat > "/etc/vallum/clients/$name.conf" <<CLIENT
[interface]
name = "vallum0"
private_key = "$name.key"
address = "$ip/24"
listen = "0.0.0.0:0"
control = "/run/vallum/vallum0.sock"

[log]
level = "info"

[[peer]]
name = "server"
public_key = "$(cat /etc/vallum/server.pub)"
endpoint = "$(hostname -I | awk '{print $1}'):$PORT"
allowed_ips = ["0.0.0.0/0"]
persistent_keepalive = 25
CLIENT
    if command -v qrencode >/dev/null 2>&1 && [ "$DRY" -eq 0 ]; then
        qrencode -t ANSI256UTF8 < "/etc/vallum/clients/$name.conf"
    fi
    echo "client config: /etc/vallum/clients/$name.conf"
}
remove_client() {
    local name=$1
    [ -n "$name" ] || { echo "--remove-client needs a name" >&2; exit 1; }
    say "removing client $name"
    if [ "$DRY" -eq 0 ]; then
        awk -v name="$name" '
            /^\[\[peer\]\]/ { block = $0 "\n"; in_peer = 1; next }
            in_peer { block = block $0 "\n"; if ($0 ~ /^\[/) { in_peer = 0 } }
            in_peer && block ~ ("name = \"" name "\"") { next }
            { if (in_peer) { printf "%s", block; in_peer = 0; block = "" } print }
        ' /etc/vallum/vallum0.toml > /etc/vallum/vallum0.toml.new
        mv /etc/vallum/vallum0.toml.new /etc/vallum/vallum0.toml
        rm -f "/etc/vallum/clients/$name.key" "/etc/vallum/clients/$name.pub" \
              "/etc/vallum/clients/$name.conf"
    fi
    run /usr/local/bin/vallum syncconf /etc/vallum/vallum0.toml
}
uninstall() {
    say "uninstalling"
    run systemctl disable --now vallum@vallum0
    run rm -f /etc/systemd/system/vallum@.service
    run systemctl daemon-reload
    run rm -rf /etc/vallum /run/vallum
    run rm -f /usr/local/bin/vallum /usr/local/bin/vallum-quick
    if [ "$DRY" -eq 0 ]; then
        nft delete table inet vallum 2>/dev/null || true
    fi
}

need_root
detect_os

if [ "$UNINSTALL" -eq 1 ]; then
    uninstall
    exit 0
fi

if [ ! -x /usr/local/bin/vallum ]; then
    say "installing binaries and dependencies"
    install_deps
    install_binaries
    install_config
    install_service
    install_nat
fi

if [ -n "$ADD_CLIENT" ]; then
    add_client "$ADD_CLIENT"
elif [ -n "$REMOVE_CLIENT" ]; then
    remove_client "$REMOVE_CLIENT"
else
    say "done"
    echo "server config: /etc/vallum/vallum0.toml"
    echo "add a client:  scripts/install.sh --add-client laptop"
fi
