#!/usr/bin/env bash
#
# Install Vallum, then prepare this host as a tunnel server.
#
#   scripts/install.sh                     # install, then `vallum server init`
#   scripts/install.sh --install-only      # binaries, units, man pages only
#   scripts/install.sh --from-release      # download the latest release first
#   scripts/install.sh --from-release v0.1.4
#   scripts/install.sh --local             # install target/release, no download
#   scripts/install.sh --add-client NAME   # enrol a client (writes a bundle)
#   scripts/install.sh --remove-client NAME
#   scripts/install.sh --uninstall
#
# Everything after `--` is passed to `vallum server init`, so the full set of
# setup flags (`--endpoint`, `--address`, `--no-nat`, `--dry-run`, ...) works
# here without being repeated in this script.
#
# The repository is private, so `--from-release` needs `GH_TOKEN` or
# `GITHUB_TOKEN` unless the release assets are reachable anonymously.
set -euo pipefail

REPO="KidIkaros/vallum"
BIN_DIR="/usr/bin"
CONFIG_DIR="/etc/vallum"
RUNTIME_DIR="/run/vallum"
UNIT_DIR="/etc/systemd/system"
SYSCTL_FILE="/etc/sysctl.d/90-vallum.conf"

MODE="local"
VERSION=""
UNINSTALL=0
INSTALL_ONLY=0
DRY=0
ADD_CLIENT=""
REMOVE_CLIENT=""
ENDPOINT=""
PASSTHRU=()

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

while [ $# -gt 0 ]; do
    case "$1" in
        --from-release)
            MODE="release"
            if [ $# -gt 1 ] && [ "${2#-}" = "$2" ]; then
                VERSION=$2
                shift
            fi
            ;;
        --local) MODE="local" ;;
        --install-only) INSTALL_ONLY=1 ;;
        --add-client) shift; ADD_CLIENT=${1:-} ;;
        --remove-client) shift; REMOVE_CLIENT=${1:-} ;;
        --endpoint) shift; ENDPOINT=${1:-}; PASSTHRU+=(--endpoint "$ENDPOINT") ;;
        --uninstall) UNINSTALL=1 ;;
        --dry-run) DRY=1; PASSTHRU+=(--dry-run) ;;
        --help|-h)
            sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        --) shift; PASSTHRU+=("$@"); break ;;
        *) PASSTHRU+=("$1") ;;
    esac
    shift
done

# ── release download ────────────────────────────────────────────────

arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "x86_64" ;;
        aarch64|arm64)
            echo "unsupported: release artifacts are x86_64 only" >&2
            exit 1
            ;;
        *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
    esac
}

auth_header() {
    local token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
    if [ -n "$token" ]; then
        printf 'Authorization: token %s' "$token"
    fi
}

latest_version() {
    if command -v gh >/dev/null 2>&1; then
        gh release view --repo "$REPO" --json tagName -q .tagName
        return
    fi
    local header
    header=$(auth_header)
    if [ -n "$header" ]; then
        curl -fsSL -H "$header" "https://api.github.com/repos/$REPO/releases/latest"
    else
        curl -fsSL "https://api.github.com/repos/$REPO/releases/latest"
    fi | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1
}

download_asset() {
    local tag=$1 name=$2 out=$3
    local url="https://github.com/$REPO/releases/download/$tag/$name"
    local header token asset_id
    header=$(auth_header)
    token=${GH_TOKEN:-${GITHUB_TOKEN:-}}
    if command -v gh >/dev/null 2>&1 && [ -z "$token" ]; then
        gh release download "$tag" --repo "$REPO" --pattern "$name" --dir "$(dirname "$out")" --clobber
        return
    fi
    if [ -n "$header" ]; then
        # A private repository's `releases/download/...` URL is the web front
        # end: it wants a browser session and answers 404 to a token. The REST
        # asset endpoint is the one that accepts one, so resolve the id first.
        asset_id=$(curl -fsSL -H "$header" \
            "https://api.github.com/repos/$REPO/releases/tags/$tag" \
            | awk -v want="$name" '
                /"id":/ { line = $0; sub(/.*"id": */, "", line); sub(/,.*/, "", line); last = line }
                $0 ~ "\"name\": \"" want "\"" { print last; exit }
            ')
        if [ -n "$asset_id" ]; then
            curl -fsSL -H "$header" -H "Accept: application/octet-stream" \
                -o "$out" "https://api.github.com/repos/$REPO/releases/assets/$asset_id"
            return
        fi
        # No id resolved: fall back to the web URL rather than failing here.
        curl -fsSL -H "$header" -o "$out" "$url"
    else
        curl -fsSL -o "$out" "$url"
    fi
}

install_from_release() {
    local tag=$1 work=$2 target sums
    target="vallum-$tag-x86_64-linux.tar.gz"
    say "downloading $tag"
    download_asset "$tag" "$target" "$work/$target"
    download_asset "$tag" "SHA256SUMS" "$work/SHA256SUMS"
    ( cd "$work" && grep " $target\$" SHA256SUMS | sha256sum -c - )
    tar -C "$work" -xzf "$work/$target"
    SOURCE_DIR="$work/vallum-$tag-x86_64-linux"
}

# ── local build ─────────────────────────────────────────────────────

install_from_local() {
    local candidate
    for candidate in target/release target/debug; do
        if [ -x "$candidate/vallum" ] && [ -x "$candidate/vallum-quick" ]; then
            SOURCE_DIR=$candidate
            return
        fi
    done
    echo "no local build found; run 'cargo build --release -p vallum -p vallum-quick'" >&2
    echo "or pass --from-release to download one" >&2
    exit 1
}

# ── install ─────────────────────────────────────────────────────────

install_binaries() {
    run install -d -m 0755 "$BIN_DIR" "$CONFIG_DIR" "$RUNTIME_DIR"
    run install -m 0755 "$SOURCE_DIR/vallum" "$BIN_DIR/vallum"
    run install -m 0755 "$SOURCE_DIR/vallum-quick" "$BIN_DIR/vallum-quick"
}

install_docs() {
    local unit
    for unit in vallum@.service vallum-quick@.service; do
        if [ -f "$SOURCE_DIR/$unit" ]; then
            run install -m 0644 "$SOURCE_DIR/$unit" "$UNIT_DIR/$unit"
        elif [ -f "packaging/$unit" ]; then
            run install -m 0644 "packaging/$unit" "$UNIT_DIR/$unit"
        fi
    done
    local man
    for man in vallum.8 vallum-quick.8 vallum.toml.5; do
        if [ -f "$SOURCE_DIR/$man" ]; then
            run install -D -m 0644 "$SOURCE_DIR/$man" "/usr/share/man/man${man##*.}/$man"
        elif [ -f "packaging/$man" ]; then
            run install -D -m 0644 "packaging/$man" "/usr/share/man/man${man##*.}/$man"
        fi
    done
    if [ -f "$SOURCE_DIR/vallum.bash" ]; then
        run install -D -m 0644 "$SOURCE_DIR/vallum.bash" \
            /usr/share/bash-completion/completions/vallum
    elif [ -f "packaging/vallum.bash" ]; then
        run install -D -m 0644 "packaging/vallum.bash" \
            /usr/share/bash-completion/completions/vallum
    fi
}

# ── client shims ────────────────────────────────────────────────────

add_client() {
    local name=$1 bundle
    [ -n "$name" ] || { echo "--add-client needs a name" >&2; exit 1; }
    bundle="$name.vallum-bundle"
    local args=(peer add "$name" --bundle-out "$bundle" --forget-key)
    if [ -n "$ENDPOINT" ]; then
        args+=(--endpoint "$ENDPOINT")
    fi
    if [ "$DRY" -eq 1 ]; then
        echo "   would run: vallum ${args[*]}"
        return
    fi
    /usr/bin/vallum "${args[@]}"
    echo
    echo "hand $bundle to the device, then there:"
    echo "   sudo vallum import-bundle $bundle --install"
}

remove_client() {
    local name=$1
    [ -n "$name" ] || { echo "--remove-client needs a name" >&2; exit 1; }
    if [ "$DRY" -eq 1 ]; then
        echo "   would run: vallum peer remove $name"
        return
    fi
    /usr/bin/vallum peer remove "$name"
}

uninstall() {
    local instance
    say "uninstalling"
    for instance in $(systemctl list-units --all --plain --no-legend 'vallum*@*' 2>/dev/null \
        | awk '{print $1}' | sed 's/\.service$//' | sort -u); do
        run systemctl disable --now "$instance"
    done
    run rm -f "$UNIT_DIR/vallum@.service" "$UNIT_DIR/vallum-quick@.service"
    run systemctl daemon-reload
    run rm -rf "$CONFIG_DIR" "$RUNTIME_DIR"
    run rm -f "$BIN_DIR/vallum" "$BIN_DIR/vallum-quick"
    if [ "$DRY" -eq 0 ]; then
        nft delete table inet vallum 2>/dev/null || true
        rm -f "$SYSCTL_FILE"
    fi
}

# ── main ────────────────────────────────────────────────────────────

need_root

if [ "$UNINSTALL" -eq 1 ]; then
    uninstall
    exit 0
fi

WORK=""
if [ "$DRY" -eq 0 ]; then
    WORK=$(mktemp -d)
    trap 'rm -rf "$WORK"' EXIT
fi

SOURCE_DIR=""
if [ "$MODE" = "release" ]; then
    if [ -z "$VERSION" ]; then
        VERSION=$(latest_version)
    fi
    [ -n "$VERSION" ] || { echo "could not determine the latest release" >&2; exit 1; }
    if [ "$DRY" -eq 1 ]; then
        say "would download $VERSION and install it to $BIN_DIR"
    else
        install_from_release "$VERSION" "$WORK"
    fi
else
    install_from_local
fi

if [ "$DRY" -eq 0 ] || [ -n "$SOURCE_DIR" ]; then
    install_binaries
    install_docs
    run systemctl daemon-reload
fi

if [ -n "$ADD_CLIENT" ]; then
    add_client "$ADD_CLIENT"
    exit 0
fi
if [ -n "$REMOVE_CLIENT" ]; then
    remove_client "$REMOVE_CLIENT"
    exit 0
fi

if [ "$INSTALL_ONLY" -eq 1 ]; then
    say "installed"
    echo "prepare this host:  sudo vallum setup --server"
    exit 0
fi

say "preparing this host as a tunnel server"
if [ "$DRY" -eq 1 ]; then
    echo "   would run: vallum server init ${PASSTHRU[*]:-}"
    exit 0
fi
exec /usr/bin/vallum server init "${PASSTHRU[@]}"
