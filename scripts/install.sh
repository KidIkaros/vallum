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
#   scripts/install.sh --uninstall           # keeps /etc/vallum (configs+keys)
#   scripts/install.sh --uninstall --purge   # removes /etc/vallum too
#   scripts/install.sh --from-release --no-verify-signature   # skip sig check
#   scripts/install.sh --from-release --require-signature     # fail if unsigned
#   scripts/install.sh --from-release --package deb|rpm       # verified dpkg/rpm install
#   scripts/install.sh --from-release --allow-downgrade       # permit an older release
#
# A release older than the installed version is refused: a signature proves
# who built a release, never when. `--allow-downgrade` is the deliberate
# rollback switch.
#
# `--package` routes the package through the same signature check as the
# tarball: `dpkg -i`/`rpm -i` verify nothing themselves, so install.sh
# verifies SHA256SUMS.sig and the package's checksum *before* handing the
# file to the package manager. Bare `--package` auto-detects deb vs rpm.
#
# Release downloads are verified before use: the release signs SHA256SUMS with
# an SSH key (`ssh-keygen -Y`); install.sh downloads SHA256SUMS.sig and
# verifies it against the release public key embedded below (the same key as
# packaging/vallum-release.pub — this script is the trust anchor, the
# checksum file then authenticates the tarball). Releases before v1.6.1 have
# no signature and install with a warning unless --require-signature is passed.
#
# Everything after `--` is passed to `vallum server init`, so the full set of
# setup flags (`--endpoint`, `--address`, `--no-nat`, `--dry-run`, ...) works
# here without being repeated in this script.
#
# `--from-release` tries the public download URL first, which needs nothing but
# curl. Installing from a private fork falls back to `gh` (run as the invoking
# user, not root) or to `GH_TOKEN`/`GITHUB_TOKEN`.
set -euo pipefail

REPO="KidIkaros/vallum"
BIN_DIR="/usr/bin"
CONFIG_DIR="/etc/vallum"
RUNTIME_DIR="/run/vallum"
UNIT_DIR="/etc/systemd/system"
TMPFILES_DIR="/etc/tmpfiles.d"
SYSCTL_FILE="/etc/sysctl.d/90-vallum.conf"

MODE="local"
VERSION=""
UNINSTALL=0
UNINSTALL_ARGS=()
INSTALL_ONLY=0
DRY=0
NO_VERIFY_SIG=0
REQUIRE_SIG=0
ALLOW_DOWNGRADE=0
ADD_CLIENT=""
REMOVE_CLIENT=""
PACKAGE=""
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
        --package)
            if [ $# -gt 1 ] && [ "${2#-}" = "$2" ]; then
                PACKAGE=$2
                shift
            else
                PACKAGE="auto"
            fi
            ;;
        --install-only) INSTALL_ONLY=1 ;;
        --no-verify-signature) NO_VERIFY_SIG=1 ;;
        --require-signature) REQUIRE_SIG=1 ;;
        --allow-downgrade) ALLOW_DOWNGRADE=1 ;;
        --add-client) shift; ADD_CLIENT=${1:-} ;;
        --remove-client) shift; REMOVE_CLIENT=${1:-} ;;
        --endpoint) shift; ENDPOINT=${1:-}; PASSTHRU+=(--endpoint "$ENDPOINT") ;;
        --uninstall) UNINSTALL=1 ;;
        --purge) UNINSTALL_ARGS+=(--purge) ;;
        --dry-run) DRY=1; PASSTHRU+=(--dry-run); UNINSTALL_ARGS+=(--dry-run) ;;
        --help|-h)
            sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'
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
        aarch64|arm64) echo "aarch64" ;;
        *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
    esac
}

# OpenSSH >= 8.0 is needed for `ssh-keygen -Y sign/verify`. ssh and ssh-keygen
# ship together, so the ssh version banner is the reliable probe.
ssh_signing_supported() {
    local v
    v=$(ssh -V 2>&1 | sed -n 's/^OpenSSH_\([0-9][0-9]*\).*/\1/p' | head -1)
    [ -n "$v" ] && [ "$v" -ge 8 ]
}

# The release signing key, pinned here AND in packaging/vallum-release.pub.
# It is embedded in this script rather than fetched from the release: the
# repository is the trust anchor, and an allowed_signers file downloaded
# alongside the signature could be swapped for an attacker's key. Release
# assets also ship allowed_signers for manual verification — it must contain
# exactly this key.
RELEASE_SIGNING_PUBKEY="vallum-release ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOcys6KuFRBEnzkhjmC5OvVQDUNCOl39qxrFcQO05dwQ"

# Verify the SSH signature over SHA256SUMS before trusting any checksum in it.
# allowed_signers is written from the pinned key above — never downloaded.
# Releases built before signing (<= v1.6.0) have no .sig and are accepted
# with a warning unless --require-signature is passed.
verify_release_signature() {
    local tag=$1 work=$2
    [ "$NO_VERIFY_SIG" -eq 0 ] || { echo "   warn  signature verification disabled (--no-verify-signature)"; return; }
    if ! download_asset "$tag" "SHA256SUMS.sig" "$work/SHA256SUMS.sig" 2>/dev/null; then
        if [ "$REQUIRE_SIG" -eq 1 ]; then
            echo "refusing: $tag carries no signature (--require-signature)" >&2
            exit 1
        fi
        echo "   warn  $tag is unsigned; trusting SHA256SUMS only"
        return
    fi
    ssh_signing_supported || {
        echo "refusing: OpenSSH >= 8.0 is required to verify the release signature" >&2
        echo "         upgrade openssh-client, or bypass with --no-verify-signature" >&2
        exit 1
    }
    echo "$RELEASE_SIGNING_PUBKEY" > "$work/allowed_signers"
    if ssh-keygen -Y verify -f "$work/allowed_signers" -n file \
        -s "$work/SHA256SUMS.sig" -I vallum-release < "$work/SHA256SUMS" 2>/dev/null; then
        echo "   ok    release signature verified (vallum-release)"
    else
        echo "refusing: SHA256SUMS.sig does not verify against allowed_signers — do not trust this download" >&2
        exit 1
    fi
}

# ── release freshness ───────────────────────────────────────────────

# Installed version, or empty when vallum is not installed yet.
installed_version() {
    local out
    out=$("$BIN_DIR/vallum" --version 2>/dev/null) || return 0
    # "vallum 1.6.2 (linux-only)"
    echo "$out" | awk '{print $2}'
}

# Strictly newer? `sort -V` is coreutils and orders semver correctly.
version_gt() {
    [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]
}

# A release older than what is installed is refused. A signature proves who
# built a release, never when: a replayed older release — validly signed,
# checksums intact — is exactly what this catches, and it is the one thing the
# signature chain cannot see. The installed binary IS the floor: no state file
# to forget, corrupt, or point at the wrong directory, and no floor an attacker
# could rewrite without already owning the host.
guard_downgrade() {
    local tag=$1 target installed
    target=${tag#v}
    installed=$(installed_version)
    [ -n "$installed" ] || return 0
    if version_gt "$installed" "$target"; then
        if [ "$ALLOW_DOWNGRADE" -eq 1 ]; then
            echo "   warn  downgrade: installed $installed -> installing $target (--allow-downgrade)"
            return 0
        fi
        echo "refusing: $target is older than the installed $installed." >&2
        echo "         A valid signature proves who built a release, not when it was built." >&2
        echo "         Pass --allow-downgrade to roll back deliberately." >&2
        exit 1
    fi
    echo "   ok    version: installed $installed, installing $target"
}

auth_header() {
    local token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
    if [ -n "$token" ]; then
        printf 'Authorization: token %s' "$token"
    fi
}

# gh reads the *caller's* config; run under sudo and it opens root's empty
# one. Delegate to the invoking user's session so their `gh auth login`
# applies (the repo is private) — the same fix verify-remote.sh needed.
gh_as_user() {
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
        sudo -u "$SUDO_USER" gh "$@"
    else
        gh "$@"
    fi
}

# Resolution order matters for DX: the anonymous public path is first
# because it is the end state — anyone can `curl | bash` a public release
# with zero tooling. gh is the *fallback* for a private repo where the
# invoking user happens to have a login, not a prerequisite.
latest_version() {
    local header out
    header=$(auth_header)
    out=$( { if [ -n "$header" ]; then
        curl -fsSL -H "$header" "https://api.github.com/repos/$REPO/releases/latest"
    else
        curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null
    fi; } | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1 )
    [ -n "$out" ] && { echo "$out"; return; }
    # Private repo and no anonymous answer: the user's gh session is the
    # last resort.
    command -v gh >/dev/null 2>&1 || return 0
    gh_as_user release view --repo "$REPO" --json tagName -q .tagName
}

download_asset() {
    local tag=$1 name=$2 out=$3
    local url="https://github.com/$REPO/releases/download/$tag/$name"
    local header token asset_id
    header=$(auth_header)
    token=${GH_TOKEN:-${GITHUB_TOKEN:-}}
    # Explicit token: private repo, authenticated API path.
    if [ -n "$token" ]; then
        if curl -fsSL -H "$header" -o "$out" "$url" 2>/dev/null; then
            return
        fi
        asset_id=$(curl -fsSL -H "$header" \
            "https://api.github.com/repos/$REPO/releases/tags/$tag" \
            | awk -v want="$name" '
                /"id":/ { line = $0; sub(/.*"id": */, "", line); sub(/,.*/, "", line); last = line }
                $0 ~ "\"name\": \"" want "\"" { print last; exit }
            ')
        [ -n "$asset_id" ] && curl -fsSL -H "$header" -H "Accept: application/octet-stream" \
            -o "$out" "https://api.github.com/repos/$REPO/releases/assets/$asset_id"
        return
    fi
    # Public repo: the release download URL answers anonymously — no gh,
    # no login, works for anyone.
    if curl -fsSL -o "$out" "$url" 2>/dev/null; then
        return
    fi
    # A private fork (or an anonymous-download outage): the user's gh login is
    # the fallback, never a gate.
    if command -v gh >/dev/null 2>&1; then
        gh_as_user release download "$tag" --repo "$REPO" --pattern "$name" --dir "$(dirname "$out")" --clobber
        return
    fi
    echo "cannot download $name — for a private fork, set GH_TOKEN or run gh auth login" >&2
    return 1
}

install_from_release() {
    local tag=$1 work=$2 target sums A
    A=$(arch)
    target="vallum-$tag-$A-linux.tar.gz"
    say "downloading $tag ($A)"
    download_asset "$tag" "$target" "$work/$target"
    download_asset "$tag" "SHA256SUMS" "$work/SHA256SUMS"
    verify_release_signature "$tag" "$work"
    ( cd "$work" && grep " $target\$" SHA256SUMS | sha256sum -c - )
    tar -C "$work" -xzf "$work/$target"
    SOURCE_DIR="$work/vallum-$tag-$A-linux"
}

# Package asset names follow the builders' conventions: cargo-deb emits
# `vallum_<ver>-<rev>_<deb-arch>.deb` (amd64/arm64), cargo-generate-rpm emits
# `vallum-<ver>-<rev>.<rpm-arch>.rpm` (x86_64/aarch64). The tag carries a
# leading `v` the package version does not.
package_asset_name() {
    local tag=$1 ver
    ver=${tag#v}
    case "$PACKAGE" in
        deb) case "$(arch)" in
            x86_64)  echo "vallum_${ver}-1_amd64.deb" ;;
            aarch64) echo "vallum_${ver}-1_arm64.deb" ;;
        esac ;;
        rpm) echo "vallum-${ver}-1.$(arch).rpm" ;;
    esac
}

# The package path exists because `dpkg -i`/`rpm -i` verify nothing: the
# signature + checksum check here is what makes a package install as
# trustworthy as the tarball path, not the package format.
install_package() {
    local tag=$1 work=$2 target
    target=$(package_asset_name "$tag")
    say "downloading $tag ($PACKAGE)"
    download_asset "$tag" "$target" "$work/$target"
    download_asset "$tag" "SHA256SUMS" "$work/SHA256SUMS"
    verify_release_signature "$tag" "$work"
    ( cd "$work" && grep " $target\$" SHA256SUMS | sha256sum -c - )
    case "$PACKAGE" in
        deb) run dpkg -i "$work/$target" ;;
        rpm)
            if command -v dnf >/dev/null 2>&1; then
                run dnf install -y "$work/$target"
            else
                run rpm -Uvh "$work/$target"
            fi
            ;;
    esac
    echo "   ok    $target installed ($PACKAGE)"
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
    for unit in vallum@.service vallum-guard@.service vallum-quick@.service \
        vallum-quick-watch@.service vallum-enroll@.service \
        vallum-cleanup.service \
        vallum-metrics.service vallum-metrics.timer; do
        if [ -f "$SOURCE_DIR/$unit" ]; then
            run install -m 0644 "$SOURCE_DIR/$unit" "$UNIT_DIR/$unit"
        elif [ -f "packaging/$unit" ]; then
            run install -m 0644 "packaging/$unit" "$UNIT_DIR/$unit"
        fi
    done
    # /run/vallum is a machine resource, not a unit's RuntimeDirectory: it must
    # exist before any unit starts and outlive any unit stopping, because every
    # daemon's control socket lives in it. See ADR-0017.
    if [ -f "$SOURCE_DIR/vallum-tmpfiles.conf" ]; then
        run install -D -m 0644 "$SOURCE_DIR/vallum-tmpfiles.conf" "$TMPFILES_DIR/vallum-tmpfiles.conf"
    elif [ -f "packaging/vallum-tmpfiles.conf" ]; then
        run install -D -m 0644 "packaging/vallum-tmpfiles.conf" "$TMPFILES_DIR/vallum-tmpfiles.conf"
    fi
    # Create the directory now rather than at the next boot: a unit started in
    # between would fail with 226/NAMESPACE, because ReadWritePaths needs the
    # path to already exist.
    # The recovery path ships with the product: an escape hatch that restores
    # egress, and a dead-man that removes the block when the tunnel stops
    # carrying. Installing a fail-closed guard without these is a machine that
    # can lose its internet and need a human to fix it.
    for tool in vallum-panic vallum-guard-deadman vallum-cleanup; do
        if [ -f "packaging/$tool" ]; then
            run install -D -m 0755 "packaging/$tool" "/usr/local/sbin/$tool"
        elif [ -f "$SOURCE_DIR/$tool" ]; then
            run install -D -m 0755 "$SOURCE_DIR/$tool" "/usr/local/sbin/$tool"
        fi
    done
    # The console's privileged path and the full-tunnel deploy scripts ship
    # with the product: without them the plan-before-apply panel is a button
    # that prints a sudo error (see the premortem, 2026-11-11).
    run install -d -m 0755 /usr/local/lib/vallum
    for lib in trial.sh go-full-tunnel.sh; do
        if [ -f "scripts/$lib" ]; then
            run install -m 0755 "scripts/$lib" "/usr/local/lib/vallum/$lib"
        fi
    done
    if [ -f "packaging/vallum-ops" ]; then
        run install -m 0755 "packaging/vallum-ops" "/usr/local/sbin/vallum-ops"
    fi
    if [ -f "packaging/vallum-ops-sudoers" ]; then
        ops_user=${SUDO_USER:-$(id -un 2>/dev/null || echo root)}
        run mkdir -p /etc/sudoers.d
        run sh -c "sed 's/@USER@/$ops_user/' packaging/vallum-ops-sudoers > /etc/sudoers.d/vallum-ops"
        run chmod 440 /etc/sudoers.d/vallum-ops
        run visudo -cf /etc/sudoers.d/vallum-ops || { run rm -f /etc/sudoers.d/vallum-ops; echo "sudoers validation failed — ops rule not installed" >&2; }
    fi
    for unit in vallum-deadman@.service vallum-deadman@.timer; do
        if [ -f "packaging/$unit" ]; then
            run install -D -m 0644 "packaging/$unit" "$UNIT_DIR/$unit"
        fi
    done
    # The restore floor is the installer's single deliberate enable (Phase 0.5):
    # every other unit starts only on explicit choice, but "a power cycle
    # restores the network" has to be true on machines where nobody ever
    # enables a tunnel at all.
    if [ -f "$UNIT_DIR/vallum-cleanup.service" ]; then
        run systemctl enable vallum-cleanup || true
    fi
    run systemctl daemon-reload || true

    if [ -f "$TMPFILES_DIR/vallum-tmpfiles.conf" ]; then
        run systemd-tmpfiles --create "$TMPFILES_DIR/vallum-tmpfiles.conf" || true
    fi
    # The metrics timer is opt-in: it only earns an `enable` when this host
    # already runs node_exporter's textfile collector, which is what it feeds.
    if [ -d /var/lib/node_exporter/textfile_collector ]; then
        run systemctl daemon-reload
        run systemctl enable --now vallum-metrics.timer
    fi
    local man
    for man in vallum.8 vallum-quick.8 vallum.toml.5; do
        if [ -f "$SOURCE_DIR/$man" ]; then
            run install -D -m 0644 "$SOURCE_DIR/$man" "/usr/share/man/man${man##*.}/$man"
        elif [ -f "packaging/$man" ]; then
            run install -D -m 0644 "packaging/$man" "/usr/share/man/man${man##*.}/$man"
        fi
    done
    for shell in bash zsh fish; do
        local dest
        case "$shell" in
            bash) dest=/usr/share/bash-completion/completions/vallum ;;
            zsh)  dest=/usr/share/zsh/site-functions/_vallum ;;
            fish) dest=/usr/share/fish/vendor_completions.d/vallum.fish ;;
        esac
        if [ -f "$SOURCE_DIR/vallum.$shell" ]; then
            run install -D -m 0644 "$SOURCE_DIR/vallum.$shell" "$dest"
        elif [ -f "packaging/vallum.$shell" ]; then
            run install -D -m 0644 "packaging/vallum.$shell" "$dest"
        fi
    done
}

# ── client shims ────────────────────────────────────────────────────

add_client() {
    local name=$1 bundle
    [ -n "$name" ] || { echo "--add-client needs a name" >&2; exit 1; }
    bundle="$name.vallum-bundle"
    local args=(peer add "$name" --ship-key --bundle-out "$bundle" --forget-key)
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
    # The binary owns the install manifest — delegate to it so this list
    # cannot drift behind it. Only binaries from before `vallum uninstall`
    # existed (pre-1.6.2) take the inline fallback below.
    if [ "$DRY" -eq 0 ] && /usr/bin/vallum uninstall --help >/dev/null 2>&1; then
        exec /usr/bin/vallum uninstall "$@"
    fi
    say "uninstalling (vallum uninstall not available on this binary — legacy path)"
    local instance
    for instance in $(systemctl list-units --all --plain --no-legend 'vallum*@*' 2>/dev/null \
        | awk '{print $1}' | sed 's/\.service$//;s/\.timer$//' | sort -u); do
        run systemctl disable --now "$instance"
    done
    run systemctl disable --now vallum-metrics.timer 2>/dev/null || true
    run rm -f /usr/local/sbin/vallum-panic /usr/local/sbin/vallum-guard-deadman
    run systemctl disable vallum-cleanup 2>/dev/null || true
    run rm -f "$UNIT_DIR/vallum-cleanup.service"
    run rm -f "$UNIT_DIR/vallum-deadman@.service" "$UNIT_DIR/vallum-deadman@.timer"
    run rm -f "$UNIT_DIR/vallum@.service" "$UNIT_DIR/vallum-guard@.service" \
        "$UNIT_DIR/vallum-quick@.service" \
        "$UNIT_DIR/vallum-quick-watch@.service" \
        "$UNIT_DIR/vallum-enroll@.service" "$UNIT_DIR/vallum-metrics.service" \
        "$UNIT_DIR/vallum-metrics.timer"
    # The tmpfiles entry goes with the package; the directory it creates is
    # /run, which is cleared at boot, so there is nothing else to remove.
    run rm -f "$TMPFILES_DIR/vallum-tmpfiles.conf"
    run rm -f /usr/share/man/man8/vallum.8 /usr/share/man/man8/vallum-quick.8 \
        /usr/share/man/man5/vallum.toml.5 \
        /usr/share/bash-completion/completions/vallum \
        /usr/share/zsh/site-functions/_vallum \
        /usr/share/fish/vendor_completions.d/vallum.fish
    run systemctl daemon-reload
    run rm -rf "$RUNTIME_DIR"
    # /etc/vallum holds private keys: kept by default, removed only by --purge.
    if printf '%s\n' "$@" | grep -qx -- '--purge'; then
        run rm -rf "$CONFIG_DIR"
    else
        echo "   kept  $CONFIG_DIR (pass --purge to remove configs and keys)"
    fi
    run rm -f "$BIN_DIR/vallum" "$BIN_DIR/vallum-quick"
    if [ "$DRY" -eq 0 ]; then
        nft delete table inet vallum 2>/dev/null || true
        rm -f "$SYSCTL_FILE"
        sysctl --system >/dev/null 2>&1 || true
    fi
}

# ── main ────────────────────────────────────────────────────────────

need_root

if [ "$UNINSTALL" -eq 1 ]; then
    uninstall "${UNINSTALL_ARGS[@]}"
    exit 0
fi

WORK=""
if [ "$DRY" -eq 0 ]; then
    WORK=$(mktemp -d)
    trap 'rm -rf "$WORK"' EXIT
    # gh runs as the invoking user, so the download dir must be writable by
    # them — mktemp -d under sudo lands 0700 root.
    chown "${SUDO_USER:-root}" "$WORK" 2>/dev/null || true
fi

if [ -n "$PACKAGE" ]; then
    if [ "$MODE" != "release" ]; then
        echo "--package only makes sense with --from-release (local builds have no package)" >&2
        exit 1
    fi
    if [ "$PACKAGE" = "auto" ]; then
        if command -v dpkg >/dev/null 2>&1; then PACKAGE=deb
        elif command -v rpm >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then PACKAGE=rpm
        else echo "could not detect a package manager; pass --package deb|rpm" >&2; exit 1; fi
    fi
    case "$PACKAGE" in
        deb) command -v dpkg >/dev/null 2>&1 || { echo "dpkg not found on this host" >&2; exit 1; } ;;
        rpm) ;;
        *) echo "--package must be deb or rpm" >&2; exit 1 ;;
    esac
fi

SOURCE_DIR=""
if [ "$MODE" = "release" ]; then
    if [ -z "$VERSION" ]; then
        VERSION=$(latest_version)
    fi
    [ -n "$VERSION" ] || { echo "could not determine the latest release" >&2; exit 1; }
    # One call site, before anything is downloaded or printed: a dry run has to
    # report the refusal too, or it is a plan the real run will not follow.
    guard_downgrade "$VERSION"
    if [ "$DRY" -eq 1 ]; then
        if [ -n "$PACKAGE" ]; then
            say "would download $(package_asset_name "$VERSION"), verify the signature, and $PACKAGE-install it"
        else
            say "would download $VERSION and install it to $BIN_DIR"
        fi
    elif [ -n "$PACKAGE" ]; then
        install_package "$VERSION" "$WORK"
    else
        install_from_release "$VERSION" "$WORK"
    fi
else
    install_from_local
fi

# A package's own maintainer scripts lay down and reload everything; manual
# file installation is only for the tarball/local paths.
if [ -z "$PACKAGE" ] && { [ "$DRY" -eq 0 ] || [ -n "$SOURCE_DIR" ]; }; then
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

# Installing is not the same as becoming a server. Only prepare the host when
# the operator actually said something about the server (`--endpoint`,
# `--address`, `--listen`, …); otherwise a plain install on a laptop would
# silently start a daemon, open a port and add NAT rules.
# `--dry-run` lands in PASSTHRU too, so count only arguments that actually say
# something about the server.
substantive=0
for arg in "${PASSTHRU[@]:-}"; do
    case "$arg" in
        --dry-run | "") ;;
        *) substantive=1 ;;
    esac
done
if [ "$INSTALL_ONLY" -eq 1 ] || [ "$substantive" -eq 0 ]; then
    if [ "$DRY" -eq 1 ]; then say "would install, and stop here"; else say "installed"; fi
    echo "this machine is ready. To make it a server:  sudo vallum setup --server"
    echo "to join an existing server:                  sudo vallum setup --remote user@host"
    exit 0
fi

say "preparing this host as a tunnel server"
if [ "$DRY" -eq 1 ]; then
    echo "   would run: vallum server init ${PASSTHRU[*]:-}"
    exit 0
fi
exec /usr/bin/vallum server init "${PASSTHRU[@]}"
