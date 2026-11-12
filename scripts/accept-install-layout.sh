#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The install layout gate: run the installer into a staging directory and check
# what it actually produced.
#
#   scripts/accept-install-layout.sh
#
# Why this exists: scripts/check-package-manifest.sh compares install.sh's
# declared file list against the deb and rpm tables. All three are written by
# the same hand, so a passing parity check establishes that the three
# manifests agree with each other - not that any of them installs the product.
# A file that install.sh's loops do not actually install, a unit installed with
# the wrong mode, a path that lands somewhere the manifest does not name: the
# parity check cannot see any of it.
#
# This gate runs the real installer, with --root, into a temporary directory.
# It needs no root, no docker, no container runtime and no network, so it runs
# on any machine - including the CI runner.
#
# What it asserts:
#   1. every packaging file the manifests promise is in the staged tree;
#   2. the modes are right (binaries and tools 0755, units and config 0644,
#      the sudoers rule 0440);
#   3. the installer touched nothing outside the staging directory.
set -uo pipefail
cd "$(dirname "$0")/.."
REPO=$(pwd)

STAGE=$(mktemp -d)
FAILURES=0

cleanup() {
    rm -rf "$STAGE"
}
trap cleanup EXIT

say() { printf '[layout] %s\n' "$*"; }
ok() { printf '   ok    %s\n' "$*"; }
bad() { printf '   FAIL  %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

# ── 1. build what is being installed ────────────────────────────────────────
say "building the release binaries"
if ! cargo build --release -p vallum -p vallum-quick >/dev/null 2>&1; then
    say "FAIL: cargo build --release -p vallum -p vallum-quick failed"
    exit 1
fi

# ── 1b. the completions are generated artefacts ──────────────────────────────
# packaging/vallum.{bash,zsh,fish} are gitignored: scripts/gen-completions.sh
# makes them from the binary, and scripts/release.sh runs it before packaging.
# The gate does the same, so it stages what a release would stage - and then
# asserts that what it staged is what the binary produces right now.
say "generating the shell completions"
if ! bash scripts/gen-completions.sh >/tmp/accept-install-layout-gen.log 2>&1; then
    say "FAIL: scripts/gen-completions.sh failed"
    tail -10 /tmp/accept-install-layout-gen.log | sed 's/^/         /'
    exit 1
fi

# ── 2. a snapshot of the places the installer writes to ─────────────────────
# (so the third assertion can prove it wrote nowhere else)
snapshot() {
    for d in /usr/bin /etc/systemd/system /etc/tmpfiles.d /usr/local/sbin \
             /usr/local/lib/vallum /etc/sudoers.d /usr/share/man/man8 \
             /usr/share/man/man5 /usr/share/bash-completion/completions \
             /usr/share/zsh/site-functions /usr/share/fish/vendor_completions.d; do
        [ -d "$d" ] || continue
        find "$d" -maxdepth 1 -name 'vallum*' -printf '%p %m\n' 2>/dev/null
    done
    [ -d /usr/share/man/man8 ] && find /usr/share/man/man8 -maxdepth 1 -name 'vallum*' -printf '%p %m\n' 2>/dev/null
    [ -d /usr/share/man/man5 ] && find /usr/share/man/man5 -maxdepth 1 -name 'vallum*' -printf '%p %m\n' 2>/dev/null
}
BEFORE=$(snapshot)

# ── 3. stage the install ────────────────────────────────────────────────────
say "staging the install into $STAGE"
if ! bash scripts/install.sh --local --install-only --root "$STAGE" >/tmp/accept-install-layout.log 2>&1; then
    bad "the installer failed"
    tail -20 /tmp/accept-install-layout.log | sed 's/^/         /'
    exit 1
fi
ok "the installer completed"

# ── 4. every promised file is there ─────────────────────────────────────────
# The manifests name the files; the staged tree is what the installer produced.
manifest_files=$(
    {
        sed -n '/^install_docs/,/^}/p' scripts/install.sh \
            | tr ' \\' '\n\n' \
            | grep -oE 'vallum[a-z0-9@._-]*\.(service|timer|conf|[0-9])'
        sed -n '/^install_docs/,/^}/p' scripts/install.sh \
            | grep -oE 'for shell in.*' | tr -s ' ;' '\n\n' \
            | grep -vxE 'for|shell|in|do' | sed 's/^/vallum./'
    } | sort -u
)

# A file's name in the manifest is not always its name on disk: the zsh
# completion is `vallum.zsh` and lands as `_vallum`. The check is on the
# DESTINATION, which is what the installer actually promises.
staged_paths=$(find "$STAGE" -type f -printf '%P\n' | sort -u)
missing=0
while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$f" in
        vallum.bash) want=usr/share/bash-completion/completions/vallum ;;
        vallum.zsh)  want=usr/share/zsh/site-functions/_vallum ;;
        vallum.fish) want=usr/share/fish/vendor_completions.d/vallum.fish ;;
        vallum.toml) want=etc/vallum/vallum.toml ;;
        *)           want="" ;;
    esac
    if [ -n "$want" ]; then
        if ! printf '%s\n' "$staged_paths" | grep -qx "$want"; then
            bad "the manifest promises '$f' and the installer did not stage it (as $want)"
            missing=$((missing + 1))
        fi
        continue
    fi
    if printf '%s\n' "$staged_paths" | grep -q "/$f$"; then
        :
    else
        bad "the manifest promises '$f' and the installer did not stage it"
        missing=$((missing + 1))
    fi
done <<<"$manifest_files"
[ "$missing" -eq 0 ] && ok "every promised file is in the staged tree ($(printf '%s\n' "$manifest_files" | wc -l) files)"

# ── 5. the modes ────────────────────────────────────────────────────────────
mode_of() { find "$STAGE" -type f -name "$1" -printf '%m\n' 2>/dev/null | head -1; }
# `vallum-ops` is two files: the dispatcher in /usr/local/sbin (0755) and the
# sudoers rule in /etc/sudoers.d (0440). A basename check would find the
# first and call the second wrong.
mode_at() { find "$STAGE" -type f -path "$STAGE/$1" -printf '%m\n' 2>/dev/null | head -1; }
check_mode_at() {
    local path=$1 want=$2 got
    got=$(mode_at "$path")
    if [ -z "$got" ]; then
        bad "$path is not in the staged tree (mode $want expected)"
    elif [ "$got" != "$want" ]; then
        bad "$path has mode $got, expected $want"
    else
        ok "$path is mode $want"
    fi
}
check_mode() {
    local name=$1 want=$2 got
    got=$(mode_of "$name")
    if [ -z "$got" ]; then
        bad "$name is not in the staged tree (mode $want expected)"
    elif [ "$got" != "$want" ]; then
        bad "$name has mode $got, expected $want"
    else
        ok "$name is mode $want"
    fi
}
for unit in vallum@.service vallum-guard@.service vallum-quick@.service \
            vallum-quick-watch@.service vallum-enroll@.service \
            vallum-cleanup.service vallum-metrics.service vallum-metrics.timer \
            vallum-deadman@.service vallum-deadman@.timer; do
    check_mode "$unit" 644
done
for tool in vallum-panic vallum-guard-deadman vallum-cleanup \
            vallum-heal-runtime-dir vallum-ops; do
    check_mode_at "usr/local/sbin/$tool" 755
done
# The two binaries, by path: the bash completion is also called `vallum`, and a
# basename check finds that one first.
check_mode_at usr/bin/vallum 755
check_mode_at usr/bin/vallum-quick 755
check_mode_at etc/sudoers.d/vallum-ops 440
check_mode vallum-tmpfiles.conf 644

# The completions are generated artefacts. If the CLI's command set changes and
# they are not regenerated, a user's shell completes the wrong commands - and
# nothing else notices, because a stale file is a valid file.
if [ -x target/release/vallum ]; then
    for shell in bash zsh fish; do
        generated=$(mktemp)
        if target/release/vallum completions "$shell" > "$generated" 2>/dev/null; then
            if diff -q "$generated" "packaging/vallum.$shell" >/dev/null 2>&1; then
                ok "the $shell completion matches what the CLI generates"
            else
                bad "packaging/vallum.$shell is stale - regenerate it with 'vallum completions $shell'"
            fi
        fi
        rm -f "$generated"
    done
fi

# ── 6. nothing outside the staging directory ────────────────────────────────
AFTER=$(snapshot)
if [ "$BEFORE" = "$AFTER" ]; then
    ok "the installer wrote nothing outside the staging directory"
else
    bad "the installer changed the host:"
    diff <(printf '%s\n' "$BEFORE") <(printf '%s\n' "$AFTER") | sed 's/^/         /'
fi

echo
if [ "$FAILURES" -eq 0 ]; then
    echo "== PASS - the installer produced what the manifests promise, and touched nothing else"
    scripts/verdict.sh accept-install-layout passed 4
    exit 0
fi
echo "== FAIL - $FAILURES check(s) failed"
scripts/verdict.sh accept-install-layout failed "$FAILURES"
exit 1
