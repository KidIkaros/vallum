#!/usr/bin/env bash
# One install manifest, three channels: install.sh, the cargo-deb asset table,
# and the cargo-generate-rpm asset table must all ship the same packaging/
# files. A file added to one and forgotten in the others means hosts running
# different channels end up in different states — this check is the guard.
#
# Compares basenames: where a file lands differs by channel (deb/rpm use
# /lib/systemd/system, install.sh /etc/systemd/system; zsh's source is
# vallum.zsh but lands as _vallum) — what must agree is what ships.
set -euo pipefail
cd "$(dirname "$0")/.."

# install.sh's canonical list: the `for x in A B C` loops in install_docs().
# Completions install as "vallum.$shell", so expand the shell loop's words
# into the filenames it produces.
install_list=$(
    {
        sed -n '/^install_docs/,/^}/p' scripts/install.sh \
            | tr ' \\' '\n\n' \
            | grep -oE 'vallum[a-z0-9@._-]*\.(service|timer|[0-9])'
        sed -n '/^install_docs/,/^}/p' scripts/install.sh \
            | grep -oE 'for shell in.*' | tr -s ' ;' '\n\n' \
            | grep -vxE 'for|shell|in|do' | sed 's/^/vallum./'
    } | sort -u
)

# deb assets: "../../packaging/<file>" entries inside [package.metadata.deb].
deb_list=$(
    awk '/\[package.metadata.deb\]/,/^\[package.metadata.generate-rpm\]/' \
        crates/vallum/Cargo.toml \
        | grep -oE 'packaging/vallum[a-zA-Z0-9@._-]+' | sed 's|packaging/||' | sort -u
)

# rpm assets: "packaging/<file>" entries inside [package.metadata.generate-rpm].
rpm_list=$(
    awk '/\[package.metadata.generate-rpm\]/,/^\[package.metadata.generate-rpm.scriptlets\]/' \
        crates/vallum/Cargo.toml \
        | grep -oE 'packaging/vallum[a-zA-Z0-9@._-]+' | sed 's|packaging/||' | sort -u
)

fail=0
for channel in "install.sh:$install_list" "deb:$deb_list" "rpm:$rpm_list"; do
    name=${channel%%:*}; list=${channel#*:}
    missing=$(comm -23 <(echo "$install_list") <(echo "$list") | sed 's/^/    /')
    extra=$(comm -13 <(echo "$install_list") <(echo "$list") | sed 's/^/    /')
    if [ -n "$missing" ] || [ -n "$extra" ]; then
        fail=1
        echo "package manifest drift: $name differs from install.sh" >&2
        [ -n "$missing" ] && { echo "  missing from $name:" >&2; echo "$missing" >&2; }
        [ -n "$extra" ]    && { echo "  only in $name:" >&2;      echo "$extra" >&2; }
    fi
done

if [ "$fail" -eq 0 ]; then
    echo "ok — install.sh, deb, and rpm ship the same $(echo "$install_list" | wc -l) packaging files"
fi
exit "$fail"
