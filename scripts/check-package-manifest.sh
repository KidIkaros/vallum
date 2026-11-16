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

# install.sh's canonical list: the `for x in A B C` loops in install_docs(),
# plus the tmpfiles entry, which is installed by an if-block rather than a loop.
# Completions install as "vallum.$shell", so expand the shell loop's words
# into the filenames it produces.
install_list=$(
    {
        # The words are checked against the tree, not against a pattern: a name
        # with no extension (vallum-ops, vallum-panic, vallum-cleanup,
        # vallum-heal-runtime-dir, vallum-guard-deadman) is as much a shipped
        # file as a unit is, and a pattern that only matches known extensions
        # cannot see it. The pattern is what let the deb, the rpm and the
        # installer agree on all omitting the executables their units run.
        sed -n '/^install_docs/,/^}/p' scripts/install.sh \
            | grep -oE 'vallum[a-zA-Z0-9@._-]*' \
            | while read -r name; do
                # Two components ship files: packaging/ (units and helpers) and
                # service/ (the enrolment desk). A name that exists in either
                # is a shipped file.
                { [ -f "packaging/$name" ] || [ -f "service/$name" ]; } && echo "$name"
            done
        sed -n '/^install_docs/,/^}/p' scripts/install.sh \
            | grep -oE 'for shell in.*' | tr -s ' ;' '\n\n' \
            | grep -vxE 'for|shell|in|do' | sed 's/^/vallum./'
    } | sort -u
)

# The one file a channel legitimately differs on. The sudoers rule names a
# user, and a package cannot know who is installing it, so the installer
# renders it while the packages print the line at install time. It is a
# template, not a shipped file, so it is in neither list.
EXCLUDE="vallum-ops-sudoers"
install_list=$(printf '%s\n' "$install_list" | grep -vx "$EXCLUDE" || true)

# deb assets: "../../packaging/<file>" entries inside [package.metadata.deb].
deb_list=$(
    awk '/\[package.metadata.deb\]/,/^\[package.metadata.generate-rpm\]/' \
        crates/vallum/Cargo.toml \
        | grep -oE '(packaging|service)/vallum[a-zA-Z0-9@._-]+' | sed -e 's|packaging/||' -e 's|service/||' | sort -u
)

# rpm assets: "packaging/<file>" entries inside [package.metadata.generate-rpm].
rpm_list=$(
    awk '/\[package.metadata.generate-rpm\]/,/^\[package.metadata.generate-rpm.scriptlets\]/' \
        crates/vallum/Cargo.toml \
        | grep -oE '(packaging|service)/vallum[a-zA-Z0-9@._-]+' | sed -e 's|packaging/||' -e 's|service/||' | sort -u
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
