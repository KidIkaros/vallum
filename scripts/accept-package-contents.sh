#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# What every shipped channel actually contains, checked against what the
# shipped units actually need.
#
# The gap this closes. `check-package-manifest.sh` compares the three
# channels to EACH OTHER, which answers "do they agree?" — and two channels
# can agree on being wrong. They did: the deb and rpm shipped every unit, and
# not one of the five executables those units exec. `vallum@.service`'s
# `ExecStartPre=+/usr/local/sbin/vallum-heal-runtime-dir` therefore failed on
# every packaged start, and `ExecStartPre` failure is fatal.
#
# The authority is the unit: a path a SHIPPED unit executes must exist in the
# same channel, at the right mode, or the unit dies at the worst possible
# moment. So the required set is derived per channel, from the units that
# channel actually ships — which is also why a unit that no channel installs
# (`vallum-exit-notice.service`) is not this gate's business.
#
# Channels checked:
#   * the deb      — built for real with cargo-deb, read with dpkg-deb
#   * the tarball  — assembled by scripts/package-tarball.sh, the same script
#                    the release uses, so the two cannot drift
#
# Exits non-zero on any failure. A missing tool is a skip, never a pass.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

FAILURES=0
note() { printf '   %s\n' "$*"; }
fail() { FAILURES=$((FAILURES + 1)); printf '   FAIL  %s\n' "$*"; }
ok()   { printf '   ok    %s\n' "$*"; }
skip() { printf '   skip  %s\n' "$*"; }

# The paths a unit executes, from its Exec lines.
#
# `sed 's/^Exec[A-Za-z]*=//'` strips the assignment; the second expression
# strips systemd's `+` (run with full privileges). They are two expressions
# because in a basic regular expression `+` is a LITERAL plus, not a
# quantifier: `=+` would mean "equals followed by one or more plus signs",
# which silently drops every ordinary Exec line.
exec_paths_of() {
    grep -hE '^Exec[A-Za-z]*=' "$@" 2>/dev/null \
        | sed 's/^Exec[A-Za-z]*=//; s/^+//' \
        | awk '{print $1}' \
        | grep -E '^/' \
        | sort -u
}

# The paths this project owns. A unit may also exec a system binary
# (/usr/bin/test, /bin/sh, /usr/bin/python3); those are the distribution's
# problem, not ours.
is_ours() {
    case "$1" in
        /usr/local/sbin/vallum*|/usr/bin/vallum*|/usr/share/vallum/*) return 0 ;;
        *) return 1 ;;
    esac
}

# ── channel 1: the deb, built for real ─────────────────────────────────────
check_deb() {
    if ! command -v cargo-deb >/dev/null 2>&1 || ! command -v dpkg-deb >/dev/null 2>&1; then
        skip "the deb (cargo-deb or dpkg-deb is not installed)"
        return
    fi
    if [ ! -x target/release/vallum ] || [ ! -x target/release/vallum-quick ]; then
        note "building the release binaries the package carries"
        cargo build --release -p vallum -p vallum-quick >/tmp/package-contents-build.log 2>&1 || {
            fail "cannot build the release binaries (see /tmp/package-contents-build.log)"
            return
        }
    fi
    rm -rf target/debian
    cargo deb -p vallum --no-build >/tmp/package-contents-deb.log 2>&1 || {
        fail "cargo deb failed (see /tmp/package-contents-deb.log)"
        return
    }
    local deb
    deb=$(ls -t target/debian/*.deb 2>/dev/null | head -1)
    [ -n "$deb" ] || { fail "cargo deb produced no .deb"; return; }
    note "the deb is $(basename "$deb")"

    # Canonical form: no leading "./" and no leading "/", so a package path
    # and an absolute required path compare equal.
    local listing
    listing=$(dpkg-deb -c "$deb" | awk '{print $NF}' | sed 's|^\./||; s|^/||' | sort -u)

    # The units this package ships, and what they need.
    local stage unit
    stage=$(mktemp -d /tmp/vallum-deb-units.XXXXXX) || { fail "no staging directory"; return; }
    dpkg-deb -x "$deb" "$stage" || { fail "cannot unpack the deb"; rm -rf "$stage"; return; }

    local required=() path
    while read -r unit; do
        [ -n "$unit" ] || continue
        while read -r path; do
            is_ours "$path" || continue
            required+=("$path")
        done < <(exec_paths_of "$unit")
    done < <(find "$stage" -type f \( -name '*.service' -o -name '*.timer' \) | sort)

    if [ "${#required[@]}" -eq 0 ]; then
        fail "the deb ships no unit, so nothing could be checked"
        rm -rf "$stage"
        return
    fi
    note "the deb ships $(printf '%s\n' "${required[@]}" | sort -u | wc -l) paths that its units execute"

    while read -r path; do
        [ -n "$path" ] || continue
        if printf '%s\n' "$listing" | grep -qx "$(printf '%s' "$path" | sed 's|^/||')"; then
            ok "the deb ships $path"
        else
            fail "the deb does not ship $path, which a unit it ships executes"
        fi
    done < <(printf '%s\n' "${required[@]}" | sort -u)
    rm -rf "$stage"
}

# ── channel 2: the tarball, assembled by the release's own script ──────────
check_tarball() {
    if [ ! -x scripts/package-tarball.sh ]; then
        skip "the tarball (scripts/package-tarball.sh is missing)"
        return
    fi
    local stage
    stage=$(mktemp -d /tmp/vallum-tarball-stage.XXXXXX) || { fail "no staging directory"; return; }
    if ! scripts/package-tarball.sh "$stage" >/tmp/package-contents-tarball.log 2>&1; then
        fail "package-tarball.sh failed (see /tmp/package-contents-tarball.log)"
        rm -rf "$stage"
        return
    fi

    local required=() path unit
    for unit in "$stage"/*.service "$stage"/*.timer; do
        [ -f "$unit" ] || continue
        while read -r path; do
            is_ours "$path" || continue
            required+=("$path")
        done < <(exec_paths_of "$unit")
    done

    if [ "${#required[@]}" -eq 0 ]; then
        fail "the tarball ships no unit, so nothing could be checked"
        rm -rf "$stage"
        return
    fi
    note "the tarball ships $(printf '%s\n' "${required[@]}" | sort -u | wc -l) paths that its units execute"

    # The tarball is flat: everything at the top level, as it has always been.
    # So the question is whether the file it needs is in there at all.
    while read -r path; do
        [ -n "$path" ] || continue
        if [ -e "$stage/$(basename "$path")" ]; then
            ok "the tarball ships $path"
        else
            fail "the tarball does not ship $path, which a unit it ships executes"
        fi
    done < <(printf '%s\n' "${required[@]}" | sort -u)
    rm -rf "$stage"
}

echo "== the deb"
check_deb
echo "== the release tarball"
check_tarball

echo
if [ "$FAILURES" -gt 0 ]; then
    echo "== FAIL - $FAILURES check(s) failed"
    exit 1
fi
echo "== PASS - every channel ships what the units it ships execute"
