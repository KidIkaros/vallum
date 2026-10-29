#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The zstd advisories (RUSTSEC-2026-0391, -0398, -0403) are fixed in zstd
# 0.14.3 / zstd-safe 8.2.0, which is where OriginSDK v0.7.4 pins the crate.
# This tripwire keeps the locks and deny.toml tied to that fact: a fixed lock
# may not carry a stale ignore, and a vulnerable lock (a pin regression) must
# carry the documented ignores rather than pass silently.
#
# Both locks are checked. The fuzz crate is its own workspace with its own
# committed lock, and it resolves the SDK through the same workspace-inherited
# dependency — so it can hold an older pin than the root lock and would
# otherwise regress without any gate noticing.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

lock_version() { # $1 = crate name, $2 = lock file
    awk -v want="$1" '
        /^\[\[package\]\]/ { name = ""; version = "" }
        /^name = /    { name = $0; sub(/^name = "/, "", name); sub(/"$/, "", name) }
        /^version = / { version = $0; sub(/^version = "/, "", version); sub(/"$/, "", version) }
        name == want && version != "" { print version; exit }
    ' "$2"
}

version_ge() { # $1 >= $2, semver enough for these crates
    [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n 1)" = "$1" ]
}

ignores="RUSTSEC-2026-0391 RUSTSEC-2026-0398 RUSTSEC-2026-0403"

status=0
for lock in Cargo.lock fuzz/Cargo.lock; do
    if [ ! -f "$lock" ]; then
        echo "missing $lock: the dependency shape changed; re-read deny.toml" >&2
        status=1
        continue
    fi

    zstd=$(lock_version zstd "$lock")
    safe=$(lock_version zstd-safe "$lock")
    if [ -z "$zstd" ] || [ -z "$safe" ]; then
        echo "$lock: no zstd/zstd-safe entry; the dependency shape changed; re-read deny.toml" >&2
        status=1
        continue
    fi

    fixed=1
    version_ge "$zstd" 0.14.3 || fixed=0
    version_ge "$safe" 8.2.0 || fixed=0

    if [ "$fixed" = 1 ]; then
        for id in $ignores; do
            if grep -q "\"$id\"" deny.toml; then
                echo "$lock: zstd $zstd / zstd-safe $safe are past every fix, but" >&2
                echo "deny.toml still ignores $id. Retire the zstd ignores in the same" >&2
                echo "change that moves the SDK's pin." >&2
                status=1
            fi
        done
        echo "$lock: zstd $zstd / zstd-safe $safe: past every fix, no stale ignores"
    else
        for id in $ignores; do
            if ! grep -q "\"$id\"" deny.toml; then
                echo "$lock still resolves zstd $zstd / zstd-safe $safe, but deny.toml" >&2
                echo "does not ignore $id. Add the documented ignore with its" >&2
                echo "reachability argument, or move the pin: this lock is vulnerable." >&2
                status=1
            fi
        done
        echo "$lock: zstd $zstd / zstd-safe $safe: the documented ignores are still required"
    fi
done

exit "$status"
