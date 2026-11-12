#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Assemble the release tarball's contents.
#
# One list, used by the release and by the gate that checks it, so the two
# cannot drift. The release used to carry its own copy list, and a copy line
# edited in the wrong place shipped a tarball without the enrolment unit;
# nobody noticed until it was installed on a host.
#
# Usage: scripts/package-tarball.sh <staging-directory>
#
# Prints the member names it copied, one per line, so a caller can assert
# that the archive contains exactly what was staged.
set -euo pipefail

STAGE=${1:?usage: package-tarball.sh <staging-directory>}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

BINDIR=${BINDIR:-target/release}

# The canonical list. Everything the product needs to be installed and to run:
# the binaries, the man pages, the completions, EVERY unit (the guard, the
# cleanup floor and the dead-man included - a fail-closed guard without them
# is a machine that can lose its internet and need a human to fix it), the
# tmpfiles rule, and the executables those units run.
#
# The executables are the part that was missing: `vallum@.service` runs
# `ExecStartPre=+/usr/local/sbin/vallum-heal-runtime-dir`, and ExecStartPre
# failure is fatal, so a tarball without it cannot start a tunnel at all.
UNITS=(
    vallum@.service
    vallum-guard@.service
    vallum-quick@.service
    vallum-quick-watch@.service
    vallum-enroll@.service
    vallum-cleanup.service
    vallum-metrics.service
    vallum-metrics.timer
    vallum-deadman@.service
    vallum-deadman@.timer
)

EXECUTABLES=(
    vallum-panic
    vallum-guard-deadman
    vallum-cleanup
    vallum-heal-runtime-dir
    vallum-ops
)

DOCS=(
    vallum.8
    vallum-quick.8
    vallum.toml.5
    vallum.bash
    vallum.zsh
    vallum.fish
    vallum-alerts.yml
    vallum-tmpfiles.conf
)

mkdir -p "$STAGE"

copied=()
copy_one() {
    local src=$1
    [ -f "$src" ] || { echo "package-tarball: missing $src" >&2; exit 1; }
    cp "$src" "$STAGE/"
    copied+=("$(basename "$src")")
}

copy_one "$BINDIR/vallum"
copy_one "$BINDIR/vallum-quick"
copy_one LICENSE
copy_one README.md
for f in "${UNITS[@]}" "${DOCS[@]}" "${EXECUTABLES[@]}"; do
    copy_one "packaging/$f"
done

# The completions are generated from the release binary and are gitignored, so
# they are build artifacts: an empty one ships a shell that completes nothing.
for shell in bash zsh fish; do
    [ -s "packaging/vallum.$shell" ] || {
        echo "package-tarball: packaging/vallum.$shell is empty or missing;" \
             "gen-completions.sh produced nothing" >&2
        exit 1
    }
done

printf '%s\n' "${copied[@]}"
