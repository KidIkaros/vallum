#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Every durable state root the shipped tree names must be named in
# docs/deployment/backup.md.
#
# That document used to open with a claim — "all durable Vallum state lives in
# one directory" — and an operator's whole disaster-recovery plan was built on
# it. A component that keeps state somewhere else silently falsified the claim,
# and nothing in the delivery path asked the question: the desk shipped in
# 1.8.0 with its account database at /var/lib/vallum/desk.sqlite, outside every
# backup instruction, and the account number it holds is the service's only
# credential and the one thing with no reset flow.
#
# So the rule is structural rather than remembered: a durable root that
# appears in shipped code must appear in the backup document. Roots, not
# paths — a component may add files under a documented root without touching
# this gate.
#
# What counts as durable is deliberately narrow: /etc/vallum and /var/lib are
# the two roots the product treats as surviving a reboot. /run is tmpfs
# (ADR-0017) and is never durable, so it is never required here. A third root
# means adding it to the pattern and to the document in the same change.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

doc=docs/deployment/backup.md
[ -f "$doc" ] || { echo "missing $doc: the backup contract has no home" >&2; exit 1; }

# Shipped code only: the crates, the service, the units and the installer.
# Docs and tests are excluded — they mention paths without owning them.
#
# Every scanned path is asserted present first. `2>/dev/null` on the scan would
# otherwise turn a renamed directory into a silently narrower scan that still
# exits 0 — the failure mode this gate exists to catch, applied to itself.
scanned="crates service packaging scripts/install.sh"
for path in $scanned; do
    [ -e "$path" ] || { echo "scanned path '$path' is missing: the scan is narrower than it claims" >&2; exit 1; }
done

roots=$(
    grep -rhoE '/(etc|var/lib|opt|srv)/vallum[a-zA-Z0-9_-]*' \
        crates service packaging scripts/install.sh 2>/dev/null \
        | sort -u || true
)

if [ -z "$roots" ]; then
    echo "no durable state roots found in shipped code: the scan is broken" >&2
    exit 1
fi

# The match is anchored to a markdown table row carrying the root inside
# backticks — the "Where" column. A prose sentence that merely mentions the
# path ("we never use /opt/vallum") documents nothing an operator can follow,
# and a bare substring match would accept it.
status=0
echo "durable state roots named by the tree:"
for r in $roots; do
    if grep -qE "^\|.*\`${r}(/[^\`]*)?\`" "$doc"; then
        printf '   ok    %-20s documented in the table\n' "$r"
    else
        printf '   MISS  %-20s not a row in %s\n' "$r" "$doc"
        status=1
    fi
done

if [ "$status" -ne 0 ]; then
    cat >&2 <<'EOF'

A component keeps durable state somewhere the backup document does not name.
An operator following that document restores a host and loses that state
silently. Add it to the table in docs/deployment/backup.md — what lives
there, what is lost without it, how to take a copy, and how to prove the
restored copy is readable — in the same change that introduces it.
EOF
fi

exit "$status"
