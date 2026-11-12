#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Record a gate's verdict as an artefact bound to the commit.
#
# A PASS printed in prose goes stale the moment the script moves on, and nobody
# notices until something breaks (the rot mode). A verdict that names its commit,
# its target, its timestamp and how many assertions it ran can be compared, and
# a shrinking assertion count is visible - which is the early-warning signal the
# premortem asked for.
#
#   scripts/verdict.sh <gate> <status> [assertions]
#
# VERDICT_DIR defaults to .vallum-verdicts/ in the repo. A failing gate still
# records its verdict: a red record is evidence too.
set -uo pipefail

GATE=${1:-unknown}
STATUS=${2:-failed}
ASSERTIONS=${3:-0}
DIR=${VERDICT_DIR:-"$(cd "$(dirname "$0")/.." && pwd)/.vallum-verdicts"}
mkdir -p "$DIR"

COMMIT=$(git -C "$(dirname "$0")/.." rev-parse HEAD 2>/dev/null || echo unknown)
TREE=$(git -C "$(dirname "$0")/.." rev-parse --short HEAD 2>/dev/null || echo unknown)
STAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
TARGET=${VERDICT_TARGET:-$(hostname 2>/dev/null || echo unknown)}

cat >"$DIR/$GATE.json" <<EOF
{
  "gate": "$GATE",
  "status": "$STATUS",
  "commit": "$COMMIT",
  "tree": "$TREE",
  "assertions": $ASSERTIONS,
  "target": "$TARGET",
  "recorded_at": "$STAMP"
}
EOF
echo "   verdict: $GATE $STATUS ($ASSERTIONS assertions) -> $DIR/$GATE.json"
