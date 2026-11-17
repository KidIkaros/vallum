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
# A verdict is also signed when the release key is present: an unsigned record
# can be written by hand, and evidence that can be forged is evidence of nothing
# — `release.sh` refuses to consume a passing verdict whose signature does not
# verify against `packaging/allowed_signers`. Signing needs OpenSSH >= 8.0 for
# `ssh-keygen -Y`.
#
#   scripts/verdict.sh <gate> <status> [assertions] [producer-script]
#
# The optional fourth argument is the path of the gate script that ran (pass
# "$0" or "${BASH_SOURCE[0]}"); it is hashed into the record so a verdict names
# what produced it.
#
# VERDICT_DIR defaults to .vallum-verdicts/ in the repo. A failing gate still
# records its verdict: a red record is evidence too.
set -uo pipefail

GATE=${1:-unknown}
STATUS=${2:-failed}
ASSERTIONS=${3:-0}
SCRIPT_PATH=${4:-}
DIR=${VERDICT_DIR:-"$(cd "$(dirname "$0")/.." && pwd)/.vallum-verdicts"}
mkdir -p "$DIR"

COMMIT=$(git -C "$(dirname "$0")/.." rev-parse HEAD 2>/dev/null || echo unknown)
TREE=$(git -C "$(dirname "$0")/.." rev-parse --short HEAD 2>/dev/null || echo unknown)
STAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
TARGET=${VERDICT_TARGET:-$(hostname 2>/dev/null || echo unknown)}
# The producer is the machine that wrote the record, never the target it names:
# a two-host pass is produced on the invoking host and names the remote one, and
# a skip names no host at all (VERDICT_TARGET=unrun) — recording "produced by
# ikaaros@unrun" would be a fact about nothing.
PRODUCER="$(id -un 2>/dev/null || echo unknown)@$(hostname 2>/dev/null || echo unknown)"
SCRIPT_SHA=""
if [ -n "$SCRIPT_PATH" ] && [ -f "$SCRIPT_PATH" ]; then
    SCRIPT_SHA=$(sha256sum "$SCRIPT_PATH" 2>/dev/null | cut -d' ' -f1)
fi

# An optional note. A `skipped` record without its reason is a fact with no
# content — "the two-host gate did not run" is worth little on its own; "it did
# not run because the only host is the live one" is the thing a later reader
# needs. The note is inside the signed file, so it cannot be edited afterwards.
NOTE_LINE=""
if [ -n "${VERDICT_NOTE:-}" ]; then
    note=$(printf '%s' "$VERDICT_NOTE" | tr '\n' ' ' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
    NOTE_LINE="  \"note\": \"$note\","
fi

cat >"$DIR/$GATE.json" <<EOF
{
  "gate": "$GATE",
  "status": "$STATUS",
  "commit": "$COMMIT",
  "tree": "$TREE",
  "assertions": $ASSERTIONS,
  "target": "$TARGET",
  "producer": "$PRODUCER",
  "script_sha256": "$SCRIPT_SHA",
$NOTE_LINE
  "recorded_at": "$STAMP"
}
EOF
echo "   verdict: $GATE $STATUS ($ASSERTIONS assertions) -> $DIR/$GATE.json"

# Sign the record when the release key is present. The same key signs release
# assets, so `packaging/allowed_signers` is the trust anchor on both ends.
SIGN_KEY=${VALLUM_VERDICT_KEY:-${VALLUM_RELEASE_KEY:-$HOME/.config/vallum/release-signing-key}}
rm -f "$DIR/$GATE.json.sig"
if [ -f "$SIGN_KEY" ] && command -v ssh-keygen >/dev/null 2>&1; then
    if ssh-keygen -Y sign -f "$SIGN_KEY" -n file "$DIR/$GATE.json" 2>/dev/null; then
        echo "   signed: $DIR/$GATE.json.sig"
    else
        echo "   unsigned: ssh-keygen -Y sign failed; release.sh refuses unsigned verdicts" >&2
    fi
else
    echo "   unsigned: no verdict key at $SIGN_KEY; release.sh refuses unsigned verdicts" >&2
fi
