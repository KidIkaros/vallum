#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The fuzzing gate: every target, for a bounded time, with the committed seeds.
#
# Usage:
#   scripts/fuzz.sh [seconds-per-target]     # default 60
#
# Exit status 0 means every target ran to its time limit without a crash. A
# crash writes its input under `fuzz/artifacts/<target>/` and fails this script;
# the artifact is the whole bug report and should be committed with the fix.
#
# CI runs this same script: a 60 s matrix on pull requests, and a long run
# nightly (`.github/workflows/fuzz.yml`).

set -euo pipefail

SECONDS_PER_TARGET=${1:-60}
ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

for target in message_parse handshake_decode replay shaping enroll_parse epoch_open segment_reassembly; do
    mkdir -p "fuzz/corpus/$target"
    if [ -d "fuzz/seeds/$target" ]; then
        cp -n "fuzz/seeds/$target"/* "fuzz/corpus/$target"/ 2>/dev/null || true
    fi

    echo "fuzz: $target for ${SECONDS_PER_TARGET}s"
    cargo +nightly fuzz run "$target" -- \
        -max_total_time="$SECONDS_PER_TARGET" \
        -rss_limit_mb=2048 \
        -timeout=10
done

echo "fuzz: PASS"
