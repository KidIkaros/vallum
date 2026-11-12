#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The crypto dependency must appear exactly once in the lockfile, and it must
# be the pinned git tag.
#
# Why this needs its own check. `deny.toml` sets `multiple-versions = "warn"`
# (the workspace legitimately carries duplicates - zstd, ring, and others), so
# cargo-deny cannot fail on a duplicate of one specific crate. That leaves the
# one dependency where a duplicate would be genuinely dangerous - the SDK
# itself - unenforced, and unenforced is where the one-way door sits:
#
#   * The registry carries only 0.7.2; 0.7.3 and 0.7.4 exist only as git
#     tags. Moving a tree between them is a SOURCE swap, not a version bump.
#   * Vallum cannot move backwards at all: the adapter calls
#     `MlKem768Kem::encapsulate_deterministic`, which does not exist in
#     v0.7.2, so the adapter would not compile.
#   * So a second, registry copy of the SDK is the only way two versions could
#     ever coexist - and it would compile, and cargo-deny would only warn.
#
# One entry means one SDK in the binary. It is three lines of arithmetic over
# the lockfile, and it is the difference between "the pinning policy" and the
# pinning policy being enforced.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
LOCK="$ROOT/Cargo.lock"

[ -f "$LOCK" ] || { echo "no Cargo.lock at $LOCK" >&2; exit 1; }

count=$(grep -c '^name = "origin-crypto-sdk"$' "$LOCK" || true)
if [ "$count" != "1" ]; then
    echo "the lockfile names origin-crypto-sdk $count times; it must name it once." >&2
    echo "Two copies would mean two SDKs in one binary, from two different sources," >&2
    echo "and the supply-chain gate only warns about that." >&2
    echo "" >&2
    grep -A2 '^name = "origin-crypto-sdk"$' "$LOCK" >&2
    exit 1
fi

# And it must be the pinned tag, not a registry version.
source_line=$(grep -A2 '^name = "origin-crypto-sdk"$' "$LOCK" | grep '^source = ' || true)
case "$source_line" in
    *OriginSDK*) ;;
    *)
        echo "origin-crypto-sdk does not come from the pinned git source:" >&2
        echo "  ${source_line:-<no source line>}" >&2
        echo "A registry copy is 0.7.2, which the adapter cannot compile against." >&2
        exit 1
        ;;
esac

echo "ok    one origin-crypto-sdk, from the pinned source: ${source_line#source = }"
