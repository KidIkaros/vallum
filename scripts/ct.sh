#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The constant-time gate: run the DudeCT harnesses and judge the result.
#
# Why a script and not a `cargo test`: timing evidence depends on the machine.
# The control must show a leak before any other result is trusted, the CPU is
# pinned so the samples are comparable, and each benchmark is run several times
# because a single dudect run can be unlucky.
#
# Usage:
#   scripts/ct.sh
#
# Environment:
#   RUNS=2       how many times each example is run (the worst |t| is kept)
#   CT_CPU=2     the CPU to pin to, when `taskset` is available
#
# Exit status 0 means: the control leaked (so the harness works) and every
# gated benchmark stayed below |t| = 10. `aead_success_vs_failure` is
# informational — it is expected to differ, and why is in
# `docs/proof/constant-time.md`.

set -euo pipefail

RUNS=${RUNS:-2}
CPU=${CT_CPU:-2}
ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

PIN=()
if command -v taskset >/dev/null 2>&1; then
    PIN=(taskset -c "$CPU")
fi

# benchmark name -> control | gate | info
declare -A KIND=(
    [control]=control
    [ntru_decaps_bitflip]=gate
    [ntru_decaps_wrong_key]=gate
    [aead_tag_compare]=gate
    [aead_failure_causes]=gate
    [aead_success_vs_failure]=info
)

declare -A WORST=()

parse() {
    # `bench <name> ... : n == ..., max t = <value>, ...`
    sed -n 's/^bench \(.*\) *\.\.\. : .*max t = \([-+0-9.]*\).*/\1 \2/p' "$1"
}

for example in ct_control ct_ntru ct_aead; do
    for _ in $(seq 1 "$RUNS"); do
        out=$(mktemp)
        "${PIN[@]}" cargo run --release -q -p vallum-crypto-sdk --example "$example" >"$out" 2>&1
        while read -r name value; do
            [ -n "$name" ] || continue
            abs=$(awk -v x="$value" 'BEGIN { if (x < 0) x = -x; print x }')
            previous=${WORST[$name]:-0}
            WORST[$name]=$(awk -v a="$previous" -v b="$abs" 'BEGIN { print (b > a ? b : a) }')
        done < <(parse "$out")
        rm -f "$out"
    done
done

printf '\n%-28s %-6s %10s  %s\n' benchmark kind "max |t|" verdict
printf '%-28s %-6s %10s  %s\n' ---------------------------- ------ ---------- -------

fail=0
for name in $(printf '%s\n' "${!WORST[@]}" | sort); do
    value=${WORST[$name]}
    kind=${KIND[$name]:-gate}
    verdict=ok

    case "$kind" in
        control)
            # The control *must* leak, or the machine/harness is unusable.
            if awk -v t="$value" 'BEGIN { exit !(t >= 5) }'; then
                verdict="leaked as required"
            else
                verdict="DID NOT LEAK - harness unusable"
                fail=1
            fi
            ;;
        gate)
            if awk -v t="$value" 'BEGIN { exit !(t >= 10) }'; then
                verdict="LEAK"
                fail=1
            elif awk -v t="$value" 'BEGIN { exit !(t >= 5) }'; then
                verdict="suspicious - rerun"
            fi
            ;;
        info)
            verdict="informational (expected to differ)"
            ;;
    esac

    printf '%-28s %-6s %10.3f  %s\n' "$name" "$kind" "$value" "$verdict"
done

echo
if [ "$fail" -ne 0 ]; then
    echo "ct: FAILED" >&2
    exit 1
fi
echo "ct: PASS"
