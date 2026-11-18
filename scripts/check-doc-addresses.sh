#!/bin/bash
# Fail when a document claims a LIVE deployment address that is really the test
# harness's.
#
# The defect this exists for, found 2026-11-17: `docs/alpha-readiness-2026-11-12.md`
# recorded a stranger's join as `10.99.90.8/32 via 107.175.238.82:51921`, and said
# the public desk ran as `vallum-desk@vallumrc`. Every one of those values is
# `scripts/verify-remote.sh`'s scratch default — `SUBNET=10.99.90.0/24`,
# `CIFACE=vallumrc0`, `PORT=51921` — which exists precisely so the two-host test
# can run BESIDE a live server without touching it. A published verdict described
# a test rig as production, and two later readers (a human and an agent) each
# built a wrong story on top of it before anyone checked the host.
#
# The check is mechanical because the mistake is: a document that talks about the
# live deployment, the public desk, a stranger, or production, and uses an
# address that the harness owns. That combination is almost always a conflation,
# and when it is not — a doc deliberately explaining the harness — it says so,
# and the line is exempt with the marker below.
#
# Usage:
#   scripts/check-doc-addresses.sh          # check, exit 1 on a finding
#   scripts/check-doc-addresses.sh -v       # also print every claim it accepted
set -u
cd "$(dirname "$0")/.." || exit 1
VERBOSE=${1:-}

# The harness's addressing, read from the script rather than copied, so the two
# cannot drift. A default changed in verify-remote.sh is picked up here.
HARNESS_PORT=$(sed -n 's/^PORT=\${PORT:-\([0-9]*\)}.*/\1/p' scripts/verify-remote.sh | head -1)
HARNESS_SUBNET=$(sed -n 's/^SUBNET=\${SUBNET:-\([0-9./]*\)}.*/\1/p' scripts/verify-remote.sh | head -1)
HARNESS_IFACE=$(sed -n 's/^CIFACE=\([a-z0-9]*\).*/\1/p' scripts/verify-remote.sh | head -1)
for value in "$HARNESS_PORT" "$HARNESS_SUBNET" "$HARNESS_IFACE"; do
    if [ -z "$value" ]; then
        echo "FAIL  could not read the harness defaults from scripts/verify-remote.sh"
        echo "      the check cannot run, and a check that silently passes is worse than none"
        exit 1
    fi
done
# The subnet's /24 stem, so `10.99.90.8/32` is caught as well as `10.99.90.0/24`.
SUBNET_STEM=${HARNESS_SUBNET%/*}
SUBNET_STEM=${SUBNET_STEM%.*}
# The interface's stem, so the unit name `vallum-desk@vallumrc` is caught as well
# as the interface `vallumrc0`. Without this the check missed the exact sentence
# that started it: the doc said `vallum-desk@vallumrc` and the harness names its
# interface `vallumrc0`, so a literal match on the interface found nothing. Found
# by testing the check against the original error rather than against a
# paraphrased one.
IFACE_STEM=${HARNESS_IFACE%%[0-9]*}

# A document is making a live claim if it uses any of these about itself.
LIVE_WORDS='live deployment|public desk|a stranger|stranger.s|in production|production host|the deployment|open signup|desk\.wingman\.gold'

# An explicit exemption, because some paragraphs must mention harness addresses
# while discussing the harness. It is deliberately a visible marker, and it
# covers the whole PARAGRAPH it appears in (up to a blank line): a correction
# block that names the harness's values cannot put the marker on every line
# without becoming unreadable, and a per-line rule would force it to.
EXEMPT='harness-address-ok'

fail=0
scanned=0

# Only operator-facing prose. ADRs and CHANGELOG are included because both have
# carried harness addresses as if they were deployment facts.
while IFS= read -r file; do
    # Which lines are inside an exempted paragraph. Computed first so the check
    # below stays a plain loop over findings.
    exempt=$(awk -v marker="$EXEMPT" '
        /^[[:space:]]*$/ { inside = 0; next }
        index($0, marker) { inside = 1; print NR; next }
        inside { print NR }
    ' "$file" 2>/dev/null || true)
    while IFS=: read -r lineno line; do
        scanned=$((scanned + 1))
        if printf '%s\n' "$exempt" | grep -qx "$lineno"; then
            [ -n "$VERBOSE" ] && printf 'ok(exempt) %s:%s\n' "$file" "$lineno"
            continue
        fi
        if printf '%s' "$line" | grep -qiE "$LIVE_WORDS"; then
            echo "FAIL  $file:$lineno"
            echo "      a live-deployment claim using the test harness's addressing"
            echo "      ($HARNESS_IFACE / $HARNESS_SUBNET / port $HARNESS_PORT)"
            echo "      $(printf '%s' "$line" | sed 's/^[[:space:]]*//' | cut -c1-140)"
            fail=1
        else
            [ -n "$VERBOSE" ] && printf 'ok        %s:%s\n' "$file" "$lineno"
        fi
    done < <(grep -nE "$SUBNET_STEM|$HARNESS_PORT|$IFACE_STEM" "$file" 2>/dev/null || true)
done < <(find docs -name '*.md' -type f; echo CHANGELOG.md; echo README.md)

if [ "$fail" -eq 0 ]; then
    echo "PASS  $scanned line(s) mention the harness's addressing, none as a live-deployment claim"
    exit 0
fi
echo
echo "Fix: say which deployment you mean. The harness's values are"
echo "  interface $HARNESS_IFACE, subnet $HARNESS_SUBNET, port $HARNESS_PORT"
echo "and the live deployment's are whatever /etc/vallum/*.toml says on the host —"
echo "read it there, or cite a ticket's own output, rather than the test rig's."
exit 1
