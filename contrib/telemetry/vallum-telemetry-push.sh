#!/bin/bash
# Push one scrape of Vallum's metrics into VictoriaMetrics.
#
# The daemon owns the counters; this only moves them into a store that survives
# a daemon restart. A counter reset on restart is handled by rate()/increase().
#
# Two files are pushed, not one:
#
#   `vallum metrics` output   the daemon's own counters, scraped fresh
#   /run/vallum/verify.prom   the scheduled two-host gate's last result
#
# The second one is here because the gate is what proves the tunnel, and a proof
# nobody records is a proof nobody can trend. `scripts/verify-scheduled.sh` writes
# it; this ships it to the same store, so the alerts that watch the tunnel also
# watch the evidence that the tunnel works.
set -u
CONFIG=${1:-/etc/vallum/vallum0.toml}
VM=${VM_URL:-http://127.0.0.1:8428/api/v1/import/prometheus}
VERIFY_FILE=${VALLUM_VERIFY_METRICS:-/run/vallum/verify.prom}

push() { curl -sS --max-time 10 -X POST --data-binary @- "$VM" >/dev/null; }

OUT=$(/usr/bin/vallum metrics --config "$CONFIG" 2>/dev/null)
if [ -n "$OUT" ]; then
    printf '%s\n' "$OUT" | push
fi

# Absent until the first scheduled run: absence means "the gate has never run
# here", which the alert distinguishes from "it ran and failed".
if [ -s "$VERIFY_FILE" ]; then
    push < "$VERIFY_FILE"
fi

# A scrape that produced nothing is a scrape that did not happen; exit nonzero so
# the unit's state says so, and let `vallum_up 0` be the alert.
[ -n "$OUT" ] || exit 1
exit 0
