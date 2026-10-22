#!/bin/bash
# Push one scrape of Vallum's metrics into VictoriaMetrics.
#
# The daemon owns the counters; this only moves them into a store that survives
# a daemon restart. A counter reset on restart is handled by rate()/increase().
set -u
CONFIG=${1:-/etc/vallum/vallum0.toml}
OUT=$(/usr/bin/vallum metrics --config "$CONFIG" 2>/dev/null) || exit 0
[ -n "$OUT" ] || exit 0
printf '%s\n' "$OUT" | curl -sS --max-time 10 -X POST \
  --data-binary @- http://127.0.0.1:8428/api/v1/import/prometheus >/dev/null
