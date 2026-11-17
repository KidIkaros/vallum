#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Run the two-host gate on a schedule, record every result, and publish it as a
# metric.
#
# `scripts/verify-remote.sh` is the only check that proves a real client reaches
# a real server over a real network, and it is also the only one that is run by
# hand. A gate run by hand is a gate that runs when someone remembers, and its
# evidence is a stamp that the next run overwrites — so "did it pass last week,
# and did it pass the week before" is a question nobody can answer afterwards.
#
# This wraps it:
#
#   * one JSON line per run in a history file, so pass→fail transitions and a
#     shrinking assertion count are visible as a series rather than a memory;
#   * a Prometheus textfile in the daemon's runtime directory, so the monitoring
#     stack can alert on the gate being stale or failing — the same pipeline that
#     watches the tunnel now watches the thing that proves the tunnel;
#   * a nonzero exit on a *transition* or a regression, not on every failure, so
#     a scheduled unit shows red when something changed and stays quiet while a
#     known-bad state persists.
#
#   scripts/verify-scheduled.sh                  # run the gate now
#   scripts/verify-scheduled.sh --dry-run        # record nothing, run nothing
#   HOST=wingman-vps scripts/verify-scheduled.sh
#
# Exit: 0 pass, 1 the gate failed, 2 the run could not start, 3 a regression
# (fewer assertions than the previous pass, or pass→fail).
#
set -uo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO" || exit 2

HOST=${HOST:-wingman-vps}

# Where the record lives. On the server it is /var/lib/vallum beside the rest of
# the durable state; on an operator's machine the gate runs as a user and cannot
# write there, so it falls back to the XDG state directory. Same data, and the
# metric is pushed either way.
STATE_ROOT=/var/lib/vallum
[ -w "$STATE_ROOT" ] || STATE_ROOT="${XDG_STATE_HOME:-$HOME/.local/state}/vallum"
mkdir -p "$STATE_ROOT" 2>/dev/null

HISTORY=${VALLUM_VERIFY_HISTORY:-$STATE_ROOT/verify-history.jsonl}
METRICS=${VALLUM_VERIFY_METRICS:-$STATE_ROOT/verify.prom}
LAST_SUCCESS=${VALLUM_VERIFY_LAST_SUCCESS:-$STATE_ROOT/verify-last-success}

say() { printf '%s\n' "$*"; }
die() { printf 'verify-scheduled: %s\n' "$*" >&2; exit 2; }

DRY=0
PUSH=1
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY=1 ;;
        --no-push) PUSH=0 ;;
        *) die "unknown argument: $arg" ;;
    esac
done

[ -x scripts/verify-remote.sh ] || die "missing scripts/verify-remote.sh"
command -v git >/dev/null || die "git is required"

commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)

if [ "$DRY" = 1 ]; then
    say "would run: scripts/verify-remote.sh $HOST"
    say "  history: $HISTORY"
    say "  metrics: $METRICS"
    say "  push:    $([ "$PUSH" = 1 ] && echo "to $HOST's VictoriaMetrics" || echo 'no')"
    say "  commit:  $commit"
    exit 0
fi

# The previous run, if any — read before this one overwrites the metric file.
prev_status=""
prev_assertions=""
if [ -s "$HISTORY" ]; then
    prev_line=$(tail -1 "$HISTORY")
    prev_status=$(printf '%s' "$prev_line" | sed -n 's/.*"status":"\([a-z]*\)".*/\1/p')
    prev_assertions=$(printf '%s' "$prev_line" | sed -n 's/.*"assertions":\([0-9]*\).*/\1/p')
fi

say "running the two-host gate against $HOST at $commit"
log=$(mktemp -t vallum-verify.XXXXXX)
scripts/verify-remote.sh "$HOST" >"$log" 2>&1
rc=$?

# The gate prints its own assertion count in the summary; the verdict file is
# the structured copy, and it is what the release path reads.
assertions=0
if [ -f .vallum-verdicts/verify-remote.json ]; then
    assertions=$(sed -n 's/.*"assertions": *\([0-9]*\).*/\1/p' .vallum-verdicts/verify-remote.json | head -1)
    [ -n "$assertions" ] || assertions=0
fi

if [ "$rc" -eq 0 ]; then status=pass; else status=fail; fi
finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)

mkdir -p "$(dirname "$HISTORY")" 2>/dev/null
printf '{"commit":"%s","status":"%s","assertions":%s,"host":"%s","started":"%s","finished":"%s","exit":%d}\n' \
    "$commit" "$status" "$assertions" "$HOST" "$started" "$finished" "$rc" >> "$HISTORY"

# Publish as a metric. Atomic write: the collector must never read a torn file.
if [ -d "$(dirname "$METRICS")" ]; then
    tmp=$(mktemp "$METRICS.XXXXXX" 2>/dev/null) || tmp=""
    if [ -n "$tmp" ]; then
        {
            printf '# HELP vallum_verify_passed Whether the last scheduled two-host run passed.\n'
            printf '# TYPE vallum_verify_passed gauge\n'
            printf 'vallum_verify_passed{host="%s",commit="%s"} %s\n' "$HOST" "$commit" "$([ "$rc" -eq 0 ] && echo 1 || echo 0)"
            printf '# HELP vallum_verify_assertions Assertions the last scheduled two-host run made.\n'
            printf '# TYPE vallum_verify_assertions gauge\n'
            printf 'vallum_verify_assertions{host="%s",commit="%s"} %s\n' "$HOST" "$commit" "$assertions"
            printf '# HELP vallum_verify_last_success_timestamp_seconds When the gate last passed.\n'
            printf '# TYPE vallum_verify_last_success_timestamp_seconds gauge\n'
            if [ "$rc" -eq 0 ]; then
                now_epoch=$(date -u +%s)
                mkdir -p "$(dirname "$LAST_SUCCESS")" 2>/dev/null
                printf '%s\n' "$now_epoch" > "$LAST_SUCCESS" 2>/dev/null || true
                printf 'vallum_verify_last_success_timestamp_seconds{host="%s"} %s\n' "$HOST" "$now_epoch"
            else
                # Carry the previous success forward so "how long has it been
                # failing" is answerable. 0 means never passed — which is a
                # different fact, and the alert says so.
                last=$(cat "$LAST_SUCCESS" 2>/dev/null | head -1)
                printf 'vallum_verify_last_success_timestamp_seconds{host="%s"} %s\n' "$HOST" "${last:-0}"
            fi
        } > "$tmp" && chmod 0644 "$tmp" && mv -f "$tmp" "$METRICS"
    fi

    # The store is on the target, listening on loopback only. Pushing over SSH is
    # the same trust path the gate already uses, and it keeps the store closed.
    if [ "$PUSH" = 1 ] && [ -s "$METRICS" ]; then
        if ssh -o BatchMode=yes -o ConnectTimeout=10 "$HOST" \
            'curl -sS --max-time 10 -X POST --data-binary @- http://127.0.0.1:8428/api/v1/import/prometheus >/dev/null' \
            < "$METRICS" 2>/dev/null; then
            say "pushed the result to $HOST's VictoriaMetrics"
        else
            say "WARN  could not push the result to $HOST — the metric is local at $METRICS"
        fi
    fi
fi

# The report. A pass is one line; a failure carries the gate's own output,
# because that is the only place the cause is recorded.
if [ "$rc" -eq 0 ]; then
    say "PASS  $commit  $assertions assertions  ($HOST, ${started}..${finished})"
    if [ -n "$prev_assertions" ] && [ "$assertions" -lt "$prev_assertions" ]; then
        say "REGRESSION  assertions fell from $prev_assertions to $assertions — a gate got weaker"
        say "  the count is the early warning: check what stopped asserting"
        exit 3
    fi
    exit 0
fi

say "FAIL  $commit  $assertions assertions  ($HOST)  exit $rc"
say "--- the gate's last 30 lines ---"
tail -30 "$log"
[ -n "$prev_status" ] && [ "$prev_status" = pass ] && say "TRANSITION  the previous run passed; this one did not"
exit 1
