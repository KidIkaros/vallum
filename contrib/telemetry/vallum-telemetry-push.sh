#!/bin/bash
# Push one scrape of Vallum's metrics into VictoriaMetrics.
#
# The daemon owns the counters; this only moves them into a store that survives
# a daemon restart. A counter reset on restart is handled by rate()/increase().
#
# Four sources are pushed, not one:
#
#   `vallum metrics` output      the daemon's own counters, scraped fresh
#   /run/vallum/verify.prom      the scheduled two-host gate's last result
#   `vallum-desk --metrics`      the alpha funnel: tickets minted vs handshakes
#   `systemctl --failed`         units that are down, which nothing watched
#
# The second one is here because the gate is what proves the tunnel, and a proof
# nobody records is a proof nobody can trend. `scripts/verify-scheduled.sh` writes
# it; this ships it to the same store, so the alerts that watch the tunnel also
# watch the evidence that the tunnel works.
#
# The last two exist because of what they did NOT catch. `vallum-quick@vallumrc`
# entered `failed` and stayed there for 30 hours with all 19 alert rules green:
# every rule read Vallum's own metrics, and a unit that is not running produces
# no metrics to read. And on the same deployment 14 join tickets were minted with
# zero devices ever connecting, which the desk reported as 14 healthy `active`
# devices because nothing compared the two numbers. Both are absences, and an
# absence needs a series that is present and zero.
set -u
CONFIG=${1:-/etc/vallum/vallum0.toml}
VM=${VM_URL:-http://127.0.0.1:8428/api/v1/import/prometheus}
VERIFY_FILE=${VALLUM_VERIFY_METRICS:-/run/vallum/verify.prom}
DESK_BIN=${VALLUM_DESK_BIN:-/usr/local/lib/vallum/vallum-desk}
DESK_STATE=${VALLUM_DESK_STATE:-/var/lib/vallum/desk.sqlite}
DESK_TOKEN_FILE=${VALLUM_DESK_TOKEN_FILE:-/etc/vallum/desk-admin-token}

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

# The alpha funnel. Only where a desk is installed and has a database: a config
# naming a desk path on a host without one must not produce a misleading zero.
if [ -x "$DESK_BIN" ] && [ -f "$DESK_STATE" ]; then
    FUNNEL=$(/usr/bin/python3 "$DESK_BIN" --config "$CONFIG" --state "$DESK_STATE" \
        --admin-token-file "$DESK_TOKEN_FILE" --metrics 2>/dev/null)
    if [ -n "$FUNNEL" ]; then
        printf '%s\n' "$FUNNEL" | push
    fi
fi

# Unit health. `systemctl --failed` is the one command that answers "is anything
# on this host broken", and it was not in the store.
#
# Per-unit series plus a total: the total is what an alert reads, the per-unit
# label is what tells a reader which unit. `--plain` keeps output to
# `<unit> <load> <active> <sub> <description>`, and a unit name is a label value
# that must not contain a quote.
FAILED=$(systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}')
# The host label is carried explicitly. The first version of this pushed bare
# series, and the alert's summary read "3 systemd unit(s) on  are failed" — a
# sentence with a hole in it, because `$labels.instance` had nothing to
# interpolate. A series that cannot name its own host is not addressable once a
# second host pushes to the same store.
HOST=${VALLUM_HOST:-$(hostname -s 2>/dev/null || echo unknown)}
{
    printf '# HELP vallum_unit_failed 1 when a systemd unit is in the failed state.\n'
    printf '# TYPE vallum_unit_failed gauge\n'
    if [ -n "$FAILED" ]; then
        printf '%s\n' "$FAILED" | while read -r unit; do
            [ -n "$unit" ] || continue
            printf 'vallum_unit_failed{instance="%s",unit="%s"} 1\n' \
                "${HOST//\"/}" "${unit//\"/}"
        done
    fi
    printf '# HELP vallum_failed_units_total Units in the failed state.\n'
    printf '# TYPE vallum_failed_units_total gauge\n'
    if [ -n "$FAILED" ]; then
        printf 'vallum_failed_units_total{instance="%s"} %s\n' \
            "${HOST//\"/}" "$(printf '%s\n' "$FAILED" | grep -c .)"
    else
        printf 'vallum_failed_units_total{instance="%s"} 0\n' "${HOST//\"/}"
    fi
} | push

# The monitoring pipeline's own heartbeat. Every other alert depends on this
# pusher running; if it stops, the rules go silent and silence reads as green —
# the same absence that let three failed units hide for thirty hours. A present,
# fresh series lets `time() - heartbeat > N` alert on the absence of monitoring
# itself. Pushed even when the daemon scrape was empty: the pusher ran, which is
# the fact this series records, not whether the daemon answered.
{
    printf '# HELP vallum_monitoring_heartbeat_seconds Unix time of the last telemetry push.\n'
    printf '# TYPE vallum_monitoring_heartbeat_seconds gauge\n'
    printf 'vallum_monitoring_heartbeat_seconds{instance="%s"} %s\n' \
        "${HOST//\"/}" "$(date +%s)"
} | push

# The pager path itself. Alertmanager routes every alert to ntfy; if it is down,
# the rules fire into a void and the heartbeat alert above cannot route either.
# The pusher is a separate timer, so it can notice Alertmanager is gone and page
# ntfy DIRECTLY, bypassing the broken router. PAGER_URL is the same unguessable
# topic Alertmanager uses, kept 0600 beside the admin token and never committed.
# A cooldown stops a down Alertmanager from paging every fifteen seconds.
PAGER_URL=${VALLUM_PAGER_URL:-$(cat /etc/vallum/pager-url 2>/dev/null)}
PAGER_STATE=${VALLUM_PAGER_STATE:-/var/lib/vallum/pager-direct-last}
AM_CODE=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' \
    http://127.0.0.1:9093/api/v2/status 2>/dev/null || echo 000)
{
    printf '# HELP vallum_pager_path_ok 1 when Alertmanager is reachable.\n'
    printf '# TYPE vallum_pager_path_ok gauge\n'
    if [ "$AM_CODE" = "200" ]; then
        printf 'vallum_pager_path_ok{instance="%s"} 1\n' "${HOST//\"/}"
    else
        printf 'vallum_pager_path_ok{instance="%s"} 0\n' "${HOST//\"/}"
    fi
} | push
if [ "$AM_CODE" != "200" ] && [ -n "$PAGER_URL" ]; then
    NOW=$(date +%s)
    PREV=$(cat "$PAGER_STATE" 2>/dev/null || echo 0)
    if [ $((NOW - PREV)) -ge 300 ]; then
        # Cooldown only after a page actually lands: a failed page must retry next
        # cycle, not be suppressed for five minutes (premortem mode 4).
        if curl -fsS --max-time 10 \
            -H "Title: Vallum pager path broken" -H "Priority: urgent" \
            -H "Tags: rotating_light" \
            -d "Alertmanager on $HOST is unreachable (HTTP $AM_CODE). Alerts are not being routed. The telemetry pusher is still alive and paging you directly. Check: systemctl status alertmanager; journalctl -u alertmanager -n 50." \
            "$PAGER_URL" >/dev/null 2>&1; then
            echo "$NOW" > "$PAGER_STATE" 2>/dev/null
        fi
    fi
fi

# External dead-man's switch (premortem 2026-11-19, mode 4): ping a
# healthchecks.io-style check each cycle. If this host dies — or the pusher stops —
# the pings stop and the external service alerts independently of everything on
# this host, which no on-host watchdog can. The URL lives in a 0600 file (or
# VALLUM_HEALTHCHECKS_URL); absent, this is a no-op, so the wiring ships before the
# operator creates the check. Create a free check, then:
#   sudo sh -c 'umask 077; echo https://hc-ping.com/<uuid> > /etc/vallum/healthchecks-url'
HC_URL=${VALLUM_HEALTHCHECKS_URL:-$(cat /etc/vallum/healthchecks-url 2>/dev/null)}
if [ -n "$HC_URL" ]; then
    curl -fsS --max-time 10 -o /dev/null "$HC_URL" >/dev/null 2>&1 || true
fi

# A scrape that produced nothing is a scrape that did not happen; exit nonzero so
# the unit's state says so, and let `vallum_up 0` be the alert.
[ -n "$OUT" ] || exit 1
exit 0
