#!/bin/bash
# Independent dead-man's switch — run on a SECOND always-on host, NOT the one
# it watches. The watched host's pusher and Alertmanager can die together (host
# down, OOM, full disk); nothing on that host can then page. This watches from
# outside: over ssh it asks whether the monitoring heartbeat is fresh and
# Alertmanager is up, and pages ntfy DIRECTLY if not — or if the host does not
# answer at all. It is independent of the watched host's entire stack, which is
# the point: a dead-man's switch that shares the failure it watches is not one.
#
# Configure via environment (a systemd drop-in or /etc/default/vallum-watchdog):
#   VALLUM_WATCH_HOST       ssh target to watch (e.g. wingman-vps)   [required]
#   VALLUM_PAGER_URL        the unguessable ntfy topic URL           [required]
#   VALLUM_WATCH_THRESHOLD  heartbeat age in seconds before paging   [300]
#   VALLUM_WATCH_STATE      cooldown state file                      [~/.cache/...]
#
# The ssh key must be non-interactive (BatchMode). Pages are rate-limited to one
# per five minutes per cause so a sustained outage does not flood the topic.
set -u
WATCH_HOST=${VALLUM_WATCH_HOST:?set VALLUM_WATCH_HOST to the ssh target to watch}
PAGER_URL=${VALLUM_PAGER_URL:?set VALLUM_PAGER_URL to the ntfy topic URL}
THRESHOLD=${VALLUM_WATCH_THRESHOLD:-300}
STATE=${VALLUM_WATCH_STATE:-$HOME/.cache/vallum-watchdog-last}

page() { # $1 title, $2 body — cooldown so an outage pages once per 5 min
    NOW=$(date +%s)
    PREV=$(cat "$STATE" 2>/dev/null || echo 0)
    if [ $((NOW - PREV)) -ge 300 ]; then
        mkdir -p "$(dirname "$STATE")" 2>/dev/null
        echo "$NOW" > "$STATE" 2>/dev/null
        curl -sS --max-time 10 -H "Title: $1" -H "Priority: urgent" \
            -H "Tags: rotating_light" -d "$2" "$PAGER_URL" >/dev/null 2>&1
    fi
}

# One ssh round-trip gathers both facts. The remote python parses the store's
# JSON properly (a grep for the value would confuse the sample timestamp with
# the heartbeat). If ssh itself fails, the host is gone.
FACTS=$(ssh -o BatchMode=yes -o ConnectTimeout=10 "$WATCH_HOST" '
    HB=$(curl -sS --max-time 5 "http://127.0.0.1:8428/api/v1/query?query=vallum_monitoring_heartbeat_seconds" 2>/dev/null \
        | /usr/bin/python3 -c "import json,sys
try:
    r=json.load(sys.stdin)[\"data\"][\"result\"]
    print(int(float(r[0][\"value\"][1])) if r else 0)
except Exception:
    print(0)" 2>/dev/null || echo 0)
    AM=$(curl -sS --max-time 5 -o /dev/null -w "%{http_code}" http://127.0.0.1:9093/api/v2/status 2>/dev/null || echo 000)
    echo "${HB:-0} $AM"
' 2>/dev/null)
RC=$?
NOW=$(date +%s)

if [ $RC -ne 0 ] || [ -z "$FACTS" ]; then
    page "Vallum host unreachable" \
        "The watchdog cannot reach $WATCH_HOST over ssh (rc=$RC). The host or its network may be down; monitoring on it cannot page. Investigate the host directly."
    exit 1
fi

HB=$(echo "$FACTS" | awk '{print $1}')
AM=$(echo "$FACTS" | awk '{print $2}')
AGE=$((NOW - HB))

if [ "$HB" = "0" ] || [ "$AGE" -gt "$THRESHOLD" ]; then
    page "Vallum monitoring silent" \
        "The telemetry heartbeat on $WATCH_HOST is ${AGE}s old (threshold ${THRESHOLD}s). The pusher or VictoriaMetrics is down; alerts on that host are not being produced. Check vallum-telemetry.timer and the store on 127.0.0.1:8428."
fi
if [ "$AM" != "200" ]; then
    page "Vallum pager path broken" \
        "Alertmanager on $WATCH_HOST is unreachable (HTTP $AM). Alerts are not being routed. Check alertmanager on that host."
fi
exit 0
