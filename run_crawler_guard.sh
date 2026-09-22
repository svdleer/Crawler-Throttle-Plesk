#!/bin/sh
set -eu

BASE=/opt/scripts/crawler-guard
CONFIG=/etc/digisteden-crawler-guard/crawler-guard.env
STATE=$BASE/state
LOCK=/run/lock/digisteden-crawler-guard.lock

# Never allow overlapping cron runs to race on state and Cloudflare updates.
exec 9>"$LOCK"
flock -n 9 || exit 0

if [ -f /etc/digisteden-crawler-guard/force-apply.lock ]; then
    mode=$(grep '^MODE=' "$CONFIG" | tail -1 | cut -d= -f2)
    policy=$(grep '^POLICY_MODE=' "$CONFIG" | tail -1 | cut -d= -f2)
    if [ "$mode" != "apply" ] || [ "$policy" != "apply" ]; then
        echo "Apply-only lock rejects MODE=$mode POLICY_MODE=$policy" >&2
        exit 1
    fi
fi

umask 027
mkdir -p "$STATE"
JSON_TMP=$(mktemp "$STATE/latest.json.XXXXXX")
POLICY_TMP=$(mktemp "$STATE/policy-last.json.XXXXXX")
SUMMARY_TMP=$(mktemp "$STATE/dashboard-summary.json.XXXXXX")
HTML_TMP=$(mktemp "$STATE/status.html.XXXXXX")
trap 'rm -f "$JSON_TMP" "$POLICY_TMP" "$SUMMARY_TMP" "$HTML_TMP"' EXIT

if "$BASE/light_monitor.py" "$CONFIG" "$STATE/light-monitor-state.json" "$JSON_TMP" "$STATE/slow-candidates.json"; then
    mv "$JSON_TMP" "$STATE/latest.json"

    # Control-plane release: the scheduled path is explicitly local dry-run.
    # Any later apply run must be a separate, reviewed manual operation.
    "$BASE/crawler_control.py" "$CONFIG" "$STATE/latest.json" "$STATE/slow-candidates.json" \
        "$STATE/control-state.json" "$STATE/owner-cache.json" "$STATE/events.ndjson" \
        > "$POLICY_TMP"
    mv "$POLICY_TMP" "$STATE/policy-last.json"

    "$BASE/build_dashboard_summary.py" "$CONFIG" "$STATE/policy-last.json" \
        "$STATE/control-state.json" "$SUMMARY_TMP"
    mv "$SUMMARY_TMP" "$STATE/dashboard-summary.json"
    chmod 0644 "$STATE/events.ndjson" "$STATE/dashboard-summary.json"

    "$BASE/render_status.py" "$STATE/latest.json" "$HTML_TMP" "$STATE/dashboard-summary.json"
    mv "$HTML_TMP" "$STATE/status.html"
    chmod 0644 "$STATE/status.html"
else
    exit 1
fi
