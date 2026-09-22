#!/usr/bin/env python3
"""Build a local control-plane dashboard summary without Cloudflare API calls."""
from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

ESCALATION = (
    {"level": 1, "duration": "1 minuut", "action": "Tijdelijke 403"},
    {"level": 2, "duration": "5 minuten", "action": "Tijdelijke 403"},
    {"level": 3, "duration": "50 minuten", "action": "Tijdelijke 403"},
    {"level": 4, "duration": "blijvend", "action": "Permanent block proposal"},
)


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return default


def parse(value: str) -> datetime:
    return datetime.fromisoformat(value)


def view(record: dict, status: str) -> dict:
    return {
        "ip": record.get("ip", "—"),
        "level": record.get("level", "—"),
        "until": record.get("until") or record.get("permanent_until") or "—",
        "owner": record.get("owner", "unknown"),
        "asn": record.get("asn", "—"),
        "country": record.get("country", "—"),
        "ip_tooltip": record.get("crawler_status", "Crawler list status not checked"),
        "reason": record.get("reason", "—"),
        "status": status,
    }


def transition_view(event: dict) -> dict:
    kind = event.get("type", "unknown")
    level = event.get("level", "—")
    if kind == "temporary_403":
        duration = event.get("duration_seconds", 0)
        description = f"Temporary 403 scheduled: level {level}, {duration // 60} minute(s)"
    elif kind == "temporary_expired":
        description = f"Temporary 403 expired after level {level}"
    elif kind == "permanent_block":
        duration = event.get("duration_seconds", 0)
        description = f"Permanent block started: maximum {duration // 3600} hour(s)"
    elif kind == "permanent_expired":
        description = "Permanent block expired and removed"
    elif kind == "temporary_removed":
        description = "Temporary block removed from local policy"
    else:
        description = "Onbekende policy-transitie"
    return {"at": event.get("at", "—"), "ip": event.get("ip", "—"), "level": level, "reason": event.get("reason", "—"), "description": description}


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit("usage: build_dashboard_summary.py CONFIG POLICY_LAST CONTROL_STATE OUTPUT")
    _, config_path, policy_path, state_path, output_path = sys.argv
    config = {}
    for line in Path(config_path).read_text().splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            key, value = line.split('=', 1); config[key.strip()] = value.strip()
    policy = read_json(Path(policy_path), {})
    state = read_json(Path(state_path), {"records": {}, "events": []})
    current = datetime.now(timezone.utc)
    cutoff = current - timedelta(hours=24)
    mode = policy.get("mode", "dry-run")
    records = list(state.get("records", {}).values())
    active = [view(record, "Temporary 403 scheduled" if mode == "dry-run" else "Temporary 403 active") for record in records if record.get("until") and parse(record["until"]) > current]
    permanent = [view(record, "Permanent block proposal" if mode == "dry-run" else "Permanent block") for record in records if record.get("permanent")]
    nominations = [view(record, "Recidivism nomination") for record in records if not record.get("permanent")]
    events = []
    for event in state.get("events", []):
        try:
            if parse(event.get("at", "")) >= cutoff:
                events.append(event)
        except (TypeError, ValueError):
            continue
    recent = [transition_view(event) for event in events[-50:]]
    light_state = read_json(Path('/opt/scripts/crawler-guard/state/light-monitor-state.json'), {'ips': {}})
    hour_cutoff = current.timestamp() - 3600
    url_counts = Counter(path for events in light_state.get('ips', {}).values() for ts, path in events if ts >= hour_cutoff)
    top_urls_1h = [{'url': url, 'requests': count} for url, count in url_counts.most_common(10)]
    output = {
        "generated_at": current.isoformat(),
        "mode": mode,
        "tooling_enabled": config.get("TOOLING_ENABLED", "on") == "on",
        "dry_run_enabled": config.get("MODE", "apply") == "dry-run" or config.get("POLICY_MODE", "apply") == "dry-run",
        "top_urls_1h": top_urls_1h,
        "active_temp_blocks": active,
        "permanent_blocks": permanent,
        "recidive_nominations": nominations,
        "escalation": list(ESCALATION),
        "recent_transitions": recent,
        "transition_counts_24h": {
            "temporary_started": sum(event.get("type") == "temporary_403" for event in events),
            "temporary_expired": sum(event.get("type") == "temporary_expired" for event in events),
            "permanent_proposed": sum(event.get("type") == "permanent_block" for event in events),
        },
    }
    Path(output_path).write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
