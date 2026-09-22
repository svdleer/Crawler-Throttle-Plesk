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
    {"level": 4, "duration": "blijvend", "action": "Permanente blokkade voorgesteld"},
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
        description = f"Tijdelijke 403 gepland: niveau {level}, {duration // 60} minuut/minuten"
    elif kind == "temporary_expired":
        description = f"Tijdelijke 403 verlopen na niveau {level}"
    elif kind == "permanent_block":
        duration = event.get("duration_seconds", 0)
        description = f"Permanente blokkade gestart: maximaal {duration // 3600} uur"
    elif kind == "permanent_expired":
        description = "Permanente blokkade verlopen en verwijderd"
    elif kind == "temporary_removed":
        description = "Tijdelijke blokkade verwijderd uit lokale policy"
    else:
        description = "Onbekende policy-transitie"
    return {"at": event.get("at", "—"), "ip": event.get("ip", "—"), "level": level, "reason": event.get("reason", "—"), "description": description}


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit("usage: build_dashboard_summary.py CONFIG POLICY_LAST CONTROL_STATE OUTPUT")
    _, _config, policy_path, state_path, output_path = sys.argv
    policy = read_json(Path(policy_path), {})
    state = read_json(Path(state_path), {"records": {}, "events": []})
    current = datetime.now(timezone.utc)
    cutoff = current - timedelta(hours=24)
    mode = policy.get("mode", "dry-run")
    records = list(state.get("records", {}).values())
    active = [view(record, "Geplande tijdelijke 403" if mode == "dry-run" else "Tijdelijke 403 actief") for record in records if record.get("until") and parse(record["until"]) > current]
    permanent = [view(record, "Permanente blokkade voorgesteld" if mode == "dry-run" else "Permanente blokkade") for record in records if record.get("permanent")]
    nominations = [view(record, "Recidive-nominatie") for record in records if not record.get("permanent")]
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
