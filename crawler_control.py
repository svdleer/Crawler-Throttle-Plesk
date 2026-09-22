#!/usr/bin/env python3
"""Low-load crawler enforcement control-plane.

The monitor supplies suspicious-IP nominations.  This controller keeps durable
local policy state, emits auditable transitions, and only contacts external
services when a separately invoked apply mode explicitly permits it.
"""
from __future__ import annotations

import argparse
import secrets
import ipaddress
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.request import Request, urlopen

DURATIONS = (60, 300, 3000)  # Escalation levels: 1 / 5 / 50 minutes.
PERMANENT_MIN_SECONDS = 18 * 60 * 60
PERMANENT_MAX_SECONDS = 24 * 60 * 60


def load_env(path: Path) -> dict[str, str]:
    data = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            data[key.strip()] = value.strip()
    return data


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return default


def write_json(path: Path, value) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def now() -> datetime:
    return datetime.now(timezone.utc)


def stamp(value: datetime) -> str:
    return value.isoformat()


def parse(value: str) -> datetime:
    return datetime.fromisoformat(value)


def subnet(ip: str) -> str:
    address = ipaddress.ip_address(ip)
    prefix = 24 if address.version == 4 else 64
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def cf_request(config: dict[str, str], path: str, method: str = "GET", body=None):
    token = Path(config["CF_API_TOKEN_FILE"]).read_text().strip()
    request = Request(
        "https://api.cloudflare.com/client/v4" + path,
        method=method,
        data=json.dumps(body).encode() if body else None,
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    )
    with urlopen(request, timeout=20) as response:
        payload = json.loads(response.read().decode())
    if not payload.get("success", True):
        raise RuntimeError(payload.get("errors"))
    return payload.get("result")


def cf_ips(expression: str) -> set[str]:
    return set(expression.split("{", 1)[1].split("}", 1)[0].split()) if "{" in expression else set()


def cf_expression(ips: set[str]) -> str:
    def address_key(value: str) -> tuple[int, int]:
        address = ipaddress.ip_address(value)
        return address.version, int(address)
    return "ip.src in {" + " ".join(sorted(ips, key=address_key)) + "}" if ips else "ip.src eq 192.0.2.1"


def trusted_sources(ip: str, config: dict[str, str]) -> list[str]:
    address = ipaddress.ip_address(ip)
    matches = []
    labels = {
        'office-exceptions.conf': 'office exception',
        'google-special-crawlers.conf': 'Google crawler range',
        'facebook-crawlers.conf': 'Facebook/Meta range',
        'known-good-bots.conf': 'known-good bot range',
    }
    for filename in config.get('TRUSTED_LISTS', '').split(':'):
        path = Path(filename)
        for raw in path.read_text().splitlines():
            try:
                if address in ipaddress.ip_network(raw.split()[0].rstrip(';'), strict=False):
                    matches.append(labels.get(path.name, path.name))
                    break
            except (IndexError, ValueError):
                continue
    return matches


def owner_details(ip: str, cache: dict, lookup_mode: str, current: datetime) -> dict[str, str]:
    cached = cache.get(ip)
    if cached and cached.get("expires"):
        try:
            if parse(cached["expires"]) > current:
                return cached
        except (TypeError, ValueError):
            pass
    if lookup_mode != "rdap":
        return {"owner": "unknown", "country": "—", "asn": "—"}

    # RDAP is opt-in. The normal runner supplies --owner-lookup off.
    try:
        request = Request("https://rdap.org/ip/" + ip, headers={"Accept": "application/rdap+json"})
        with urlopen(request, timeout=10) as response:
            data = json.loads(response.read().decode())
        result = {
            "owner": data.get("name") or data.get("handle") or "unknown",
            "country": data.get("country") or "—",
            "asn": str(data.get("autnum") or data.get("asn") or "—"),
        }
    except Exception:
        result = {"owner": "lookup unavailable", "country": "—", "asn": "—"}
    result["expires"] = stamp(current + timedelta(days=7))
    cache[ip] = result
    return result


def noncloud_google_ranges(config: dict[str, str]):
    ranges = []
    for raw in Path(config['GOOGLE_NONCLOUD_LIST']).read_text().splitlines():
        line = raw.strip()
        if line and not line.startswith('#'):
            try: ranges.append(ipaddress.ip_network(line.split()[0].rstrip(';'), strict=False))
            except ValueError: pass
    return ranges


def in_noncloud_google(ip: str, ranges) -> bool:
    return any(ipaddress.ip_address(ip) in network for network in ranges)


def candidate_map(latest: dict, slow: dict, urgent: str | None) -> dict[str, dict]:
    candidates: dict[str, dict] = {}
    for source, entries in (("local", latest.get("local_candidates", [])), ("slow", slow.get("slow_candidates", []))):
        for entry in entries:
            if not isinstance(entry, dict) or not entry.get("ip"):
                continue
            ip = str(entry["ip"]).strip()
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            candidate = candidates.setdefault(ip, {"ip": ip, "sources": [], "reasons": []})
            candidate["sources"].append(source)
            reason = entry.get("reason") or f"{source}_candidate"
            if reason not in candidate["reasons"]:
                candidate["reasons"].append(reason)
    if urgent:
        ipaddress.ip_address(urgent)
        candidates[urgent] = {"ip": urgent, "sources": ["manual"], "reasons": ["manual_urgent"]}
    return candidates


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("config")
    parser.add_argument("latest")
    parser.add_argument("slow")
    parser.add_argument("state")
    parser.add_argument("owners")
    parser.add_argument("events")
    parser.add_argument("--dry-run", action="store_true", help="Prevent Cloudflare writes regardless of configuration.")
    parser.add_argument("--owner-lookup", choices=("off", "rdap"), help="Override OWNER_LOOKUP_MODE.")
    parser.add_argument("--urgent")
    parser.add_argument("--remove")
    args = parser.parse_args()

    config = load_env(Path(args.config))
    mode = "dry-run" if args.dry_run else config.get("POLICY_MODE", config.get("MODE", "dry-run")).strip().lower()
    lock_path = Path('/etc/digisteden-crawler-guard/force-apply.lock')
    approval_path = Path('/etc/digisteden-crawler-guard/allow-dry-run.once')
    if lock_path.exists() and mode != "apply":
        if approval_path.exists():
            approval_path.unlink()
        else:
            raise RuntimeError("Apply-only lock is active; dry-run requires explicit one-time confirmation")
    if mode not in {"dry-run", "apply"}:
        raise ValueError("POLICY_MODE must be dry-run or apply")
    lookup_mode = args.owner_lookup or config.get("OWNER_LOOKUP_MODE", "off").strip().lower()
    if lookup_mode not in {"off", "rdap"}:
        raise ValueError("OWNER_LOOKUP_MODE must be off or rdap")

    state_path, owners_path = Path(args.state), Path(args.owners)
    state = read_json(state_path, {"records": {}, "events": []})
    state.setdefault("records", {})
    state.setdefault("events", [])
    cache = read_json(owners_path, {})
    noncloud_ranges = noncloud_google_ranges(config)
    current = now()
    cutoff = current - timedelta(hours=24)
    latest = read_json(Path(args.latest), {})
    slow = read_json(Path(args.slow), {})
    candidates = candidate_map(latest, slow, args.urgent)
    transitions = []

    for ip, record in list(state["records"].items()):
        if in_noncloud_google(ip, noncloud_ranges):
            record["permanent"] = False
            record["permanent_until"] = None
            record["until"] = None
            record["reason"] = "google_services_noncloud_429_only"
            record["crawler_status"] = "Matched google-services-noncloud.conf: 429 only, no IP block"
            continue
        if record.get("permanent"):
            expiry = record.get("permanent_until")
            if not expiry:
                duration = PERMANENT_MIN_SECONDS + secrets.randbelow(PERMANENT_MAX_SECONDS - PERMANENT_MIN_SECONDS + 1)
                record["permanent_until"] = stamp(current + timedelta(seconds=duration))
                expiry = record["permanent_until"]
            if parse(expiry) <= current:
                record.update({"permanent": False, "permanent_until": None, "until": None, "level": 0})
                transitions.append({"at": stamp(current), "type": "permanent_expired", "ip": ip})
            continue
        until = record.get("until")
        if until:
            try:
                if parse(until) <= current:
                    record["until"] = None
                    transitions.append({"at": stamp(current), "type": "temporary_expired", "ip": ip, "level": record.get("level", 0)})
            except (TypeError, ValueError):
                record["until"] = None
        if not record.get("permanent") and not record.get("until"):
            try:
                if parse(record["last_seen"]) < cutoff:
                    del state["records"][ip]
            except (KeyError, TypeError, ValueError):
                del state["records"][ip]

    for ip, candidate in candidates.items():
        if in_noncloud_google(ip, noncloud_ranges):
            record = state["records"].setdefault(ip, {"ip": ip, "subnet": subnet(ip), "level": 0, "first_seen": stamp(current), "last_seen": stamp(current)})
            record.update({"last_seen": stamp(current), "reason": "google_services_noncloud_429_only", "crawler_status": "Matched google-services-noncloud.conf: 429 only, no IP block", "permanent": False, "until": None})
            continue
        reason = "; ".join(candidate["reasons"])
        record = state["records"].setdefault(
            ip,
            {"ip": ip, "subnet": subnet(ip), "level": 0, "first_seen": stamp(current), "last_seen": stamp(current)},
        )
        record["last_seen"] = stamp(current)
        record["reason"] = reason
        record["sources"] = candidate["sources"]
        record['trusted_matches'] = trusted_sources(ip, config)
        record['crawler_status'] = ('Known trusted range: ' + ', '.join(record['trusted_matches'])) if record['trusted_matches'] else 'Checked: not in Google/Facebook/office/known-good crawler IP lists'
        details = owner_details(ip, cache, lookup_mode, current)
        record.update({key: details.get(key, "—") for key in ("owner", "country", "asn")})
        if record.get("permanent") or record.get("until"):
            continue
        record["level"] = min(int(record.get("level", 0)) + 1, 4)
        if record["level"] <= len(DURATIONS):
            duration = DURATIONS[record["level"] - 1]
            record["until"] = stamp(current + timedelta(seconds=duration))
            transitions.append({"at": stamp(current), "type": "temporary_403", "ip": ip, "duration_seconds": duration, "level": record["level"], "reason": reason})
        else:
            duration = PERMANENT_MIN_SECONDS + secrets.randbelow(PERMANENT_MAX_SECONDS - PERMANENT_MIN_SECONDS + 1)
            record["permanent"] = True
            record["permanent_until"] = stamp(current + timedelta(seconds=duration))
            record["until"] = None
            transitions.append({"at": stamp(current), "type": "permanent_block", "ip": ip, "level": 4, "reason": reason, "duration_seconds": duration, "permanent_until": record["permanent_until"]})

    if args.remove:
        state["records"].pop(args.remove, None)
        transitions.append({"at": stamp(current), "type": "temporary_removed", "ip": args.remove})

    state["events"] = [event for event in state["events"] if event.get("at") and parse(event["at"]) >= cutoff] + transitions
    write_json(state_path, state)
    write_json(owners_path, cache)

    active = sorted(ip for ip, record in state["records"].items() if record.get("until") and parse(record["until"]) > current)
    permanent = sorted(ip for ip, record in state["records"].items() if record.get("permanent") and record.get("permanent_until") and parse(record["permanent_until"]) > current)
    # The cron runner always passes --dry-run. Apply remains a separate, explicit operation.
    if mode == "apply" and config.get("IP_BLOCK_MODE", "off") == "apply":
        base = f"/zones/{config['CF_ZONE_ID']}/rulesets/{config['CF_RULESET_ID']}"
        rules = cf_request(config, base)["rules"]
        for key, addresses, description in (
            ("CF_TEMP_403_RULE_ID", active, "Temporary 403 crawler escalation"),
            ("CF_PERMANENT_BLOCK_RULE_ID", permanent, "Crawler permanent block"),
        ):
            rule = next(rule for rule in rules if rule["id"] == config[key])
            desired = set(addresses)
            if key == "CF_PERMANENT_BLOCK_RULE_ID":
                desired |= cf_ips(rule["expression"])
                desired = {ip for ip in desired if not in_noncloud_google(ip, noncloud_ranges)}
            cf_request(config, base + "/rules/" + rule["id"], "PATCH", {"action": "block", "description": description, "enabled": True, "expression": cf_expression(desired)})

    with Path(args.events).open("a") as stream:
        for event in transitions:
            stream.write(json.dumps(event) + "\n")
    nominations = [record for record in state["records"].values() if not record.get("permanent")]
    print(json.dumps({"mode": mode, "active_temporary": active, "permanent": permanent, "nominations": nominations, "transitions": transitions}, indent=2))


if __name__ == "__main__":
    main()
