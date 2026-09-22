#!/usr/bin/env python3
"""Dry-run-first crawler monitor for Digisteden.

Phase 1: Cloudflare rate limiting returns 429.
Phase 2: this monitor reads Cloudflare Security Events; repeated rate-limit
violations by an untrusted IP are appended to a dedicated Cloudflare block rule.
Distributed patterns from access_ssl_log are reported, never auto-blocked.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.request import Request, urlopen

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"
IP_SET = re.compile(r"^\s*ip\.src\s+in\s+\{(?P<ips>[^}]*)\}\s*$", re.S)
LEGACY_BROWSER = re.compile(r"MSIE|Windows; U|Firefox/[0-9]\.|Chrome/[0-9]\.", re.I)
KNOWN_BOT_NAMES = ("googlebot", "bingbot", "facebookexternalhit", "meta-external", "baiduspider", "dotbot", "ahrefsbot", "semrush", "oai-searchbot", "exa", "perplexity", "grok")


def load_env(path: Path) -> dict[str, str]:
    if not path.exists():
        raise FileNotFoundError(f"Missing config file: {path}")
    result: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, marker, value = line.partition("=")
        if not marker:
            raise ValueError(f"Invalid config line: {raw!r}")
        result[key.strip()] = value.strip().strip("'\"")
    return result


def get(config: dict[str, str], key: str, default: str | None = None) -> str:
    value = config.get(key, default)
    if value is None:
        raise ValueError(f"Missing {key}")
    return value


def integer(config: dict[str, str], key: str, default: int) -> int:
    value = int(config.get(key, str(default)))
    if value < 1:
        raise ValueError(f"{key} must be positive")
    return value


def csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def tail(path: Path, max_bytes: int) -> str:
    with path.open("rb") as stream:
        stream.seek(0, os.SEEK_END)
        stream.seek(max(0, stream.tell() - max_bytes))
        data = stream.read()
    # Discard a potentially partial first line.
    return data.decode("utf-8", errors="replace").split("\n", 1)[-1]


def trusted_networks(files: tuple[str, ...]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for filename in files:
        path = Path(filename)
        if not path.exists():
            raise FileNotFoundError(f"Trusted list missing: {path}")
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                networks.append(ipaddress.ip_network(line.split()[0].rstrip(";"), strict=False))
            except ValueError:
                pass
    return networks


def is_trusted(address: ipaddress.IPv4Address | ipaddress.IPv6Address, networks: list[object]) -> bool:
    return any(address in network for network in networks)


def route(path: str, prefixes: tuple[str, ...]) -> str | None:
    for prefix in prefixes:
        if path == prefix or path.startswith(prefix.rstrip("/") + "/"):
            return prefix
    return None


def ua_family(agent: str) -> str:
    lower = agent.lower()
    for name in KNOWN_BOT_NAMES:
        if name in lower:
            return name
    return "rotating-legacy-browser" if LEGACY_BROWSER.search(agent) else "browser-like"


def network_bucket(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    return str(ipaddress.ip_network(f"{address}/{24 if address.version == 4 else 64}", strict=False))


def log_observations(config: dict[str, str], networks: list[object]) -> tuple[Counter[str], dict[str, set[str]], list[dict[str, object]]]:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=integer(config, "LOG_WINDOW_SECONDS", 60))
    dynamic = csv(get(config, "DYNAMIC_PREFIXES"))
    excluded = csv(get(config, "EXCLUDED_PREFIXES"))
    lines = tail(Path(get(config, "ACCESS_LOG")), integer(config, "LOG_READ_BYTES", 4_000_000))
    per_ip: Counter[str] = Counter()
    urls: dict[str, set[str]] = defaultdict(set)
    clusters: dict[tuple[str, str], set[str]] = defaultdict(set)
    cluster_count: Counter[tuple[str, str]] = Counter()
    subnets: dict[str, set[str]] = defaultdict(set)
    subnet_count: Counter[str] = Counter()

    for line in lines.splitlines():
        fields = line.split('"')
        if len(fields) < 6:
            continue
        request, header = fields[1].split(), fields[0].split()
        if len(request) < 2 or len(header) < 5:
            continue
        try:
            address = ipaddress.ip_address(header[0])
            moment = datetime.strptime(f"{header[3].lstrip('[')} {header[4].rstrip(']')}", TIME_FORMAT)
        except ValueError:
            continue
        path = request[1].split("?", 1)[0]
        category = route(path, dynamic)
        if moment < cutoff or not category or any(path.startswith(item) for item in excluded) or is_trusted(address, networks):
            continue
        ip = str(address)
        family = ua_family(fields[5])
        per_ip[ip] += 1
        urls[ip].add(path)
        signature = (category, family)
        clusters[signature].add(ip)
        cluster_count[signature] += 1
        subnet = network_bucket(address)
        subnets[subnet].add(ip)
        subnet_count[subnet] += 1

    reports: list[dict[str, object]] = []
    cluster_threshold = integer(config, "CLUSTER_THRESHOLD", 30)
    cluster_ips = integer(config, "CLUSTER_MIN_IPS", 8)
    for signature, count in cluster_count.items():
        if count >= cluster_threshold and len(clusters[signature]) >= cluster_ips:
            reports.append({"kind": "behaviour_cluster", "route": signature[0], "ua_family": signature[1], "requests": count, "unique_ips": len(clusters[signature])})
    subnet_threshold = integer(config, "SUBNET_THRESHOLD", 40)
    subnet_ips = integer(config, "SUBNET_MIN_IPS", 4)
    for subnet, count in subnet_count.items():
        if count >= subnet_threshold and len(subnets[subnet]) >= subnet_ips:
            reports.append({"kind": "network_cluster", "network": subnet, "requests": count, "unique_ips": len(subnets[subnet])})
    return per_ip, urls, reports


def cloudflare(config: dict[str, str], path: str, method: str = "GET", payload: dict | None = None) -> dict:
    token = Path(get(config, "CF_API_TOKEN_FILE")).read_text(encoding="utf-8").strip()
    request = Request("https://api.cloudflare.com/client/v4" + path, data=json.dumps(payload).encode() if payload else None, method=method, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    with urlopen(request, timeout=30) as response:
        answer = json.loads(response.read().decode())
    if answer.get("errors"):
        raise RuntimeError(str(answer["errors"]))
    return answer


def recidivists(config: dict[str, str], networks: list[object]) -> Counter[str]:
    lookback = integer(config, "CF_EVENT_LOOKBACK_SECONDS", 900)
    since = (datetime.now(timezone.utc) - timedelta(seconds=lookback)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    zone = get(config, "CF_ZONE_ID")
    query = """query Events($zone: string, $since: Time!) { viewer { zones(filter: {zoneTag: $zone}) { firewallEventsAdaptive(filter: {datetime_geq: $since} limit: 10000 orderBy: [datetime_DESC]) { action clientIP source } } } }"""
    data = cloudflare(config, "/graphql", "POST", {"query": query, "variables": {"zone": zone, "since": since}})
    events = data.get("data", {}).get("viewer", {}).get("zones", [{}])[0].get("firewallEventsAdaptive", [])
    sources = {source.lower() for source in csv(get(config, "RECIDIVE_SOURCES", "ratelimit"))}
    count: Counter[str] = Counter()
    for event in events:
        source = str(event.get("source", "")).lower()
        if source not in sources or event.get("action") not in {"block", "managed_challenge"}:
            continue
        try:
            address = ipaddress.ip_address(event["clientIP"])
        except ValueError:
            continue
        if not is_trusted(address, networks):
            count[str(address)] += 1
    return count


def update_blocklist(config: dict[str, str], ips: list[str]) -> list[str]:
    zone, ruleset, rule_id = get(config, "CF_ZONE_ID"), get(config, "CF_RULESET_ID"), get(config, "CF_BLOCK_RULE_ID")
    base = f"/zones/{zone}/rulesets/{ruleset}"
    rules = cloudflare(config, base)["result"]["rules"]
    rule = next((item for item in rules if item["id"] == rule_id), None)
    if rule is None:
        raise RuntimeError("CF_BLOCK_RULE_ID not found")
    match = IP_SET.match(rule["expression"])
    if not match:
        raise RuntimeError("Block rule expression must be only: ip.src in { ... }")
    existing = set(match.group("ips").split())
    additions = [ip for ip in ips if ip not in existing]
    merged = sorted(existing | set(additions), key=lambda ip: ipaddress.ip_address(ip))
    if len(merged) > integer(config, "MAX_BLOCKLIST_ENTRIES", 100):
        raise RuntimeError("Refusing update: blocklist capacity reached")
    if additions:
        cloudflare(config, f"{base}/rules/{rule_id}", "PATCH", {"action": "block", "description": rule.get("description", "Automated crawler blocklist"), "enabled": True, "expression": "ip.src in {" + " ".join(merged) + "}"})
    return additions


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/digisteden-crawler-guard/crawler-guard.env")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    config = load_env(Path(args.config))
    mode = "dry-run" if args.dry_run else get(config, "MODE", "dry-run").lower()
    networks = trusted_networks(tuple(get(config, "TRUSTED_LISTS").split(":")))
    counts, urls, clusters = log_observations(config, networks)
    ip_threshold = integer(config, "IP_THRESHOLD", 15)
    unique_urls = integer(config, "MIN_UNIQUE_URLS", 5)
    local_candidates = {ip for ip, count in counts.items() if count >= ip_threshold and len(urls[ip]) >= unique_urls}
    events = recidivists(config, networks)
    recidive_threshold = integer(config, "RECIDIVE_429_THRESHOLD", 3)
    block_candidates = sorted(ip for ip, count in events.items() if count >= recidive_threshold and ip in local_candidates)
    report: dict[str, object] = {"mode": mode, "window_seconds": integer(config, "LOG_WINDOW_SECONDS", 60), "local_candidates": [{"ip": ip, "requests": counts[ip], "unique_urls": len(urls[ip]), "429_events": events[ip]} for ip in sorted(local_candidates)], "block_candidates": block_candidates, "pattern_alerts": clusters}
    if mode == "apply" and block_candidates:
        report["cloudflare_added"] = update_blocklist(config, block_candidates)
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"crawler_guard: {exc}", file=sys.stderr)
        raise SystemExit(1)
