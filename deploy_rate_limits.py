#!/usr/bin/env python3
"""Apply the strict dynamic crawler 429 policy to all active CF zones except dordrecht."""
import json
import os
import urllib.request

HEADERS = {"Authorization": "Bearer " + os.environ["CF_API_TOKEN"], "Content-Type": "application/json"}


def request(path, method="GET", body=None):
    req = urllib.request.Request(
        "https://api.cloudflare.com/client/v4" + path,
        method=method,
        data=json.dumps(body).encode() if body else None,
        headers=HEADERS,
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        payload = json.load(response)
    if not payload.get("success", True):
        raise RuntimeError(payload.get("errors"))
    return payload["result"]


for zone in request("/zones?status=active&per_page=50"):
    name = zone["name"]
    if name == "dordrecht.net":
        continue
    zone_id = zone["id"]
    rulesets = request(f"/zones/{zone_id}/rulesets")
    rate_ruleset = next(item for item in rulesets if item.get("phase") == "http_ratelimit" and item.get("kind") == "zone")
    ruleset_id = rate_ruleset["id"]
    rule_id = request(f"/zones/{zone_id}/rulesets/{ruleset_id}")["rules"][0]["id"]
    expression = (
        f'http.host in {{"{name}" "www.{name}"}} and '
        'http.request.method in {"GET" "HEAD"} and '
        '(starts_with(http.request.uri.path, "/nieuws") or '
        'starts_with(http.request.uri.path, "/agenda") or '
        'starts_with(http.request.uri.path, "/trefwoorden") or '
        'starts_with(http.request.uri.path, "/columns") or '
        'starts_with(http.request.uri.path, "/vacatures") or '
        'starts_with(http.request.uri.path, "/adressen") or '
        'starts_with(http.request.uri.path, "/rss"))'
    )
    request(
        f"/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}",
        "PATCH",
        {
            "action": "block",
            "action_parameters": {"response": {"status_code": 429, "content": "Too many requests. Please try again later.", "content_type": "text/plain"}},
            "description": "Emergency: 429 public dynamic crawler requests over 2/10s/IP",
            "enabled": True,
            "expression": expression,
            "ratelimit": {"characteristics": ["ip.src", "cf.colo.id"], "period": 10, "requests_per_period": 2, "mitigation_timeout": 10},
        },
    )
    print(name)
