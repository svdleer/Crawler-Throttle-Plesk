# Crawler guard: 429 first, Cloudflare block on recidive

## Policy

1. Cloudflare rate limiting returns HTTP 429 for excessive public dynamic requests.
2. This monitor reads `access_ssl_log` and Cloudflare Security Events.
3. It excludes all CIDRs in the existing Nginx office, Google, Meta and known-good lists.
4. It reports distributed patterns: `/24` IPv4 and `/64` IPv6 clusters, route/UA signatures, rotating legacy browser UAs, and high URL diversity.
5. It adds an **individual IP** to Cloudflare only when both conditions hold:
   - the origin log sees at least `IP_THRESHOLD` public dynamic requests and `MIN_UNIQUE_URLS` URLs in the recent window; and
   - Cloudflare recorded at least `RECIDIVE_429_THRESHOLD` rate-limit actions for that IP in the lookback period.

Distributed clusters are alerts only. Do not automatically block a subnet, ASN, UA family, or behavioural signature; those can include legitimate users or shared NATs.

## Cloudflare prerequisite

Create a **dedicated** custom WAF block rule, separate from your manual `block` rule. Its initial expression must be:

```text
ip.src in {192.0.2.1}
```

Set action to **Block** and keep it enabled. `192.0.2.1` is documentation-only and is used as a harmless placeholder. Put its rule ID in `CF_BLOCK_RULE_ID`.

The monitor preserves all entries in that dedicated rule and appends only qualifying recidivist IPs. The API token needs Zone WAF Edit and must be stored in `/etc/digisteden-crawler-guard/cloudflare.token` with mode `0600`.

## Server installation

```bash
sudo install -d -m 0750 /opt/digisteden-crawler-guard /etc/digisteden-crawler-guard
sudo install -m 0750 crawler_guard.py /opt/digisteden-crawler-guard/crawler_guard.py
sudo install -m 0640 crawler-guard.env.example /etc/digisteden-crawler-guard/crawler-guard.env
sudo chown -R root:root /opt/digisteden-crawler-guard /etc/digisteden-crawler-guard
```

Set the actual `CF_BLOCK_RULE_ID`, review thresholds, and run dry-run mode first:

```bash
sudo /opt/digisteden-crawler-guard/crawler_guard.py --config /etc/digisteden-crawler-guard/crawler-guard.env --dry-run
```

When dry-run results have been reviewed, change only this value:

```text
MODE=apply
```

Run once per minute with cron:

```cron
* * * * * root /opt/digisteden-crawler-guard/crawler_guard.py --config /etc/digisteden-crawler-guard/crawler-guard.env >> /var/log/digisteden-crawler-guard.log 2>&1
```

## Rollback

1. Set `MODE=dry-run`.
2. Remove an accidental address from the dedicated Cloudflare block rule in the dashboard.
3. Disable the cron line.
4. Rotate the Cloudflare API token if it has been exposed.

## Apply-only production lock

Production crawler enforcement is protected by:

```text
/etc/digisteden-crawler-guard/force-apply.lock
```

While this root-owned file exists, both `MODE` and `POLICY_MODE` must be `apply` and the controller rejects `--dry-run` before reading or changing policy state.

To explicitly authorize exactly one dry-run, a root operator must create:

```bash
sudo install -m 0600 -o root -g root /dev/null /etc/digisteden-crawler-guard/allow-dry-run.once
```

The controller consumes and deletes that file on the next dry-run invocation. Removing `force-apply.lock` disables the apply-only safeguard and should only be done with an explicit operational decision.
