#!/bin/sh
# Install Crawler-Throttle-Plesk without enabling enforcement.
set -eu

ROOT=${1:-/opt/crawler-throttle-plesk}
CONFIG=/etc/crawler-throttle-plesk
STATE="$ROOT/state"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo ./install.sh" >&2
  exit 1
fi
for command in python3 nginx fail2ban-client; do
  command -v "$command" >/dev/null 2>&1 || { echo "Missing required command: $command" >&2; exit 1; }
done
if ! command -v plesk >/dev/null 2>&1 && [ ! -e /usr/local/psa/version ]; then
  echo "This installer requires Plesk." >&2
  exit 1
fi

install -d -m 0750 -o root -g root "$ROOT" "$STATE" "$CONFIG"
for file in \
  crawler_guard.py light_monitor.py slow_crawler.py crawler_control.py \
  build_dashboard_summary.py render_status.py control_api.py \
  run_crawler_guard.sh mysql_select_killer.py php_fpm_recovery.py pressure_429.py; do
  [ -f "$SCRIPT_DIR/$file" ] || continue
  install -m 0750 -o root -g root "$SCRIPT_DIR/$file" "$ROOT/$file"
done
for file in pressure-429-base.conf vhost_nginx.conf; do
  [ -f "$SCRIPT_DIR/$file" ] || continue
  install -m 0644 -o root -g root "$SCRIPT_DIR/$file" "$ROOT/$file.example"
done

if [ ! -e "$CONFIG/crawler-guard.env" ]; then
  install -m 0640 -o root -g root "$SCRIPT_DIR/crawler-guard.env.example" "$CONFIG/crawler-guard.env"
fi
if [ ! -e "$CONFIG/mysql-killer.env" ]; then
  install -m 0640 -o root -g root "$SCRIPT_DIR/mysql-killer.env.example" "$CONFIG/mysql-killer.env"
fi

install -m 0644 -o root -g root "$SCRIPT_DIR/crawler-guard-control.service" /etc/systemd/system/crawler-throttle-control.service
systemctl daemon-reload
systemctl enable crawler-throttle-control.service

cat <<'EOF'
Installed safely. Enforcement is NOT enabled.

Next steps:
1. Configure /etc/crawler-throttle-plesk/crawler-guard.env.
2. Add a root-only Cloudflare token file referenced by CF_API_TOKEN_FILE.
3. Select the Plesk subscriptions/domains to protect.
4. Use `plesk bin subscription --list` to inventory domains.
5. Compare domains with Cloudflare API zones; use Fail2ban fallback for non-Cloudflare domains.
6. Copy the example pressure/Nginx config only into the server's normal nginx http context after `nginx -t`.
7. Enable cron files only after dry-run output is reviewed.
EOF
