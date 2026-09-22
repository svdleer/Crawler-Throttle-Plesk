#!/usr/bin/env python3
"""Kill only eligible long-running Digisteden SELECT queries during sustained overload."""
from __future__ import annotations
import argparse, fcntl, json, os, subprocess, time
from datetime import datetime, timezone
from pathlib import Path

BASE = Path('/opt/scripts/crawler-guard')
STATE = BASE / 'state/mysql-select-killer-state.json'
LOCK = Path('/run/lock/digisteden-mysql-select-killer.lock')
LOG = Path('/var/log/digisteden-mysql-select-killer.log')


def env(path: Path) -> dict[str, str]:
    result = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if line and not line.startswith('#') and '=' in line:
            key, value = line.split('=', 1); result[key.strip()] = value.strip()
    return result


def mysql_rows() -> list[dict]:
    query = "SELECT ID,USER,DB,COMMAND,TIME,INFO FROM information_schema.PROCESSLIST WHERE COMMAND IN ('Query','Execute')"
    output = subprocess.check_output(['sudo','-n','mysql','--batch','--skip-column-names','-e',query], text=True)
    rows = []
    for line in output.splitlines():
        fields = line.split('\t', 5)
        if len(fields) == 6:
            rows.append(dict(zip(('id','user','db','command','time','info'), fields)))
    return rows


def mariadb_cpu(previous: dict) -> tuple[float, dict]:
    pid = int(subprocess.check_output(['pgrep','-o','mariadbd'], text=True).strip())
    stat = Path(f'/proc/{pid}/stat').read_text().split()
    ticks = int(stat[13]) + int(stat[14])
    current = {'pid': pid, 'ticks': ticks, 'at': time.time()}
    if previous.get('pid') != pid or not previous.get('at'):
        return 0.0, current
    elapsed = current['at'] - previous['at']
    cpu = (ticks - int(previous['ticks'])) / max(elapsed, 1) / os.sysconf('SC_CLK_TCK') * 100
    return cpu, current


def log(message: str) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open('a') as stream:
        stream.write(f"{datetime.now(timezone.utc).isoformat()} {message}\n")


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument('--config', default='/etc/digisteden-mysql-killer.env'); parser.add_argument('--dry-run', action='store_true'); args = parser.parse_args()
    config = env(Path(args.config)); mode = 'dry-run' if args.dry_run else config.get('MODE','dry-run')
    with LOCK.open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = json.loads(STATE.read_text()) if STATE.exists() else {'overload_samples': 0, 'mysql': {}}
        load = float(Path('/proc/loadavg').read_text().split()[0]); cpu, mysql_state = mariadb_cpu(state.get('mysql', {}))
        threshold_load = float(config.get('LOAD_THRESHOLD','10')); threshold_cpu = float(config.get('MYSQL_CPU_THRESHOLD','70'))
        state['overload_samples'] = state.get('overload_samples',0)+1 if load > threshold_load and cpu > threshold_cpu else 0
        state['mysql'] = mysql_state
        STATE.parent.mkdir(parents=True, exist_ok=True); STATE.write_text(json.dumps(state))
        required = int(config.get('REQUIRED_SAMPLES','3'))
        if state['overload_samples'] < required:
            log(f"sample load={load:.2f} mysql_cpu={cpu:.1f} overload_samples={state['overload_samples']}/{required}")
            return 0
        allowed_users = set(config.get('ALLOWED_USERS','digisteden_31298379').split(',')); min_time = int(config.get('MIN_QUERY_SECONDS','60'))
        for row in mysql_rows():
            sql = row['info'].lstrip().lower()
            if row['user'] not in allowed_users or row['db'] != 'digisteden' or int(row['time']) < min_time: continue
            if not sql.startswith('select') or 'information_schema' in sql or 'performance_schema' in sql: continue
            message = f"eligible id={row['id']} user={row['user']} db={row['db']} seconds={row['time']} load={load:.2f} mysql_cpu={cpu:.1f} mode={mode}"
            if mode == 'apply':
                subprocess.run(['sudo','-n','mysql','-e',f'KILL QUERY {int(row["id"])}'], check=True)
                log('KILLED '+message)
            else:
                log('WOULD_KILL '+message)
    return 0

if __name__ == '__main__':
    main()
