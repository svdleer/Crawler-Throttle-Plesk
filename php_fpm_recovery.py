#!/usr/bin/env python3
"""Restart Plesk PHP 8.4 only after sustained Digisteden pool saturation."""
import fcntl, json, re, subprocess, time
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE=Path('/opt/scripts/crawler-guard'); STATE=BASE/'state/php-fpm-recovery.json'; LOCK=Path('/run/lock/digisteden-php-fpm-recovery.lock'); LOG=Path('/var/log/digisteden-php-fpm-recovery.log'); EVENTS=BASE/'state/events.ndjson'
LOAD_THRESHOLD=10.0; REQUIRED_SAMPLES=3; COOLDOWN_SECONDS=1200; SERVICE='plesk-php84-fpm.service'

def log(text):
    with LOG.open('a') as f:f.write(f'{datetime.now(timezone.utc).isoformat()} {text}\n')
def status():
    text=subprocess.check_output(['systemctl','status',SERVICE,'--no-pager','-n','0'],text=True,stderr=subprocess.STDOUT)
    match=re.search(r'Processes active:\s*(\d+), idle:\s*(\d+)',text)
    active,idle=(int(match.group(1)),int(match.group(2))) if match else (0,0)
    pool=len(re.findall(r'php-fpm: pool digisteden\.nl',text))
    return active,idle,pool
def main():
    with LOCK.open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        now=datetime.now(timezone.utc); state=json.loads(STATE.read_text()) if STATE.exists() else {'samples':0}
        load=float(Path('/proc/loadavg').read_text().split()[0]); active,idle,pool=status()
        saturated=load>LOAD_THRESHOLD and pool>=15 and idle==0
        state['samples']=state.get('samples',0)+1 if saturated else 0
        state['last']=now.isoformat(); state['metrics']={'load':load,'active':active,'idle':idle,'digisteden_pool':pool}
        last=parse(state.get('last_restart')) if state.get('last_restart') else None
        can_restart=state['samples']>=REQUIRED_SAMPLES and (not last or (now-last).total_seconds()>=COOLDOWN_SECONDS)
        event={'at':now.isoformat(),'type':'php_fpm_overload_sample','load':load,'active':active,'idle':idle,'digisteden_pool':pool,'samples':state['samples']}
        if can_restart:
            subprocess.run(['sudo','-n','systemctl','restart',SERVICE],check=True,timeout=60)
            state['last_restart']=now.isoformat();state['samples']=0
            event.update({'type':'php_fpm_restart','reason':'sustained_load_and_pool_saturation','cooldown_seconds':COOLDOWN_SECONDS})
            log('RESTART '+json.dumps(event))
        else: log('SAMPLE '+json.dumps(event))
        STATE.parent.mkdir(parents=True,exist_ok=True);STATE.write_text(json.dumps(state));EVENTS.open('a').write(json.dumps(event)+'\n')
def parse(v):return datetime.fromisoformat(v)
if __name__=='__main__':main()
