#!/usr/bin/env python3
"""Generate a normal-Nginx temporary 429 map from actual PHP-FPM pressure."""
import fcntl,json,re,subprocess,time
from pathlib import Path
BASE=Path('/opt/scripts/crawler-guard'); STATE=BASE/'state/pressure-429.json'; LOCK=Path('/run/lock/digisteden-pressure-429.lock'); OUT=Path('/etc/nginx/pressure-429.map')
def status():
 t=subprocess.check_output(['systemctl','status','plesk-php84-fpm.service','--no-pager','-n','0'],text=True,stderr=subprocess.STDOUT);m=re.search(r'Processes active:\s*(\d+), idle:\s*(\d+)',t);a,i=(int(m.group(1)),int(m.group(2))) if m else (0,0);p=len(re.findall(r'php-fpm: pool digisteden\.nl',t));return a,i,p
def main():
 with LOCK.open('w') as l:
  fcntl.flock(l,fcntl.LOCK_EX|fcntl.LOCK_NB);s=json.loads(STATE.read_text()) if STATE.exists() else {};load=float(Path('/proc/loadavg').read_text().split()[0]);a,i,p=status();pressure=load>10 and p>=12 and i==0
  records=json.loads((BASE/'state/control-state.json').read_text()).get('records',{})
  ips=[]
  if pressure:
   for ip,r in records.items():
    if not r.get('permanent') and r.get('reason') not in ('google_services_noncloud_429_only',): ips.append(ip)
  lines=['# Auto-generated temporary pressure 429 map; normal nginx http context.','map $binary_remote_addr $pressure_429_key {','    default "";']+[f'    {ip} $binary_remote_addr;' for ip in sorted(set(ips))]+['}']
  tmp=OUT.with_suffix('.tmp');tmp.write_text('\n'.join(lines)+'\n');tmp.replace(OUT)
  STATE.write_text(json.dumps({'load':load,'active':a,'idle':i,'pool':p,'pressure':pressure,'ips':ips,'at':time.time()}));subprocess.run(['nginx','-t'],check=True);subprocess.run(['systemctl','reload','nginx'],check=True)
if __name__=='__main__':main()
