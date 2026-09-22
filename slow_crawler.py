#!/usr/bin/env python3
import ipaddress,json,os,sys
from collections import defaultdict
from datetime import datetime,timedelta,timezone
from pathlib import Path
FMT='%d/%b/%Y:%H:%M:%S %z'
def env(p):
 d={}
 for x in Path(p).read_text().splitlines():
  if '=' in x and not x.lstrip().startswith('#'): a,b=x.split('=',1);d[a.strip()]=b.strip()
 return d
def nets(files):
 r=[]
 for f in files.split(':'):
  for x in Path(f).read_text().splitlines():
   try:r.append(ipaddress.ip_network(x.split()[0].rstrip(';'),strict=False))
   except:pass
 return r
def main():
 c=env(sys.argv[1]); state_p,out_p=map(Path,sys.argv[2:4]); now=datetime.now(timezone.utc); cutoff=now-timedelta(hours=24); dyn=tuple(c['DYNAMIC_PREFIXES'].split(',')); exc=tuple(c['EXCLUDED_PREFIXES'].split(',')); trust=nets(c['TRUSTED_LISTS']);
 with Path(c['ACCESS_LOG']).open('rb') as f:f.seek(max(0,os.path.getsize(c['ACCESS_LOG'])-4000000));text=f.read().decode(errors='replace').split('\n',1)[-1]
 state=json.loads(state_p.read_text()) if state_p.exists() else {}; seen={k:set(v) for k,v in state.items()}
 for line in text.splitlines():
  q=line.split('"'); h=q[0].split() if len(q)>1 else []; req=q[1].split() if len(q)>1 else []
  if len(h)<5 or len(req)<2:continue
  try:ip=ipaddress.ip_address(h[0]); t=datetime.strptime(h[3].lstrip('[')+' '+h[4].rstrip(']'),FMT)
  except:continue
  path=req[1].split('?',1)[0]
  if t<cutoff or any(ip in n for n in trust) or any(path.startswith(x) for x in exc) or not any(path==x or path.startswith(x.rstrip('/')+'/') for x in dyn):continue
  seen.setdefault(str(ip),set()).add(t.isoformat()+'|'+path)
 candidates=[]; cleaned={}
 for ip,items in seen.items():
  rows=sorted((datetime.fromisoformat(x.split('|',1)[0]),x.split('|',1)[1]) for x in items if datetime.fromisoformat(x.split('|',1)[0])>=cutoff)
  if len(rows)>200:rows=rows[-200:]
  cleaned[ip]={t.isoformat()+'|'+p for t,p in rows}
  intervals=[(rows[i][0]-rows[i-1][0]).total_seconds() for i in range(1,len(rows))]
  periodic=[x for x in intervals if 55<=x<=70]
  if len(periodic)>=4 and len({p for _,p in rows[-20:]})>=3:candidates.append({'ip':ip,'requests_24h':len(rows),'unique_urls':len({p for _,p in rows[-20:]}),'avg_interval_seconds':round(sum(periodic)/len(periodic),1),'matching_intervals':len(periodic),'reason':'slow_periodic_crawler'})
 state_p.write_text(json.dumps({k:list(v) for k,v in cleaned.items()}));out_p.write_text(json.dumps({'generated_at':now.isoformat(),'slow_candidates':candidates},indent=2))
if __name__=='__main__':main()
