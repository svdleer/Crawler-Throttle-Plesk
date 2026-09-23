#!/usr/bin/env python3
"""Incremental low-load access-log reader for crawler detection."""
import ipaddress,json,os,sys
from collections import Counter
from datetime import datetime,timedelta,timezone
from pathlib import Path
FMT='%d/%b/%Y:%H:%M:%S %z'
def env(p):
 d={}
 for l in Path(p).read_text().splitlines():
  if '=' in l and not l.lstrip().startswith('#'):a,b=l.split('=',1);d[a.strip()]=b.strip()
 return d
def nets(files):
 r=[]
 for f in files.split(':'):
  for l in Path(f).read_text().splitlines():
   try:r.append(ipaddress.ip_network(l.split()[0].rstrip(';'),strict=False))
   except:pass
 return r
def trusted(ip,ns):return any(ip in n for n in ns)
def main():
 c=env(sys.argv[1]); state_p,latest_p,slow_p=map(Path,sys.argv[2:5]); log=Path(c['ACCESS_LOG']); now=datetime.now(timezone.utc); ns=nets(c['TRUSTED_LISTS']); dyn=tuple(c['DYNAMIC_PREFIXES'].split(',')); exc=tuple(c['EXCLUDED_PREFIXES'].split(',')); window_sec=int(c.get('WINDOW_SECONDS',60)); ip_thresh=int(c.get('IP_THRESHOLD',15)); min_urls=int(c.get('MIN_UNIQUE_URLS',5)); st=json.loads(state_p.read_text()) if state_p.exists() else {'inode':None,'offset':None,'ips':{}}
 info=log.stat(); inode=str(info.st_ino)
 if st['inode']!=inode or st['offset'] is None: st['inode'],st['offset']=inode,info.st_size; state_p.write_text(json.dumps(st)); latest_p.write_text(json.dumps({'mode':c.get('MODE','dry-run'),'window_seconds':window_sec,'local_candidates':[],'block_candidates':[],'pattern_alerts':[]})); slow_p.write_text(json.dumps({'slow_candidates':[]})); return
 with log.open('rb') as f:f.seek(st['offset']);data=f.read(1048576);st['offset']=f.tell()
 cutoff=(now-timedelta(hours=24)).timestamp(); recent=(now-timedelta(seconds=window_sec)).timestamp(); top_urls=Counter()
 for line in data.decode(errors='replace').splitlines():
  q=line.split('"');h=q[0].split() if len(q)>1 else [];req=q[1].split() if len(q)>1 else []
  if len(h)<5 or len(req)<2:continue
  try:
   ip_idx=0 if ':' not in h[0] or h[0].startswith('[') else 1
   ip=ipaddress.ip_address(h[ip_idx].strip('[]'));t=datetime.strptime(h[3+ip_idx].lstrip('[')+' '+h[4+ip_idx].rstrip(']'),FMT).timestamp()
  except:continue
  path=req[1].split('?',1)[0]
  if trusted(ip,ns) or any(path.startswith(x) for x in exc) or not any(path==x or path.startswith(x.rstrip('/')+'/') for x in dyn):continue
  k=str(ip);top_urls[path]+=1;st['ips'].setdefault(k,[]).append([t,path])
 candidates=[];slow=[];patterns=Counter()
 for ip,ev in list(st['ips'].items()):
  ev=[x for x in ev if x[0]>=cutoff][-120:]
  if not ev:del st['ips'][ip];continue
  st['ips'][ip]=ev;one=[x for x in ev if x[0]>=recent];urls={x[1] for x in one}
  if len(one)>=ip_thresh and len(urls)>=min_urls:candidates.append({'ip':ip,'requests':len(one),'unique_urls':len(urls),'429_events':0})
  intervals=[ev[i][0]-ev[i-1][0] for i in range(1,len(ev))];periodic=[x for x in intervals if 55<=x<=70]
  if len(periodic)>=4 and len({x[1] for x in ev[-20:]})>=3:slow.append({'ip':ip,'requests_24h':len(ev),'unique_urls':len({x[1] for x in ev[-20:]}),'avg_interval_seconds':round(sum(periodic)/len(periodic),1),'matching_intervals':len(periodic),'reason':'slow_periodic_crawler'})
 hour_cutoff=(now-timedelta(hours=1)).timestamp();hour_urls=Counter(path for ev in st['ips'].values() for ts,path in ev if ts>=hour_cutoff)
 st['inode']=inode;state_p.write_text(json.dumps(st));latest_p.write_text(json.dumps({'mode':c.get('MODE','dry-run'),'window_seconds':window_sec,'local_candidates':candidates,'block_candidates':[],'pattern_alerts':slow,'top_urls':[{'url':u,'requests':n} for u,n in top_urls.most_common(10)],'top_urls_1h':[{'url':u,'requests':n} for u,n in hour_urls.most_common(10)]}));slow_p.write_text(json.dumps({'generated_at':now.isoformat(),'slow_candidates':slow}))
if __name__=='__main__':main()
