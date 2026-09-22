#!/usr/bin/env python3
import ipaddress,json,sys
from datetime import datetime,timedelta,timezone
from pathlib import Path
from urllib.request import Request,urlopen

def env(p):
 d={}
 for l in Path(p).read_text().splitlines():
  if '=' in l and not l.lstrip().startswith('#'):a,b=l.split('=',1);d[a.strip()]=b.strip()
 return d
def api(c,path,payload=None):
 t=Path(c['CF_API_TOKEN_FILE']).read_text().strip();r=Request('https://api.cloudflare.com/client/v4'+path,data=json.dumps(payload).encode() if payload else None,method='PATCH' if payload else 'GET',headers={'Authorization':'Bearer '+t,'Content-Type':'application/json'})
 with urlopen(r,timeout=30) as x:return json.loads(x.read().decode())['result']
def subnet(ip):
 a=ipaddress.ip_address(ip);return str(ipaddress.ip_network(f'{a}/{24 if a.version==4 else 64}',strict=False))
def expr(ips):return 'ip.src in {'+' '.join(sorted(ips,key=ipaddress.ip_address))+'}' if ips else 'ip.src eq 192.0.2.1'
def patch(c,rid,ips,desc):api(c,f"/zones/{c['CF_ZONE_ID']}/rulesets/{c['CF_RULESET_ID']}/rules/{rid}",{'action':'block','description':desc,'enabled':True,'expression':expr(ips)})
def main():
 c=env(sys.argv[1]);sp,lp,ep,slp=map(Path,sys.argv[2:6]);now=datetime.now(timezone.utc);latest=json.loads(lp.read_text());slow=json.loads(slp.read_text()) if slp.exists() else {'slow_candidates':[]};st=json.loads(sp.read_text()) if sp.exists() else {'candidates':{},'temporary':{},'transitions':[]}
 oldtemp=dict(st['temporary']);st.setdefault('transitions',[]);expired=[ip for ip,t in oldtemp.items() if datetime.fromisoformat(t)<now];st['temporary']={ip:t for ip,t in oldtemp.items() if ip not in expired};cut=now-timedelta(hours=24);st['candidates']={ip:v for ip,v in st['candidates'].items() if datetime.fromisoformat(v['at'])>=cut};allc=latest.get('local_candidates',[])+slow.get('slow_candidates',[]);oldnets={v['subnet'] for v in st['candidates'].values()};follow=[];permanent=[]
 for x in allc:
  ip=x['ip'];net=subnet(ip)
  if x.get('reason')=='slow_periodic_crawler' or (net in oldnets and ip not in st['candidates']):follow.append(ip)
  if x.get('429_events',0)>=int(c.get('RECIDIVE_429_THRESHOLD','3')):permanent.append(ip)
  st['candidates'][ip]={'subnet':net,'at':now.isoformat()}
 addtemp=[ip for ip in follow if ip not in st['temporary'] and ip not in permanent];ttl=int(c.get('TEMP_403_TTL_SECONDS','900'));st['temporary'].update({ip:(now+timedelta(seconds=ttl)).isoformat() for ip in addtemp})
 rules=api(c,f"/zones/{c['CF_ZONE_ID']}/rulesets/{c['CF_RULESET_ID']}")['rules'];permr=next(x for x in rules if x['id']==c['CF_PERMANENT_BLOCK_RULE_ID']);existing=set(permr['expression'].split('{',1)[1].split('}',1)[0].split());newperm=[ip for ip in permanent if ip not in existing]
 mode=c.get('POLICY_MODE','dry-run')
 if mode=='apply':patch(c,c['CF_TEMP_403_RULE_ID'],set(st['temporary']),'Temporary 403 repeat crawler subnet follow-up');patch(c,c['CF_PERMANENT_BLOCK_RULE_ID'],existing|set(newperm),permr.get('description','block'))
 event={'at':now.isoformat(),'temporary_added':addtemp,'temporary_expired':expired,'permanent_added':newperm,'active_temporary':sorted(st['temporary'])}
 if addtemp or expired or newperm:st['transitions'].append(event)
 st['transitions']=[x for x in st['transitions'] if datetime.fromisoformat(x['at'])>=cut];sp.write_text(json.dumps(st));ep.open('a').write(json.dumps(event)+'\n');print(json.dumps(event))
if __name__=='__main__':main()
