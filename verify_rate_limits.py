import json,os,urllib.request
H={'Authorization':'Bearer '+os.environ['CF_API_TOKEN']}
def g(p):
 r=urllib.request.Request('https://api.cloudflare.com/client/v4'+p,headers=H);return json.load(urllib.request.urlopen(r))['result']
for z in g('/zones?status=active&per_page=50'):
 rs=[x for x in g('/zones/%s/rulesets'%z['id']) if x.get('phase')=='http_ratelimit' and x.get('kind')=='zone']; r=g('/zones/%s/rulesets/%s'%(z['id'],rs[0]['id']))['rules'][0]; q=r.get('ratelimit',{});print(z['name'],r.get('description'),q.get('requests_per_period'),q.get('period'),r.get('action_parameters',{}).get('response',{}).get('status_code'),sep='\t')
