#!/usr/bin/env python3
import fcntl, ipaddress, json, subprocess
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE=Path('/opt/scripts/crawler-guard'); CONFIG=Path('/etc/digisteden-crawler-guard/crawler-guard.env'); STATE=BASE/'state'; LOCK=Path('/run/lock/digisteden-crawler-guard.lock')
def write_config(values):
 lines=CONFIG.read_text().splitlines();seen=set();out=[]
 for line in lines:
  key=line.split('=',1)[0]
  if key in values:out.append(key+'='+values[key]);seen.add(key)
  else:out.append(line)
 out += [k+'='+v for k,v in values.items() if k not in seen]
 CONFIG.write_text('\n'.join(out)+'\n')
def refresh():
 subprocess.run([str(BASE/'build_dashboard_summary.py'),str(CONFIG),str(STATE/'policy-last.json'),str(STATE/'control-state.json'),str(STATE/'dashboard-summary.json')],check=True,timeout=30)
 subprocess.run([str(BASE/'render_status.py'),str(STATE/'latest.json'),str(STATE/'status.html'),str(STATE/'dashboard-summary.json')],check=True,timeout=30);(STATE/'status.html').chmod(0o644)
def run(flag,ip):
 with LOCK.open('w') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  cmd=[str(BASE/'crawler_control.py'),str(CONFIG),str(STATE/'latest.json'),str(STATE/'slow-candidates.json'),str(STATE/'control-state.json'),str(STATE/'owner-cache.json'),str(STATE/'events.ndjson'),flag,ip]
  out=subprocess.run(cmd,check=True,capture_output=True,text=True,timeout=45).stdout;refresh();return json.loads(out)
def set_mode(data):
 tooling=str(data.get('tooling','on'));dry=bool(data.get('dry_run',False))
 if tooling not in {'on','off'}:raise ValueError('invalid tooling state')
 write_config({'TOOLING_ENABLED':tooling,'MODE':'dry-run' if dry else 'apply','POLICY_MODE':'dry-run' if dry else 'apply'})
 lock=CONFIG.parent/'force-apply.lock'
 if dry:lock.unlink(missing_ok=True)
 else:lock.touch(mode=0o600,exist_ok=True)
 refresh();return {'tooling':tooling,'dry_run':dry,'apply_lock':lock.exists()}
class H(BaseHTTPRequestHandler):
 def log_message(self,*_):pass
 def reply(self,status,payload):
  b=json.dumps(payload).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(b)));self.send_header('Cache-Control','no-store');self.end_headers();self.wfile.write(b)
 def do_GET(self):self.reply(HTTPStatus.OK,{'ok':True}) if self.path=='/health' else self.reply(HTTPStatus.NOT_FOUND,{'error':'not found'})
 def do_POST(self):
  try:
   data=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))))
   if self.path=='/mode':result=set_mode(data)
   elif self.path in ('/urgent','/remove'):
    ip=str(data['ip']).strip();ipaddress.ip_address(ip);result=run('--urgent' if self.path=='/urgent' else '--remove',ip)
   else:raise ValueError('not found')
   self.reply(HTTPStatus.OK,{'ok':True,'result':result})
  except ValueError as e:self.reply(HTTPStatus.BAD_REQUEST,{'ok':False,'error':str(e)})
  except Exception as e:self.reply(HTTPStatus.INTERNAL_SERVER_ERROR,{'ok':False,'error':str(e)})
ThreadingHTTPServer(('127.0.0.1',9187),H).serve_forever()
