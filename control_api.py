import fcntl,ipaddress,json,subprocess
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
B=Path('/opt/scripts/crawler-guard'); C=Path('/etc/digisteden-crawler-guard/crawler-guard.env'); S=B/'state'; L=Path('/run/lock/digisteden-crawler-guard.lock')
def run(flag,ip):
 with L.open('w') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  cmd=[str(B/'crawler_control.py'),str(C),str(S/'latest.json'),str(S/'slow-candidates.json'),str(S/'control-state.json'),str(S/'owner-cache.json'),str(S/'events.ndjson'),flag,ip]
  out=subprocess.run(cmd,check=True,capture_output=True,text=True,timeout=45).stdout
  subprocess.run([str(B/'build_dashboard_summary.py'),str(C),str(S/'policy-last.json'),str(S/'control-state.json'),str(S/'dashboard-summary.json')],check=True,timeout=30)
  subprocess.run([str(B/'render_status.py'),str(S/'latest.json'),str(S/'status.html'),str(S/'dashboard-summary.json')],check=True,timeout=30)
  (S/'status.html').chmod(0o644)
 return json.loads(out)
class H(BaseHTTPRequestHandler):
 def log_message(self,*_):pass
 def reply(self,status,payload):
  b=json.dumps(payload).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
 def do_GET(self):self.reply(200,{'ok':True}) if self.path=='/health' else self.reply(404,{'error':'not found'})
 def do_POST(self):
  try:
   if self.path not in ('/urgent','/remove'):raise ValueError('not found')
   data=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))));ip=str(data['ip']).strip();ipaddress.ip_address(ip)
   self.reply(200,{'ok':True,'action':self.path[1:],'ip':ip,'policy':run('--urgent' if self.path=='/urgent' else '--remove',ip)})
  except ValueError as e:self.reply(400,{'ok':False,'error':str(e)})
  except Exception as e:self.reply(500,{'ok':False,'error':str(e)})
ThreadingHTTPServer(('127.0.0.1',9187),H).serve_forever()
