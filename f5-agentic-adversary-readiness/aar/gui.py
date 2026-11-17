"""Local web GUI. Binds to 127.0.0.1 only; credentials are used for the collection call and never written to disk."""
import json, secrets, threading, webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from .clients import CollectError, collect_bigip, collect_xc
from .engine import build_report
from .report import to_html, to_markdown, CSS

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>F5 Agentic Adversary Readiness</title><style>%(css)s
fieldset{border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:0;background:var(--panel)}legend{font-weight:600;padding:0 6px}
label{display:block;font-size:12px;color:var(--ink2);margin-top:8px}input[type=text],input[type=password]{width:100%%;padding:7px 9px;border:1px solid var(--line);
border-radius:6px;background:var(--bg);color:var(--ink);font:inherit}.chk{display:flex;gap:6px;align-items:center;font-size:13px;color:var(--ink)}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0;align-items:center}button.go{background:var(--ink);color:var(--bg);border:0;border-radius:8px;padding:9px 18px;font:inherit;font-weight:600;cursor:pointer}
button.alt,a.alt{background:var(--panel);color:var(--ink);border:1px solid var(--line);border-radius:8px;padding:8px 14px;font:inherit;cursor:pointer;text-decoration:none}
button:disabled{opacity:.5;cursor:wait}#msg{color:var(--ink2)}#msg.err{color:var(--crit);font-weight:600}iframe{width:100%%;height:75vh;border:1px solid var(--line);border-radius:10px;background:var(--bg)}
</style></head><body><main>
<h1>F5 Agentic Adversary Readiness</h1>
<p class="sub">Read-only validation of BIG-IP and Distributed Cloud against the agentic adversary control catalog. Runs on this machine; credentials are sent only to the target you name.</p>
<form id="f"><div class="grid">
<fieldset><legend>BIG-IP</legend>
<label for="bh">Management host</label><input type="text" id="bh" placeholder="bigip.example.com" autocomplete="off">
<label for="bu">Username (Auditor role is enough for most checks)</label><input type="text" id="bu" autocomplete="off">
<label for="bp">Password</label><input type="password" id="bp" autocomplete="off">
<label class="chk"><input type="checkbox" id="bi"> Skip TLS verification (self-signed management certificate)</label></fieldset>
<fieldset><legend>Distributed Cloud</legend>
<label for="xt">Tenant</label><input type="text" id="xt" placeholder="acme-corp" autocomplete="off">
<label for="xk">API token</label><input type="password" id="xk" autocomplete="off">
<label for="xn">Namespaces (comma separated, blank for all)</label><input type="text" id="xn" autocomplete="off"></fieldset>
<fieldset><legend>Offline snapshots</legend>
<label for="sf">Snapshot JSON files saved with <code>--save-snapshot</code></label><input type="file" id="sf" accept=".json" multiple>
<p class="note">Use this when the device is not reachable from here: collect on a jump host, assess anywhere.</p></fieldset>
</div>
<div class="actions"><button class="go" type="submit">Run assessment</button><button class="alt" type="button" id="demo">Load demo data</button><span id="msg" role="status"></span></div></form>
<div id="out" hidden><div class="actions"><a class="alt" id="dh" download="aar-report.html">Download HTML</a><a class="alt" id="dj" download="aar-report.json">Download JSON</a>
<a class="alt" id="dm" download="aar-report.md">Download Markdown</a><a class="alt" id="ds" download="aar-snapshot.json">Download raw snapshot</a></div>
<iframe id="fr" title="Readiness report" sandbox="allow-scripts"></iframe></div>
<script>
var TOKEN=%(token)s, $=function(i){return document.getElementById(i)};
function blob(id,text,type){$(id).href=URL.createObjectURL(new Blob([text],{type:type}))}
async function run(body){var m=$('msg');m.className='';m.textContent='Collecting and assessing…';document.querySelectorAll('button').forEach(function(b){b.disabled=true});
 try{var r=await fetch('/api/assess',{method:'POST',headers:{'Content-Type':'application/json','X-AAR-Token':TOKEN},body:JSON.stringify(body)});var j=await r.json();
  if(!r.ok)throw new Error(j.error||('HTTP '+r.status));$('fr').srcdoc=j.html;blob('dh',j.html,'text/html');blob('dj',JSON.stringify(j.report,null,1),'application/json');
  blob('dm',j.markdown,'text/markdown');blob('ds',JSON.stringify(j.snapshots,null,1),'application/json');$('out').hidden=false;
  m.textContent='Done. '+j.report.targets.map(function(t){return t.target+': '+t.readiness+'/100 ('+t.tier+')'}).join(' · ');$('out').scrollIntoView({behavior:'smooth'})}
 catch(e){m.className='err';m.textContent=e.message}
 document.querySelectorAll('button').forEach(function(b){b.disabled=false})}
$('demo').onclick=function(){run({demo:true})};
$('f').onsubmit=async function(e){e.preventDefault();var b={snapshots:[]};
 if($('bh').value.trim())b.bigip={host:$('bh').value.trim(),user:$('bu').value,password:$('bp').value,insecure:$('bi').checked};
 if($('xt').value.trim())b.xc={tenant:$('xt').value.trim(),token:$('xk').value,namespaces:$('xn').value.split(',').map(function(s){return s.trim()}).filter(Boolean)};
 for(var f of $('sf').files){try{var j=JSON.parse(await f.text());b.snapshots=b.snapshots.concat(j)}catch(x){$('msg').className='err';$('msg').textContent=f.name+' is not valid JSON';return}}
 if(!b.bigip&&!b.xc&&!b.snapshots.length){$('msg').className='err';$('msg').textContent='Enter a BIG-IP, a tenant, or choose a snapshot file.';return}
 run(b)};
</script></main></body></html>"""


def _handler(token, port):
    allowed_hosts = {"127.0.0.1:%d" % port, "localhost:%d" % port}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json"):
            raw = body.encode() if isinstance(body, str) else body
            self.send_response(code); self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(raw))); self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff"); self.end_headers(); self.wfile.write(raw)

        def _ok_host(self):  # blocks DNS rebinding
            return self.headers.get("Host") in allowed_hosts

        def do_GET(self):
            if self.path == "/favicon.ico":
                return self._send(204, "")
            if not self._ok_host() or self.path != "/":
                return self._send(404, "{}")
            self._send(200, PAGE % {"css": CSS, "token": json.dumps(token)}, "text/html")

        def do_POST(self):
            if not self._ok_host() or self.path != "/api/assess" or self.headers.get("X-AAR-Token") != token:
                return self._send(403, json.dumps({"error": "forbidden"}))
            try:
                n = int(self.headers.get("Content-Length") or 0)
                if n > 64 * 1024 * 1024:
                    raise ValueError("request too large")
                body = json.loads(self.rfile.read(n) or b"{}")
                snaps = [s for s in body.get("snapshots") or [] if isinstance(s, dict) and s.get("platform") in ("bigip", "xc")]
                if body.get("demo"):
                    from .__main__ import SAMPLES
                    for p in SAMPLES:
                        with open(p) as f:
                            snaps.append(json.load(f))
                if body.get("bigip"):
                    b = body["bigip"]
                    snaps.append(collect_bigip(b["host"], b["user"], b["password"], verify=not b.get("insecure")))
                if body.get("xc"):
                    x = body["xc"]
                    snaps.append(collect_xc(x["tenant"], x["token"], x.get("namespaces") or None))
                if not snaps:
                    raise ValueError("nothing to assess")
                rep = build_report(snaps)
                self._send(200, json.dumps({"report": rep, "html": to_html(rep), "markdown": to_markdown(rep), "snapshots": snaps}))
            except (CollectError, ValueError, KeyError) as e:
                self._send(400, json.dumps({"error": str(e)}))
            except Exception as e:
                self._send(500, json.dumps({"error": "%s: %s" % (type(e).__name__, e)}))
    return H


def make_server(port=8765):
    token = secrets.token_urlsafe(24)
    srv = ThreadingHTTPServer(("127.0.0.1", port), BaseHTTPRequestHandler)
    srv.RequestHandlerClass = _handler(token, srv.server_address[1])  # after bind, so port 0 works
    return srv, token


def serve(port=8765, open_browser=True):
    srv, _ = make_server(port)
    url = "http://127.0.0.1:%d/" % srv.server_address[1]
    print("Agentic Adversary Readiness GUI on %s  (Ctrl+C to stop)" % url)
    if open_browser:
        threading.Timer(0.5, webbrowser.open, [url]).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print()
    return 0
