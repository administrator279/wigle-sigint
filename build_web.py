#!/usr/bin/env python3
"""
build_web.py - Generate a self-contained drag-drop web app from the kit.

Produces wigle_web.html: a single file that runs the *exact same* Python
analysis modules in the browser via Pyodide (WASM). Drop a WiGLE CSV (and
optionally oui.json for vendor naming) onto the page and it renders the full
wigle_report.build() report inline. The CSV is processed entirely client-side
and never leaves the device.

Re-run this whenever you change the wigle_*.py sources to refresh the bundle.

Usage:
  python3 build_web.py [--out wigle_web.html] [--pyodide <cdn-base>]

Note: first open needs internet to fetch Pyodide (~6MB, then browser-cached);
after that the analysis itself is fully local. Copy wigle_web.html to a phone
and open it in any browser.
"""
import os, sys, base64, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
# Modules the in-browser report needs (wigle_db/sqlite3 is intentionally excluded).
MODULES = ["wigle_common.py", "wigle_analyze.py", "wigle_track.py",
           "wigle_map.py", "wigle_report.py"]

PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WiGLE SIGINT — drop a capture</title>
<style>
:root{--bg:#0c0e10;--panel:#15181b;--line:#262b30;--fg:#d7dde3;--mut:#8b97a3;--green:#39d353;--amber:#ffb02d}
*{box-sizing:border-box}html,body{margin:0;height:100%;background:var(--bg);color:var(--fg);
font:14px/1.5 ui-monospace,Menlo,Consolas,monospace}
#top{padding:14px 18px;border-bottom:1px solid var(--line);display:flex;gap:14px;align-items:center;flex-wrap:wrap}
h1{font:700 18px system-ui;margin:0}
#drop{border:2px dashed var(--line);border-radius:10px;padding:34px;margin:18px;text-align:center;
color:var(--mut);transition:.15s}
#drop.hot{border-color:var(--green);color:var(--fg);background:#10160f}
#status{font-size:12.5px;color:var(--mut);margin-left:auto}
button,label.btn{background:var(--panel);border:1px solid var(--line);color:var(--fg);
padding:7px 12px;border-radius:7px;cursor:pointer;font:inherit}
button:hover,label.btn:hover{border-color:var(--green)}
#frame{width:100%;height:calc(100vh - 60px);border:0;display:none;background:#0c0e10}
.hint{font-size:12px;color:var(--mut)}
input[type=file]{display:none}
.ok{color:var(--green)}.warn{color:var(--amber)}
</style></head><body>
<div id="top">
  <h1>WiGLE SIGINT</h1>
  <label class="btn">Choose files<input id="file" type="file" multiple accept=".csv,.gz,.json"></label>
  <span class="hint">drop a WiGLE CSV (+ optional oui.json) anywhere</span>
  <span id="status">loading engine…</span>
</div>
<div id="drop">
  <div style="font-size:42px">📡</div>
  <div>Drop your <b>WigleWifi_*.csv</b> here</div>
  <div class="hint">add <b>oui.json</b> to name hardware vendors · everything stays on this device</div>
</div>
<iframe id="frame"></iframe>

<script src="__PYODIDE__/pyodide.js"></script>
<script>
const PYFILES = __PYFILES__;
const statusEl = document.getElementById('status');
const drop = document.getElementById('drop');
const frame = document.getElementById('frame');
let pyodide = null, ready = false;

function setStatus(t, cls){ statusEl.className = cls||''; statusEl.textContent = t; }

async function boot(){
  setStatus('loading engine…');
  pyodide = await loadPyodide({indexURL:"__PYODIDE__/"});
  for(const [name, b64] of Object.entries(PYFILES)){
    // Decode base64 to RAW BYTES. Passing a JS string here would make Pyodide
    // re-encode the already-UTF-8 source as UTF-8 again (double-encoding), which
    // mangles every non-ASCII char (— · →) in the report templates.
    pyodide.FS.writeFile(name, Uint8Array.from(atob(b64), c=>c.charCodeAt(0)));
  }
  pyodide.runPython("import sys; sys.path.insert(0,'.')");
  ready = true;
  setStatus('engine ready · drop a capture', 'ok');
}

async function handle(files){
  if(!ready){ setStatus('still loading engine…','warn'); return; }
  let csv=null, oui=null;
  for(const f of files){
    const n=f.name.toLowerCase();
    if(n.endsWith('oui.json')) oui=f;
    else if(n.endsWith('.csv')||n.endsWith('.gz')) csv=f;
  }
  if(!csv){ setStatus('no .csv found in selection','warn'); return; }
  setStatus('reading '+csv.name+'…');
  const safe = csv.name.replace(/[^A-Za-z0-9._-]/g,'_');
  const csvPath = '/tmp/'+safe;
  pyodide.FS.writeFile(csvPath, new Uint8Array(await csv.arrayBuffer()));
  let ouiArg = "'oui.json'";
  if(oui){
    pyodide.FS.writeFile('/tmp/oui.json', new Uint8Array(await oui.arrayBuffer()));
    ouiArg = "'/tmp/oui.json'";
  }
  setStatus('analysing… (large captures take a few seconds)');
  try{
    const html = await pyodide.runPythonAsync(
      "import importlib,wigle_report; importlib.reload(wigle_report); "+
      "wigle_report.build('"+csvPath+"', "+ouiArg+")");
    frame.srcdoc = html;
    frame.style.display='block';
    drop.style.display='none';
    setStatus('done · '+csv.name+(oui?' + oui.json':' (no vendor names)'), 'ok');
  }catch(e){ setStatus('error: '+e.message,'warn'); console.error(e); }
}

document.getElementById('file').addEventListener('change', e=>handle(e.target.files));
['dragenter','dragover'].forEach(ev=>document.addEventListener(ev,e=>{
  e.preventDefault(); drop.classList.add('hot');}));
['dragleave','drop'].forEach(ev=>document.addEventListener(ev,e=>{
  e.preventDefault(); if(ev==='drop'){drop.classList.remove('hot'); handle(e.dataTransfer.files);}
  else drop.classList.remove('hot');}));
boot();
</script></body></html>"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(HERE, "wigle_web.html"))
    ap.add_argument("--pyodide", default="https://cdn.jsdelivr.net/pyodide/v0.26.2/full",
                    help="Pyodide CDN base (or a local path for offline use)")
    a = ap.parse_args()

    files = {}
    for m in MODULES:
        # Normalise CRLF -> LF so the base64 (hence the whole bundle) is identical
        # whether built on a CRLF (Windows) or LF (Linux/CI) checkout.
        src = open(os.path.join(HERE, m), "rb").read().replace(b"\r\n", b"\n")
        files[m] = base64.b64encode(src).decode("ascii")
    import json
    page = (PAGE.replace("__PYFILES__", json.dumps(files))
                .replace("__PYODIDE__", a.pyodide))
    # newline="" + explicit \n keeps the output LF on every platform.
    with open(a.out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(page)
    kb = len(page) // 1024
    print(f"[+] wrote {a.out} ({kb} KB, {len(files)} modules inlined)")
    print("    open it in a browser; first load fetches Pyodide from the CDN.")


if __name__ == "__main__":
    main()
