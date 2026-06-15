Part 1 — WiGLE SIGINT tools (local research folder)
Full command reference with worked examples + sample output: see USAGE.md
Files: wigle_cluster.py, wigle_analyze.py, SIGINT_PROJECT.md
powershellmkdir C:\Users\timfl\Tools\wigle-sigint
# move the 3 files there, then regenerate the OUI database:

cd C:\Users\timfl\Tools\wigle-sigint
npm i oui-data
node -e "require('fs').writeFileSync('oui.json',JSON.stringify(require('oui-data')))"

Run it on any capture (set CSV once, reuse):
powershell$csv = "C:\path\to\WigleWifi_xxx.csv"
python wigle_analyze.py $csv --oui oui.json --json out.json     # one-shot intel
python wigle_cluster.py $csv --oui oui.json --min-bssids 3 --include-ble   # BSSID/BLE -> devices
python wigle_track.py   $csv --oui oui.json                     # co-travel + trilateration
python wigle_map.py     $csv --oui oui.json --out survey        # -> survey.geojson/.kml/.html
python wigle_db.py ingest $csv --oui oui.json                   # add to multi-capture db
python wigle_db.py diff --near=-33.8568,151.2153 --km 1         # what's new near a point

One launcher (recommended):
  python wigle.py all $csv            # report + map + db-ingest in one go
  python wigle.py report $csv         # just the bundled HTML report
  python wigle.py analyze|cluster|track|map|db ...   # any single tool

Tools (all stdlib — no pip installs):
  wigle.py          unified launcher / dispatcher (analyze|cluster|track|map|report|db|all)
  wigle_common.py   shared helpers (imported by the rest; UTF-8 fixes live here)
  wigle_analyze.py  one-shot SIGINT pass (+ BLE/BT, channel, WPS-vendor, evil-twin dedup)
  wigle_cluster.py  BSSID-family de-anonymiser (+ --include-ble)
  wigle_track.py    co-travel / tail detection + RSSI trilateration (uses timestamps)
  wigle_map.py      GeoJSON + KML (Google Earth) + self-contained Leaflet HTML
  wigle_db.py       SQLite ingest + cross-capture diff
  wigle_report.py   one self-contained dark "RF-scope" HTML report (analyze+track+map)

Portability:
  ON A PHONE (Termux): pkg install python; copy this folder over; same commands work
    (oui.json is auto-found next to the scripts, so run from anywhere).
  BROWSER DRAG-DROP: python build_web.py  ->  wigle_web.html  (single self-contained
    file; runs the same Python in-browser via Pyodide). Open it on any device, drop a
    WiGLE CSV (+ optional oui.json), get the report. The CSV never leaves the device.
    First open fetches Pyodide (~6MB) from a CDN, then it's browser-cached.
    Re-run build_web.py whenever you change the wigle_*.py sources.

No Python packages needed — stdlib only (sqlite3 ships with Python). The Leaflet HTML map pulls
map tiles + leaflet.js from a CDN, so that one file needs internet to render; GeoJSON/KML are fully
offline. SIGINT_PROJECT.md is the reference; paste it into a Claude Project's instructions to resume.
The earlier outputs (wardrive_report.html, threat_opsec_brief.html, footprint.png, devices.json) are
just results — keep or bin, the tools don't need them.