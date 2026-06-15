# WiGLE SIGINT Toolkit — Consolidated Usage Guide

One place that documents every command, with a worked example and illustrative
sample output for each. **All sample output below uses synthetic identifiers**
(documentation MACs like `02:…`, generic SSIDs, example coordinates); the shapes
and counts mirror a real ~15,500-observation capture but no real device,
network, or location is shown. For the method and analyst doctrine see
`SIGINT_PROJECT.md`; for the quick-start see `README.txt`.

- **Location:** all files live in `C:\Users\timfl\Tools\wigle-sigint\`.
- **Dependencies:** none — Python 3 standard library only (`sqlite3` ships with Python).
- **Vendor naming:** needs `oui.json` (already present). Tools auto-find it next to
  the scripts, so you can run from any directory. Regenerate it with:
  ```
  npm i oui-data && node -e "require('fs').writeFileSync('oui.json',JSON.stringify(require('oui-data')))"
  ```
- **Convention below:** `$csv` = path to a `WigleWifi_*.csv` (or `.csv.gz`).

```powershell
$csv = "C:\path\to\WigleWifi_xxx.csv"
```

---

## File map

| File | Run directly? | Purpose |
|------|:---:|---------|
| `wigle.py` | ✅ | Unified launcher / dispatcher for everything below |
| `wigle_common.py` | ❌ library | Shared helpers (parsing, MAC math, OUI, geo, trilateration); UTF-8 fixes |
| `wigle_analyze.py` | ✅ | One-shot intel pass |
| `wigle_cluster.py` | ✅ | BSSID-family → physical-device de-anonymiser |
| `wigle_track.py` | ✅ | Co-travel / tail detection + RSSI trilateration |
| `wigle_map.py` | ✅ | GeoJSON + KML + self-contained Leaflet HTML |
| `wigle_db.py` | ✅ | Multi-capture SQLite ingest + cross-capture diff |
| `wigle_report.py` | ✅ | One self-contained dark "RF-scope" HTML report |
| `build_web.py` | ✅ | Generates `wigle_web.html` (browser drag-drop app) |
| `wigle_web.html` | open in browser | The drag-drop web app (runs the Python in-browser via Pyodide) |

Every runnable tool also supports `--help` for a live flag reference, e.g.
`python wigle.py track --help`.

---

## The launcher — `wigle.py`

One entry point for all six tools, plus an `all` pipeline. Works identically on
Windows, Linux and Android/Termux.

```
python wigle.py analyze $csv [--oui oui.json] [--json out.json]
python wigle.py cluster $csv [--include-ble] [--min-bssids 3]
python wigle.py track   $csv [--min-trips 3] [--min-sep-km 0.5]
python wigle.py map     $csv [--out survey]
python wigle.py report  $csv [--out report.html]
python wigle.py db ingest $csv      (also: db stats | db captures | db diff ...)
python wigle.py all     $csv        # report + map + db-ingest in one go
```

### `all` — the field one-liner

```powershell
python wigle.py all $csv
```
```
=== report -> WigleWifi_20260614143812.report.html ===
[+] wrote WigleWifi_20260614143812.report.html (982 KB)
=== map -> WigleWifi_20260614143812.geojson/.kml/.html ===
# wigle_map - 4720 located emitters  {'BLE': 1136, 'BT': 94, 'LTE': 25, 'OPEN': 364, 'WEP': 13, 'WPA2/3': 643, 'WPS': 1396, 'randomized': 1049}
=== db ingest ===
[+] ingested 'WigleWifi_...csv' (OPPO CPH2695) - 15493 rows, 15452 new observations
[done] open WigleWifi_20260614143812.report.html
```
Output files are named after the capture stem. Open the `.report.html` for the
full picture.

---

## Step-by-step (a full desktop session)

Run these in order in PowerShell from inside the kit folder. Each `#` line
explains what the step does.

```powershell
## Step 0 — go to the toolkit folder
cd C:\Users\timfl\Tools\wigle-sigint        # all commands run from here

## Step 1 — point a variable at your capture (so you don't retype the path)
$csv = "C:\Users\timfl\Downloads\WigleWifi_20260614143812.csv"

## Step 2 — quick text intel pass (read this first to see what you've got)
python wigle.py analyze $csv                 # prints the summary to the screen

## Step 3 — find anything following you across multiple outings
python wigle.py track $csv                   # co-travel flags + located transmitters

## Step 4 — collapse BSSIDs into real physical devices (+ BLE/BT)
python wigle.py cluster $csv --include-ble   # de-duplicates one AP's many BSSIDs

## Step 5 — build map layers you can open in Google Earth / any browser
python wigle.py map $csv --out survey        # -> survey.geojson / .kml / .html

## Step 6 — make the single shareable report
python wigle.py report $csv --out report.html   # one self-contained HTML file

## Step 7 — save this capture into the rolling database (for future diffs)
python wigle.py db ingest $csv               # idempotent: safe to re-run

## Step 8 — later, after another wardrive, see what's NEW near a location
python wigle.py db diff --near=-33.8568,151.2153 --km 1   # note the '=' before the negative lat
```

**Shortcut:** Steps 5–7 in one command —
```powershell
python wigle.py all $csv     # = report + map + db-ingest together
```

---

## `wigle_analyze.py` — one-shot intelligence pass

Parse → classify → security → fingerprint → BLE/BT → channels → WPS-by-vendor →
anomalies → OPSEC, in one go.

```powershell
python wigle.py analyze $csv --json out.json
# or standalone:  python wigle_analyze.py $csv --oui oui.json --json out.json
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--oui` | `oui.json` | OUI database for vendor naming |
| `--json` | (off) | also write the full structured result to JSON |

**Sample output (trimmed):**
```
# WiGLE SIGINT — 15493 obs, 5919 unique emitters
types: {'WIFI': 11270, 'LTE': 573, 'BLE': 3218, 'BT': 432}
window: 2026-05-18 23:34:11 -> 2026-06-14 04:37:48 (12 active days)

WiFi: 3904 APs | 46.0% randomized(LAA) | bands {'5GHz': 1835, '2.4GHz': 2068}
security: {'WPA2': 3050, 'WPS_enabled': 1570, 'WPA2/3-transition': 651, 'OPEN': 180, 'WEP': 15, ...}
WPS on default-ISP SSIDs (Pixie-Dust risk): 709
  WPS on historically-weak vendors: [('Sagemcom Broadband SAS', 233), ('Arcadyan Corporation', 214), ...]
busiest channels: 2.4GHzch6=529, 2.4GHzch1=496, 5GHzch149=369, ...
BLE: 1832 devices | addr {'RPA': 816, 'NRPA': 624, 'static-random': 355} | 129 named
[!] WEP nets: 15  Seos badge readers: 9 @ [(-33.8401, 151.2110), ...]
[!] persistent stable-LAA emitters (fixed device, not rotating):
    02:11:22:ac:b3:d1  124 sightings / 11 days
[OPSEC] base cell (-33.8568, 151.2153) = 46% of obs within ~150m | survey span 4.04km
```

---

## `wigle_cluster.py` — BSSID → physical device

Collapses the many BSSIDs one access point emits (per-band, guest, hidden) back
into single devices; with `--include-ble`, also groups BLE/BT by name across
address rotation.

```powershell
python wigle.py cluster $csv --min-bssids 3 --include-ble
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--window` | `8` | max last-octet gap to merge into one device |
| `--min-bssids` | `1` | only show devices emitting ≥ N BSSIDs |
| `--include-ble` | (off) | also cluster BLE/BT devices |
| `--no-vendor` | (off) | skip vendor naming |
| `--json` | (off) | write full device list to JSON |

**Sample output (trimmed):**
```
WiFi rows 11270 | unique BSSIDs 3904 | physical devices 2833 (collapse 3904->2833, 27% reduction)

BSSIDs   bands hid  vendor                       ssids
    11   2.4/5   0  Cisco Systems, Inc           Corp-AP-1, Corp-AP-2, Corp-AP-3 +7
    10   2.4/5   0  Fortinet, Inc.               Site-A, Site-B, Site-C +2
     6   2.4/5   2  eero inc.                    HomeMesh, HomeMesh Guest

BLE/BT logical devices (named, merged across address rotation): 211
addrs   types  cat          name
    5     BLE  Uncategorize Seos
    4  BLE/BT  Display/Spea [TV] Samsung BE 85 TV
    4      BT  Handsfree    CAR AUDIO
```

---

## `wigle_track.py` — co-travel / tail detection + trilateration

The temporal pass. Splits the capture into trips by time gap, then flags
emitters that follow you across multiple trips at separated places, and
estimates each transmitter's actual location from RSSI.

```powershell
python wigle.py track $csv --min-trips 3 --min-sep-km 0.5
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--gap` | `20` | minutes of silence that starts a new "trip" |
| `--min-trips` | `3` | flag emitters seen in ≥ N trips |
| `--min-sep-km` | `0.5` | trip centroids ≥ this far apart count as distinct places |
| `--locate-min` | `4` | min fixes needed to trilaterate a MAC |
| `--json` | (off) | write trips + co-travel + located list to JSON |

**Sample output (trimmed):**
```
# wigle_track - 15493 obs split into 24 trips (>20min gap = new trip)

[CO-TRAVEL] 102 emitters shadow you across >=3 trips & >=2 places (>0.5km apart):
  02:39:10:bf:52:d8  WIFI  23trips/2places ~1.05km  MyRouter-5G     WIFI emitter across trips
  06:11:22:ac:b3:d1  WIFI  21trips/2places ~1.05km  (unnamed)       stable-LAA Wi-Fi (fixed device shadowing route)

[LOCATED] top transmitter estimates (552 with >=4 fixes), tightest spread first:
  -33.86010,151.20850  +/-~0.0km   rssi -61  ExampleNet-1         02:fa:b8:01:78:fa
  -33.86015,151.20870  +/-~0.011km rssi -59  GuestWiFi            02:36:da:2b:82:a2
```
> **Note:** your own gateway appears here too (a high trip-count family like
> `MyRouter-5G`). Identify and exclude your own kit before trusting a "tail" flag.

---

## `wigle_map.py` — map layers

Emits three artefacts: `PREFIX.geojson`, `PREFIX.kml` (Google Earth), and a
self-contained `PREFIX.html` Leaflet map. Each emitter is placed by RSSI-weighted
trilateration (strongest-signal fallback) and coloured by severity.

```powershell
python wigle.py map $csv --out survey
# produces survey.geojson, survey.kml, survey.html
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--out` | `wigle_map` | output filename prefix |
| `--types` | `WIFI,BLE,BT,LTE` | which emitter types to map |
| `--min-rssi` | `-95` | drop sightings weaker than this |

**Sample output:**
```
# wigle_map - 4720 located emitters  {'WPS': 1396, 'BLE': 1136, 'randomized': 1049, 'WPA2/3': 643, 'OPEN': 364, ...}
[+] survey.geojson
[+] survey.kml
[+] survey.html
```
Severity colours: red WEP · orange OPEN · amber WPS · yellow randomized ·
green WPA2/3 · blue BLE/BT · violet LTE. GeoJSON/KML are fully offline; the HTML
map pulls tiles + leaflet.js from a CDN.

---

## `wigle_db.py` — multi-capture database + diff

Persists captures into a local SQLite file and answers longitudinal questions:
what's NEW near a point, what keeps reappearing. Ingest is idempotent
(dedup by MAC + timestamp), so re-ingesting the same file is a no-op.

```powershell
python wigle.py db ingest $csv
python wigle.py db stats
python wigle.py db captures
python wigle.py db diff --near=-33.8568,151.2153 --km 1 --type WIFI
```
> **Argparse note:** use `--near=-33.8568,151.2153` with the `=` — a leading `-`
> on the latitude confuses the parser if you use a space.

| Command | Key flags | Meaning |
|---------|-----------|---------|
| `ingest CSV` | `--oui`, `--db` | add a capture to the db |
| `stats` | `--db` | summarise the whole db |
| `captures` | `--db` | list ingested captures |
| `diff` | `--capture`, `--near=LAT,LON`, `--km`, `--type` | what the latest (or named) capture added vs all earlier ones |

**Sample output:**
```
[+] ingested 'WigleWifi_...csv' (OPPO CPH2695) - 15493 rows, 15452 new observations, 15452 total in db
# wigle.db - 1 captures, 15452 observations, 5919 unique emitters
  WIFI  3904
  BLE   1832
# diff - capture '...' vs all earlier captures
[NEW] 1498 emitters not seen before within 1.0km of (-33.8568, 151.2153) [WIFI]:
  02:44:89:5e:ca:56  WIFI  rssi  -6  -33.85681,151.21530  TP-Link Systems Inc
```

---

## `wigle_report.py` — single bundled HTML report

Combines analyze + track + map into one self-contained dark "RF-scope" HTML file:
headline cards, embedded trilateration map, security table, co-travel table,
anomalies, BLE/BT, OPSEC. All computation is local.

```powershell
python wigle.py report $csv --out report.html
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--out` | `report.html` | output HTML path |
| `--oui` | `oui.json` | vendor database |

**Sample output:**
```
[+] wrote report.html (982 KB)
```
Open it in any browser. (The page fetches map tiles + leaflet.js from a CDN to
draw the map; the analysis was done locally before the file was written.)

---

## Running on a phone (Termux) — full step-by-step

The wardrive happens on the phone, so the CSV is already there. With Termux you
can run the full toolkit on the phone itself, no PC needed. Do steps 1–4 once;
steps 5–7 every time you analyse a capture.

### Part A — one-time setup

**Step 1 — Install Termux.**
Install **Termux** from **F-Droid** (https://f-droid.org) — the Google Play
version is outdated and breaks `pkg`. Open the app once installed.

**Step 2 — Update Termux and install Python.**
```bash
pkg update && pkg upgrade        # press Y / Enter if prompted
pkg install python               # installs Python 3 (stdlib only — that's all we need)
```

**Step 3 — Give Termux access to your phone's storage.**
```bash
termux-setup-storage             # tap "Allow" on the popup
```
This creates `~/storage/` shortcuts. Your phone's Download folder is now at
`~/storage/downloads`.

**Step 4 — Get the toolkit folder onto the phone.** Pick ONE:

- *Cable / Quick Share / cloud:* copy the whole `wigle-sigint` folder from your PC
  into the phone's **Download** folder. You only need the `.py` files + `oui.json`
  + `USAGE.md`; you can skip `node_modules` (large, not needed). Then in Termux:
  ```bash
  cp -r ~/storage/downloads/wigle-sigint ~/      # copy it into Termux's home
  cd ~/wigle-sigint
  ```
- *Or, if you keep the kit in a git repo:*
  ```bash
  pkg install git
  git clone <your-repo-url> ~/wigle-sigint
  cd ~/wigle-sigint
  ```

Verify it's there:
```bash
ls                               # you should see wigle.py, oui.json, etc.
```

### Part B — every time you want to analyse a capture

**Step 5 — Export the capture from the WiGLE app (if you haven't).**
In **WiGLE → Database/Data tab → "CSV Export" (or "Export run to CSV")**. WiGLE
writes a `WigleWifi_<timestamp>.csv` into your **Download** folder (or its own app
folder — note where it says it saved). 

**Step 6 — Find the CSV path in Termux.**
```bash
ls ~/storage/downloads/WigleWifi_*.csv        # lists your captures with full names
```
Copy the exact filename it prints.

**Step 7 — Run the toolkit on it.**
```bash
cd ~/wigle-sigint
python wigle.py all ~/storage/downloads/WigleWifi_20260614143812.csv
```
This produces `WigleWifi_20260614143812.report.html` (plus map layers) **in the
current folder** (`~/wigle-sigint`). `oui.json` is auto-found next to the scripts,
so vendor names work from anywhere.

**Step 8 — Open the report on your phone.**
Copy the report into Download so your normal browser/file-manager can open it:
```bash
cp ~/wigle-sigint/*.report.html ~/storage/downloads/
```
Then open your **Files/Downloads** app, tap the `.report.html`, and choose your
browser. (The map needs internet to draw tiles; all analysis already happened
offline on the phone.)

> Tip: any single tool works the same way, e.g.
> `python wigle.py analyze ~/storage/downloads/WigleWifi_xxx.csv` for a quick
> on-screen summary without generating files.

---

## Browser drag-drop web app — `wigle_web.html`

For a zero-setup look on *any* device (phone, tablet, someone else's PC). Runs
the exact same Python modules in-browser via Pyodide; the dropped CSV never
leaves the device.

**Generate / refresh the bundle** (re-run after editing any `wigle_*.py`):
```powershell
python build_web.py
```
```
[+] wrote wigle_web.html (65 KB, 5 modules inlined)
```

**Use it on a PC:**
1. Double-click `wigle_web.html` (or drag it into a browser tab).
2. Click **Choose files** (or drag-drop) and pick your `WigleWifi_*.csv` —
   add `oui.json` too if you want hardware vendor names.
3. The full report renders inline.

**Use it on a phone (step-by-step):**
1. **Transfer `wigle_web.html` to the phone.** Copy it into the phone's
   **Download** folder via cable, Quick Share, email-to-yourself, or any cloud
   drive. (It's a single 65 KB file — no other files needed.)
2. **Open it in the phone's browser.** In your Files/Downloads app, tap
   `wigle_web.html` and choose Chrome (or any browser). Wait a few seconds on the
   first open while it fetches the engine.
3. **Load your capture.** Tap **Choose files**, then pick your
   `WigleWifi_*.csv` from Downloads. (Optionally also pick `oui.json` for vendor
   names — transfer it the same way if you want it.)
4. **Read the report** — it renders right on the page.

> First open needs internet to fetch Pyodide (~6 MB, then browser-cached). After
> that the analysis itself is fully local — the CSV is read in the browser's
> sandbox and never uploaded anywhere.

---

## At a glance — which tool when

| You want to… | Run |
|--------------|-----|
| A fast text intel summary | `wigle.py analyze $csv` |
| Collapse BSSIDs into real devices | `wigle.py cluster $csv --include-ble` |
| Know what's following you | `wigle.py track $csv` |
| See it on a map | `wigle.py map $csv --out survey` |
| Track changes across wardrives | `wigle.py db ingest $csv` then `db diff` |
| One shareable report | `wigle.py report $csv` |
| Everything at once | `wigle.py all $csv` |
| Analyse on the phone | Termux + `wigle.py all` |
| Analyse anywhere, no install | `wigle_web.html` |

_All analysis is local; no network is accessed to read or process a capture.
Passive 802.11 collection sits in an AU legal grey zone — treat this as security
research on your own captures._
