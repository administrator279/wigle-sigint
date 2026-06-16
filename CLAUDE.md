# CLAUDE.md — project context for AI agents

Read this before working in this repo. It captures the non-obvious conventions
and the bugs that have already bitten, so you don't reintroduce them.

## What this is
A **WiGLE wardrive-CSV signal-intelligence toolkit**. It parses a `WigleWifi_*.csv`
export (Wi-Fi APs, BLE/BT devices, LTE cells with GPS + RSSI + timestamps) into
security posture, device de-anonymisation, counter-surveillance (who follows
you), RSSI-trilaterated transmitter locations, pentest target lists, and styled
HTML reports. All analysis is **local**; no network is touched to process a capture.

## Hard constraints (do not break)
- **Standard library only.** No `pip install`, no third-party imports. `sqlite3`
  ships with Python. Portability (Windows / Linux / Android-Termux / in-browser
  via Pyodide) depends on this. If you think you need a dependency, you don't.
- **Privacy / OPSEC.** A capture and its derived reports pinpoint the operator's
  home and log third parties' networks. **Never commit** capture data, reports,
  exclusion lists, or anything with real coordinates/identity. `.gitignore`
  enforces this (`*.csv`, `*.report.html`, `recon/threat/report_*.html`,
  `exclude.txt`, `*_exclude.txt`, `*_devices.csv`, `targets.csv`, `*.db`, maps).
  Docs use **synthetic** identifiers/coords only (Sydney example points, `02:…`
  MACs) — keep it that way.

## Architecture
- `wigle_common.py` — the shared substrate every tool imports. File I/O (UTF-8,
  gz), MAC bit-analysis + LAA vendor recovery, OUI lookup + vendor-name
  normalisation, band maths, BLE address typing, haversine, RSSI trilateration,
  trip-building, GPS-density base detection, per-MAC sighting aggregation, and
  exclusion-list handling. **Fix shared logic here once**, not per-tool.
- Per-tool modules: `wigle_analyze` (one-shot intel), `wigle_cluster`
  (BSSID→device), `wigle_track` (co-travel + trilateration), `wigle_map`
  (GeoJSON/KML/Leaflet), `wigle_db` (SQLite multi-capture + diff),
  `wigle_report` (quick bundled HTML), `wigle_report2` (styled recon/threat
  reports, exposed as `brief`), `wigle_homebase` (classify + build exclusion
  list), `wigle_follow` (deepened tail/convoy detection), `wigle_targets`
  (pentest target CSV).
- `wigle.py` — single launcher/dispatcher (`wigle.py <cmd> ...`, plus `all`).
- `build_web.py` → `wigle_web.html` — inlines five modules (common, analyze,
  track, map, report) base64 and runs them **in the browser via Pyodide**. This
  is generated; the CI rebuilds it (see below).
- `oui.json` — IEEE OUI map (committed for clone-and-go). Tools auto-find it next
  to the scripts, so they run from any cwd.

## Conventions you must follow
- **`oui.json` and `exclude.txt` auto-resolve** from the script directory
  (`W.load_oui`, `W.resolve_exclude`). Most tools take `--exclude FILE` (default:
  auto-find `exclude.txt`) and `--no-exclude` to opt out. `exclude.txt` is a
  user's curated home-base/own-kit MAC list and is gitignored.
- **`exclude.txt` is built by `homebase`** (classifies emitters OWN/HOME/
  NEAR_HOME/MOBILE by GPS-density base detection) and grown by
  `follow --append-exclude` (promote confirmed own kit, e.g. a car).
- Reports embed a Leaflet map; **cap markers (~1000 strongest)** — thousands of
  circle-markers freeze mobile browsers.

## Bugs already fixed — don't reintroduce
- **Windows cp1252** crashes on em-dash / full-width commas. `wigle_common`
  forces UTF-8 on stdout/stderr at import and opens `oui.json` as UTF-8.
- **RSSI `0` is a WiGLE "no reading" sentinel**, not 0 dBm. `W.parse_rssi`
  treats `>= 0` as missing — otherwise it inflates "best signal" and dominates
  the RSSI-weighted trilateration (weight `10^(0/20)=1`). Use `parse_rssi`, never
  raw `int(rssi)`, for signal maths.
- **`.gitignore` ate a source file once**: `wigle_map.*` matched `wigle_map.py`.
  Ignore generated outputs by explicit extension, never `name.*`.
- **Pyodide encoding**: `build_web.py` writes module bytes to the Pyodide FS as a
  `Uint8Array` (not a JS string) or UTF-8 double-encodes the source.
- Coordinate parsing goes through `W.fpt` + `None` guards (a malformed lat/lon
  that passes `has_fix` would crash bare `float()` / `round(None)`).

## How to run / verify
```bash
python wigle.py homebase CAPTURE.csv          # -> exclude.txt (review home_devices.csv)
python wigle.py brief    CAPTURE.csv --mode threat   # styled report, home auto-excluded
python wigle.py all      CAPTURE.csv          # report + map + db ingest
python -m py_compile wigle*.py build_web.py    # cheap sanity check before committing
```
There are no unit tests; verify by running tools against a real capture and
sanity-checking counts. Compile-check everything before committing.

## CI
`.github/workflows/build-web.yml` compile-checks all modules and rebuilds
`wigle_web.html` when `wigle_*.py` / `build_web.py` change (auto-commits the
refreshed bundle on push to `main`; validates freshness on PRs). If you change
any inlined module, **regenerate the bundle** (`python build_web.py`) in the same
commit so the PR check stays green.

## Git workflow
Solo public repo (`administrator279/wigle-sigint`). Large features go on a
feature branch → PR. Keep commit messages descriptive. The user pushes / merges
unless they ask otherwise.
