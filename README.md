# WiGLE SIGINT Toolkit

[![build-web](https://github.com/administrator279/wigle-sigint/actions/workflows/build-web.yml/badge.svg)](https://github.com/administrator279/wigle-sigint/actions/workflows/build-web.yml)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Python 3.7+](https://img.shields.io/badge/python-3.7%2B-blue.svg)
![Dependencies: none](https://img.shields.io/badge/dependencies-none%20(stdlib)-success.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20Android%20(Termux)%20%7C%20browser-lightgrey.svg)

Local signal-intelligence tooling for [WiGLE](https://wigle.net) wardrive CSV
exports. Parse a capture into security posture, hardware/ISP fingerprints,
de-anonymised physical devices, counter-surveillance (co-travel / tail
detection), RSSI-trilaterated transmitter locations, map layers, and a
self-contained HTML report — **with no third-party dependencies**.

> **All analysis is local.** No network is accessed to read or process a capture.
> (The HTML map *renders* using CDN map tiles; the analysis itself is offline.)
> Passive 802.11 collection sits in legal grey zones in some jurisdictions —
> treat this as security research on **your own** captures.

## Why it's portable

- **Python 3 standard library only** — nothing to `pip install` (`sqlite3` ships
  with Python). Clone and run.
- Runs the same on **Windows, Linux, and Android via Termux**.
- Ships a **browser drag-drop app** (`wigle_web.html`) that runs the exact same
  Python in-browser via [Pyodide](https://pyodide.org) — the dropped CSV never
  leaves the device.

## Tools

| Command | Does |
|---------|------|
| `wigle.py analyze` | One-shot intel: security, BLE/BT, channels, WPS-by-vendor, anomalies, OPSEC |
| `wigle.py cluster` | Collapse an AP's many BSSIDs into physical devices (+ BLE/BT) |
| `wigle.py track` | Co-travel / tail detection + RSSI transmitter-location estimates |
| `wigle.py map` | GeoJSON + KML (Google Earth) + self-contained Leaflet HTML |
| `wigle.py db` | Multi-capture SQLite ingest + cross-capture diff |
| `wigle.py report` | One bundled dark "RF-scope" HTML report (analyze + track + map) |
| `wigle.py homebase` | Classify emitters OWN/HOME/NEAR_HOME/MOBILE; export an `exclude.txt` |
| `wigle.py follow` | Deepened tail detection: on-body RSSI, convoys, tracker-RPA, confidence |
| `wigle.py targets` | Pentest target CSV: per-AP attack vectors + physical recon (Seos/WEP) |
| `wigle.py brief` | Styled report, `--mode recon` (teardown) or `--mode threat` (red/blue) |
| `wigle.py all` | report + map + db-ingest in one command |

Most tools **auto-load a repo-local `exclude.txt`** (built by `homebase`) to drop
your home-base/own gear by default — pass `--exclude FILE` to point elsewhere, or
`--no-exclude` to keep everything. `exclude.txt` is gitignored (it lists your own
MACs). `wigle_common.py` holds shared helpers; `build_web.py` regenerates the
browser app.

### Counter-surveillance workflow
```bash
python wigle.py homebase capture.csv               # -> home_exclude.txt (review home_devices.csv)
python wigle.py follow   capture.csv --exclude home_exclude.txt   # who follows you, home removed
python wigle.py brief    capture.csv --mode threat --exclude home_exclude.txt
```

## Quick start

```bash
# get oui.json once (committed here already; regenerate if you like):
#   npm i oui-data && node -e "require('fs').writeFileSync('oui.json',JSON.stringify(require('oui-data')))"

python wigle.py all path/to/WigleWifi_xxxx.csv      # full pipeline -> report.html + map + db
python wigle.py analyze path/to/WigleWifi_xxxx.csv  # just the text summary
```

**Browser, no install:** open `wigle_web.html`, drop a `WigleWifi_*.csv`
(+ optional `oui.json`), read the report.

**On a phone (Termux):** `pkg install python`, clone this repo, then
`python wigle.py all <capture>.csv`.

Full command reference, flags, worked examples, and step-by-step desktop/phone
instructions: **[USAGE.md](USAGE.md)**. Analyst method & doctrine:
**[SIGINT_PROJECT.md](SIGINT_PROJECT.md)**.

## License

[MIT](LICENSE).
