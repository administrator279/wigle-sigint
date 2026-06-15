#!/usr/bin/env python3
"""
wigle_report.py - One self-contained dark "RF-scope" HTML report per capture.

Pulls the three analysis passes together into a single file you can open on any
device: the one-shot intel summary (wigle_analyze), the temporal counter-
surveillance pass (wigle_track: co-travel + trilateration) and an embedded
Leaflet map of located emitters (wigle_map). Green/amber/red severity per the
project doctrine. All computation is local; no network is accessed to build it
(the rendered page pulls map tiles + leaflet.js from a CDN to draw the map).

Usage:
  python3 wigle_report.py CAPTURE.csv[.gz] [--oui oui.json] [--out report.html]
"""
import sys, os, json, html, argparse, datetime as dt
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wigle_common as W
import wigle_analyze as A
import wigle_track as T
import wigle_map as M

CSS = """
:root{--bg:#0c0e10;--panel:#15181b;--line:#262b30;--fg:#d7dde3;--mut:#8b97a3;
--red:#ff3b3b;--amber:#ffb02d;--green:#39d353;--blue:#4da6ff;--violet:#b06dff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 'IBM Plex Mono',ui-monospace,Menlo,Consolas,monospace}
h1,h2{font-family:Archivo,system-ui,sans-serif;font-weight:700;letter-spacing:.3px}
h1{font-size:22px;margin:0 0 2px}h2{font-size:15px;margin:26px 0 10px;color:var(--mut);
text-transform:uppercase;letter-spacing:1.5px;border-bottom:1px solid var(--line);padding-bottom:6px}
.wrap{max-width:1100px;margin:0 auto;padding:22px 18px 60px}
.sub{color:var(--mut);font-size:12px;margin-bottom:18px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.card .n{font-size:24px;font-family:Archivo,sans-serif;font-weight:700}
.card .l{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:1px}
.r{color:var(--red)}.a{color:var(--amber)}.g{color:var(--green)}.b{color:var(--blue)}.v{color:var(--violet)}
table{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:6px}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);white-space:nowrap;
overflow:hidden;text-overflow:ellipsis;max-width:280px}
th{color:var(--mut);font-weight:600;text-transform:uppercase;font-size:10.5px;letter-spacing:1px}
tr:hover td{background:#1b1f23}
.pill{display:inline-block;padding:1px 7px;border-radius:10px;font-size:11px;border:1px solid var(--line)}
#map{height:460px;border:1px solid var(--line);border-radius:8px;margin-top:8px;background:#111}
.legend{background:#1b1b1bdd;color:#ddd;padding:7px 9px;font:11px monospace;border-radius:6px}
.legend i{display:inline-block;width:9px;height:9px;margin-right:5px;border-radius:50%}
.foot{color:var(--mut);font-size:11px;margin-top:30px;border-top:1px solid var(--line);padding-top:12px}
.kv{color:var(--mut)}.warn{color:var(--amber)}
"""

LEAFLET_JS = """
var pts=__PTS__;
if(document.getElementById('map')){
var map=L.map('map');
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}.png',
 {attribution:'&copy; OpenStreetMap, &copy; CARTO',maxZoom:20}).addTo(map);
var g=L.featureGroup();
pts.forEach(function(p){L.circleMarker([p.lat,p.lon],{radius:5,color:p.color,
 fillColor:p.color,fillOpacity:.8,weight:1}).bindPopup('<b>'+(p.ssid||p.vendor||p.mac)+
 '</b><br>'+p.type+' / '+p.cat+'<br>'+p.mac+'<br>'+(p.vendor||'')+'<br>rssi '+p.rssi+
 ' | '+p.fixes+' fixes ±'+p.spread_km+'km').addTo(g);});
g.addTo(map);
if(pts.length)map.fitBounds(g.getBounds().pad(.08));else map.setView([0,0],2);
var lg=L.control({position:'bottomright'});lg.onAdd=function(){var d=L.DomUtil.create('div','legend');
d.innerHTML='<i style="background:#ff3b3b"></i>WEP<br><i style="background:#ff5e2d"></i>OPEN'+
'<br><i style="background:#ffb02d"></i>WPS<br><i style="background:#ffd84d"></i>randomized'+
'<br><i style="background:#39d353"></i>WPA2/3<br><i style="background:#4da6ff"></i>BLE/BT'+
'<br><i style="background:#b06dff"></i>LTE<br>'+pts.length+' located';return d;};lg.addTo(map);}
"""


def esc(x):
    return html.escape(str(x))


def table(headers, rows, classes=None):
    classes = classes or {}
    h = "".join(f"<th>{esc(x)}</th>" for x in headers)
    body = []
    for r in rows:
        tds = "".join(f'<td class="{classes.get(i,"")}">{esc(c)}</td>'
                      for i, c in enumerate(r))
        body.append(f"<tr>{tds}</tr>")
    return f"<table><tr>{h}</tr>{''.join(body)}</table>"


def card(n, label, cls=""):
    return f'<div class="card"><div class="n {cls}">{esc(n)}</div><div class="l">{esc(label)}</div></div>'


def build(csv_path, oui_path="oui.json"):
    oui = W.load_oui(oui_path)
    R = A.analyze(csv_path, oui_path)
    _, rows = W.read_wigle(csv_path)
    trips, flagged = T.co_travel(rows, oui, 20, 3, 0.5)
    located = T.locate(rows, oui, ("WIFI",), 4)
    pts = M.best_points(rows, oui, ("WIFI", "BLE", "BT", "LTE"), -95)
    pts.sort(key=lambda p: p["cat"])

    sensor = R["opsec_sensor"]
    ts = R.get("timespan", {})
    geo = R.get("opsec_geo", {})
    sec = R["security"]

    parts = ['<!doctype html><html><head><meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width,initial-scale=1">',
             '<title>WiGLE SIGINT report</title>',
             '<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>',
             '<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>',
             '<link rel="preconnect" href="https://fonts.googleapis.com">',
             '<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@600;700&family=IBM+Plex+Mono:wght@400;600&display=swap" rel="stylesheet">',
             f'<style>{CSS}</style></head><body><div class="wrap">']

    parts.append(f"<h1>WiGLE SIGINT — {esc(os.path.basename(csv_path))}</h1>")
    parts.append(f'<div class="sub">sensor: {esc(sensor.get("brand"))} {esc(sensor.get("model"))} '
                 f'build {esc(sensor.get("display","?"))} &nbsp;·&nbsp; '
                 f'window {esc(ts.get("first","?"))} → {esc(ts.get("last","?"))} '
                 f'({esc(ts.get("active_days","?"))} active days) &nbsp;·&nbsp; '
                 f'generated {dt.datetime.now():%Y-%m-%d %H:%M} · all analysis local</div>')

    # headline cards
    parts.append('<div class="cards">')
    parts.append(card(R["totals"]["obs"], "observations"))
    parts.append(card(R["totals"]["unique_macs"], "unique emitters"))
    parts.append(card(R["wifi_unique"], "wifi APs"))
    parts.append(card(f'{R["laa_pct"]}%', "randomized"))
    parts.append(card(sec.get("WEP", 0), "WEP nets", "r" if sec.get("WEP") else ""))
    parts.append(card(sec.get("OPEN", 0), "open nets", "a" if sec.get("OPEN") else ""))
    parts.append(card(R["wps_default_isp"], "WPS default-ISP", "a"))
    parts.append(card(len(R["seos_readers"]), "Seos readers", "v" if R["seos_readers"] else ""))
    parts.append(card(len(flagged), "co-travel flags", "a" if flagged else ""))
    parts.append(card(R["ble"]["unique"], "BLE devices", "b"))
    parts.append('</div>')

    # map
    parts.append('<h2>Located emitters</h2>')
    parts.append(f'<div class="sub">{len(pts)} emitters placed by RSSI-weighted trilateration '
                 f'(strongest-signal fallback). Colour = severity.</div><div id="map"></div>')

    # security + bands
    parts.append('<h2>Security posture</h2>')
    parts.append(table(["mode", "count"], sorted(sec.items(), key=lambda x: -x[1])))
    if R.get("wps_weak_vendors"):
        parts.append('<div class="sub warn">WPS on historically-weak vendors (verify per model):</div>')
        parts.append(table(["vendor", "WPS APs"], R["wps_weak_vendors"]))

    # co-travel
    parts.append('<h2>Co-travel / tail candidates</h2>')
    parts.append('<div class="sub">Emitters seen across ≥3 separate trips at ≥2 places &gt;0.5km apart — '
                 'your own kit will appear here too; identify and exclude it first.</div>')
    parts.append(table(
        ["MAC", "type", "trips", "places", "max km", "name", "signature"],
        [[d["mac"], d["type"], d["trips"], d["places"], d["max_sep_km"],
          (d["ssid"] or d["vendor"] or "")[:30], d["signature"]] for d in flagged[:30]]))

    # located detail
    parts.append('<h2>Tightest transmitter fixes</h2>')
    parts.append(table(
        ["lat", "lon", "±km", "rssi", "name", "MAC"],
        [[f'{d["lat"]:.5f}', f'{d["lon"]:.5f}', d["spread_km"], d["best_rssi"],
          (d["ssid"] or d["vendor"] or "(hidden)")[:26], d["mac"]] for d in located[:25]]))

    # anomalies
    parts.append('<h2>Anomalies</h2>')
    if R["wep"]:
        parts.append('<div class="sub r">WEP networks (broken encryption):</div>')
        parts.append(table(["MAC", "SSID", "ch"], [[w["mac"], w["ssid"], w["ch"]] for w in R["wep"]]))
    if R["persistent_laa"]:
        parts.append('<div class="sub a">Persistent stable-LAA emitters (fixed device, not rotating):</div>')
        parts.append(table(["MAC", "sightings", "days"],
                           [[p["mac"], p["sightings"], p["days"]] for p in R["persistent_laa"]]))
    if R["evil_twin_candidates"]:
        parts.append('<div class="sub a">Evil-twin candidates (one SSID, multiple universal vendors):</div>')
        parts.append(table(["SSID", "vendors"],
                           [[s, ", ".join(v)] for s, v in R["evil_twin_candidates"]]))
    if R["joke_ssids"]:
        parts.append(f'<div class="sub">curio SSIDs: {esc(", ".join(R["joke_ssids"]))}</div>')

    # BLE / BT
    parts.append('<h2>BLE / BT</h2>')
    b = R["ble"]
    parts.append(f'<div class="sub">BLE {b["unique"]} devices · addr-types {esc(b["addr_types"])} · '
                 f'{b["named_count"]} named · MfgrIds {esc(R.get("mfgr_ids"))}</div>')
    parts.append(table(["device type", "count"], b["device_types"]))
    if b["named_sample"]:
        parts.append(f'<div class="sub">named sample: {esc(", ".join(b["named_sample"][:30]))}</div>')

    # OPSEC
    parts.append('<h2>OPSEC (collector exposure)</h2>')
    if geo:
        parts.append(f'<div class="sub warn">Home-base centroid {esc(geo["base_cell"])} holds '
                     f'{geo["pct_near_base"]}% of fixes within ~150m · survey span {geo["span_km"]}km · '
                     f'bbox {esc(geo["bbox"])}. Strip header + clip GPS near base before sharing.</div>')

    parts.append('<div class="foot">Generated locally by wigle_report.py — no network accessed during '
                 'analysis. Passive 802.11 collection sits in an AU legal grey zone; treat this as '
                 'security research on your own captures.</div></div>')

    parts.append('<script>')
    slim = [{k: p[k] for k in ("lat", "lon", "mac", "ssid", "type", "vendor",
                               "cat", "color", "rssi", "fixes", "spread_km")} for p in pts]
    parts.append(LEAFLET_JS.replace("__PTS__", json.dumps(slim)))
    parts.append('</script></body></html>')
    return "\n".join(parts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--oui", default="oui.json")
    ap.add_argument("--out", default="report.html")
    a = ap.parse_args()
    htmldoc = build(a.csv, a.oui)
    open(a.out, "w", encoding="utf-8").write(htmldoc)
    print(f"[+] wrote {a.out} ({len(htmldoc)//1024} KB)")


if __name__ == "__main__":
    main()
