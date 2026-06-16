#!/usr/bin/env python3
"""
wigle_map.py - Turn a WiGLE capture into map layers you can open anywhere.

Emits three artefacts from one run (all pure-stdlib, no plotting deps):

  PREFIX.geojson  - one Point per unique emitter at its RSSI-weighted estimated
                    location, with vendor/security/type properties. Opens in
                    QGIS, geojson.io, Leaflet, Mapbox, Felt, kepler.gl...
  PREFIX.kml      - same points styled by severity for Google Earth (desktop or
                    the phone app) -- the easiest "show me on a map" on mobile.
  PREFIX.html     - a self-contained Leaflet page (map tiles + marker JS from
                    CDN) that double-clicks open in any browser. Colour = risk:
                    red WEP/OPEN, amber WPS/randomized, green WPA2/3, blue
                    BLE/BT, purple LTE.

Location per emitter is the trilateration estimate from wigle_common when there
are multiple fixes, else the single strongest-RSSI sighting.

Usage:
  python3 wigle_map.py CAPTURE.csv[.gz] [--oui oui.json] [--out PREFIX]
        [--types WIFI,BLE,BT,LTE] [--min-rssi -95]
"""
import sys, os, re, json, html, argparse, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wigle_common as W


def severity(row):
    """(category, hexcolour) used for styling. Lower = noisier/safer."""
    t = row.get("Type")
    a = row.get("AuthMode", "") or ""
    if t == "WIFI":
        if "WEP" in a:
            return "WEP", "#ff2d2d"
        if a.strip() in ("", "[ESS]") or all(x not in a for x in ("PSK", "SAE", "OWE", "WEP")):
            return "OPEN", "#ff5e2d"
        if "WPS" in a:
            return "WPS", "#ffb02d"
        if W.is_laa(row["MAC"]):
            return "randomized", "#ffd84d"
        return "WPA2/3", "#39d353"
    if t == "BLE":
        return "BLE", "#4da6ff"
    if t == "BT":
        return "BT", "#2d7dff"
    if t == "LTE":
        return "LTE", "#b06dff"
    return t or "?", "#aaaaaa"


def best_points(rows, oui, types, min_rssi):
    """One located record per MAC, using trilateration when >1 fix exists."""
    sight = collections.defaultdict(list)
    label = {}
    for r in rows:
        if r.get("Type") not in types or not W.has_fix(r):
            continue
        pr = W.parse_rssi(r.get("RSSI"))
        rv = pr if pr is not None else -999
        if rv < min_rssi:
            continue
        la, lo = W.fpt(r["CurrentLatitude"]), W.fpt(r["CurrentLongitude"])
        if la is None or lo is None:
            continue
        m = r["MAC"].lower()
        sight[m].append((la, lo, rv))
        if m not in label or W.is_named(r):
            label[m] = r
    out = []
    for m, pts in sight.items():
        est = W.estimate_location(pts)
        if not est:
            continue
        r = label[m]
        cat, col = severity(r)
        out.append({
            "mac": m, "lat": est["lat"], "lon": est["lon"],
            "ssid": (r.get("SSID") or "").strip(),
            "type": r.get("Type"), "vendor": W.vendor_name(oui, m) or "",
            "auth": (r.get("AuthMode") or "").strip(),
            "cat": cat, "color": col, "rssi": est["best_rssi"],
            "fixes": est["n"], "spread_km": est["spread_km"],
        })
    return out


def write_geojson(pts, path):
    fc = {"type": "FeatureCollection", "features": [
        {"type": "Feature",
         "geometry": {"type": "Point", "coordinates": [p["lon"], p["lat"]]},
         "properties": {k: p[k] for k in
                        ("mac", "ssid", "type", "vendor", "auth", "cat",
                         "rssi", "fixes", "spread_km", "color")}}
        for p in pts]}
    json.dump(fc, open(path, "w", encoding="utf-8"), indent=0)


_XML_BAD = re.compile(r"[^\x09\x0A\x0D\x20-퟿-�]")

def _xml_clean(s):
    """Drop characters illegal in XML 1.0 (some BLE names contain NULs etc.)."""
    return _XML_BAD.sub("", s)


def write_kml(pts, path):
    styles = {}
    for p in pts:
        styles[p["cat"]] = p["color"]
    s = ['<?xml version="1.0" encoding="UTF-8"?>',
         '<kml xmlns="http://www.opengis.net/kml/2.2"><Document>',
         '<name>WiGLE SIGINT</name>']
    for cat, col in styles.items():
        # KML colour is aabbggrr; our hex is #rrggbb
        rr, gg, bb = col[1:3], col[3:5], col[5:7]
        s.append(f'<Style id="{cat}"><IconStyle><color>ff{bb}{gg}{rr}</color>'
                 f'<scale>0.8</scale></IconStyle></Style>')
    for p in pts:
        nm = html.escape(_xml_clean(p["ssid"] or p["vendor"] or p["mac"]))
        desc = html.escape(_xml_clean(f"{p['type']} | {p['cat']} | {p['mac']} | "
                           f"{p['vendor']} | rssi {p['rssi']} | "
                           f"{p['fixes']} fixes +/-{p['spread_km']}km | {p['auth']}"))
        s.append(f'<Placemark><name>{nm}</name><description>{desc}</description>'
                 f'<styleUrl>#{p["cat"]}</styleUrl>'
                 f'<Point><coordinates>{p["lon"]},{p["lat"]}</coordinates></Point></Placemark>')
    s.append('</Document></kml>')
    open(path, "w", encoding="utf-8").write("\n".join(s))


HTML_TMPL = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WiGLE SIGINT map</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>html,body,#m{height:100%;margin:0}#m{background:#111}
.legend{background:#1b1b1bdd;color:#ddd;padding:8px 10px;font:12px monospace;border-radius:6px}
.legend i{display:inline-block;width:10px;height:10px;margin-right:6px;border-radius:50%}</style>
</head><body><div id="m"></div><script>
var pts=__PTS__;
var map=L.map('m');
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}.png',
 {attribution:'&copy; OpenStreetMap, &copy; CARTO',maxZoom:20}).addTo(map);
var g=L.featureGroup();
pts.forEach(function(p){
 L.circleMarker([p.lat,p.lon],{radius:5,color:p.color,fillColor:p.color,
  fillOpacity:0.8,weight:1}).bindPopup(
  '<b>'+(p.ssid||p.vendor||p.mac)+'</b><br>'+p.type+' / '+p.cat+
  '<br>'+p.mac+'<br>'+(p.vendor||'')+'<br>rssi '+p.rssi+
  ' | '+p.fixes+' fixes +/-'+p.spread_km+'km<br><code>'+p.auth+'</code>').addTo(g);
});
g.addTo(map);
if(pts.length) map.fitBounds(g.getBounds().pad(0.1)); else map.setView([0,0],2);
var lg=L.control({position:'bottomright'});
lg.onAdd=function(){var d=L.DomUtil.create('div','legend');
 d.innerHTML='<i style="background:#ff2d2d"></i>WEP<br><i style="background:#ff5e2d"></i>OPEN'+
 '<br><i style="background:#ffb02d"></i>WPS<br><i style="background:#ffd84d"></i>randomized'+
 '<br><i style="background:#39d353"></i>WPA2/3<br><i style="background:#4da6ff"></i>BLE/BT'+
 '<br><i style="background:#b06dff"></i>LTE<br>'+pts.length+' emitters';return d;};
lg.addTo(map);
</script></body></html>"""


def write_html(pts, path):
    slim = [{k: p[k] for k in ("lat", "lon", "mac", "ssid", "type", "vendor",
                               "auth", "cat", "color", "rssi", "fixes", "spread_km")}
            for p in pts]
    open(path, "w", encoding="utf-8").write(HTML_TMPL.replace("__PTS__", json.dumps(slim)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--oui", default="oui.json")
    ap.add_argument("--out", default="wigle_map")
    ap.add_argument("--types", default="WIFI,BLE,BT,LTE")
    ap.add_argument("--min-rssi", type=int, default=-95)
    ap.add_argument("--exclude", help="MAC exclusion list (e.g. home_exclude.txt) to drop")
    a = ap.parse_args()

    oui = W.load_oui(a.oui)
    _, rows = W.read_wigle(a.csv)
    if a.exclude:
        ex = W.load_exclude(a.exclude)
        rows = [r for r in rows if r["MAC"].lower() not in ex]
    types = tuple(t.strip().upper() for t in a.types.split(","))
    pts = best_points(rows, oui, types, a.min_rssi)
    pts.sort(key=lambda p: p["cat"])

    gj, kml, htmlp = a.out + ".geojson", a.out + ".kml", a.out + ".html"
    write_geojson(pts, gj)
    write_kml(pts, kml)
    write_html(pts, htmlp)
    by = collections.Counter(p["cat"] for p in pts)
    print(f"# wigle_map - {len(pts)} located emitters  {dict(by)}")
    print(f"[+] {gj}\n[+] {kml}\n[+] {htmlp}")


if __name__ == "__main__":
    main()
