#!/usr/bin/env python3
"""
wigle_report2.py - Data-driven RF-scope reports in two modes.

Generates the two hand-built prototype designs from REAL capture data:

  --mode recon   "RF Capture Teardown" (green/cyan): stat grid, signal-mix bars,
                 de-anonymisation, security posture, vendor/ISP fingerprint,
                 the Bluetooth zoo, curiosities, clustering method + map.

  --mode threat  "Threat & OPSEC Brief" (red/cyan): home-base tell, tail/follow
                 findings with severity, red<->blue team reads generated from the
                 target list, physical-access recon, and the OPSEC leak table.

Both honour --exclude (home-base MACs vanish) and embed a Leaflet map. All
computation is local; the page only fetches map tiles + leaflet.js to draw.

Usage:
  python3 wigle_report2.py CAPTURE.csv[.gz] [--oui oui.json] [--mode recon|threat]
      [--exclude exclude.txt] [--out report.html]
"""
import sys, os, json, html, argparse, collections, datetime as dt
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wigle_common as W
import wigle_analyze as A
import wigle_homebase as HB
import wigle_follow as F
import wigle_targets as TG
import wigle_map as M

PALETTE = {
    "recon":  {"accent": "#39ff8a", "accent2": "#3ad6ff", "tag": "SIGNAL INTELLIGENCE BRIEF",
               "glow": "rgba(57,255,138,.045)"},
    "threat": {"accent": "#ff4d5e", "accent2": "#3ad6ff", "tag": "THREAT · OPSEC · RED↔BLUE",
               "glow": "rgba(255,77,94,.05)"},
}


def esc(x):
    return html.escape(str(x))


def css(mode):
    p = PALETTE[mode]
    return f"""
:root{{--bg:#080b0e;--bg2:#0d1318;--panel:#0f1620;--line:#1c2832;
--green:{p['accent']};--cyan:{p['accent2']};--amber:#ffb02e;--red:#ff4d5e;
--txt:#c9d6df;--dim:#5c707e;--white:#eef5f9;--grid:{p['glow']}}}
*{{margin:0;padding:0;box-sizing:border-box}}html{{scroll-behavior:smooth}}
body{{background:var(--bg);color:var(--txt);font-family:'IBM Plex Mono',monospace;line-height:1.55;
background-image:linear-gradient(var(--grid) 1px,transparent 1px),linear-gradient(90deg,var(--grid) 1px,transparent 1px);
background-size:44px 44px;overflow-x:hidden}}
.wrap{{max-width:1040px;margin:0 auto;padding:0 20px 80px}}
header{{padding:50px 0 28px;border-bottom:1px solid var(--line)}}
.tag{{font-size:11px;letter-spacing:.4em;color:var(--green);text-transform:uppercase;margin-bottom:16px;display:flex;gap:10px;align-items:center}}
.blip{{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 12px var(--green);animation:pulse 1.8s infinite}}
@keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.25}}}}
h1{{font-family:'Archivo',sans-serif;font-weight:900;font-size:clamp(32px,5.5vw,58px);line-height:.96;color:var(--white);letter-spacing:-.02em}}
h1 .accent{{color:var(--green)}}
.sub{{margin-top:15px;color:var(--dim);font-size:13px;max-width:660px}}
.meta-row{{display:flex;flex-wrap:wrap;gap:22px;margin-top:24px;font-size:12px;color:var(--dim)}}
.meta-row b{{color:var(--cyan);font-weight:600}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1px;background:var(--line);border:1px solid var(--line);margin:32px 0}}
.stat{{background:var(--panel);padding:20px 18px}}
.stat .n{{font-family:'Archivo';font-weight:800;font-size:32px;color:var(--white);line-height:1}}
.stat .n.g{{color:var(--green)}}.stat .n.a{{color:var(--amber)}}.stat .n.r{{color:var(--red)}}.stat .n.c{{color:var(--cyan)}}
.stat .l{{font-size:10.5px;letter-spacing:.18em;text-transform:uppercase;color:var(--dim);margin-top:9px}}
section{{margin-top:50px}}
.shead{{display:flex;align-items:baseline;gap:14px;margin-bottom:20px;border-bottom:1px solid var(--line);padding-bottom:11px}}
.snum{{color:var(--green);font-size:13px;font-weight:700}}
.shead h2{{font-family:'Archivo';font-weight:800;font-size:21px;color:var(--white)}}
.shead .note{{margin-left:auto;font-size:11px;color:var(--dim)}}
p.lead{{font-size:14px;margin-bottom:18px;max-width:800px}}
.dim{{color:var(--dim)}}.green{{color:var(--green)}}.amber{{color:var(--amber)}}.red{{color:var(--red)}}.cyan{{color:var(--cyan)}}.w{{color:var(--white)}}
.bars{{display:flex;flex-direction:column;gap:10px}}
.bar{{display:grid;grid-template-columns:180px 1fr 56px;align-items:center;gap:14px;font-size:12.5px}}
.bar .lab{{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.bar .track{{height:14px;background:var(--bg2);border:1px solid var(--line);position:relative;overflow:hidden}}
.bar .fill{{position:absolute;left:0;top:0;bottom:0;background:linear-gradient(90deg,var(--green),#1fa862)}}
.bar .fill.a{{background:linear-gradient(90deg,var(--amber),#a86d12)}}
.bar .fill.c{{background:linear-gradient(90deg,var(--cyan),#1a7fa0)}}
.bar .fill.r{{background:var(--red);box-shadow:0 0 10px rgba(255,77,94,.4)}}
.bar .v{{text-align:right;color:var(--white);font-weight:600}}
table{{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:4px}}
th{{text-align:left;color:var(--dim);font-weight:500;font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;padding:8px 10px;border-bottom:1px solid var(--line)}}
td{{padding:8px 10px;border-bottom:1px solid rgba(28,40,50,.55)}}
tr:hover td{{background:rgba(57,255,138,.03)}}
.mono{{color:var(--cyan);font-size:11.5px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}}
.card{{background:var(--panel);border:1px solid var(--line);padding:20px;position:relative;overflow:hidden}}
.card::before{{content:'';position:absolute;left:0;top:0;width:3px;height:100%;background:var(--green)}}
.card.amber::before{{background:var(--amber)}}.card.red::before{{background:var(--red)}}.card.cyan::before{{background:var(--cyan)}}
.card h3{{font-family:'Archivo';font-weight:700;font-size:15px;color:var(--white);margin-bottom:8px}}
.card .big{{font-family:'Archivo';font-weight:900;font-size:30px;color:var(--green);line-height:1;margin-bottom:6px}}
.card.amber .big{{color:var(--amber)}}.card.red .big{{color:var(--red)}}.card.cyan .big{{color:var(--cyan)}}
.card p{{font-size:12px;color:var(--dim)}}
.card code,code{{background:var(--bg2);padding:1px 5px;color:var(--cyan);font-size:11px;border-radius:2px}}
.chips{{display:flex;flex-wrap:wrap;gap:8px}}
.chip{{background:var(--bg2);border:1px solid var(--line);padding:5px 11px;font-size:11.5px;color:var(--txt);border-radius:2px}}
.rb{{display:grid;grid-template-columns:1fr 1fr;gap:18px}}
@media(max-width:720px){{.rb{{grid-template-columns:1fr}}.bar{{grid-template-columns:120px 1fr 44px}}}}
.team{{border:1px solid var(--line);background:var(--panel);padding:22px}}
.team.red{{border-top:3px solid var(--red)}}.team.blue{{border-top:3px solid var(--cyan)}}
.team h3{{font-family:'Archivo';font-weight:800;font-size:16px;margin-bottom:14px}}
.team.red h3{{color:var(--red)}}.team.blue h3{{color:var(--cyan)}}
.team ul{{list-style:none;display:flex;flex-direction:column;gap:12px}}
.team li{{font-size:12.5px;padding-left:18px;position:relative}}
.team li::before{{content:'▸';position:absolute;left:0}}
.team.red li::before{{color:var(--red)}}.team.blue li::before{{color:var(--cyan)}}
.team li b{{color:var(--white)}}
.findings{{display:flex;flex-direction:column;gap:14px}}
.f{{border:1px solid var(--line);background:var(--panel);padding:18px 20px;display:grid;grid-template-columns:auto 1fr;gap:16px;align-items:start}}
.sev{{font-size:9.5px;font-weight:700;letter-spacing:.1em;padding:4px 9px;border-radius:2px;text-transform:uppercase;white-space:nowrap}}
.sev.hi{{background:rgba(255,77,94,.14);color:var(--red);border:1px solid rgba(255,77,94,.35)}}
.sev.med{{background:rgba(255,176,46,.14);color:var(--amber);border:1px solid rgba(255,176,46,.35)}}
.sev.info{{background:rgba(58,214,255,.12);color:var(--cyan);border:1px solid rgba(58,214,255,.3)}}
.f h4{{font-family:'Archivo';font-weight:700;font-size:14.5px;color:var(--white);margin-bottom:5px}}
.f p{{font-size:12.5px}}
.leak{{display:grid;grid-template-columns:200px 1fr;gap:8px 16px;font-size:12.5px;border:1px solid var(--amber);background:rgba(255,176,46,.04);padding:22px}}
.leak dt{{color:var(--dim)}}.leak dd{{color:var(--white)}}
#map{{height:440px;border:1px solid var(--line);margin-top:8px;background:#0b0e11}}
.legend{{background:#11161bdd;color:#ddd;padding:7px 9px;font:11px monospace;border-radius:4px}}
.legend i{{display:inline-block;width:9px;height:9px;margin-right:5px;border-radius:50%}}
footer{{margin-top:60px;padding-top:22px;border-top:1px solid var(--line);font-size:11px;color:var(--dim)}}
"""


def bar(lab, val, maxval, cls=""):
    pct = 0 if not maxval else min(100, val / maxval * 100)
    return (f'<div class="bar"><span class="lab">{esc(lab)}</span>'
            f'<span class="track"><span class="fill {cls}" style="width:{pct:.1f}%"></span></span>'
            f'<span class="v">{esc(val)}</span></div>')


def card(title, body, big=None, cls=""):
    b = f'<div class="big">{esc(big)}</div>' if big is not None else ""
    h = f'<h3>{esc(title)}</h3>' if title else ""
    return f'<div class="card {cls}">{h}{b}<p>{body}</p></div>'


def table(headers, rows):
    h = "".join(f"<th>{esc(x)}</th>" for x in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><tr>{h}</tr>{body}</table>"


def shead(num, title, note=""):
    n = f'<span class="note">{esc(note)}</span>' if note else ""
    return f'<div class="shead"><span class="snum">{num}</span><h2>{esc(title)}</h2>{n}</div>'


LEAFLET = """<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>var pts=__PTS__;if(document.getElementById('map')){var map=L.map('map');
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}.png',{attribution:'&copy; OSM, &copy; CARTO',maxZoom:20}).addTo(map);
var g=L.featureGroup();pts.forEach(function(p){L.circleMarker([p.lat,p.lon],{radius:5,color:p.color,fillColor:p.color,fillOpacity:.8,weight:1}).bindPopup('<b>'+(p.ssid||p.vendor||p.mac)+'</b><br>'+p.type+' / '+p.cat+'<br>'+p.mac).addTo(g);});
g.addTo(map);if(pts.length)map.fitBounds(g.getBounds().pad(.08));else map.setView([0,0],2);}</script>"""


def map_block(rows, oui, exclude, cap=1000):
    # Cap markers to the strongest `cap` emitters: a few thousand Leaflet
    # circle-markers freeze mobile browsers. The full set stays in wigle_map.py's
    # GeoJSON/KML for GIS use; this inline map is for at-a-glance orientation.
    pts = M.best_points(rows, oui, ("WIFI", "BLE", "BT", "LTE"), -95)
    pts = [p for p in pts if p["mac"] not in exclude]
    total = len(pts)
    pts.sort(key=lambda p: -p["rssi"])
    pts = pts[:cap]
    slim = [{k: p[k] for k in ("lat", "lon", "mac", "ssid", "type", "vendor", "cat", "color")} for p in pts]
    return total, LEAFLET.replace("__PTS__", json.dumps(slim))


# ----------------------------------------------------------------- RECON ----

def recon_sections(R, rows, oui, exclude):
    out = []
    t = R["types"]
    out.append('<section>' + shead("01", "What's on the air", "unique by MAC"))
    mx = max(R["wifi_unique"], R["ble"]["unique"], 1)
    out.append('<div class="bars">'
               + bar("WiFi APs / BSSIDs", R["wifi_unique"], mx)
               + bar("Bluetooth LE", R["ble"]["unique"], mx, "c")
               + bar("LTE cells", R["lte"]["cells"], mx, "a")
               + bar("Bluetooth Classic", R["bt"]["unique"], mx, "c") + '</div>')
    chans = ", ".join(f"<code>{c['band']} ch{c['ch']}</code>={c['aps']}" for c in R["channel_congestion"][:4])
    carriers = ", ".join(f"{n} ({c})" for p, n, c in R["lte"]["carriers"][:3])
    out.append('<div class="cards" style="margin-top:22px">'
               + card("Band split", f"{R['bands'].get('2.4GHz',0)} on 2.4 GHz · {R['bands'].get('5GHz',0)} on 5 GHz · "
                      f"{R['bands'].get('6GHz',0)} on 6 GHz.", cls="cyan")
               + card("Busiest channels", chans or "n/a")
               + card("Cellular", f"{R['lte']['cells']} cells; carriers: {carriers or 'n/a'}") + '</div></section>')

    # de-anon
    out.append('<section>' + shead("02", "De-anonymisation", "recovered from randomized BSSIDs"))
    out.append(f'<p class="lead"><span class="amber">{R["laa_pct"]}%</span> of WiFi BSSIDs carry the '
               f'locally-administered "randomized" bit — most aren\'t random. <code>XOR 0x02</code> on '
               f'octet-0 recovers the real IEEE OUI.</p>')
    tv = [[esc(v), f'<span class="mono">{n}</span>'] for v, n in R.get("top_vendors", [])[:8]]
    out.append(table(["recovered vendor", "count"], tv) + '</section>')

    # security
    s = R["security"]
    out.append('<section>' + shead("03", "Security posture", "unique WiFi APs"))
    mx = max(s.values()) if s else 1
    out.append('<div class="bars">'
               + bar("WPA2-PSK", s.get("WPA2", 0), mx)
               + bar("WPA2/WPA3 transition", s.get("WPA2/3-transition", 0), mx)
               + bar("Open (no encryption)", s.get("OPEN", 0), mx, "a")
               + bar("WEP (broken)", s.get("WEP", 0), mx, "r")
               + bar("WPA3-only (SAE)", s.get("WPA3-only", 0), mx, "c") + '</div>')
    out.append('<div class="cards" style="margin-top:22px">'
               + card("WPS exposure", f"{s.get('WPS_enabled',0)} APs with WPS on; "
                      f"<span class='w'>{R['wps_default_isp']}</span> on default-ISP SSIDs — the Pixie-Dust target set.",
                      big=R["wps_default_isp"], cls="red")
               + card("WEP networks", f"{len(R['wep'])} broken-encryption nets still on the air.",
                      big=len(R["wep"]), cls="red")
               + card("WPA3 adoption", "transition mode aside, almost everything is WPA2-PSK; "
                      "no PMF-required means deauth still lands.",
                      big=f"{round(s.get('WPA3-only',0)/max(1,R['wifi_unique'])*100,1)}%", cls="amber")
               + '</div></section>')

    # vendor & isp
    out.append('<section>' + shead("04", "Vendor & ISP fingerprint", "read off the air"))
    isp = [[esc(n), f'<span class="mono">{c}</span>'] for n, c in R["isp"] if c][:6]
    ven = [[esc(v), f'<span class="mono">{n}</span>'] for v, n in R.get("top_vendors", [])[:6]]
    out.append('<div style="display:grid;grid-template-columns:1fr 1fr;gap:26px">'
               + '<div>' + table(["ISP (default SSID)", "nets"], isp) + '</div>'
               + '<div>' + table(["hardware vendor", "APs"], ven) + '</div></div></section>')

    # BLE zoo
    b = R["ble"]
    out.append('<section>' + shead("05", "The Bluetooth zoo", f"{b['named_count']} named of {b['unique']}"))
    dt_rows = b["device_types"][:6]
    mxb = max((n for _, n in dt_rows), default=1)
    out.append('<div class="bars">' + "".join(bar(k or "(uncat)", n, mxb, "c") for k, n in dt_rows) + '</div>')
    seos, wep = TG.physical_recon(rows)
    out.append('<div class="cards" style="margin-top:22px">'
               + card("Physical-security leak", f"{len(seos)} <code>Seos</code> badge-reader location(s) "
                      "advertising over BLE — maps secured doors passively.", cls="amber")
               + card("MfgrId company IDs", esc(dict(R.get("mfgr_ids", [])[:5])), cls="cyan")
               + card("Named sample", esc(", ".join(b["named_sample"][:10])) or "—") + '</div></section>')

    # curiosities
    if R["joke_ssids"]:
        out.append('<section>' + shead("06", "Curiosities & jokers", "every drive has them"))
        out.append('<div class="chips">' + "".join(f'<span class="chip">{esc(s)}</span>' for s in R["joke_ssids"][:14]) + '</div></section>')

    # map
    nmap, mapjs = map_block(rows, oui, exclude)
    out.append('<section>' + shead("07", "Located emitters", f"{nmap} placed, severity-coloured")
               + '<div id="map"></div></section>')
    out.append(mapjs)
    return "\n".join(out)


# ---------------------------------------------------------------- THREAT ----

def threat_sections(R, rows, oui, exclude, bases, classified, follow_cands, convoys, targets, n_excl):
    out = []
    geo = R.get("opsec_geo", {})
    # movement / home base
    out.append('<section>' + shead("01", "Movement & the base tell", f"{R.get('timespan',{}).get('active_days','?')} active days"))
    if geo:
        out.append('<div class="findings"><div class="f"><span class="sev hi">High</span><div>'
                   f'<h4>Home base is trivially derivable</h4><p><span class="red">{geo["pct_near_base"]}% of observations</span> '
                   f'fall within ~150 m of <code>{esc(geo["base_cell"])}</code>. {len(bases)} base(s) detected; '
                   f'{n_excl} home/own MACs were excluded from the reads below.</p></div></div></div>')
    nmap, mapjs = map_block(rows, oui, exclude)
    out.append(f'<div id="map" style="margin-top:18px"></div></section>{mapjs}')

    # follow / tail
    out.append('<section>' + shead("02", "Following / tail candidates", "home-base excluded first"))
    out.append('<p class="lead">After removing your own kit and base-anchored radios, these still appear with '
               'you across separated places. Your own car/phone may still surface — confirm and add to '
               '<code>exclude.txt</code>.</p><div class="findings">')
    if not follow_cands:
        out.append('<div class="f"><span class="sev info">Info</span><div><h4>No external follower signal</h4>'
                   '<p>Nothing unanchored shadows you across multiple places once home-base is removed.</p></div></div>')
    for c in follow_cands[:6]:
        sev = "hi" if c["confidence"] >= 0.8 else ("med" if c["confidence"] >= 0.55 else "info")
        nm = esc(c["ssid"] or c["vendor"] or "(unnamed)")
        conv = f' · convoy #{c["convoy"]}' if c["convoy"] is not None else ""
        out.append(f'<div class="f"><span class="sev {sev}">conf {c["confidence"]}</span><div>'
                   f'<h4>{nm} <span class="dim">{esc(c["mac"])}</span></h4>'
                   f'<p>{c["type"]} · {c["trips"]} trips / {c["places"]} places · med RSSI {c["med_rssi"]} · '
                   f'{c["max_sep_km"]}km span{conv}<br><span class="dim">{esc(", ".join(c["reasons"]))}</span></p></div></div>')
    out.append('</div>')
    if convoys:
        out.append('<div class="cards" style="margin-top:16px">'
                   + "".join(card(f"Convoy #{i}", esc(", ".join(g)) + " — radios that always travel together "
                             "(one vehicle/person?).", cls="cyan") for i, g in enumerate(convoys[:3]))
                   + '</div>')
    out.append('</section>')

    # red / blue
    by_vec = collections.Counter(v for t in targets for v in t["vectors"].split("|"))
    seos, wep = TG.physical_recon(rows)
    out.append('<section>' + shead("03", "Red team ↔ Blue team", "what the data hands each side"))
    out.append('<div class="rb"><div class="team red"><h3>🔴 Offensive read</h3><ul>'
               f'<li><b>{by_vec.get("WPS-pixie",0)} WPS default-ISP APs.</b> Pixie-Dust / known-PIN against '
               f'<code>OPTUS_/Telstra…</code> gateways.</li>'
               f'<li><b>{by_vec.get("WEP-crack",0)} WEP nets</b> = passive-IV cracks.</li>'
               f'<li><b>{by_vec.get("open-MITM",0)} open nets</b> — captive-portal / client-side MITM surface.</li>'
               f'<li><b>{by_vec.get("deauth-handshake",0)} WPA2 APs without PMF-required</b> → deauth + 4-way capture.</li>'
               f'<li><b>{len(seos)} HID Seos reader location(s)</b> → physical-access recon.</li></ul></div>'
               '<div class="team blue"><h3>🔵 Defensive read</h3><ul>'
               '<li><b>Kill WPS everywhere</b> — top exposure, buys nothing on modern clients.</li>'
               '<li><b>Retire WEP / legacy bridges</b> — cleartext-equivalent.</li>'
               '<li><b>WPA3-SAE + PMF-required</b> defeats most of the offensive list.</li>'
               '<li><b>Segment IoT / casting / signage</b> off flat networks.</li>'
               '<li><b>Hidden SSIDs ≠ security</b> — they still beacon BSSIDs.</li></ul></div></div></section>')

    # physical
    out.append('<section>' + shead("04", "Physical-access recon", "doors & legacy bridges"))
    seos_rows = [[f'<span class="mono">{la},{lo}</span>', "HID Seos badge reader"] for la, lo in seos[:10]]
    wep_rows = [[f'<span class="mono">{w["bssid"]}</span>', esc(w["ssid"] or "(hidden)"), f'{w["band"]} ch{w["ch"]}'] for w in wep[:10]]
    out.append('<div style="display:grid;grid-template-columns:1fr 1fr;gap:26px">'
               + '<div>' + table(["Seos location", "what"], seos_rows) + '</div>'
               + '<div>' + table(["WEP bssid", "ssid", "band"], wep_rows) + '</div></div></section>')

    # opsec leak
    sensor = R["opsec_sensor"]
    own = [r for r in classified if r["class"] == "OWN"][:6]
    own_str = ", ".join((r["ssid"] or r["vendor"] or r["mac"]) for r in own) or "—"
    out.append('<section>' + shead("05", "Your OPSEC", "turn the lens around"))
    out.append('<dl class="leak">'
               f'<dt>Sensor hardware</dt><dd>{esc(sensor.get("brand"))} <code>{esc(sensor.get("model"))}</code> '
               f'build {esc(sensor.get("display","?"))}</dd>'
               f'<dt>Home / base</dt><dd>{esc(geo.get("base_cell","?"))} — {geo.get("pct_near_base","?")}% of fixes within ~150 m</dd>'
               f'<dt>Mobile carrier</dt><dd>{esc(", ".join(n for _,n,_ in R["lte"]["carriers"][:2]) or "—")} (from LTE PLMN)</dd>'
               f'<dt>Your own devices</dt><dd>{esc(own_str)}</dd>'
               f'<dt>Survey span</dt><dd>{geo.get("span_km","?")} km</dd></dl>')
    out.append('<p class="lead dim" style="margin-top:14px">Strip the header + <code>FirstSeen</code> before sharing; '
               'clip GPS near base; store encrypted (PII-grade). AU passive 802.11 sits in a legal grey zone.</p></section>')
    return "\n".join(out)


def build(csv_path, oui_path="oui.json", mode="recon", exclude=None):
    oui = W.load_oui(oui_path)
    if not isinstance(exclude, set):
        exclude = W.load_exclude(exclude) if exclude else set()
    R = A.analyze(csv_path, oui_path)
    _, rows = W.read_wigle(csv_path)
    p = PALETTE[mode]

    head = ['<!doctype html><html><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width,initial-scale=1">',
            f'<title>WiGLE {mode} report</title>',
            '<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>',
            '<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@600;700;800;900&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">',
            f'<style>{css(mode)}</style></head><body><div class="wrap">']

    sensor = R["opsec_sensor"]; ts = R.get("timespan", {}); geo = R.get("opsec_geo", {})
    title = ('RF Capture<br><span class="accent">Teardown.</span>' if mode == "recon"
             else 'Capture as <span class="accent">Attack Surface,</span><br>Capture as <span class="cyan">Liability.</span>')
    head.append('<header><div class="tag"><span class="blip"></span> '
                f'WiGLE // {esc(p["tag"])}</div><h1>{title}</h1>'
                f'<p class="sub">Passive radio survey, decomposed locally. {esc(os.path.basename(csv_path))}.</p>'
                '<div class="meta-row">'
                f'<span>SENSOR <b>{esc(sensor.get("brand"))} {esc(sensor.get("model"))}</b></span>'
                f'<span>WINDOW <b>{esc(ts.get("first","?"))} → {esc(ts.get("last","?"))}</b></span>'
                f'<span>CENTROID <b>{esc(geo.get("base_cell","?"))}</b></span></div></header>')

    sec = R["security"]
    head.append('<div class="stats">'
                f'<div class="stat"><div class="n">{R["totals"]["obs"]}</div><div class="l">Observations</div></div>'
                f'<div class="stat"><div class="n g">{R["totals"]["unique_macs"]}</div><div class="l">Unique emitters</div></div>'
                f'<div class="stat"><div class="n c">{R["wifi_unique"]}</div><div class="l">WiFi APs</div></div>'
                f'<div class="stat"><div class="n a">{R["laa_pct"]}%</div><div class="l">Randomized</div></div>'
                f'<div class="stat"><div class="n r">{sec.get("WEP",0)}</div><div class="l">WEP nets</div></div></div>')

    if mode == "recon":
        body = recon_sections(R, rows, oui, exclude)
    else:
        bases, trips, classified = HB.classify(rows, oui)
        drop = {"OWN", "HOME"}
        auto_excl = exclude or {r["mac"] for r in classified if r["class"] in drop}
        _, n_excl, convoys, cands = F.follow(rows, oui, auto_excl)
        targets = TG.build(rows, oui, auto_excl)
        body = threat_sections(R, rows, oui, auto_excl, bases, classified, cands, convoys, targets, len(auto_excl))

    foot = (f'<footer>Generated locally from {esc(os.path.basename(csv_path))} · '
            f'{dt.datetime.now():%Y-%m-%d %H:%M} · no network accessed during analysis · '
            'severities are analyst judgement on passively-observed metadata.</footer></div></body></html>')
    return "\n".join(head) + "\n" + body + "\n" + foot


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--oui", default="oui.json")
    ap.add_argument("--mode", choices=["recon", "threat"], default="recon")
    ap.add_argument("--exclude", help="MAC exclusion list (default: auto-find exclude.txt)")
    ap.add_argument("--no-exclude", action="store_true", help="don't auto-load exclude.txt")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    out = a.out or f"report_{a.mode}.html"
    ex, _ex_src = W.resolve_exclude(a.exclude, a.no_exclude)
    doc = build(a.csv, a.oui, a.mode, ex)
    open(out, "w", encoding="utf-8").write(doc)
    print(f"[+] wrote {out} ({len(doc)//1024} KB, mode={a.mode})")


if __name__ == "__main__":
    main()
