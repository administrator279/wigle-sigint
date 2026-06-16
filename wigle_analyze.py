#!/usr/bin/env python3
"""
wigle_analyze.py - One-shot signal-intelligence pass over a WiGLE CSV export.

Runs the full workflow in one go:
  - parse + dedupe by MAC, classify Type (WIFI/BLE/BT/LTE)
  - MAC bit analysis (I/G, U/L) and LAA-vendor recovery (XOR 0x02 -> OUI)
  - security posture (WEP / open / WPS / WPA2 / WPA3-SAE / PMF)
  - WPS Pixie-Dust enrichment: default-ISP exposure + historically-weak vendors
  - ISP fingerprint (default SSIDs) + LTE carrier (PLMN)
  - BLE/BT pass: device-type tally, address-type mix, named devices
  - channel congestion per band
  - anomaly hunt: persistent stable-LAA emitters, HID Seos readers,
    mesh estates, evil-twin candidates (vendor-normalised), joke SSIDs
  - RCOIs (Passpoint roaming) + MfgrId surfacing when present
  - OPSEC: header sensor leak + home-base density centroid

Usage:
  python3 wigle_analyze.py CAPTURE.csv[.gz] [--oui oui.json] [--json report.json]

oui.json = JSON dump of the npm `oui-data` package:
  npm i oui-data && node -e "require('fs').writeFileSync('oui.json',JSON.stringify(require('oui-data')))"
Run with no oui.json and vendor naming is simply skipped.

Companion tools (same folder): wigle_cluster.py (BSSID->device), wigle_track.py
(co-travel + trilateration), wigle_map.py (GeoJSON/KML/HTML), wigle_db.py
(multi-capture SQLite + diff).
"""
import sys, os, json, argparse, collections, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wigle_common as W

CARRIER = {"50501": "Telstra", "50502": "Optus", "50503": "Vodafone/TPG",
           "50506": "TPG/iiNet", "50571": "Telstra-IoT", "50590": "Optus"}
ISP_PAT = {"Telstra": r"^Telstra", "Optus": r"^OPTUS_|^Optus_", "Belong": r"^Belong",
           "TPG": r"^TPG-", "Vodafone": r"^VODAFONE", "Dodo": r"^DODO",
           "Aussie BB": r"^Aussie", "iiNet": r"^iiNet|BigPond",
           "TP-Link": r"^TP-Link", "Netgear": r"^NETGEAR"}
# Vendors whose Wi-Fi Protected Setup has historically yielded to Pixie-Dust /
# weak PIN entropy. Heuristic only -- verify per chipset/model, but a WPS-enabled
# AP from one of these is worth a closer look.
WPS_WEAK = ("Ralink", "MediaTek", "Realtek", "Broadcom", "Arcadyan",
            "Sagemcom", "TP-Link", "D-Link", "Netgear", "Belkin", "Technicolor")


def analyze(path, oui_path="oui.json", exclude=None):
    oui = W.load_oui(oui_path)
    def vendor(mac): return W.vendor_name(oui, mac)
    header, rows = W.read_wigle(path)
    if exclude:
        ex = exclude if isinstance(exclude, set) else W.load_exclude(exclude)
        rows = [r for r in rows if r["MAC"].lower() not in ex]
    R = {"header": header}

    R["totals"] = {"obs": len(rows), "unique_macs": len({r["MAC"].lower() for r in rows})}
    R["types"] = dict(collections.Counter(r["Type"] for r in rows))

    wifi = [r for r in rows if r["Type"] == "WIFI"]
    uw = {r["MAC"].lower(): r for r in wifi}
    R["wifi_unique"] = len(uw)
    R["laa_pct"] = round(sum(1 for m in uw if W.is_laa(m)) / max(1, len(uw)) * 100, 1)
    R["bands"] = dict(collections.Counter(W.band(r["Frequency"]) for r in uw.values()))

    # ---- security ----
    sec = collections.Counter()
    for m, r in uw.items():
        a = r["AuthMode"]
        if "WEP" in a: sec["WEP"] += 1
        elif "SAE" in a and "PSK" in a: sec["WPA2/3-transition"] += 1
        elif "SAE" in a: sec["WPA3-only"] += 1
        elif "WPA2" in a or "RSN" in a: sec["WPA2"] += 1
        elif "WPA" in a: sec["WPA1"] += 1
        elif a.strip() in ("", "[ESS]") or all(x not in a for x in ("PSK", "SAE", "WEP", "OWE")):
            sec["OPEN"] += 1
        if "WPS" in a: sec["WPS_enabled"] += 1
        if "OWE" in a: sec["OWE"] += 1
    R["security"] = dict(sec)
    R["wps_default_isp"] = len({r["MAC"].lower() for r in wifi
                                if "WPS" in r["AuthMode"]
                                and re.match(r"(OPTUS_|Telstra|Belong|TPG|VODAFONE)", r["SSID"])})
    # WPS exposure broken down by historically-weak vendor
    wps_vendors = collections.Counter()
    for m, r in uw.items():
        if "WPS" in r["AuthMode"] and (v := vendor(m)):
            if any(w.lower() in v.lower() for w in WPS_WEAK):
                wps_vendors[v.split(",")[0]] += 1
    R["wps_weak_vendors"] = wps_vendors.most_common(8)

    if oui:
        R["top_vendors"] = collections.Counter(
            v for m in uw if (v := vendor(m))).most_common(12)
    ssids = set(r["SSID"] for r in uw.values() if r["SSID"].strip())
    R["isp"] = sorted(((n, sum(1 for s in ssids if re.search(p, s, re.I)))
                       for n, p in ISP_PAT.items()), key=lambda x: -x[1])

    # ---- channel congestion ----
    chan = collections.Counter()
    for r in uw.values():
        b = W.band(r["Frequency"])
        if b != "?" and r.get("Channel"):
            chan[(b, r["Channel"])] += 1
    R["channel_congestion"] = [{"band": b, "ch": c, "aps": n}
                               for (b, c), n in chan.most_common(10)]

    # ---- LTE ----
    lte = [r for r in rows if r["Type"] == "LTE"]
    plmn = collections.Counter(r["MAC"].split("_")[0] for r in lte if "_" in r["MAC"])
    R["lte"] = {"obs": len(lte), "cells": len({r["MAC"] for r in lte}),
                "carriers": [(p, CARRIER.get(p, "?"), c) for p, c in plmn.most_common()]}

    # ---- BLE / BT pass ----
    ble = [r for r in rows if r["Type"] == "BLE"]
    bt = [r for r in rows if r["Type"] == "BT"]
    uble = {r["MAC"].lower(): r for r in ble}
    ubt = {r["MAC"].lower(): r for r in bt}
    addr_mix = collections.Counter(W.ble_subtype(m) for m in uble)
    cat_mix = collections.Counter(W.device_category(r) for r in uble.values()
                                  if W.device_category(r))
    named_ble = sorted({r["SSID"].strip() for r in uble.values() if W.is_named(r)})
    R["ble"] = {"unique": len(uble), "addr_types": dict(addr_mix),
                "device_types": cat_mix.most_common(10),
                "named_sample": named_ble[:25], "named_count": len(named_ble)}
    R["bt"] = {"unique": len(ubt),
               "device_types": collections.Counter(
                   W.device_category(r) for r in ubt.values() if W.device_category(r)).most_common(8),
               "named_sample": sorted({r["SSID"].strip() for r in ubt.values() if W.is_named(r)})[:15]}

    # ---- anomaly hunt ----
    seen = collections.defaultdict(list)
    for r in rows:
        if r["Type"] == "WIFI" and W.is_laa(r["MAC"]) and r["FirstSeen"] and not r["FirstSeen"].startswith("1970"):
            seen[r["MAC"].lower()].append(r["FirstSeen"])
    persist = []
    for m, ts in seen.items():
        if len(ts) >= 8:
            days = {t[:10] for t in ts}
            if len(days) >= 3:
                persist.append({"mac": m, "sightings": len(ts), "days": len(days),
                                "span_days": (max(ts)[:10], min(ts)[:10])})
    R["persistent_laa"] = sorted(persist, key=lambda x: -x["sightings"])[:10]

    R["wep"] = [{"mac": r["MAC"], "ssid": r["SSID"], "ch": r["Channel"]}
                for m, r in uw.items() if "WEP" in r["AuthMode"]]
    _seos = set()
    for r in rows:
        if r["SSID"] == "Seos" and W.has_fix(r):
            la, lo = W.fpt(r["CurrentLatitude"]), W.fpt(r["CurrentLongitude"])
            if la is not None and lo is not None:
                _seos.add((round(la, 4), round(lo, 4)))
    R["seos_readers"] = sorted(_seos)

    bss = collections.defaultdict(set)
    for r in uw.values():
        if r["SSID"].strip(): bss[r["SSID"]].add(r["MAC"].lower())
    R["mesh"] = sorted(((s, len(m)) for s, m in bss.items() if len(m) >= 3), key=lambda x: -x[1])[:12]

    # evil-twin: same SSID under >=2 DISTINCT vendors, normalised so
    # "TP-Link Systems Inc" / "...Inc." don't count as two vendors.
    byname = collections.defaultdict(dict)   # ssid -> {vendor_key: display}
    for r in uw.values():
        if r["SSID"].strip() and oui and not W.is_laa(r["MAC"]):
            if v := vendor(r["MAC"]):
                byname[r["SSID"]][W.vendor_key(v)] = v
    R["evil_twin_candidates"] = [(s, sorted(d.values()))
                                 for s, d in byname.items() if len(d) >= 2][:10]

    R["joke_ssids"] = sorted(s for s in ssids if re.search(
        r"fbi|surveillance|wi-fry|hack|virus|pretty fly|drop it|404|honey i", s, re.I))[:15]

    # ---- Passpoint / MfgrId surfacing (often empty, surface when present) ----
    rcois = collections.Counter(r["RCOIs"] for r in wifi if r.get("RCOIs", "").strip())
    mfgr = collections.Counter(r["MfgrId"] for r in rows if r.get("MfgrId", "").strip())
    R["passpoint_rcois"] = rcois.most_common(8)
    R["mfgr_ids"] = mfgr.most_common(8)

    # ---- OPSEC ----
    R["opsec_sensor"] = W.header_kv(header)
    pts = [(W.fpt(r["CurrentLatitude"]), W.fpt(r["CurrentLongitude"]))
           for r in rows if W.has_fix(r)]
    pts = [(la, lo) for la, lo in pts if la is not None and lo is not None]
    if pts:
        dens = collections.Counter((round(la, 3), round(lo, 3)) for la, lo in pts)
        base = dens.most_common(1)[0]
        near = sum(1 for la, lo in pts if abs(la - base[0][0]) < .0015 and abs(lo - base[0][1]) < .0015)
        lats = [p[0] for p in pts]; lons = [p[1] for p in pts]
        R["opsec_geo"] = {"base_cell": base[0], "base_obs": base[1],
                          "pct_near_base": round(near / len(pts) * 100),
                          "bbox": [round(min(lats), 4), round(min(lons), 4),
                                   round(max(lats), 4), round(max(lons), 4)],
                          "span_km": round(W.haversine(min(lats), min(lons), max(lats), max(lons)), 2)}
    ts_all = sorted(r["FirstSeen"] for r in rows if r["FirstSeen"] and not r["FirstSeen"].startswith("1970"))
    if ts_all:
        R["timespan"] = {"first": ts_all[0], "last": ts_all[-1],
                         "active_days": len({t[:10] for t in ts_all})}
    return R


def fmt(R):
    o = []
    o.append(f"# WiGLE SIGINT — {R['totals']['obs']} obs, {R['totals']['unique_macs']} unique emitters")
    o.append(f"types: {R['types']}")
    if "timespan" in R:
        o.append(f"window: {R['timespan']['first']} -> {R['timespan']['last']} ({R['timespan']['active_days']} active days)")
    o.append(f"\nWiFi: {R['wifi_unique']} APs | {R['laa_pct']}% randomized(LAA) | bands {R['bands']}")
    o.append(f"security: {R['security']}")
    o.append(f"WPS on default-ISP SSIDs (Pixie-Dust risk): {R['wps_default_isp']}")
    if R.get("wps_weak_vendors"):
        o.append(f"  WPS on historically-weak vendors: {R['wps_weak_vendors'][:6]}")
    if "top_vendors" in R: o.append(f"top vendors: {R['top_vendors'][:6]}")
    o.append(f"ISP fingerprint: {[x for x in R['isp'] if x[1]][:6]}")
    if R.get("channel_congestion"):
        cc = ", ".join(f"{c['band']}ch{c['ch']}={c['aps']}" for c in R['channel_congestion'][:6])
        o.append(f"busiest channels: {cc}")
    o.append(f"LTE: {R['lte']['obs']} obs / {R['lte']['cells']} cells / carriers {R['lte']['carriers']}")

    b = R["ble"]
    o.append(f"\nBLE: {b['unique']} devices | addr {b['addr_types']} | "
             f"types {b['device_types'][:5]} | {b['named_count']} named")
    if b["named_sample"]:
        o.append(f"  named BLE: {b['named_sample'][:12]}")
    o.append(f"BT: {R['bt']['unique']} devices | types {R['bt']['device_types'][:4]} | "
             f"named {R['bt']['named_sample'][:8]}")

    o.append(f"\n[!] WEP nets: {len(R['wep'])}  Seos badge readers: {len(R['seos_readers'])} @ {R['seos_readers']}")
    if R["persistent_laa"]:
        o.append("[!] persistent stable-LAA emitters (fixed device, not rotating):")
        for p in R["persistent_laa"][:5]:
            o.append(f"    {p['mac']}  {p['sightings']} sightings / {p['days']} days")
    o.append(f"mesh estates(>=3 BSSID): {R['mesh'][:6]}")
    if R["evil_twin_candidates"]: o.append(f"evil-twin candidates: {R['evil_twin_candidates'][:5]}")
    o.append(f"joke SSIDs: {R['joke_ssids'][:8]}")
    if R.get("passpoint_rcois"): o.append(f"Passpoint RCOIs: {R['passpoint_rcois']}")
    if R.get("mfgr_ids"): o.append(f"MfgrIds: {R['mfgr_ids']}")

    o.append(f"\n[OPSEC] sensor: {R['opsec_sensor'].get('brand')} {R['opsec_sensor'].get('model')} "
             f"build {R['opsec_sensor'].get('display', '?')}")
    if "opsec_geo" in R:
        g = R["opsec_geo"]
        o.append(f"[OPSEC] base cell {g['base_cell']} = {g['pct_near_base']}% of obs within ~150m "
                 f"| survey span {g['span_km']}km")
    return "\n".join(o)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv"); ap.add_argument("--oui", default="oui.json"); ap.add_argument("--json")
    ap.add_argument("--exclude", help="MAC exclusion list (default: auto-find exclude.txt)")
    ap.add_argument("--no-exclude", action="store_true", help="don't auto-load exclude.txt")
    a = ap.parse_args()
    ex, _ex_src = W.resolve_exclude(a.exclude, a.no_exclude)
    R = analyze(a.csv, a.oui, ex)
    print(fmt(R))
    if a.json:
        json.dump(R, open(a.json, "w"), indent=2, default=str); print(f"\n[+] wrote {a.json}")


if __name__ == "__main__":
    main()
