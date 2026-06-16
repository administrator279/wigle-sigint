#!/usr/bin/env python3
"""
wigle_targets.py - Turn a passive capture into a scoped pentest target list.

Tags each Wi-Fi AP with concrete attack vectors and an ease rating, emits a
machine-readable targets.csv (sortable, importable), and a physical-recon layer
(HID Seos door readers, legacy WEP AV/camera bridges). Honours --exclude so your
own/home gear never lands on an engagement target list.

Vectors:
  WEP-crack        WEP -> passive IV capture, broken since 2001            (easy)
  WPS-pixie        WPS + default-ISP SSID -> Pixie-Dust / known PIN algo   (easy)
  WPS-pin          WPS enabled (any) -> online PIN brute (Reaver)          (medium)
  open-MITM        no encryption -> captive-portal / client-side MITM      (easy)
  deauth-handshake WPA2-PSK, PMF not required -> deauth + 4-way capture    (medium)
  sae-downgrade    WPA2/WPA3 transition -> downgrade to PSK path           (medium)
  default-PSK?     default-ISP SSID pattern -> vendor default-key algo      (recon)

This is reconnaissance output for AUTHORISED testing of networks you own or are
scoped to assess. Observing beacons is passive; attacking a network you are not
authorised to test is not. The ease/vector tags are analyst judgement on
metadata, not proof of exploitability.

Usage:
  python3 wigle_targets.py CAPTURE.csv[.gz] [--oui oui.json] [--exclude exclude.txt]
      [--out targets.csv]
"""
import sys, os, csv, re, argparse, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wigle_common as W

DEFAULT_ISP = re.compile(r"^(OPTUS_|Telstra|Belong|TPG-|VODAFONE|DODO|Aussie|iiNet|BigPond|EXETEL)", re.I)
EASE_RANK = {"easy": 0, "medium": 1, "hard": 2, "recon": 3}


def vectors(auth, ssid):
    """Return (list_of_vectors, ease) for an AP's AuthMode + SSID."""
    a = auth or ""
    vs = []
    ease = "recon"
    pmf_req = "MFPR" in a            # management-frame protection REQUIRED
    is_default = bool(DEFAULT_ISP.match(ssid or ""))

    if "WEP" in a:
        vs.append("WEP-crack"); ease = "easy"
    open_net = a.strip() in ("", "[ESS]") or all(x not in a for x in ("PSK", "SAE", "WEP", "OWE"))
    if open_net and "WEP" not in a:
        vs.append("open-MITM"); ease = "easy"
    if "WPS" in a:
        if is_default:
            vs.append("WPS-pixie"); ease = "easy"
        else:
            vs.append("WPS-pin")
            if ease not in ("easy",):
                ease = "medium"
    if ("WPA2" in a or "RSN" in a) and "SAE" not in a and not open_net and "WEP" not in a:
        if not pmf_req:
            vs.append("deauth-handshake")
            if ease == "recon":
                ease = "medium"
    if "SAE" in a and "PSK" in a:
        vs.append("sae-downgrade")
        if ease == "recon":
            ease = "medium"
    if is_default:
        vs.append("default-PSK?")
    return vs, ease


def build(rows, oui, exclude=None):
    exclude = exclude or set()
    # one best row per WiFi MAC, with a located position
    sight = collections.defaultdict(list)
    best = {}
    for r in rows:
        if r.get("Type") != "WIFI":
            continue
        m = r["MAC"].lower()
        if m in exclude:
            continue
        pr = W.parse_rssi(r.get("RSSI"))
        rv = pr if pr is not None else -999
        if W.has_fix(r):
            la, lo = W.fpt(r["CurrentLatitude"]), W.fpt(r["CurrentLongitude"])
            if la is not None and lo is not None:
                sight[m].append((la, lo, rv))
        cur = best.get(m)
        if cur is None or rv > cur["_r"] or (not (cur.get("SSID") or "").strip() and (r.get("SSID") or "").strip()):
            r = dict(r); r["_r"] = rv; best[m] = r

    targets = []
    for m, r in best.items():
        vs, ease = vectors(r.get("AuthMode"), r.get("SSID"))
        if not vs:
            continue
        loc = W.estimate_location(sight[m]) if sight.get(m) else None
        targets.append({
            "bssid": m, "ssid": (r.get("SSID") or "").strip(),
            "channel": r.get("Channel", ""), "freq": r.get("Frequency", ""),
            "band": W.band(r.get("Frequency")),
            "vendor": W.vendor_name(oui, m) or "",
            "auth": (r.get("AuthMode") or ""),
            "vectors": "|".join(vs), "ease": ease,
            "best_rssi": r["_r"],
            "lat": loc["lat"] if loc else "", "lon": loc["lon"] if loc else "",
        })
    targets.sort(key=lambda t: (EASE_RANK[t["ease"]], t["band"], -t["best_rssi"]))
    return targets


def physical_recon(rows):
    """Seos badge readers + WEP AV/camera bridges with locations."""
    seos_pts = set()
    for r in rows:
        if r.get("SSID") == "Seos" and W.has_fix(r):
            la, lo = W.fpt(r["CurrentLatitude"]), W.fpt(r["CurrentLongitude"])
            if la is not None and lo is not None:
                seos_pts.add((round(la, 5), round(lo, 5)))
    seos = sorted(seos_pts)
    wep = []
    for r in rows:
        if r.get("Type") == "WIFI" and "WEP" in (r.get("AuthMode") or ""):
            wep.append({"bssid": r["MAC"].lower(), "ssid": (r.get("SSID") or "").strip(),
                        "ch": r.get("Channel", ""), "band": W.band(r.get("Frequency"))})
    # dedupe wep by bssid
    wep = list({w["bssid"]: w for w in wep}.values())
    return seos, wep


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--oui", default="oui.json")
    ap.add_argument("--exclude", help="MAC exclusion list (default: auto-find exclude.txt)")
    ap.add_argument("--no-exclude", action="store_true", help="don't auto-load exclude.txt")
    ap.add_argument("--out", default="targets.csv")
    a = ap.parse_args()

    oui = W.load_oui(a.oui)
    _, rows = W.read_wigle(a.csv)
    exclude, _ex_src = W.resolve_exclude(a.exclude, a.no_exclude)
    targets = build(rows, oui, exclude)
    seos, wep = physical_recon(rows)

    with open(a.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["bssid", "ssid", "channel", "band", "vendor", "vectors",
                    "ease", "best_rssi", "lat", "lon", "auth"])
        for t in targets:
            w.writerow([t["bssid"], t["ssid"], t["channel"], t["band"], t["vendor"],
                        t["vectors"], t["ease"], t["best_rssi"], t["lat"], t["lon"], t["auth"]])

    by_ease = collections.Counter(t["ease"] for t in targets)
    by_vec = collections.Counter(v for t in targets for v in t["vectors"].split("|"))
    print(f"# wigle_targets - {len(targets)} attackable APs "
          f"({len(exclude)} excluded)  ease={dict(by_ease)}")
    print(f"  vectors: {dict(by_vec)}")
    print(f"[+] {a.out}")
    print(f"\nphysical recon: {len(seos)} Seos reader location(s), {len(wep)} WEP net(s)")
    for la, lo in seos[:10]:
        print(f"  Seos @ {la},{lo}")
    print("\ntop easy targets:")
    for t in [t for t in targets if t["ease"] == "easy"][:12]:
        print(f"  {t['bssid']}  {t['band']:6} {t['vectors']:30} {(t['ssid'] or '(hidden)')[:26]}")


if __name__ == "__main__":
    main()
