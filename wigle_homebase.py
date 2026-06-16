#!/usr/bin/env python3
"""
wigle_homebase.py - Classify emitters by their relationship to YOUR base(s),
and export an exclusion list so home/own/neighbour noise can be dropped from
every future report (and fed into WiGLE's address-exclusion list).

Why: counter-surveillance and pentest reads are drowned out by the radios that
are always around you - your own gateway, your phone, your immediate neighbours.
Those light up co-travel and "persistent emitter" lists every time you go home.
Strip them once and everything downstream gets sharp.

Classes (per unique MAC):
  OWN        on-body signal (very strong RSSI) seen across most of your trips
             -> your own kit (phone, laptop, watch, car)
  HOME       transmitter located within --home-radius of a detected base
  NEAR_HOME  located within --near-radius of a base (neighbours; recon noise)
  MOBILE     seen at >=2 separated places away from base -> the interesting set
  AMBIENT    everything else (passed once, not near any base)

Bases are auto-detected by GPS density (supports several: home + work + ...).

Outputs (with --out-prefix home):
  home_devices.csv   full table for REVIEW before you trust it
  home_exclude.txt   newline MAC list (OWN+HOME by default; --include-near adds them)
                     -> read by every tool via --exclude, and easy to paste into
                        WiGLE's per-MAC exclusion settings
  home_bases.json    the detected bases

Usage:
  python3 wigle_homebase.py CAPTURE.csv[.gz] [--oui oui.json]
      [--home-radius 0.075] [--near-radius 0.30] [--gap 20]
      [--own-rssi -45] [--include-near] [--out-prefix home]
"""
import sys, os, csv, json, argparse, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wigle_common as W


def classify(rows, oui, home_km=0.075, near_km=0.30, gap=20, own_rssi=-45,
             own_trip_frac=0.5):
    bases = W.detect_bases(rows)
    trips = W.build_trips(rows, gap)
    n_trips = max(1, len(trips))
    # which trips each MAC appears in (for OWN "follows you everywhere" test)
    mac_trip_count = collections.Counter()
    for t in trips:
        for m in t["macs"]:
            mac_trip_count[m] += 1

    agg = W.mac_sightings(rows)
    out = []
    for m, d in agg.items():
        loc = W.estimate_location(d["fixes"]) if d["fixes"] else None
        # nearest base distance (km) to this emitter's estimated location
        dist = None
        if loc and bases:
            dist = min(W.haversine(loc["lat"], loc["lon"], b["centroid"][0], b["centroid"][1])
                       for b in bases)
        # distinct away-from-base places this MAC was *heard* from
        places = _distinct_places([(la, lo) for la, lo, _ in d["fixes"]], 0.5)
        trip_frac = mac_trip_count[m] / n_trips

        ven = W.vendor_name(oui, m) if d["type"] == "WIFI" else None
        cls = _classify_one(d, loc, dist, places, trip_frac, home_km, near_km,
                            own_rssi, own_trip_frac)
        out.append({
            "mac": m, "type": d["type"],
            "ssid": (d["label"].get("SSID") or "").strip() or None,
            "vendor": ven, "class": cls,
            "best_rssi": d["best_rssi"],
            "dist_base_km": round(dist, 3) if dist is not None else None,
            "sightings": len(d["ts"]), "trips": mac_trip_count[m],
            "places": places, "lat": loc["lat"] if loc else None,
            "lon": loc["lon"] if loc else None,
        })
    order = {"OWN": 0, "HOME": 1, "NEAR_HOME": 2, "MOBILE": 3, "AMBIENT": 4}
    out.sort(key=lambda r: (order[r["class"]], r["dist_base_km"] if r["dist_base_km"] is not None else 9e9))
    return bases, trips, out


def _distinct_places(latlons, sep_km):
    places = []
    for la, lo in latlons:
        if la is None:
            continue
        if not any(W.haversine(la, lo, p[0], p[1]) < sep_km for p in places):
            places.append((la, lo))
    return len(places)


def _classify_one(d, loc, dist, places, trip_frac, home_km, near_km, own_rssi, own_trip_frac):
    # OWN: on-body strength AND present across most outings (or a named BLE you carry)
    if d["best_rssi"] >= own_rssi and (trip_frac >= own_trip_frac or d["type"] in ("BLE", "BT")):
        if places >= 2 or trip_frac >= own_trip_frac:
            return "OWN"
    if dist is not None:
        if dist <= home_km:
            return "HOME"
        if dist <= near_km:
            return "NEAR_HOME"
    if places >= 2:
        return "MOBILE"
    return "AMBIENT"


def write_outputs(bases, classified, prefix, include_near):
    csv_path = f"{prefix}_devices.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["mac", "class", "type", "ssid", "vendor", "best_rssi",
                    "dist_base_km", "sightings", "trips", "places", "lat", "lon"])
        for r in classified:
            w.writerow([r["mac"], r["class"], r["type"], r["ssid"] or "", r["vendor"] or "",
                        r["best_rssi"], r["dist_base_km"], r["sightings"], r["trips"],
                        r["places"], r["lat"] if r["lat"] is not None else "",
                        r["lon"] if r["lon"] is not None else ""])

    drop_classes = {"OWN", "HOME"} | ({"NEAR_HOME"} if include_near else set())
    excl = [r for r in classified if r["class"] in drop_classes]
    txt_path = f"{prefix}_exclude.txt"
    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write("# WiGLE SIGINT home-base exclusion list\n")
        fh.write(f"# classes excluded: {', '.join(sorted(drop_classes))}\n")
        fh.write("# one MAC per line; paste into WiGLE address-exclusion, or pass --exclude to the tools\n")
        for r in excl:
            tag = r["ssid"] or r["vendor"] or r["type"]
            fh.write(f"{r['mac']}  # {r['class']} {tag}\n")

    json_path = f"{prefix}_bases.json"
    json.dump({"bases": bases}, open(json_path, "w"), indent=2)
    return csv_path, txt_path, json_path, len(excl)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--oui", default="oui.json")
    ap.add_argument("--home-radius", type=float, default=0.075, help="km: <= this from a base = HOME")
    ap.add_argument("--near-radius", type=float, default=0.30, help="km: <= this from a base = NEAR_HOME")
    ap.add_argument("--gap", type=int, default=20)
    ap.add_argument("--own-rssi", type=int, default=-45, help="dBm: >= this + multi-trip = OWN/on-body")
    ap.add_argument("--include-near", action="store_true", help="also exclude NEAR_HOME (neighbours)")
    ap.add_argument("--out-prefix", default="home")
    a = ap.parse_args()

    oui = W.load_oui(a.oui)
    _, rows = W.read_wigle(a.csv)
    bases, trips, classified = classify(rows, oui, a.home_radius, a.near_radius, a.gap, a.own_rssi)

    counts = collections.Counter(r["class"] for r in classified)
    print(f"# wigle_homebase - {len(classified)} emitters, {len(trips)} trips, {len(bases)} base(s)")
    for b in bases:
        print(f"  base @ {b['centroid']}  {b['obs']} obs ({int(b['frac']*100)}% of fixes)")
    print(f"  classes: {dict(counts)}")

    csv_p, txt_p, json_p, n_excl = write_outputs(bases, classified, a.out_prefix, a.include_near)
    print(f"\n[+] {csv_p}   (review this)")
    print(f"[+] {txt_p}   ({n_excl} MACs -> use with --exclude, or paste into WiGLE)")
    print(f"[+] {json_p}")
    print("\ntop OWN / HOME candidates:")
    for r in [r for r in classified if r["class"] in ("OWN", "HOME")][:12]:
        nm = r["ssid"] or r["vendor"] or "(unnamed)"
        print(f"  {r['mac']}  {r['class']:9} {r['type']:4} rssi{r['best_rssi']:>4} "
              f"{r['dist_base_km']}km  {nm[:30]}")


if __name__ == "__main__":
    main()
