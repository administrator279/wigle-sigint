#!/usr/bin/env python3
"""
wigle_track.py - Temporal counter-surveillance over a WiGLE capture.

Two questions the one-shot analyser can't answer because it ignores time:

  1. CO-TRAVEL / TAIL DETECTION
     Which emitters appear with YOU across multiple separate trips at different
     places? A device seen once is background. A device seen on three different
     outings, at locations kilometres apart, is moving *with* the collector --
     it is either your own kit or something following you. We split the capture
     into trips by time gaps, then flag MACs present in >=N trips spanning >=2
     well-separated locations, ranked by how many distinct places they shadow.

  2. TRANSMITTER LOCATION (trilateration)
     Each MAC is heard from many GPS points at many signal strengths. An
     RSSI-weighted estimate turns those into an approximate fixed location for
     the transmitter itself -- so WEP nets, Seos readers and stable emitters
     become physically locatable rather than just "heard near here".

Stable-LAA emitters and persistent *unnamed* BLE devices get special attention:
an address that never rotates yet follows you is the classic tracker signature
(note: WiGLE exports no advertising payload, so this is behavioural inference,
not an AirTag protocol decode -- it flags candidates, it doesn't name them).

Usage:
  python3 wigle_track.py CAPTURE.csv[.gz] [--oui oui.json] [--gap 20]
        [--min-trips 3] [--min-sep-km 0.5] [--json out.json]
"""
import sys, os, argparse, collections, datetime as dt
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wigle_common as W


def parse_ts(s):
    if not s or s.startswith("1970"):
        return None
    try:
        return dt.datetime.strptime(s.strip(), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def build_trips(rows, gap_min=20):
    """
    Order every fixed observation by time and cut a new trip whenever the gap to
    the previous observation exceeds gap_min minutes. Returns a list of trips,
    each a dict with time bounds, centroid and the row indices it contains.
    """
    timed = []
    for r in rows:
        ts = parse_ts(r.get("FirstSeen"))
        if ts and W.has_fix(r):
            timed.append((ts, r))
    timed.sort(key=lambda x: x[0])
    trips, cur = [], []
    last = None
    gap = dt.timedelta(minutes=gap_min)
    for ts, r in timed:
        if last is not None and ts - last > gap:
            trips.append(cur); cur = []
        cur.append((ts, r)); last = ts
    if cur:
        trips.append(cur)

    out = []
    for t in trips:
        lats = [W.fpt(r["CurrentLatitude"]) for _, r in t]
        lons = [W.fpt(r["CurrentLongitude"]) for _, r in t]
        out.append({
            "start": t[0][0], "end": t[-1][0],
            "centroid": (sum(lats) / len(lats), sum(lons) / len(lons)),
            "n_obs": len(t),
            "macs": {r["MAC"].lower() for _, r in t},
        })
    return out


def distinct_locations(centroids, min_sep_km):
    """Greedy-cluster trip centroids into well-separated places."""
    places = []
    for c in centroids:
        if not any(W.haversine(c[0], c[1], p[0], p[1]) < min_sep_km for p in places):
            places.append(c)
    return places


def co_travel(rows, oui, gap_min, min_trips, min_sep_km):
    trips = build_trips(rows, gap_min)
    # map each MAC -> indices of trips it appeared in
    mac_trips = collections.defaultdict(list)
    for i, tr in enumerate(trips):
        for m in tr["macs"]:
            mac_trips[m].append(i)

    # quick row lookup for labelling (last seen wins for SSID/type)
    info = {}
    for r in rows:
        m = r["MAC"].lower()
        if m not in info or W.is_named(r):
            info[m] = r

    flagged = []
    for m, idxs in mac_trips.items():
        uniq = sorted(set(idxs))
        if len(uniq) < min_trips:
            continue
        cents = [trips[i]["centroid"] for i in uniq]
        places = distinct_locations(cents, min_sep_km)
        if len(places) < 2:
            continue
        r = info[m]
        typ = r.get("Type", "?")
        named = W.is_named(r)
        ssid = (r.get("SSID") or "").strip()
        ven = W.vendor_name(oui, m) if typ == "WIFI" else None
        sep = max(W.haversine(a[0], a[1], b[0], b[1])
                  for a in places for b in places)
        # tracker-likeness: address that never rotates yet shadows you
        if typ == "WIFI" and W.is_laa(m):
            sig = "stable-LAA Wi-Fi (fixed device shadowing route)"
        elif typ == "BLE" and not named:
            sig = "persistent unnamed BLE (possible tracker)"
        elif typ == "BLE":
            sig = "named BLE device travelling with you"
        else:
            sig = f"{typ} emitter across trips"
        flagged.append({
            "mac": m, "type": typ, "ssid": ssid or None,
            "vendor": ven, "trips": len(uniq), "places": len(places),
            "max_sep_km": round(sep, 2), "signature": sig,
        })
    flagged.sort(key=lambda x: (-x["places"], -x["trips"], -x["max_sep_km"]))
    return trips, flagged


def locate(rows, oui, want_types=("WIFI",), min_pts=3):
    """RSSI-weighted transmitter estimate per MAC with >= min_pts fixes."""
    sight = collections.defaultdict(list)
    label = {}
    for r in rows:
        if r.get("Type") not in want_types or not W.has_fix(r):
            continue
        rv = W.parse_rssi(r.get("RSSI"))
        if rv is None:
            continue
        la, lo = W.fpt(r["CurrentLatitude"]), W.fpt(r["CurrentLongitude"])
        if la is None or lo is None:
            continue
        m = r["MAC"].lower()
        sight[m].append((la, lo, rv))
        if m not in label or W.is_named(r):
            label[m] = r
    located = []
    for m, pts in sight.items():
        if len(pts) < min_pts:
            continue
        est = W.estimate_location(pts)
        if not est:
            continue
        r = label[m]
        located.append({
            "mac": m, "ssid": (r.get("SSID") or "").strip() or None,
            "type": r.get("Type"), "vendor": W.vendor_name(oui, m),
            "auth": (r.get("AuthMode") or "")[:40],
            **est,
        })
    located.sort(key=lambda d: (d["spread_km"], -d["best_rssi"]))
    return located


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--oui", default="oui.json")
    ap.add_argument("--gap", type=int, default=20, help="minutes gap that starts a new trip")
    ap.add_argument("--min-trips", type=int, default=3)
    ap.add_argument("--min-sep-km", type=float, default=0.5)
    ap.add_argument("--locate-min", type=int, default=4, help="min fixes to trilaterate a MAC")
    ap.add_argument("--exclude", help="MAC exclusion list (e.g. home_exclude.txt) to drop")
    ap.add_argument("--json")
    a = ap.parse_args()

    oui = W.load_oui(a.oui)
    _, rows = W.read_wigle(a.csv)
    if a.exclude:
        ex = W.load_exclude(a.exclude)
        rows = [r for r in rows if r["MAC"].lower() not in ex]
    trips, flagged = co_travel(rows, oui, a.gap, a.min_trips, a.min_sep_km)
    located = locate(rows, oui, ("WIFI",), a.locate_min)

    print(f"# wigle_track - {len(rows)} obs split into {len(trips)} trips "
          f"(>{a.gap}min gap = new trip)")
    if trips:
        span = [t["start"] for t in trips]
        print(f"  window {min(span):%Y-%m-%d %H:%M} -> {max(t['end'] for t in trips):%Y-%m-%d %H:%M}")

    print(f"\n[CO-TRAVEL] {len(flagged)} emitters shadow you across "
          f">={a.min_trips} trips & >=2 places (>{a.min_sep_km}km apart):")
    if not flagged:
        print("  (none - clean, or capture is single-location)")
    for d in flagged[:25]:
        nm = d["ssid"] or d["vendor"] or "(unnamed)"
        print(f"  {d['mac']}  {d['type']:4}  {d['trips']}trips/{d['places']}places "
              f"~{d['max_sep_km']}km  {nm[:26]:26}  {d['signature']}")

    print(f"\n[LOCATED] top transmitter estimates ({len(located)} with "
          f">={a.locate_min} fixes), tightest spread first:")
    for d in located[:20]:
        nm = d["ssid"] or d["vendor"] or "(hidden)"
        print(f"  {d['lat']:.5f},{d['lon']:.5f}  +/-~{d['spread_km']}km  "
              f"rssi{d['best_rssi']:>4}  {nm[:24]:24}  {d['mac']}")

    if a.json:
        import json
        json.dump({"trips": len(trips), "co_travel": flagged, "located": located},
                  open(a.json, "w"), indent=2, default=str)
        print(f"\n[+] wrote {a.json}")


if __name__ == "__main__":
    main()
