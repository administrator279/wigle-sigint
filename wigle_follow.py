#!/usr/bin/env python3
"""
wigle_follow.py - Deepened co-travel / tail detection.

Builds on home-base classification: it FIRST removes your own kit and the radios
anchored at your base(s), because those dominate naive co-travel lists (your
gateway "follows" you every time you go home). What's left and still appears
with you across separated places is the real signal.

For each surviving candidate it scores:
  - places        distinct, well-separated locations it shadowed you to
  - on-body       median RSSI: a follower rides at close, consistent signal;
                  a shop AP you pass is weak and occasional
  - unanchored    heard at several far-apart places = it MOVED (a fixed AP can't)
  - convoy        a cluster of MACs that always appear in the same trips together
                  AND with you = one vehicle/person carrying several radios
  - tracker       a BLE RPA address that should rotate (~15 min) but persists for
                  days, or a stable-LAA Wi-Fi MAC that never rotates -> AirTag /
                  tile / fixed-tracker class (WiGLE exports no advert payload, so
                  this is behavioural inference, not a protocol decode)

Each candidate gets a 0-1 confidence with the reasons spelled out.

Usage:
  python3 wigle_follow.py CAPTURE.csv[.gz] [--oui oui.json] [--exclude exclude.txt]
      [--gap 20] [--min-trips 3] [--min-places 2] [--min-sep-km 0.5]
      [--include-near] [--json out.json]

If --exclude is omitted it computes home-base on the fly and excludes OWN+HOME
(plus NEAR_HOME with --include-near).
"""
import sys, os, json, argparse, collections, statistics
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wigle_common as W
import wigle_homebase as HB


def _places(latlons, sep_km):
    pl = []
    for la, lo in latlons:
        if la is None:
            continue
        if not any(W.haversine(la, lo, p[0], p[1]) < sep_km for p in pl):
            pl.append((la, lo))
    return pl


def follow(rows, oui, exclude=None, gap=20, min_trips=3, min_places=2,
           sep_km=0.5, include_near=False):
    trips = W.build_trips(rows, gap)
    # mac -> set of trip indices it appears in
    mac_trips = collections.defaultdict(set)
    for i, t in enumerate(trips):
        for m in t["macs"]:
            mac_trips[m].add(i)

    # build the exclusion set
    excl = set(exclude or set())
    if not exclude:
        _, _, classified = HB.classify(rows, oui)
        drop = {"OWN", "HOME"} | ({"NEAR_HOME"} if include_near else set())
        excl = {r["mac"] for r in classified if r["class"] in drop}

    agg = W.mac_sightings(rows)
    cands = []
    for m, d in agg.items():
        if m in excl:
            continue
        idxs = mac_trips.get(m, set())
        if len(idxs) < min_trips:
            continue
        latlons = [(la, lo) for la, lo, _ in d["fixes"]]
        places = _places(latlons, sep_km)
        if len(places) < min_places:
            continue
        rssis = [r for *_, r in d["fixes"] if r > -999]
        med_rssi = int(statistics.median(rssis)) if rssis else d["best_rssi"]
        days = len({t.date() for t in d["ts"]})
        spread = 0.0
        if len(places) > 1:
            spread = max(W.haversine(a[0], a[1], b[0], b[1]) for a in places for b in places)
        tracker = _tracker_kind(m, d, days)
        cands.append({
            "mac": m, "type": d["type"],
            "ssid": (d["label"].get("SSID") or "").strip() or None,
            "vendor": W.vendor_name(oui, m) if d["type"] == "WIFI" else None,
            "trips": len(idxs), "places": len(places), "max_sep_km": round(spread, 2),
            "med_rssi": med_rssi, "best_rssi": d["best_rssi"], "days": days,
            "tracker": tracker, "_trips": idxs,
        })

    convoys = _convoys(cands)
    convoy_of = {}
    for ci, grp in enumerate(convoys):
        for m in grp:
            convoy_of[m] = ci

    for c in cands:
        c["convoy"] = convoy_of.get(c["mac"])
        c["confidence"], c["reasons"] = _score(c, convoys)
        del c["_trips"]
    cands.sort(key=lambda c: -c["confidence"])
    return trips, len(excl), convoys, cands


def _tracker_kind(mac, d, days):
    if d["type"] == "BLE":
        st = W.ble_subtype(mac)
        if st == "RPA" and days >= 2:
            return "non-rotating-RPA"      # RPA should rotate ~15min; persists days
        if st == "static-random" and days >= 2:
            return "static-BLE"
    if d["type"] == "WIFI" and W.is_laa(mac) and days >= 2:
        return "stable-LAA"
    return None


def _convoys(cands, jaccard=0.6, min_size=2):
    """Cluster candidates whose trip-membership sets are near-identical."""
    items = [(c["mac"], c["_trips"]) for c in cands]
    used, groups = set(), []
    for i, (m, ts) in enumerate(items):
        if m in used or len(ts) < 2:
            continue
        grp = [m]
        for j in range(i + 1, len(items)):
            m2, ts2 = items[j]
            if m2 in used:
                continue
            inter = len(ts & ts2); union = len(ts | ts2)
            if union and inter / union >= jaccard:
                grp.append(m2)
        if len(grp) >= min_size:
            for m2 in grp:
                used.add(m2)
            groups.append(grp)
    return groups


def _score(c, convoys):
    s, reasons = 0.0, []
    # distinct places shadowed
    p = c["places"]
    s += min(p / 5.0, 0.4)
    reasons.append(f"{p} places")
    # on-body proximity
    if c["med_rssi"] >= -60:
        s += 0.3; reasons.append(f"on-body RSSI (med {c['med_rssi']})")
    elif c["med_rssi"] >= -75:
        s += 0.12; reasons.append(f"close RSSI (med {c['med_rssi']})")
    # moved a long way with you
    if c["max_sep_km"] >= 2:
        s += 0.15; reasons.append(f"spans {c['max_sep_km']}km")
    # convoy membership
    if c["convoy"] is not None:
        s += 0.2; reasons.append(f"convoy #{c['convoy']}")
    # tracker signature
    if c["tracker"]:
        s += 0.2; reasons.append(c["tracker"])
    return round(min(s, 1.0), 2), reasons


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--oui", default="oui.json")
    ap.add_argument("--exclude", help="MAC exclusion list (default: auto-find exclude.txt)")
    ap.add_argument("--no-exclude", action="store_true",
                    help="exclude nothing (skip both exclude.txt and auto home-base)")
    ap.add_argument("--gap", type=int, default=20)
    ap.add_argument("--min-trips", type=int, default=3)
    ap.add_argument("--min-places", type=int, default=2)
    ap.add_argument("--min-sep-km", type=float, default=0.5)
    ap.add_argument("--include-near", action="store_true")
    ap.add_argument("--min-conf", type=float, default=0.0,
                    help="only show/append candidates with confidence >= this")
    ap.add_argument("--append-exclude", metavar="FILE",
                    help="append shown candidates' MACs to this exclusion file "
                         "(promote confirmed own kit, e.g. your car, so it's dropped next time)")
    ap.add_argument("--json")
    a = ap.parse_args()

    oui = W.load_oui(a.oui)
    _, rows = W.read_wigle(a.csv)
    ex_set, ex_src = W.resolve_exclude(a.exclude, a.no_exclude)
    if a.no_exclude:
        exclude, src = set(), "none (--no-exclude)"
    elif ex_set:
        exclude, src = ex_set, ex_src
    else:
        exclude, src = None, "auto home-base"   # nothing on disk -> compute it
    trips, n_excl, convoys, cands = follow(
        rows, oui, exclude, a.gap, a.min_trips, a.min_places, a.min_sep_km, a.include_near)
    cands = [c for c in cands if c["confidence"] >= a.min_conf]
    print(f"# wigle_follow - {len(trips)} trips, {n_excl} MACs excluded ({src})")
    print(f"  {len(cands)} follow candidates, {len(convoys)} convoy group(s)\n")
    print(f"{'conf':>4}  {'mac':17} {'type':4} {'trips/places':12} {'rssi':>5}  name / reasons")
    print("-" * 96)
    for c in cands[:30]:
        nm = c["ssid"] or c["vendor"] or "(unnamed)"
        print(f"{c['confidence']:>4}  {c['mac']:17} {c['type']:4} "
              f"{str(c['trips'])+'/'+str(c['places']):12} {c['med_rssi']:>5}  "
              f"{nm[:24]:24} {', '.join(c['reasons'])}")
    if convoys:
        print("\nconvoy groups (radios that always travel together):")
        for ci, grp in enumerate(convoys):
            print(f"  #{ci}: {', '.join(grp)}")

    if a.append_exclude:
        existing = W.load_exclude(a.append_exclude)
        added = 0
        with open(a.append_exclude, "a", encoding="utf-8") as fh:
            for c in cands:
                if c["mac"] not in existing:
                    tag = c["ssid"] or c["vendor"] or c["type"]
                    fh.write(f"{c['mac']}  # follow conf {c['confidence']} {tag}\n")
                    added += 1
        print(f"\n[+] appended {added} MAC(s) to {a.append_exclude} "
              f"(conf >= {a.min_conf}) — review before re-running")

    if a.json:
        json.dump({"trips": len(trips), "excluded": n_excl,
                   "convoys": convoys, "candidates": cands},
                  open(a.json, "w"), indent=2, default=str)
        print(f"\n[+] wrote {a.json}")


if __name__ == "__main__":
    main()
