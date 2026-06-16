#!/usr/bin/env python3
"""
wigle_cluster.py - De-anonymise & cluster a WiGLE CSV export into physical devices.

What it does
------------
WiGLE logs every BSSID it hears as a separate row. One physical access point
usually emits SEVERAL BSSIDs: per-band radios (2.4/5/6 GHz), guest networks,
and hidden backhaul/mesh SSIDs - often with the locally-administered (LAA) bit
set so they look "randomized". This tool collapses those back into one device by:

  1. OUI recovery   - if the LAA bit is set, XOR 0x02 on octet-0 to recover the
                      real IEEE OUI, then look it up (oui-data / oui.json).
  2. Family merge   - BSSIDs that share recovered-OUI + octets 4-5 and whose last
                      octet falls inside a small window are one device (vendors
                      allocate contiguous BSSID blocks per unit).
  3. Mesh merge     - identical non-empty SSID across >=2 BSSIDs is flagged as a
                      mesh/multi-AP system.

With --include-ble it also groups BLE/BT: named devices are merged by name (one
phone shows up under many rotating addresses but keeps its name), and stable
(static-random / universal) addresses are surfaced as individual devices.

Usage
-----
  python3 wigle_cluster.py CAPTURE.csv[.gz] [--window 8] [--include-ble] [--json out.json]

Requires oui.json (dump of the npm `oui-data` package) in the cwd, or run with
--no-vendor to skip vendor naming.
"""
import sys, os, json, argparse, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wigle_common as W

# Shared helpers come from wigle_common (single source of truth; the bare
# open(oui.json) that crashed under Windows cp1252 lives there, fixed once).
is_laa = W.is_laa
recovered_oui = W.recovered_oui


def band(fq):
    b = W.band(fq)
    return {"2.4GHz": "2.4", "5GHz": "5", "6GHz": "6"}.get(b, "?")


def cluster(rows, oui, window=8, vendor=True):
    best = {}
    for r in rows:
        if r["Type"] != "WIFI": continue
        m = r["MAC"].lower()
        cur = best.get(m)
        rssi = int(r["RSSI"]) if r["RSSI"].lstrip("-").isdigit() else -999
        if cur is None or rssi > cur["_rssi"] or (not cur["SSID"].strip() and r["SSID"].strip()):
            r = dict(r); r["_rssi"] = rssi; best[m] = r

    buckets = collections.defaultdict(list)
    for m, r in best.items():
        roui = recovered_oui(m)
        key = (roui, m[9:11], m[12:14])
        buckets[key].append((int(m[15:17], 16), m, r))

    devices = []
    for (roui, o4, o5), members in buckets.items():
        members.sort()
        runs, run = [], [members[0]]
        for prev, cur in zip(members, members[1:]):
            if cur[0] - prev[0] <= window:
                run.append(cur)
            else:
                runs.append(run); run = [cur]
        runs.append(run)
        for run in runs:
            macs = [x[1] for x in run]
            recs = [x[2] for x in run]
            ssids = sorted({x["SSID"] for x in recs if x["SSID"].strip()})
            bands = sorted({band(x["Frequency"]) for x in recs} - {"?"})
            vname = oui.get(roui) if vendor else None
            vname = vname.split("\n")[0] if vname else None
            laa_n = sum(1 for m in macs if is_laa(m))
            devices.append({
                "vendor": vname, "recovered_oui": roui,
                "bssids": macs, "n_bssids": len(macs),
                "ssids": ssids, "hidden": len(macs) - sum(1 for x in recs if x["SSID"].strip()),
                "bands": bands, "laa_bssids": laa_n,
                "best_rssi": max(x["_rssi"] for x in recs),
            })
    return devices


def cluster_ble(rows):
    """
    Group BLE/BT into logical devices. Named devices keyed by name (rotating
    addresses, one identity); unnamed stable addresses surfaced individually.
    """
    named = collections.defaultdict(lambda: {"macs": set(), "types": set(),
                                             "rssi": -999, "cat": ""})
    stable = []
    for r in rows:
        t = r.get("Type")
        if t not in ("BLE", "BT"): continue
        m = r["MAC"].lower()
        nm = (r.get("SSID") or "").strip()
        rssi = int(r["RSSI"]) if r["RSSI"].lstrip("-").isdigit() else -999
        if nm:
            d = named[nm]
            d["macs"].add(m); d["types"].add(t)
            d["rssi"] = max(d["rssi"], rssi)
            d["cat"] = d["cat"] or W.device_category(r)
        elif t == "BLE" and W.ble_subtype(m) == "static-random":
            stable.append({"name": None, "mac": m, "type": t, "rssi": rssi,
                           "cat": W.device_category(r), "addr": "static-random"})
    out = [{"name": nm, "addresses": len(d["macs"]), "types": sorted(d["types"]),
            "cat": d["cat"], "best_rssi": d["rssi"], "macs": sorted(d["macs"])}
           for nm, d in named.items()]
    out.sort(key=lambda d: (-d["addresses"], -d["best_rssi"]))
    return out, stable


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--window", type=int, default=8, help="max last-octet gap to merge")
    ap.add_argument("--json", help="write full device list to JSON")
    ap.add_argument("--no-vendor", action="store_true")
    ap.add_argument("--min-bssids", type=int, default=1, help="only show devices emitting >= N BSSIDs")
    ap.add_argument("--include-ble", action="store_true", help="also cluster BLE/BT devices")
    ap.add_argument("--oui", default="oui.json")
    ap.add_argument("--exclude", help="MAC exclusion list (default: auto-find exclude.txt)")
    ap.add_argument("--no-exclude", action="store_true", help="don't auto-load exclude.txt")
    args = ap.parse_args()

    oui = {} if args.no_vendor else W.load_oui(args.oui)
    _, rows = W.read_wigle(args.csv)
    ex, _ex_src = W.resolve_exclude(args.exclude, args.no_exclude)
    if ex:
        rows = [r for r in rows if r["MAC"].lower() not in ex]
    devs = cluster(rows, oui, args.window, not args.no_vendor)
    devs.sort(key=lambda d: (-d["n_bssids"], d["best_rssi"]))

    raw = sum(1 for r in rows if r["Type"] == "WIFI")
    uniq_bssid = len({r["MAC"].lower() for r in rows if r["Type"] == "WIFI"})
    print(f"WiFi rows {raw} | unique BSSIDs {uniq_bssid} | physical devices {len(devs)} "
          f"(collapse {uniq_bssid}->{len(devs)}, {(1-len(devs)/uniq_bssid)*100:.0f}% reduction)\n")

    shown = [d for d in devs if d["n_bssids"] >= args.min_bssids]
    print(f"{'BSSIDs':>6} {'bands':>7} {'hid':>3}  {'vendor':28} ssids")
    print("-" * 100)
    for d in shown[:40]:
        nm = (d["vendor"] or "(unknown)")[:28]
        ss = ", ".join(d["ssids"][:3]) or "(all hidden)"
        if len(d["ssids"]) > 3: ss += f" +{len(d['ssids'])-3}"
        print(f"{d['n_bssids']:>6} {'/'.join(d['bands']):>7} {d['hidden']:>3}  {nm:28} {ss}")

    ble_named = ble_stable = None
    if args.include_ble:
        ble_named, ble_stable = cluster_ble(rows)
        print(f"\nBLE/BT logical devices (named, merged across address rotation): {len(ble_named)}")
        print(f"{'addrs':>5} {'types':>7}  {'cat':12} name")
        print("-" * 70)
        for d in ble_named[:30]:
            print(f"{d['addresses']:>5} {'/'.join(d['types']):>7}  {(d['cat'] or '')[:12]:12} {d['name'][:40]}")
        print(f"\nstable (static-random) unnamed BLE: {len(ble_stable)} "
              f"(candidate persistent devices)")

    if args.json:
        out = {"wifi_devices": devs}
        if args.include_ble:
            out["ble_named"] = ble_named; out["ble_stable"] = ble_stable
        json.dump(out, open(args.json, "w"), indent=2)
        print(f"\n[+] wrote {args.json}")


if __name__ == "__main__":
    main()
