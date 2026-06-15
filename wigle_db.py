#!/usr/bin/env python3
"""
wigle_db.py - Persist many WiGLE captures and diff them over time.

The one-shot tools see a single CSV. The intelligence in wardriving is
longitudinal: what is NEW near my home this week, what VANISHED, what keeps
coming back. This ingests captures into a local SQLite file (stdlib sqlite3,
no server) and answers those questions.

Commands:
  ingest CAPTURE.csv[.gz] [--oui oui.json]   add a capture (idempotent)
  stats                                       summarise the database
  diff [--capture NAME] [--near LAT,LON --km K] [--type T]
                                              what the latest (or named) capture
                                              added vs everything seen before
  captures                                    list ingested captures

DB path defaults to ./wigle.db (override with --db). Dedup is by
(mac, firstseen) so re-ingesting the same file is a no-op.

Usage:
  python3 wigle_db.py ingest CAPTURE.csv --oui oui.json
  python3 wigle_db.py diff --near=-33.8568,151.2153 --km 1
        (use --near=LAT,LON with '='; a leading '-' on LAT confuses argparse)
"""
import sys, os, argparse, sqlite3, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wigle_common as W

SCHEMA = """
CREATE TABLE IF NOT EXISTS captures(
  id INTEGER PRIMARY KEY, name TEXT UNIQUE, sensor TEXT,
  first_seen TEXT, last_seen TEXT, n_obs INTEGER);
CREATE TABLE IF NOT EXISTS obs(
  mac TEXT, ssid TEXT, type TEXT, auth TEXT, firstseen TEXT,
  lat REAL, lon REAL, rssi INTEGER, freq TEXT, vendor TEXT,
  capture_id INTEGER,
  UNIQUE(mac, firstseen));
CREATE INDEX IF NOT EXISTS i_mac ON obs(mac);
CREATE INDEX IF NOT EXISTS i_type ON obs(type);
CREATE INDEX IF NOT EXISTS i_cap ON obs(capture_id);
"""


def connect(path):
    db = sqlite3.connect(path)
    db.executescript(SCHEMA)
    return db


def ingest(db, csv_path, oui_path):
    name = os.path.basename(csv_path)
    oui = W.load_oui(oui_path)
    header, rows = W.read_wigle(csv_path)
    sensor = " ".join(filter(None, (W.header_kv(header).get("brand"),
                                    W.header_kv(header).get("model"))))
    ts = sorted(r["FirstSeen"] for r in rows
                if r.get("FirstSeen") and not r["FirstSeen"].startswith("1970"))
    cur = db.cursor()
    cur.execute("INSERT OR IGNORE INTO captures(name,sensor,first_seen,last_seen,n_obs)"
                " VALUES(?,?,?,?,?)", (name, sensor,
                ts[0] if ts else None, ts[-1] if ts else None, len(rows)))
    cur.execute("SELECT id FROM captures WHERE name=?", (name,))
    cap_id = cur.fetchone()[0]
    n0 = db.execute("SELECT COUNT(*) FROM obs").fetchone()[0]
    payload = []
    for r in rows:
        m = r["MAC"].lower()
        ven = W.vendor_name(oui, m) if r.get("Type") == "WIFI" else None
        rssi = r.get("RSSI", "")
        payload.append((m, (r.get("SSID") or "").strip(), r.get("Type"),
                        (r.get("AuthMode") or "").strip(), r.get("FirstSeen"),
                        W.fpt(r.get("CurrentLatitude")), W.fpt(r.get("CurrentLongitude")),
                        int(rssi) if rssi and rssi.lstrip("-").isdigit() else None,
                        r.get("Frequency"), ven, cap_id))
    cur.executemany("INSERT OR IGNORE INTO obs VALUES(?,?,?,?,?,?,?,?,?,?,?)", payload)
    db.commit()
    n1 = db.execute("SELECT COUNT(*) FROM obs").fetchone()[0]
    print(f"[+] ingested '{name}' ({sensor}) - {len(rows)} rows, "
          f"{n1 - n0} new observations, {n1} total in db")


def stats(db):
    caps = db.execute("SELECT COUNT(*) FROM captures").fetchone()[0]
    obs = db.execute("SELECT COUNT(*) FROM obs").fetchone()[0]
    macs = db.execute("SELECT COUNT(DISTINCT mac) FROM obs").fetchone()[0]
    print(f"# wigle.db - {caps} captures, {obs} observations, {macs} unique emitters")
    for t, c in db.execute("SELECT type,COUNT(DISTINCT mac) FROM obs GROUP BY type ORDER BY 2 DESC"):
        print(f"  {t:5} {c}")


def list_captures(db):
    print(f"{'id':>3} {'obs':>7}  {'window':37} sensor / name")
    for row in db.execute("SELECT id,n_obs,first_seen,last_seen,sensor,name FROM captures ORDER BY id"):
        i, n, fs, ls, sen, nm = row
        print(f"{i:>3} {n:>7}  {str(fs):19} -> {str(ls)[11:19]:8}  {sen} / {nm}")


def diff(db, capture, near, km, type_filter):
    # which capture are we diffing?
    if capture:
        row = db.execute("SELECT id,name FROM captures WHERE name=?", (capture,)).fetchone()
    else:
        row = db.execute("SELECT id,name FROM captures ORDER BY id DESC LIMIT 1").fetchone()
    if not row:
        print("no captures in db"); return
    cap_id, cap_name = row

    # MACs in this capture that never appeared in any earlier capture
    q = """SELECT mac,ssid,type,auth,vendor,lat,lon,rssi FROM obs o
           WHERE capture_id=? AND mac NOT IN
             (SELECT mac FROM obs WHERE capture_id < ?)"""
    args = [cap_id, cap_id]
    seen = {}
    for mac, ssid, typ, auth, ven, lat, lon, rssi in db.execute(q, args):
        if type_filter and typ != type_filter:
            continue
        if near and lat is not None:
            if W.haversine(near[0], near[1], lat, lon) > km:
                continue
        # keep strongest sighting per mac
        if mac not in seen or (rssi or -999) > (seen[mac][7] or -999):
            seen[mac] = (mac, ssid, typ, auth, ven, lat, lon, rssi)

    where = f" within {km}km of {near}" if near else ""
    print(f"# diff - capture '{cap_name}' (id {cap_id}) vs all earlier captures")
    print(f"[NEW] {len(seen)} emitters not seen before{where}"
          f"{' ['+type_filter+']' if type_filter else ''}:")
    rows = sorted(seen.values(), key=lambda x: (x[2], -(x[7] or -999)))
    for mac, ssid, typ, auth, ven, lat, lon, rssi in rows[:40]:
        nm = ssid or ven or "(hidden)"
        loc = f"{lat:.4f},{lon:.4f}" if lat is not None else "no-fix"
        print(f"  {mac}  {typ:4}  rssi{str(rssi):>5}  {loc:18}  {nm[:30]}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="wigle.db")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("ingest"); p.add_argument("csv"); p.add_argument("--oui", default="oui.json")
    sub.add_parser("stats")
    sub.add_parser("captures")
    d = sub.add_parser("diff")
    d.add_argument("--capture"); d.add_argument("--near"); d.add_argument("--km", type=float, default=1.0)
    d.add_argument("--type")
    a = ap.parse_args()

    db = connect(a.db)
    if a.cmd == "ingest":
        ingest(db, a.csv, a.oui)
    elif a.cmd == "stats":
        stats(db)
    elif a.cmd == "captures":
        list_captures(db)
    elif a.cmd == "diff":
        near = tuple(float(x) for x in a.near.split(",")) if a.near else None
        diff(db, a.capture, near, a.km, a.type)


if __name__ == "__main__":
    main()
