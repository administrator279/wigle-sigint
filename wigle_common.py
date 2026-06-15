#!/usr/bin/env python3
"""
wigle_common.py - Shared helpers for the WiGLE SIGINT toolkit.

Pure standard-library. Importing this from any tool in the same folder gives a
single source of truth for: encoding-safe file I/O, MAC bit-analysis + LAA
vendor recovery, OUI lookup with vendor-name normalisation, band/channel maths,
BLE address-typing, WiGLE Type/AuthMode subfield parsing, haversine distance
and RSSI trilateration.

Why this file exists: the original two scripts each carried their own copies of
open_any/is_laa/recovered_oui/band/haversine, and both opened oui.json with a
bare open() that crashes under Windows' cp1252 default codec. Centralising fixes
the bug once and keeps the tools consistent.
"""
import csv, gzip, io, os, json, math, re, collections
import sys as _sys

# Windows consoles default to cp1252, which crashes on the em-dash and the
# full-width commas embedded in some IEEE vendor strings. Force UTF-8 on the
# streams once, here, so every tool that imports this module prints safely.
for _s in (_sys.stdout, _sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------- file I/O ----

def open_any(p):
    """Open a plain or .gz WiGLE CSV as UTF-8 (BOM-tolerant) text."""
    if str(p).endswith(".gz"):
        return io.TextIOWrapper(gzip.open(p, "rb"), encoding="utf-8-sig")
    return open(p, encoding="utf-8-sig")

def read_wigle(path):
    """Return (pre_header_device_line, list_of_row_dicts)."""
    f = open_any(path)
    header = f.readline().strip()           # WigleWifi-1.6,appRelease=...,model=...
    rows = list(csv.DictReader(f))
    f.close()
    return header, rows

def load_oui(path="oui.json"):
    """
    Load the oui-data JSON map. UTF-8 explicit -- the original bug was here.
    Falls back to an oui.json sitting next to these scripts, so the tools work
    from any working directory, not only when you cd into the kit folder.
    """
    candidates = [path] if path else []
    candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "oui.json"))
    for p in candidates:
        if p and os.path.exists(p):
            with open(p, encoding="utf-8") as fh:
                return json.load(fh)
    return {}

def header_kv(header):
    """Parse the 'k=v,k=v' sensor metadata out of the pre-header line."""
    return dict(kv.split("=", 1) for kv in header.split(",") if "=" in kv)

# ------------------------------------------------------------- MAC analysis ----

def _o0(mac):
    return int(mac.split(":")[0], 16)

def is_laa(mac):
    """Locally-administered ('randomized') bit set on octet 0."""
    return (_o0(mac) >> 1) & 1 == 1

def is_mcast(mac):
    return _o0(mac) & 1 == 1

def recovered_oui(mac):
    """Real 6-hex OUI, flipping the LAA bit (XOR 0x02) when set."""
    o0 = int(mac[:2], 16)
    if (o0 >> 1) & 1:
        o0 ^= 0x02
    return (f"{o0:02x}" + mac[3:5] + mac[6:8]).upper()

def ble_subtype(mac):
    """BLE random-address subtype from the top 2 bits of the MSB."""
    top = int(mac[:2], 16) >> 6
    return {0: "NRPA", 1: "RPA", 2: "RESERVED(non-BLE?)", 3: "static-random"}[top]

# ----------------------------------------------------------- vendor naming ----

# Trailing corporate-form / descriptor noise that makes "TP-Link Systems Inc"
# and "TP-Link Systems Inc." look like two different vendors.
_VENDOR_NOISE = re.compile(
    r"\b(inc|incorporated|corp|corporation|company|co|ltd|limited|llc|gmbh|"
    r"sas|sa|ag|bv|plc|pty|technologies|technology|tech|systems|system|"
    r"electronics|electronic|networks|network|communications|communication|"
    r"international|broadband|solutions)\b", re.I)

def vendor_key(name):
    """Canonical comparison key so vendor-string variants collapse to one."""
    if not name:
        return ""
    s = name.split("\n")[0].replace("，", ",")        # full-width comma -> ascii
    s = re.sub(r"[.,&]", " ", s.lower())
    s = _VENDOR_NOISE.sub(" ", s)
    return re.sub(r"\s+", " ", s).strip()

def vendor_name(oui, mac):
    """Human vendor for a MAC (after LAA recovery), or None."""
    v = oui.get(recovered_oui(mac))
    return v.split("\n")[0].strip() if v else None

# -------------------------------------------------------------- RF / bands ----

def band(fq):
    try:
        fq = int(fq)
    except (TypeError, ValueError):
        return "?"
    if 2400 <= fq < 2500: return "2.4GHz"
    if 5000 <= fq < 5900: return "5GHz"
    if 5925 <= fq <= 7125: return "6GHz"
    return "?"

# ----------------------------------------------------- WiGLE field parsing ----

def device_category(row):
    """
    For BLE/BT/LTE rows WiGLE packs the device type (and caps) into AuthMode,
    e.g. 'Laptop;12', 'Phone;6', 'LTE;50502'. Return the leading type token.
    """
    a = (row.get("AuthMode") or "").strip()
    return a.split(";")[0].strip() if a else ""

def is_named(row):
    return bool((row.get("SSID") or "").strip())

# ----------------------------------------------------------------- geo math ----

def haversine(a, b, c, d):
    """Great-circle km between (a,b) and (c,d) in degrees."""
    R = 6371.0; p = math.radians
    dl = p(c - a); do = p(d - b)
    x = math.sin(dl / 2) ** 2 + math.cos(p(a)) * math.cos(p(c)) * math.sin(do / 2) ** 2
    return 2 * R * math.asin(math.sqrt(x))

def fpt(v):
    """Float-or-None for a CSV cell that may be '', '0', or junk."""
    try:
        f = float(v)
        return f
    except (TypeError, ValueError):
        return None

def has_fix(row):
    la = row.get("CurrentLatitude"); lo = row.get("CurrentLongitude")
    return la not in (None, "", "0") and lo not in (None, "", "0")

def estimate_location(sightings):
    """
    RSSI-weighted transmitter-location estimate from many (lat, lon, rssi)
    listening points. Weight = linear field amplitude 10**(rssi/20): stronger
    (less-negative) sightings pull the estimate toward them. Returns the
    estimate plus the strongest single sighting and the point spread so callers
    can judge confidence. This converts "where I heard it" into an approximate
    "where it is" -- it is an estimate, not a survey-grade fix.
    """
    pts = [(la, lo, r) for la, lo, r in sightings if la is not None and lo is not None]
    if not pts:
        return None
    def w(r):
        return 10 ** (r / 20.0)
    sw = sum(w(r) for *_, r in pts)
    lat = sum(la * w(r) for la, lo, r in pts) / sw
    lon = sum(lo * w(r) for la, lo, r in pts) / sw
    best = max(pts, key=lambda p: p[2])
    spread = 0.0
    if len(pts) > 1:
        spread = max(haversine(p[0], p[1], q[0], q[1]) for p in pts for q in pts)
    return {
        "lat": round(lat, 6), "lon": round(lon, 6), "n": len(pts),
        "best_rssi": best[2], "best_at": (round(best[0], 6), round(best[1], 6)),
        "spread_km": round(spread, 3),
    }
