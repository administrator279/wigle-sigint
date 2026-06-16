#!/usr/bin/env python3
"""
wigle.py - Single entry point for the WiGLE SIGINT toolkit.

One command, ten tools, plus an `all` pipeline. Works the same on Windows,
Linux and Android/Termux (pure stdlib).

  python wigle.py analyze  CAPTURE.csv [--exclude exclude.txt] [--json out.json]
  python wigle.py cluster  CAPTURE.csv [--include-ble] [--min-bssids 3]
  python wigle.py track    CAPTURE.csv [--min-trips 3] [--min-sep-km 0.5]
  python wigle.py map      CAPTURE.csv [--out survey] [--exclude exclude.txt]
  python wigle.py report   CAPTURE.csv [--out report.html]          (quick bundle)
  python wigle.py brief    CAPTURE.csv --mode recon|threat [--exclude exclude.txt]
  python wigle.py homebase CAPTURE.csv [--out-prefix home]   classify + exclude.txt
  python wigle.py follow   CAPTURE.csv [--exclude exclude.txt]   tail / convoy hunt
  python wigle.py targets  CAPTURE.csv [--exclude exclude.txt]   pentest target CSV
  python wigle.py db ingest CAPTURE.csv          (and: db stats|captures|diff ...)
  python wigle.py all      CAPTURE.csv           run report + map + db-ingest

Most tools take --exclude FILE to drop a home-base MAC list (see `homebase`).
`all` is the field one-liner: drop a capture in, get a self-contained HTML
report, map layers, and the observation added to the rolling SQLite db.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

TOOLS = {
    "analyze":  "wigle_analyze",
    "cluster":  "wigle_cluster",
    "track":    "wigle_track",
    "map":      "wigle_map",
    "report":   "wigle_report",
    "brief":    "wigle_report2",
    "homebase": "wigle_homebase",
    "follow":   "wigle_follow",
    "targets":  "wigle_targets",
    "db":       "wigle_db",
}


def _dispatch(modname, argv):
    import importlib
    mod = importlib.import_module(modname)
    saved = sys.argv
    sys.argv = [f"wigle {modname.split('_')[-1]}"] + argv
    try:
        mod.main()
    finally:
        sys.argv = saved


def run_all(argv):
    """report + map + db ingest on one capture, with sensible default names."""
    if not argv:
        sys.exit("usage: wigle.py all CAPTURE.csv [--oui oui.json]")
    csv = argv[0]
    rest = argv[1:]
    stem = os.path.splitext(os.path.basename(csv))[0]
    print(f"=== report -> {stem}.report.html ===")
    _dispatch("wigle_report", [csv, "--out", f"{stem}.report.html"] + rest)
    print(f"\n=== map -> {stem}.geojson/.kml/.html ===")
    _dispatch("wigle_map", [csv, "--out", stem] + rest)
    print("\n=== db ingest ===")
    _dispatch("wigle_db", ["ingest", csv] + rest)
    print(f"\n[done] open {stem}.report.html")


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print(__doc__)
        print("commands:", ", ".join(list(TOOLS) + ["all"]))
        return
    cmd, argv = sys.argv[1], sys.argv[2:]
    if cmd == "all":
        run_all(argv)
    elif cmd in TOOLS:
        _dispatch(TOOLS[cmd], argv)
    else:
        sys.exit(f"unknown command '{cmd}'. try: {', '.join(list(TOOLS) + ['all'])}")


if __name__ == "__main__":
    main()
