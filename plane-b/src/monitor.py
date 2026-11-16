#!/usr/bin/env python3
"""Sample the broker's own resource use.

Given the Mosquitto process id, record CPU percent, resident memory and open
connection count every interval until SIGTERM. This is how the cost of a
mitigation (mitigation-only minus baseline) and the strain of an attack are
measured on the broker itself. Writes <outfile>.
"""
import argparse
import csv
import signal
import time

import psutil


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--interval", type=float, default=0.5)
    ap.add_argument("--outfile", default="broker.csv")
    args = ap.parse_args()

    stop = {"f": False}
    signal.signal(signal.SIGTERM, lambda *_: stop.update(f=True))
    signal.signal(signal.SIGINT, lambda *_: stop.update(f=True))

    try:
        p = psutil.Process(args.pid)
    except psutil.NoSuchProcess:
        print(f"monitor: no process {args.pid}")
        return
    p.cpu_percent(None)  # prime the first reading

    with open(args.outfile, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["t", "cpu_pct", "rss_kb", "connections"])
        while not stop["f"] and p.is_running():
            try:
                cpu = p.cpu_percent(None)
                rss = p.memory_info().rss // 1024
                conns = len([c for c in p.net_connections(kind="inet")
                             if c.status == psutil.CONN_ESTABLISHED])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            w.writerow([f"{time.time():.3f}", cpu, rss, conns])
            f.flush()
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
