#!/usr/bin/env python3
"""Distributed connection-exhaustion driver (threat-model probe).

Research test harness for the author's own local broker only. It launches the
single-source harness (attack_conn_exhaust.py) from several distinct loopback
source addresses at once, to show what the E2a per-source rate limit does
against a many-source (botnet-style) attacker rather than one host.

The per-source nftables meter in src/ratelimit.sh keys on ip saddr, so each
source gets its own 5/second budget. One host is throttled; N hosts each stay
under their own budget and collectively are not. This driver measures that:
run it with the rate limit on, once at --sources 1 and once at a larger value,
and compare total established connections. The global connection cap
(max_connections) is the control that still bounds the total.

Sources use 127.0.2.1.. so they never collide with the patients (127.0.0.x).
All of 127.0.0.0/8 is loopback on Linux, so everything stays on this host.

Usage (rate limit on, broker = e2a_mitig on 1883):
    bash src/ratelimit.sh on 1883
    python3 src/attack_distributed.py --sources 1 --per-source-count 200
    python3 src/attack_distributed.py --sources 8 --per-source-count 200
    bash src/ratelimit.sh off 1883
"""
import argparse
import csv
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--sources", type=int, default=8,
                    help="number of distinct source addresses")
    ap.add_argument("--per-source-count", type=int, default=200,
                    help="connections each source attempts")
    ap.add_argument("--duration", type=float, default=20.0)
    ap.add_argument("--outdir", default=os.path.join(HERE, "..", "results",
                                                     "distributed"))
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    procs = []
    tmpfiles = []
    for k in range(args.sources):
        src = f"127.0.2.{k + 1}"
        tf = tempfile.NamedTemporaryFile(
            prefix=f"dist_{src}_", suffix=".csv", delete=False,
            dir=args.outdir).name
        tmpfiles.append(tf)
        procs.append(subprocess.Popen(
            [sys.executable, os.path.join(HERE, "attack_conn_exhaust.py"),
             "--host", args.host, "--port", str(args.port),
             "--source", src, "--count", str(args.per_source_count),
             "--duration", str(args.duration), "--outfile", tf]))
    for p in procs:
        p.wait()

    attempted = established = refused = 0
    for tf in tmpfiles:
        try:
            with open(tf) as f:
                rows = list(csv.DictReader(f))
            if rows:
                established += int(rows[0]["established"])
                refused += int(rows[0]["refused"])
                attempted += int(rows[0]["attempted"])
        except (OSError, ValueError, KeyError):
            pass
        finally:
            try:
                os.remove(tf)
            except OSError:
                pass

    summ = os.path.join(args.outdir, "summary.csv")
    new = not os.path.exists(summ)
    with open(summ, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["sources", "per_source_count", "duration",
                        "attempted", "established", "refused"])
        w.writerow([args.sources, args.per_source_count, args.duration,
                    attempted, established, refused])
    print(f"distributed: sources={args.sources} attempted={attempted} "
          f"established={established} refused={refused} -> {summ}")


if __name__ == "__main__":
    main()
