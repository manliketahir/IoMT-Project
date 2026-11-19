#!/usr/bin/env python3
"""Analyse a GNS3 sweep (E2 or E6) and correct its time-based figures for the
GNS3 VM's clock rate.

    python analyze_gns3.py e2        # plane-b/results-gns3 + gns3_clock_e2.csv
    python analyze_gns3.py e6        # plane-c/results-gns3 + gns3_clock_e6.csv

Why a clock correction: on this host the GNS3 VM runs under VMware on top of
the Windows hypervisor (WSL2 keeps it on), and the VM's virtual clock was
measured to run at a steady ~0.900 of real time (Windows' clock checked against
internet NTP; two independent 60 s measurements agreed to 0.01 %). Every
timestamp inside a run comes from that one clock, so:

  * unaffected: delivery ratios, connection counts, attack outcomes, CPU %
    (CPU time / elapsed time, both on the guest clock), and every Mann-Whitney
    p-value (rank-based, so a uniform scale factor cannot change it);
  * affected: absolute latencies, which read low by the clock factor.

The sweep's clock CSV (written by the host-side sampler during the sweep) gives
the factor for that sweep; corrected latency = measured latency / factor.

Steps: run the plane's own analyser unchanged on the GNS3 results (its p-value
printout is saved to analysis_stdout.txt), then write
  clock_rate.txt                  the factor and its stability over the sweep
  <summary>_clock_corrected.csv   the analyser's summary + *_real latency columns
  comparison_with_loopback.csv    GNS3 (measured and corrected) next to loopback
"""
import csv
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TESTBED = os.path.dirname(HERE)

CFG = {
    "e2": dict(analyzer=os.path.join(TESTBED, "plane-b", "analyze.py"), env="E2_RESULTS_DIR",
               results=os.path.join(TESTBED, "plane-b", "results-gns3"), summary="summary.csv",
               timecols=["lat_ms_med", "lat_lo", "lat_hi"],
               clock=os.path.join(TESTBED, "plane-b", "gns3_clock_e2.csv"),
               loopback=os.path.join(TESTBED, "plane-b", "results", "summary-final.csv")),
    "e6": dict(analyzer=os.path.join(TESTBED, "plane-c", "analyze_e6.py"), env="E6_RESULTS_DIR",
               results=os.path.join(TESTBED, "plane-c", "results-gns3"), summary="e6_summary.csv",
               timecols=["ack_ms_med", "ack_ms_lo", "ack_ms_hi", "ack_ms_p95"],
               clock=os.path.join(TESTBED, "plane-c", "gns3_clock_e6.csv"),
               loopback=os.path.join(TESTBED, "plane-c", "results", "e6_summary.csv")),
}


def clock_factor(path):
    rows = [r for r in csv.DictReader(open(path))]
    pts = [(float(r["windows_epoch"]), float(r["guest_epoch"]), float(r["wsl_epoch"])) for r in rows]
    if len(pts) < 2:
        raise SystemExit(f"{path}: need at least two clock samples")
    (v0, g0, w0), (v1, g1, w1) = pts[0], pts[-1]
    rate = (g1 - g0) / (v1 - v0)
    seg = [(b[1] - a[1]) / (b[2] - a[2]) for a, b in zip(pts, pts[1:]) if b[2] - a[2] > 60]
    return rate, (min(seg), max(seg)) if seg else (rate, rate), len(pts), v1 - v0, (w1 - w0) / (v1 - v0)


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "e2"
    c = CFG[which]
    res = os.path.abspath(sys.argv[2]) if len(sys.argv) > 2 else c["results"]
    if not os.path.isdir(res):
        raise SystemExit(f"no GNS3 results at {res}")

    # 1. the plane's own analyser, unchanged
    env = dict(os.environ, **{c["env"]: res})
    out = subprocess.run([sys.executable, c["analyzer"]], env=env, capture_output=True, text=True)
    with open(os.path.join(res, "analysis_stdout.txt"), "w") as f:
        f.write(out.stdout + out.stderr)
    print(out.stdout.strip())
    if out.returncode != 0:
        raise SystemExit(f"analyser failed:\n{out.stderr}")

    # 2. clock factor for this sweep
    rate, (rmin, rmax), n, span, wsl_rate = clock_factor(c["clock"])
    note = (f"guest_clock_rate={rate:.5f}\nper_interval_min={rmin:.5f}\nper_interval_max={rmax:.5f}\n"
            f"samples={n}\nspan_s={span:.0f}\nwsl_vs_windows_rate={wsl_rate:.6f}\n"
            f"correction: real_latency = measured_latency / guest_clock_rate\n")
    with open(os.path.join(res, "clock_rate.txt"), "w") as f:
        f.write(note)
    print(f"\n[clock] guest/real rate {rate:.5f} over {span/60:.0f} min ({n} samples), "
          f"per-interval {rmin:.5f}..{rmax:.5f}; WSL/Windows {wsl_rate:.6f}")

    # 3. corrected summary
    summ = list(csv.DictReader(open(os.path.join(res, c["summary"]))))
    for r in summ:
        r["clock_rate"] = f"{rate:.5f}"
        for col in c["timecols"]:
            try:
                r[f"{col}_real"] = f"{float(r[col]) / rate:.3f}"
            except (ValueError, KeyError):
                r[f"{col}_real"] = "nan"
    base = os.path.splitext(c["summary"])[0]
    with open(os.path.join(res, f"{base}_clock_corrected.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(summ[0].keys()))
        w.writeheader()
        w.writerows(summ)

    # 4. side by side with loopback (smallest loopback scale >= GNS3 scale, stated)
    loop = list(csv.DictReader(open(c["loopback"]))) if os.path.exists(c["loopback"]) else []
    lat = c["timecols"][0]
    rows = []
    for r in summ:
        cand = [l for l in loop if l["exp"] == r["exp"] and l["condition"] == r["condition"]]
        same = [l for l in cand if l["scale"] == r["scale"]]
        lb = (same or sorted(cand, key=lambda l: int(l["scale"])) or [None])[0]
        rows.append({
            "exp": r["exp"], "condition": r["condition"],
            "gns3_scale": r["scale"], "loopback_scale": lb["scale"] if lb else "",
            "pdr_gns3": r["pdr_med"], "pdr_loopback": lb["pdr_med"] if lb else "",
            f"{lat}_gns3_measured": r[lat], f"{lat}_gns3_real": r[f"{lat}_real"],
            f"{lat}_loopback": lb[lat] if lb and lat in lb else "",
        })
    with open(os.path.join(res, "comparison_with_loopback.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"\n{'exp':<4} {'condition':<13} {'PDR':>6} {lat + ' meas':>14} {'real':>7} "
          f"{'loopback':>9} {'(scale)':>8}")
    for x in rows:
        print(f"{x['exp']:<4} {x['condition']:<13} {x['pdr_gns3']:>6} "
              f"{x[f'{lat}_gns3_measured']:>14} {x[f'{lat}_gns3_real']:>7} "
              f"{x[f'{lat}_loopback']:>9} {'(' + x['loopback_scale'] + ')':>8}")
    print(f"\nwrote {res}/clock_rate.txt, {base}_clock_corrected.csv, comparison_with_loopback.csv")


if __name__ == "__main__":
    main()
