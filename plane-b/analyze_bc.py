#!/usr/bin/env python3
"""Analyse the B->C boundary runs.

For each cell under results/bc/, computes two things the E2 analysis cannot,
because E2 stops at the ward broker:

  end-to-end delivery   fraction of readings a patient SENT that reached the
                        clinical consumer (patient -> broker -> adapter -> stub)
  end-to-end latency    t_recv(consumer) - t_send(patient), split into
                          ward leg    t_adapter - t_send      (patient->adapter)
                          bridge leg  t_recv    - t_adapter    (adapter->consumer)

Writes results/bc_summary.csv and prints a short table. Medians with a bootstrap
95% CI across repetitions, matching analyze.py.
"""
import csv
import glob
import os

import numpy as np

ROOT = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(ROOT, "results", "bc")


def read_csv(path):
    with open(path) as f:
        return list(csv.DictReader(f))


def cell_metrics(cell_dir):
    sent = {}
    for p in glob.glob(os.path.join(cell_dir, "sent_*.csv")):
        for r in read_csv(p):
            sent[(r["pub_id"], r["seq"])] = float(r["t_send"])
    offered = len(sent)

    e2e, ward, bridge = [], [], []
    delivered = 0
    cpath = os.path.join(cell_dir, "clinical_recv.csv")
    if os.path.exists(cpath):
        seen = set()
        for r in read_csv(cpath):
            key = (r["pub_id"], r["seq"])
            if key not in sent or key in seen:
                continue
            seen.add(key)
            delivered += 1
            try:
                ts = sent[key]
                ta = float(r["t_adapter"])
                tr = float(r["t_recv"])
                e2e.append((tr - ts) * 1000.0)
                ward.append((ta - ts) * 1000.0)
                bridge.append((tr - ta) * 1000.0)
            except (ValueError, TypeError):
                pass
    pdr = delivered / offered if offered else float("nan")
    med = lambda x: float(np.median(x)) if x else float("nan")
    return {"pdr": pdr, "e2e_ms": med(e2e), "ward_ms": med(ward),
            "bridge_ms": med(bridge)}


def boot_ci(x, n=2000):
    x = np.asarray([v for v in x if not np.isnan(v)], dtype=float)
    if len(x) == 0:
        return float("nan"), float("nan"), float("nan")
    if len(x) == 1:
        return float(x[0]), float(x[0]), float(x[0])
    rng = np.random.default_rng(0)
    boots = [np.median(rng.choice(x, len(x), replace=True)) for _ in range(n)]
    return (float(np.median(x)), float(np.percentile(boots, 2.5)),
            float(np.percentile(boots, 97.5)))


def main():
    if not os.path.isdir(RES):
        print("no results/bc yet; run run_bc.py first")
        return
    out = []
    for posture in ("plain", "hardened"):
        pdir = os.path.join(RES, posture)
        if not os.path.isdir(pdir):
            continue
        scales = sorted({int(os.path.basename(d)[1:])
                         for d in glob.glob(os.path.join(pdir, "s*"))})
        for s in scales:
            reps = sorted(glob.glob(os.path.join(pdir, f"s{s}", "r*")))
            if not reps:
                continue
            m = [cell_metrics(r) for r in reps]
            pdr, plo, phi = boot_ci([x["pdr"] for x in m])
            e2e, elo, ehi = boot_ci([x["e2e_ms"] for x in m])
            ward = float(np.nanmedian([x["ward_ms"] for x in m]))
            bridge = float(np.nanmedian([x["bridge_ms"] for x in m]))
            out.append({"posture": posture, "scale": s, "reps": len(reps),
                        "e2e_pdr_med": round(pdr, 4),
                        "e2e_pdr_lo": round(plo, 4), "e2e_pdr_hi": round(phi, 4),
                        "e2e_ms_med": round(e2e, 3),
                        "e2e_ms_lo": round(elo, 3), "e2e_ms_hi": round(ehi, 3),
                        "ward_leg_ms": round(ward, 3),
                        "bridge_leg_ms": round(bridge, 3)})

    if not out:
        print("no bc cells found")
        return
    cols = list(out[0].keys())
    with open(os.path.join(ROOT, "results", "bc_summary.csv"), "w",
              newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(out)
    print("wrote results/bc_summary.csv\n")
    print(f"{'posture':9} {'scale':>5} {'e2e_pdr':>8} {'e2e_ms':>8} "
          f"{'ward_ms':>8} {'bridge_ms':>9}")
    for r in out:
        print(f"{r['posture']:9} {r['scale']:>5} {r['e2e_pdr_med']:>8} "
              f"{r['e2e_ms_med']:>8} {r['ward_leg_ms']:>8} "
              f"{r['bridge_leg_ms']:>9}")


if __name__ == "__main__":
    main()
