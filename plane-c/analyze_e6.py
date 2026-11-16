#!/usr/bin/env python3
"""Turn the raw E6 CSVs under results/ into the reported numbers.

Per repetition it computes, for each (sub-experiment, condition):
  - gateway delivery ratio   legitimate observations ACKed AA / patient sends
  - ACK round-trip latency   t_ack - t_sent, ms, median and p95
  - listener CPU / RSS        from the resource monitor on the listener pid
  - e6a: forged acceptance    forged msgs ACKed AA / forged msgs sent
          forged persistence  forged observations stored with AA in hl7_recv
  - e6b: attacker established  connections the flood held open

Across repetitions it reports medians with a bootstrap 95% CI and runs the two
Mann-Whitney comparisons that matter. It reuses boot_ci() and mann_whitney()
from plane B's analyze.py unchanged, so the statistics match E2 exactly.

E6_RESULTS_DIR mirrors plane B's E2_RESULTS_DIR guard.
"""
import csv
import glob
import importlib.util
import os

import numpy as np

ROOT = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(ROOT, os.environ.get("E6_RESULTS_DIR", "results"))
PLANE_B_ANALYZE = os.path.normpath(
    os.path.join(ROOT, "..", "plane-b", "analyze.py"))
CONDITIONS = ["baseline", "mitig", "attack", "attack_mitig"]


def _load_plane_b():
    """Import boot_ci and mann_whitney from plane B's analyze.py by path, so
    the two planes share one definition of the statistics rather than a copy
    that can drift."""
    spec = importlib.util.spec_from_file_location("pb_analyze", PLANE_B_ANALYZE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.boot_ci, mod.mann_whitney


boot_ci, mann_whitney = _load_plane_b()


def read_csv(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return list(csv.DictReader(f))


def read_kv(path):
    d = {}
    for row in read_csv(path):
        d[row.get("key")] = row.get("value")
    return d


def cell_metrics(cell_dir, exp):
    """One repetition -> dict of metrics."""
    # offered: what the patients published
    offered = 0
    for p in glob.glob(os.path.join(cell_dir, "sent_*.csv")):
        offered += len(read_csv(p))

    # gateway deliveries and ACK latency, legitimate traffic only
    delivered = 0
    lat = []
    for row in read_csv(os.path.join(cell_dir, "hl7_sent.csv")):
        if row.get("ok") == "1":
            delivered += 1
            try:
                t_sent = float(row["t_sent"])
                t_ack = float(row["t_ack"])
                lat.append((t_ack - t_sent) * 1000.0)
            except (ValueError, KeyError):
                pass
    pdr = delivered / offered if offered else float("nan")
    lat_med = float(np.median(lat)) if lat else float("nan")
    lat_p95 = float(np.percentile(lat, 95)) if lat else float("nan")

    # listener resource use
    cpu = rss = float("nan")
    rrows = read_csv(os.path.join(cell_dir, "listener_resource.csv"))
    if rrows:
        cpus = [float(r["cpu_pct"]) for r in rrows if r.get("cpu_pct")]
        rsss = [float(r["rss_kb"]) for r in rrows if r.get("rss_kb")]
        # drop the primed first sample
        if len(cpus) > 1:
            cpu = float(np.mean(cpus[1:]))
        if rsss:
            rss = float(np.max(rsss))

    m = {"pdr": pdr, "lat_ms": lat_med, "lat_p95": lat_p95,
         "cpu": cpu, "rss_kb": rss,
         "forged_accept": float("nan"), "forged_persist": float("nan"),
         "atk_established": float("nan")}

    if exp == "e6a":
        # A tamper.csv exists only when the forging peer ran (attack,
        # attack_mitig). When it ran but sent nothing, the mitigation stopped
        # it before a single message -- forged acceptance and persistence are
        # then 0.0 (fully prevented), not NaN (undefined). NaN is reserved for
        # baseline/mitig, where no forger ran at all, so the two cases stay
        # distinguishable in the summary.
        tam_path = os.path.join(cell_dir, "tamper.csv")
        if os.path.exists(tam_path):
            tam = read_csv(tam_path)
            sent = len(tam)
            acc = sum(1 for r in tam if r.get("ack_code") == "AA")
            m["forged_accept"] = acc / sent if sent else 0.0
            recv = read_csv(os.path.join(cell_dir, "hl7_recv.csv"))
            forged_ids = {r["msg_id"] for r in tam}
            m["forged_persist"] = float(sum(
                1 for r in recv
                if r.get("msg_id") in forged_ids and r.get("ack") == "AA"))
    else:
        ex = read_kv(os.path.join(cell_dir, "exhaust.csv"))
        if ex:
            try:
                m["atk_established"] = float(ex.get("established", "nan"))
            except ValueError:
                pass
    return m


def main():
    if not os.path.isdir(RES):
        print("no results/ yet; run sweep_e6.sh first")
        return
    scales = sorted({int(os.path.basename(d)[1:])
                     for d in glob.glob(os.path.join(RES, "*", "*", "s*"))})
    out_rows = []
    series = {}

    for exp in ("e6a", "e6b"):
        for cond in CONDITIONS:
            for s in scales:
                reps = sorted(glob.glob(
                    os.path.join(RES, exp, cond, f"s{s}", "r*")))
                if not reps:
                    continue
                m = [cell_metrics(r, exp) for r in reps]
                for key in ("pdr", "lat_ms", "lat_p95", "cpu", "rss_kb",
                            "forged_accept", "forged_persist",
                            "atk_established"):
                    series[(exp, s, cond, key)] = [x[key] for x in m]
                pdr = boot_ci([x["pdr"] for x in m])
                lat = boot_ci([x["lat_ms"] for x in m])
                p95 = boot_ci([x["lat_p95"] for x in m])
                cpu = boot_ci([x["cpu"] for x in m])
                fa = boot_ci([x["forged_accept"] for x in m])
                fp = boot_ci([x["forged_persist"] for x in m])
                ae = boot_ci([x["atk_established"] for x in m])
                out_rows.append({
                    "exp": exp, "condition": cond, "scale": s, "reps": len(m),
                    "pdr_med": round(pdr[0], 4),
                    "pdr_lo": round(pdr[1], 4), "pdr_hi": round(pdr[2], 4),
                    "ack_ms_med": round(lat[0], 3),
                    "ack_ms_lo": round(lat[1], 3), "ack_ms_hi": round(lat[2], 3),
                    "ack_ms_p95": round(p95[0], 3),
                    "cpu_med": round(cpu[0], 2),
                    "rss_kb_med": round(boot_ci([x["rss_kb"] for x in m])[0], 0),
                    "forged_accept_med": round(fa[0], 4),
                    "forged_persist_med": round(fp[0], 1),
                    "atk_established_med": round(ae[0], 1),
                })

    # headline comparisons
    for exp in ("e6a", "e6b"):
        for s in scales:
            base = series.get((exp, s, "baseline", "lat_ms"))
            mit = series.get((exp, s, "mitig", "lat_ms"))
            atk = series.get((exp, s, "attack", "pdr"))
            atkm = series.get((exp, s, "attack_mitig", "pdr"))
            if base and mit:
                print(f"[{exp} s{s}] mitigation ACK-latency cost "
                      f"(baseline vs mitig): p={mann_whitney(base, mit):.4g}")
            if atk and atkm:
                print(f"[{exp} s{s}] mitigation efficacy on gateway PDR "
                      f"(attack vs attack_mitig): p={mann_whitney(atk, atkm):.4g}")
            if exp == "e6a":
                fa_atk = series.get((exp, s, "attack", "forged_accept"))
                fa_atkm = series.get((exp, s, "attack_mitig", "forged_accept"))

                def _med(v):
                    v = [x for x in (v or []) if not np.isnan(x)]
                    return np.median(v) if v else float("nan")
                if fa_atk or fa_atkm:
                    print(f"[{exp} s{s}] forged acceptance "
                          f"attack={_med(fa_atk):.3f} "
                          f"attack_mitig={_med(fa_atkm):.3f}")

    if not out_rows:
        print("no E6 cells found under results/")
        return
    summ = os.path.join(RES, "e6_summary.csv")
    with open(summ, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(out_rows[0].keys()))
        w.writeheader()
        w.writerows(out_rows)
    print(f"[*] wrote {os.path.relpath(summ, ROOT)} ({len(out_rows)} rows)")


if __name__ == "__main__":
    main()
