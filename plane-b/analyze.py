#!/usr/bin/env python3
"""Turn the raw CSVs under results/ into the numbers for the report.

For every (sub-experiment, condition, scale) cell it computes, per repetition:
  - delivery ratio for legitimate publishers (delivered / offered)
  - median end-to-end latency in milliseconds
  - mean broker CPU percent and peak resident memory
and, where present, the attacker's own outcome line.

Across repetitions it reports the median and a bootstrap 95% confidence
interval, and it runs Mann-Whitney U tests for the two comparisons that
matter: mitigation cost (baseline vs mitig, on latency) and mitigation
efficacy (attack vs attack_mitig, on delivery ratio). Writes
results/summary.csv and, if matplotlib is present, PNG plots per cell.
"""
import csv
import glob
import os

import numpy as np

ROOT = os.path.dirname(os.path.abspath(__file__))
# E2_RESULTS_DIR lets a throwaway run (the setup.sh smoke test) write and read
# its own tree instead of the real sweep's results/, so a 20 s smoke run can
# never overwrite a 60 s sweep repetition.
RES = os.path.join(ROOT, os.environ.get("E2_RESULTS_DIR", "results"))
CONDITIONS = ["baseline", "mitig", "attack", "attack_mitig"]


def read_csv(path):
    with open(path) as f:
        return list(csv.DictReader(f))


def cell_metrics(cell_dir):
    """One repetition -> dict of metrics."""
    offered = 0
    sent = {}
    for p in glob.glob(os.path.join(cell_dir, "sent_*.csv")):
        for row in read_csv(p):
            offered += 1
            sent[(row["pub_id"], row["seq"])] = float(row["t_send"])
    delivered = 0
    lat = []
    recv_path = os.path.join(cell_dir, "recv.csv")
    if os.path.exists(recv_path):
        seen = set()
        for row in read_csv(recv_path):
            key = (row["pub_id"], row["seq"])
            if key in sent and key not in seen:
                seen.add(key)
                delivered += 1
                try:
                    lat.append((float(row["t_recv"]) - sent[key]) * 1000.0)
                except ValueError:
                    pass
    pdr = delivered / offered if offered else float("nan")

    cpu = rss = float("nan")
    bpath = os.path.join(cell_dir, "broker.csv")
    if os.path.exists(bpath):
        rows = read_csv(bpath)
        if rows:
            cpu = float(np.mean([float(r["cpu_pct"]) for r in rows]))
            rss = float(np.max([float(r["rss_kb"]) for r in rows]))

    attack = ""
    apath = os.path.join(cell_dir, "attack.csv")
    if os.path.exists(apath):
        with open(apath) as f:
            lines = f.read().strip().splitlines()
            if len(lines) >= 2:
                attack = lines[1]

    return {"pdr": pdr,
            "lat_ms": float(np.median(lat)) if lat else float("nan"),
            "cpu": cpu, "rss_kb": rss, "attack": attack}


def boot_ci(x, stat=np.median, n=2000, lo=2.5, hi=97.5):
    x = np.asarray([v for v in x if not np.isnan(v)], dtype=float)
    if len(x) == 0:
        return float("nan"), float("nan"), float("nan")
    if len(x) == 1:
        return float(stat(x)), float(x[0]), float(x[0])
    rng = np.random.default_rng(0)
    boots = [stat(rng.choice(x, len(x), replace=True)) for _ in range(n)]
    return float(stat(x)), float(np.percentile(boots, lo)), float(np.percentile(boots, hi))


def mann_whitney(a, b):
    a = [v for v in a if not np.isnan(v)]
    b = [v for v in b if not np.isnan(v)]
    if len(a) < 2 or len(b) < 2:
        return float("nan")
    try:
        from scipy.stats import mannwhitneyu
        return float(mannwhitneyu(a, b, alternative="two-sided").pvalue)
    except Exception:
        return float("nan")


def main():
    if not os.path.isdir(RES):
        print("no results/ yet; run the sweep first")
        return
    scales = sorted({int(os.path.basename(d)[1:])
                     for d in glob.glob(os.path.join(RES, "*", "*", "s*"))})
    out_rows = []
    series = {}  # (exp, scale, cond, metric) -> list over reps

    for exp in ("e2a", "e2b", "e2c", "e2d"):
        for cond in CONDITIONS:
            for s in scales:
                reps = sorted(glob.glob(os.path.join(RES, exp, cond, f"s{s}", "r*")))
                if not reps:
                    continue
                m = [cell_metrics(r) for r in reps]
                for key in ("pdr", "lat_ms", "cpu", "rss_kb"):
                    series[(exp, s, cond, key)] = [x[key] for x in m]
                pdr = boot_ci([x["pdr"] for x in m])
                lat = boot_ci([x["lat_ms"] for x in m])
                cpu = boot_ci([x["cpu"] for x in m])
                attacks = [x["attack"] for x in m if x["attack"]]
                out_rows.append({
                    "exp": exp, "condition": cond, "scale": s, "reps": len(m),
                    "pdr_med": round(pdr[0], 4), "pdr_lo": round(pdr[1], 4), "pdr_hi": round(pdr[2], 4),
                    "lat_ms_med": round(lat[0], 2), "lat_lo": round(lat[1], 2), "lat_hi": round(lat[2], 2),
                    "cpu_med": round(cpu[0], 2),
                    "attack": attacks[0] if attacks else "",
                })

    # the two headline comparisons, per scale
    for exp in ("e2a", "e2b", "e2c", "e2d"):
        for s in scales:
            base = series.get((exp, s, "baseline", "lat_ms"))
            mit = series.get((exp, s, "mitig", "lat_ms"))
            atk = series.get((exp, s, "attack", "pdr"))
            atkm = series.get((exp, s, "attack_mitig", "pdr"))
            if base and mit:
                print(f"[{exp} s{s}] mitigation latency cost (baseline vs mitig): "
                      f"p={mann_whitney(base, mit):.4g}")
            if atk and atkm:
                print(f"[{exp} s{s}] mitigation efficacy on PDR (attack vs attack_mitig): "
                      f"p={mann_whitney(atk, atkm):.4g}")

    summ = os.path.join(RES, "summary.csv")
    with open(summ, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(out_rows[0].keys()))
        w.writeheader()
        w.writerows(out_rows)
    print(f"[*] wrote {os.path.relpath(summ, ROOT)} ({len(out_rows)} rows)")

    try:
        plot(series, scales)
    except Exception as e:
        print(f"(plots skipped: {e})")


def plot(series, scales):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    for exp in ("e2a", "e2b", "e2c", "e2d"):
        fig, (axp, axl) = plt.subplots(1, 2, figsize=(11, 4))
        x = np.arange(len(CONDITIONS))
        for s in scales:
            pdr = [np.nanmedian(series.get((exp, s, c, "pdr"), [np.nan])) for c in CONDITIONS]
            lat = [np.nanmedian(series.get((exp, s, c, "lat_ms"), [np.nan])) for c in CONDITIONS]
            axp.plot(x, pdr, marker="o", label=f"{s} patients")
            axl.plot(x, lat, marker="o", label=f"{s} patients")
        for ax, t, yl in ((axp, "Delivery ratio", "PDR"),
                          (axl, "Median latency", "ms")):
            ax.set_xticks(x)
            ax.set_xticklabels(CONDITIONS, rotation=20)
            ax.set_title(f"{exp.upper()}: {t}")
            ax.set_ylabel(yl)
            ax.grid(True, alpha=0.3)
            ax.legend()
        fig.tight_layout()
        out = os.path.join(RES, f"{exp}_summary.png")
        fig.savefig(out, dpi=130)
        print(f"[*] wrote {os.path.relpath(out, ROOT)}")


if __name__ == "__main__":
    main()
