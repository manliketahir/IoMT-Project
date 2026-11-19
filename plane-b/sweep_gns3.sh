#!/usr/bin/env bash
# E2 sweep on the GNS3 topology. Runs ON the GNS3 VM and drives the containers
# through run_gns3.py. There is no host-side ratelimit.sh here: run_gns3.py
# applies the per-source rate limit inside the broker container for the
# e2a/e2c/e2d mitigation conditions.
#
# Usage:  bash sweep_gns3.sh [reps] [duration] [exp...]
# Defaults: 10 reps, 60 s, experiments "e2a e2b". Scale is 10:
# GNS3 gives network realism at scale 10; the
# loopback harness still gives the 10/30/60 scaling curve.
#
# Robustness (a first sweep was silently corrupted when the topology was
# stopped underneath it):
#   * resume  - a cell whose directory holds DONE is skipped, so a stopped sweep
#               can simply be started again;
#   * retry   - a cell that exits 3 (INVALID: truncated data, a node restarted
#               mid-cell, broker failed to start) is moved to results_invalid/
#               and re-run, up to 3 attempts;
#   * abort   - a cell that exits 4 (TOPOLOGY DOWN: nodes not running or links
#               gone) stops the sweep, since every later cell would fail too.
#               Restart the nodes in GNS3, then re-run this script to resume.
# Only cells with DONE remain under results/, so analyze.py never sees bad data.
set -uo pipefail
cd "$(dirname "$0")"

REPS="${1:-10}"
DUR="${2:-60}"
shift 2 2>/dev/null || true
if [ "$#" -gt 0 ]; then EXPS=("$@"); else EXPS=(e2a e2b); fi
SCALE=10
MAX_TRIES=3

total=$(( ${#EXPS[@]} * 4 * REPS )); n=0
echo "[sweep] start $(date -Is)  exps=${EXPS[*]}  reps=$REPS  dur=${DUR}s  cells=$total"

for exp in "${EXPS[@]}"; do
  for cond in baseline mitig attack attack_mitig; do
    for r in $(seq 1 "$REPS"); do
      n=$((n + 1))
      cell="results/$exp/$cond/s$SCALE/r$r"
      if [ -f "$cell/DONE" ]; then
        echo "=== [$n/$total] $exp / $cond / r$r : already DONE, skipping ==="
        continue
      fi
      for try in $(seq 1 "$MAX_TRIES"); do
        echo "=== [$n/$total] $exp / $cond / r$r  (attempt $try) $(date +%T) ==="
        python3 -u run_gns3.py --exp "$exp" --condition "$cond" \
          --scale "$SCALE" --rep "$r" --duration "$DUR"
        rc=$?
        if [ "$rc" -eq 0 ]; then
          break
        fi
        if [ -d "$cell" ]; then
          dest="results_invalid/$exp/$cond/s$SCALE/r${r}_try${try}_$(date +%H%M%S)"
          mkdir -p "$(dirname "$dest")" && mv "$cell" "$dest"
          echo "[sweep] attempt kept for inspection: $dest"
        fi
        if [ "$rc" -eq 4 ]; then
          echo "[sweep] TOPOLOGY DOWN at $exp/$cond/r$r -- stopping. Start the" \
               "nodes in GNS3 and re-run this script; finished cells are kept."
          echo "[sweep] STOPPED $(date -Is)"
          exit 4
        fi
        echo "[sweep] cell invalid (rc=$rc); retrying in 5 s"
        sleep 5
      done
      if [ ! -f "$cell/DONE" ]; then
        echo "[sweep] GAVE UP on $exp/$cond/r$r after $MAX_TRIES attempts"
      fi
      sleep 2
    done
  done
done
done_cells=$(find results -name DONE 2>/dev/null | wc -l)
echo "[sweep] COMPLETE $(date -Is)  valid cells under results/: $done_cells"
