#!/usr/bin/env bash
# E6 sweep on the GNS3 topology (gns3_build_e6.py). Runs ON the GNS3 VM and
# drives the E6 containers through run_gns3_e6.py. Same robustness as
# plane-b/sweep_gns3.sh: resume (cells with DONE are skipped), retry an INVALID
# cell up to 3 times (failed attempts kept under results_invalid/), and stop on
# TOPOLOGY DOWN (start the E6 nodes in GNS3, then re-run to resume).
#
# Usage:  bash sweep_gns3_e6.sh [reps] [duration] [exp...]
# Defaults: 10 reps, 60 s, "e6a e6b", scale 10.
set -uo pipefail
cd "$(dirname "$0")"

REPS="${1:-10}"
DUR="${2:-60}"
shift 2 2>/dev/null || true
if [ "$#" -gt 0 ]; then EXPS=("$@"); else EXPS=(e6a e6b); fi
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
        echo "=== [$n/$total] $exp / $cond / r$r : already DONE, skipping ==="; continue
      fi
      for try in $(seq 1 "$MAX_TRIES"); do
        echo "=== [$n/$total] $exp / $cond / r$r  (attempt $try) $(date +%T) ==="
        python3 -u run_gns3_e6.py --exp "$exp" --condition "$cond" \
          --scale "$SCALE" --rep "$r" --duration "$DUR"
        rc=$?
        [ "$rc" -eq 0 ] && break
        if [ -d "$cell" ]; then
          dest="results_invalid/$exp/$cond/s$SCALE/r${r}_try${try}_$(date +%H%M%S)"
          mkdir -p "$(dirname "$dest")" && mv "$cell" "$dest"
          echo "[sweep] attempt kept for inspection: $dest"
        fi
        if [ "$rc" -eq 4 ]; then
          echo "[sweep] TOPOLOGY DOWN at $exp/$cond/r$r -- stopping; finished cells are kept."
          echo "[sweep] STOPPED $(date -Is)"; exit 4
        fi
        echo "[sweep] cell invalid (rc=$rc); retrying in 5 s"; sleep 5
      done
      [ -f "$cell/DONE" ] || echo "[sweep] GAVE UP on $exp/$cond/r$r after $MAX_TRIES attempts"
      sleep 2
    done
  done
done
echo "[sweep] COMPLETE $(date -Is)  valid cells under results/: $(find results -name DONE 2>/dev/null | wc -l)"
