#!/usr/bin/env bash
# Full E6 sweep: both sub-experiments, four conditions, one scale, N reps.
#   e6a = HL7 result tampering     (allow-list + mutual TLS)
#   e6b = connection exhaustion    (per-peer connection cap)
#
# 2 x 4 x 10 = 80 runs. At 60 s each plus teardown, ~1.5 h.
#
# Usage:  bash sweep_e6.sh [reps] [duration] [scale]
# Defaults: 10 reps, 60 s, scale 30. First smoke test: bash sweep_e6.sh 1 20
set -euo pipefail
cd "$(dirname "$0")"

REPS="${1:-10}"
DUR="${2:-60}"
SCALE="${3:-30}"

for exp in e6a e6b; do
  for cond in baseline mitig attack attack_mitig; do
    for r in $(seq 1 "$REPS"); do
      python3 run_e6.py --exp "$exp" --condition "$cond" \
        --scale "$SCALE" --rep "$r" --duration "$DUR"
      sleep 1
    done
  done
done
echo "[*] E6 sweep complete. Now: python3 analyze_e6.py"
