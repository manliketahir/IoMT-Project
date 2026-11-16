#!/usr/bin/env bash
# Full e2c (hardened / defence-in-depth) matrix, matching the main sweep:
# 4 conditions x 3 scales (10,30,60) x 10 reps x 60 s. The mitig and
# attack_mitig cells run under the per-source nftables rate limit on 8883.
# Replaces the earlier focused e2c run (scale 60, 5 reps, 30 s).
set -u
cd "$(dirname "$0")"
PY=.venv/bin/python3
REPS="${1:-10}"
DUR="${2:-60}"
SCALES=(10 30 60)

rm -rf results/e2c            # start clean so no 5-rep/30-s cells linger
pkill -f "mosquitto -c" 2>/dev/null || true; sleep 0.5

for cond in baseline mitig attack attack_mitig; do
  for s in "${SCALES[@]}"; do
    for r in $(seq 1 "$REPS"); do
      rl=0
      if [ "$cond" = "mitig" ] || [ "$cond" = "attack_mitig" ]; then
        bash src/ratelimit.sh on 8883 && rl=1
      fi
      $PY run.py --exp e2c --condition "$cond" --scale "$s" --rep "$r" --duration "$DUR"
      [ "$rl" = "1" ] && bash src/ratelimit.sh off 8883
      sleep 1
    done
  done
done

echo "############ ANALYZE ############"
$PY analyze.py
echo "E2C-MATRIX-DONE"
