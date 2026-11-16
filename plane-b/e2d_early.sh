#!/usr/bin/env bash
# E2d: the early-flood variant of E2a. The connection flood starts --attack-lead
# seconds before the patients, so it fills the connection table first. This is
# the scenario the review asked for: it gives patient delivery (PDR) room to
# drop, so the per-source rate limit's effect becomes measurable.
#
# Design (see broker_for in run.py): the connection cap is present in attack and
# attack_mitig, so the cap is the binding constraint. The only thing toggled
# between those two is the per-source nftables rate limit, so
#   efficacy = attack_mitig - attack   isolates the rate limit alone.
#
# Writes results/e2d/ ; does not touch e2a, e2b or e2c. Run from plane-b root.
#   Usage: bash e2d_early.sh [reps] [duration] [scale] [attack_lead]
set -u
cd "$(dirname "$0")"
PY=.venv/bin/python3
REPS="${1:-10}"
DUR="${2:-60}"
SCALE="${3:-60}"
LEAD="${4:-10}"

# Send everything to the terminal and to a log file at the same time, so the
# run can be watched live and still leaves a transcript afterwards.
# PYTHONUNBUFFERED stops run.py's prints from sitting in a pipe buffer behind
# each 60 s window, which is what makes the output look frozen.
mkdir -p results
LOG="results/e2d_run.log"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1
export PYTHONUNBUFFERED=1

TOTAL=$((REPS * 4))
CELL=0
START=$(date +%s)
echo "[$(date '+%H:%M:%S')] e2d start: reps=$REPS duration=${DUR}s scale=$SCALE lead=${LEAD}s"
echo "[$(date '+%H:%M:%S')] $TOTAL cells to run; this log is also at $LOG"

pkill -f "mosquitto -c" 2>/dev/null || true; sleep 0.5

for cond in baseline mitig attack attack_mitig; do
  for r in $(seq 1 "$REPS"); do
    CELL=$((CELL + 1))
    EL=$(( $(date +%s) - START ))
    printf '[%s] cell %2d/%-2d  %-12s rep %2d/%-2d  elapsed %dm%02ds\n' \
      "$(date '+%H:%M:%S')" "$CELL" "$TOTAL" "$cond" "$r" "$REPS" \
      $((EL / 60)) $((EL % 60))
    rl=0
    # Mitigation (= the rate limit) is on for mitig and attack_mitig only.
    if [ "$cond" = "mitig" ] || [ "$cond" = "attack_mitig" ]; then
      bash src/ratelimit.sh on 1883 && rl=1
    fi
    $PY run.py --exp e2d --condition "$cond" \
      --scale "$SCALE" --rep "$r" --duration "$DUR" --attack-lead "$LEAD"
    [ "$rl" = "1" ] && bash src/ratelimit.sh off 1883
    sleep 1
  done
done

echo "[$(date '+%H:%M:%S')] all $TOTAL cells done in $(( ($(date +%s) - START) / 60 )) min"
echo "############ ANALYZE ############"
$PY analyze.py
echo "############ E2D ROWS ############"
grep -E '^exp|^e2d' results/summary.csv || true
echo "E2D-DONE (log: $LOG)"
