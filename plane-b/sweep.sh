#!/usr/bin/env bash
# Run the full E2 sweep: both sub-experiments, four conditions, three scales,
# ten repetitions. For the two e2a conditions whose mitigation includes the
# per-source rate limit, turn the iptables rule on around the run.
#
# Usage:  bash sweep.sh [reps] [duration]
# Defaults: 10 reps, 60 s per run. A full sweep at the defaults is long;
# for a first smoke test try: bash sweep.sh 1 20
set -euo pipefail
cd "$(dirname "$0")"

REPS="${1:-10}"
DUR="${2:-60}"
SCALES=(10 30 60)
PORT_A=1883

# The per-source rate limit needs root. sudo -n never prompts, so if there is
# no cached/passwordless sudo it is simply skipped and E2a runs cap-only. A
# missing firewall tool never aborts the sweep (see ratelimit.sh).
needs_ratelimit() {
  [[ "$1" == "e2a" && ( "$2" == "mitig" || "$2" == "attack_mitig" ) ]]
}

for exp in e2a e2b; do
  for cond in baseline mitig attack attack_mitig; do
    for s in "${SCALES[@]}"; do
      for r in $(seq 1 "$REPS"); do
        if needs_ratelimit "$exp" "$cond"; then
          bash src/ratelimit.sh on "$PORT_A" \
            || echo "[sweep] rate limit not applied for $exp/$cond (connection cap only)"
        fi

        python3 run.py --exp "$exp" --condition "$cond" \
          --scale "$s" --rep "$r" --duration "$DUR"

        if needs_ratelimit "$exp" "$cond"; then
          bash src/ratelimit.sh off "$PORT_A" || true
        fi
        sleep 1
      done
    done
  done
done
echo "[*] sweep complete. Now: python3 analyze.py"
