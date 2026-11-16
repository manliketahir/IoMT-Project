#!/usr/bin/env bash
# Driver for the three review fixes that need runs. Additive: it does not touch
# the existing results/e2a and results/e2b data behind summary-final.csv.
#
#   Fix 2  e2c hardened sweep       -> results/e2c/            (defense-in-depth)
#   Fix 3  no-connect probe         -> results/noconnect/      (pre-CONNECT flood)
#   Fix 4  distributed bypass       -> results/distributed/    (many sources)
#
# Focused demonstration at the worst-case scale (60 patients). Parameters are
# smaller than the main sweep (REPS reps x DUR s, scale 60) and are recorded in
# the progress report. Run from the plane-b root inside Kali WSL.
set -u
cd "$(dirname "$0")"
PY=.venv/bin/python3
REPS="${1:-5}"
DUR="${2:-30}"
SCALE=60

kill_brokers() { pkill -f "mosquitto -c" 2>/dev/null || true; sleep 0.5; }

echo "############ FIX 2: e2c hardened sweep (scale $SCALE, $REPS reps, ${DUR}s) ############"
for cond in baseline mitig attack attack_mitig; do
  for r in $(seq 1 "$REPS"); do
    rl=0
    if [ "$cond" = "mitig" ] || [ "$cond" = "attack_mitig" ]; then
      bash src/ratelimit.sh on 8883 && rl=1
    fi
    $PY run.py --exp e2c --condition "$cond" --scale "$SCALE" --rep "$r" --duration "$DUR"
    [ "$rl" = "1" ] && bash src/ratelimit.sh off 8883
    sleep 1
  done
done

echo "############ FIX 3: no-connect (pre-CONNECT) probe ############"
mkdir -p results/noconnect
kill_brokers
# (a) hardened listener, cap = 100: does the cap bound silent TCP sockets?
mosquitto -c mosquitto/hardened.conf >results/noconnect/hardened_broker.log 2>&1 &
BPID=$!; sleep 1
$PY src/monitor.py --pid "$BPID" --outfile results/noconnect/hardened_broker.csv &
MPID=$!
$PY src/attack_conn_exhaust.py --host 127.0.0.1 --port 8883 --no-connect \
    --count 300 --duration "$DUR" \
    --outfile results/noconnect/hardened_attack.csv \
    --liveness results/noconnect/hardened_liveness.csv
kill "$MPID" 2>/dev/null || true
kill_brokers
# (b) plain listener, no cap: baseline for how many silent sockets persist
mosquitto -c mosquitto/baseline.conf >results/noconnect/baseline_broker.log 2>&1 &
BPID=$!; sleep 1
$PY src/attack_conn_exhaust.py --host 127.0.0.1 --port 1883 --no-connect \
    --count 300 --duration "$DUR" \
    --outfile results/noconnect/baseline_attack.csv \
    --liveness results/noconnect/baseline_liveness.csv
kill_brokers

echo "############ FIX 4: distributed per-source rate-limit bypass ############"
mkdir -p results/distributed
rm -f results/distributed/summary.csv
kill_brokers
# broker = e2a cap (100) on 1883, with the per-source nft rate limit on
mosquitto -c mosquitto/e2a_mitig.conf >results/distributed/broker.log 2>&1 &
BPID=$!; sleep 1
bash src/ratelimit.sh on 1883
$PY src/attack_distributed.py --sources 1 --per-source-count 200 --duration "$DUR"
kill_brokers
mosquitto -c mosquitto/e2a_mitig.conf >>results/distributed/broker.log 2>&1 &
BPID=$!; sleep 1
$PY src/attack_distributed.py --sources 8 --per-source-count 200 --duration "$DUR"
bash src/ratelimit.sh off 1883
kill_brokers

echo "############ ANALYZE ############"
$PY analyze.py
echo "ALL-FIXES-DONE"
