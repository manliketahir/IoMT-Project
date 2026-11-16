#!/usr/bin/env bash
# One-command rebuild of the plane-B testbed, inside Kali WSL.
#
# The .venv and the TLS certificates have been lost once before, mid-analysis.
# This script rebuilds everything a run needs from a clean checkout, and ends
# with a 1-rep smoke run so you know the pipeline is sound before trusting it.
#
# Usage:  bash setup.sh [bed-count]
#   bed-count defaults to 60 (enough for the largest scale).
#
# Run it from the plane-b root. It is safe to re-run: it reuses an existing
# .venv and only regenerates certificates if they are missing.
set -euo pipefail
cd "$(dirname "$0")"
BEDS="${1:-60}"

echo "== 1. system packages (mosquitto, clients, venv) =="
if ! command -v mosquitto >/dev/null; then
  sudo apt update
  sudo apt install -y mosquitto mosquitto-clients python3-venv
fi
# We launch our own broker, so the system service must not hold the ports.
sudo systemctl disable --now mosquitto 2>/dev/null || true

echo "== 2. python virtualenv (PEP 668: no system-wide pip on Kali) =="
if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q -r requirements.txt

echo "== 3. TLS certificates (CA + server + collector + ${BEDS} beds) =="
if [ ! -f certs/ca.crt ] || [ ! -f "certs/bed-${BEDS}.crt" ]; then
  bash certs/make-certs.sh "${BEDS}"
else
  echo "   certificates present; skipping"
fi

echo "== 4. per-source rate limit tool (E2a second control) =="
if command -v nft >/dev/null; then
  echo "   nft present: E2a can use the per-source rate limit"
else
  echo "   nft absent (common on WSL kernels): E2a runs cap-only -- fine,"
  echo "   note it in the write-up as a weaker single-host defence"
fi

echo "== 5. smoke run (1 rep, 20 s) + analysis =="
# IMPORTANT: the smoke run writes to results_smoke/, never results/. A 20 s
# smoke cell lands on the same path as a 60 s sweep repetition (r1 of each
# scale), so without this it silently overwrites real sweep data and the
# reported medians, CIs and attacker counts shift. E2_RESULTS_DIR is honoured
# by run.py and analyze.py.
export E2_RESULTS_DIR=results_smoke
bash sweep.sh 1 20
python3 analyze.py
unset E2_RESULTS_DIR
echo "   (smoke output is in results_smoke/, not results/)"

echo
echo "== setup complete =="
echo "Activate the venv in every new shell before running anything:"
echo "    source .venv/bin/activate"
echo "Then: the full sweep is 'bash sweep.sh 10 60' (long), the B->C boundary"
echo "is 'python3 run_bc.py --posture plain --scale 30 --rep 1'."
