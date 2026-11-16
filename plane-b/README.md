# Plane B / E2 testbed

This is a self-contained measurement harness for experiment **E2** of the
IoMT environment: MQTT availability and access control on the ward broker. It
runs entirely on one machine inside Kali WSL, over the loopback interface, so
no GNS3 or Docker is needed to start. Everything here targets the author's own
local broker only.

E2 has two sub-experiments, each pairing an attack with the broker-side
control that is meant to stop it:

| | Attack | Mitigation | Question it answers |
|---|---|---|---|
| **E2a** | connection exhaustion | connection cap + per-source rate limit | Do legitimate patients keep getting through while the connection table is under pressure, and what does the cap cost? |
| **E2b** | malformed frames + unauthorized publishing | mutual TLS + per-topic ACL | Are forged and unauthorized publishes refused, and where (TLS layer vs MQTT parser), and what does TLS cost? |

Each sub-experiment is run under **four conditions** so that cost and efficacy
are separated:

- `baseline` — legitimate traffic only, no mitigation
- `mitig` — legitimate traffic only, mitigation on → **cost** = `mitig` − `baseline`
- `attack` — attack + legitimate traffic, no mitigation
- `attack_mitig` — attack + legitimate traffic, mitigation on → **efficacy** = `attack_mitig` − `attack`

Three scales (10, 30, 60 patients) and ten repetitions, following the run
design in the paper. The middle scale of 30 matches the hospital-ward network
of Monteiro and Granjal.

## Files

```
mosquitto/    broker configs (baseline, server-TLS, e2a cap, e2b mutual-TLS+ACL) and the ACL
certs/        make-certs.sh  -> CA, server, collector, bed-1..N certificates
src/patient.py              one simulated patient monitor (publisher)
src/collector.py            the ward collector (subscriber, records receipts)
src/monitor.py              samples broker CPU / memory / connections
src/attack_conn_exhaust.py  E2a stimulus
src/attack_malformed.py     E2b stimulus
src/ratelimit.sh            per-source connection-rate limit (iptables)
run.py                      runs one cell (exp x condition x scale x rep)
sweep.sh                    runs the whole sweep
analyze.py                  -> results/summary.csv and plots
GUIDE.md                    the day-by-day plan and the detailed explanations
```

## Quick start (inside Kali WSL)

```bash
cp -r "/mnt/c/Uni/KSU CoEIA/testbed/plane-b" ~/plane-b && cd ~/plane-b
sudo apt update && sudo apt install -y mosquitto mosquitto-clients python3-venv
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
bash certs/make-certs.sh 60
sudo systemctl disable --now mosquitto    # we launch our own broker
bash sweep.sh 1 20                         # smoke test: 1 rep, 20 s
python3 analyze.py
```

Work from `~/plane-b`, not from the `/mnt/c` path, because the folder name has
a space in it that breaks shell scripts. Kali enforces PEP 668, so the Python
packages go in a virtual environment (`.venv`) rather than system-wide;
`pip install --break-system-packages` and the `apt` packages are both avoided
because Kali ships the old 1.x `paho-mqtt` API and the scripts use the 2.x one.
**Activate the environment in every new shell** before running anything:

```bash
source .venv/bin/activate
```

`run.py` launches its workers with the active interpreter, so once `.venv` is
on they all use it. See **GUIDE.md** for the full plan.
