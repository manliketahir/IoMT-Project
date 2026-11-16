# E2 build guide: four days, with the explanations you will need

This is the plan for building and demonstrating experiment **E2** (MQTT
availability and access control on the ward broker, plane B) in the time you
have. Days 1 to 3 build and run it; day 4 is the demonstration and the mapping
back to the architecture diagram for your progress report and meeting.

Everything runs inside Kali WSL over loopback. It is your own broker on your
own machine; the two attack harnesses are stimulus for measuring the defenses,
and both default to 127.0.0.1.

A note you can give the meeting up front: **E2 is one experiment inside one
plane.** It is the quickest to stand up because Mosquitto already implements
the controls it tests, and because it needs no GNS3 or SDN yet. It is the
natural first brick of plane B, and it moves into the GNS3 topology later
without changing the broker config or the scripts.

---

## Why E2 first (the one-paragraph justification)

Of the three planes, plane B has the lowest setup cost and a published result
to replicate on day 1 (the cost of TLS on MQTT, from Seoane et al.). Plane A
needs attacker and trust-mechanism code written in C inside Contiki-NG; plane
C needs OpenICE (an old Java codebase) and, for the full DDS Security work, a
licensed RTI Connext. E2's controls (a connection cap, mutual TLS, per-topic
ACLs) are all built into Mosquitto, so the work is configuration plus
measurement, not implementation. That is what makes it a three-day job.

---

## The design in one picture

Four conditions, so that two different things are measured cleanly:

```
                 no attack            under attack
no mitigation    baseline             attack
mitigation       mitig                attack_mitig

cost of the defense   = mitig        - baseline     (what you pay when calm)
efficacy of defense   = attack_mitig - attack       (what you get back under fire)
residual harm         = attack_mitig - baseline     (what still leaks through)
```

Every cell is run at 10, 30 and 60 patients, ten times each. The numbers you
report are medians with a bootstrap 95% confidence interval, and the two
headline comparisons get a Mann-Whitney U test (`analyze.py` prints them).

---

## Day 1 — Broker up, and the TLS-cost replication

**Goal:** a working broker, simulated patients, the collector, and the first
real result (the cost of TLS), so you know the measurement pipeline is sound.

1. **Set up** (see README quick start). Install `mosquitto`, create the `.venv`
   virtual environment and install the Python deps into it, generate the
   certificates, and disable the system Mosquitto service so your own broker
   binds the ports. Kali blocks system-wide pip (PEP 668), which is why the
   deps go in `.venv`; activate it with `source .venv/bin/activate` in every
   new shell before running `run.py`, `sweep.sh` or `analyze.py`.

2. **Smoke test** the pipeline:
   ```bash
   bash sweep.sh 1 20
   python3 analyze.py
   ```
   Open `results/summary.csv`. You should see `pdr_med` near 1.0 for the
   `baseline` rows and a latency figure of a few milliseconds. If `recv.csv`
   is empty, the collector could not subscribe; check `broker.log` in the same
   folder.

3. **The replication.** Run the baseline (plain MQTT) against server-TLS by
   hand so you can read the cost directly:
   ```bash
   python3 run.py --exp e2b --condition baseline --scale 30 --rep 1 --duration 60
   mosquitto -c mosquitto/tls.conf &        # server-cert TLS on 8883
   # then a collector + patients pointed at 8883 with --cafile certs/ca.crt
   ```
   Compare median latency and broker CPU between plain and TLS. **What to say
   about it:** this reproduces the direction of Seoane et al.'s finding that
   TLS adds measurable per-message and CPU cost on MQTT; your contribution is
   not the finding but that it anchors plane B to a published result.

**End of day 1 you can state:** the pipeline measures delivery, latency and
broker load correctly, and the cost of TLS is reproduced.

---

## Day 2 — Validate all four cells at one scale, and prove the mitigations bite

**Goal:** this is not for final numbers. It is to confirm, at a single scale,
that each attack has an effect without the mitigation and that the mitigation
prevents it, so day 3's long sweep is not wasted on a broken cell. Run
everything from `~/plane-b` with the venv active (`source .venv/bin/activate`).

### 2.0 Carry the cap fix into your working copy (do this first)

The E2a connection cap was raised from 50 to 100 so it sits above the largest
scale (60 patients + 1 collector = 61 connections) and does not deny service
to legitimate patients. You run from `~/plane-b`, a copy, so sync that one file
before anything else:

```bash
cp "/mnt/c/Uni/KSU CoEIA/testbed/plane-b/mosquitto/e2a_mitig.conf" ~/plane-b/mosquitto/e2a_mitig.conf
grep max_connections ~/plane-b/mosquitto/e2a_mitig.conf
```

You should see `max_connections 100`. If it still says 50, your s60 numbers
will be wrong (the cap would refuse patients on its own).

### 2.1 Set up the per-source rate limit (the second half of the E2a mitigation)

`src/ratelimit.sh` uses `nft` and needs root. Give it passwordless `nft` once
so `sweep.sh`'s `sudo -n` never stops to prompt:

```bash
echo "$USER ALL=(root) NOPASSWD: /usr/sbin/nft" | sudo tee /etc/sudoers.d/e2a-nft
sudo chmod 440 /etc/sudoers.d/e2a-nft
bash ~/plane-b/src/ratelimit.sh on 1883; bash ~/plane-b/src/ratelimit.sh off 1883
```

Watch the last line. `on via nft ...` means the firewall half works.
`staying cap-only` (WSL kernels often lack `nf_tables`) is fine and expected;
E2a then runs with the connection cap alone. Either way the sweep still runs.
Write down which one you got: it is a point to state honestly in the meeting,
because with the rate limit patients recover fully, while cap-only is a weaker
defence that may leave some patient loss at s60.

### 2.2 E2a — run the four conditions at the top scale (s60)

This is the scale the cap fix targets, so validate it here:

```bash
cd ~/plane-b && source .venv/bin/activate
for c in baseline mitig attack attack_mitig; do
  case "$c" in mitig|attack_mitig) bash src/ratelimit.sh on 1883 ;; esac
  python3 run.py --exp e2a --condition "$c" --scale 60 --rep 1 --duration 30
  case "$c" in mitig|attack_mitig) bash src/ratelimit.sh off 1883 ;; esac
done
for c in baseline mitig attack attack_mitig; do
  echo "== e2a/$c/s60 attack.csv:"; cat results/e2a/$c/s60/r1/attack.csv
done
```

**What you must see, and why.** A per-source rate limit assumes each client is
its own network source. On a single host every process would otherwise share
`127.0.0.1`, and the 60 patients together would trip the limit as if they were
one abusive source. So each patient binds its own loopback address
(`127.0.0.3` upward; `127.0.0.0/8` is all loopback on Linux), the collector
keeps `127.0.0.1`, and the connection-exhaustion harness keeps its single
`127.0.0.2`. The limit then throttles the harness's one busy source while each
patient, opening a single connection from its own address, stays under budget.
This per-client loopback mapping is the main single-host caveat for the
meeting: on a real ward each monitor already has a distinct IP.
- `mitig` must now deliver nearly all patient messages (the cap no longer
  denies them). If it still looks starved, step 2.0 did not take.
- `attack` `attack.csv` shows the harness established a large number of
  connections (e.g. `400,0,400` = established, refused, attempted).
- `attack_mitig` `attack.csv` must now show **refusals** (middle number > 0):
  the cap and rate limit turning the source away. Zero refusals means the
  mitigation is not engaging — stop and investigate before the sweep.

### 2.3 E2b — confirm the clean block story at one scale

```bash
for c in attack attack_mitig; do
  python3 run.py --exp e2b --condition "$c" --scale 30 --rep 1 --duration 30
  echo "== e2b/$c attack.csv:"; cat results/e2b/$c/s30/r1/attack.csv
done
grep -c rogue results/e2b/attack/s30/r1/recv.csv
grep -c rogue results/e2b/attack_mitig/s30/r1/recv.csv 2>/dev/null || echo 0
```

**What you must see:** `attack` records `accepted,reached-parser` with a
non-zero forged-reading count in `recv.csv`; `attack_mitig` records
`blocked-by-tls,blocked-by-tls` with **zero** forged readings. The handshake
fails for a client with no certificate, so the unauthorized publish never
happens and the malformed bytes never reach the parser. That is one control
refusing traffic at a named layer, the mitigation-first evidence the paper
argues for.

**End of day 2 you can state:** every cell behaves as the design predicts, at
one scale, so the sweep is worth running.

---

## Day 3 — The full sweep, the statistics, the figures, the write-up

**Goal:** real repetitions, confidence intervals, significance tests, figures,
and the half-page.

### 3.1 Put the day-1/day-2 spot runs aside so the sweep is pristine

```bash
cd ~/plane-b && mv results results_spot_checks
```

The full sweep writes a fresh `results/`; you keep the spot checks for
reference.

### 3.2 Run the sweep detached so it survives the terminal

A full sweep is 2 experiments x 4 conditions x 3 scales x 10 reps x 60 s, about
**4 hours** of wall time. Run it in the background and watch the log:

```bash
cd ~/plane-b && source .venv/bin/activate
nohup bash sweep.sh 10 60 > sweep.log 2>&1 &
tail -f sweep.log
```

Short on time? `bash sweep.sh 10 45` (~3 h) or `bash sweep.sh 8 45` is still
defensible; just report the rep count you actually used. `Ctrl-C` stops only
the `tail`, not the sweep. Check progress with `tail -n 5 sweep.log`; it prints
`sweep complete` at the end. `sweep.sh` toggles the rate limit around the E2a
mitig cells for you.

### 3.3 Analyse

```bash
cd ~/plane-b && source .venv/bin/activate
python3 analyze.py
```

This rewrites `results/summary.csv` (now `reps=10`, with real confidence
intervals), prints the Mann-Whitney p-values per scale, and writes
`results/e2a_summary.png` and `results/e2b_summary.png`. Read the printed
lines, two per experiment per scale: `mitigation latency cost (baseline vs
mitig)` is the price of the defence when calm; `mitigation efficacy on PDR
(attack vs attack_mitig)` is the delivery won back under attack. Expect that
efficacy line to be near-flat for E2a: patient delivery stays about 1.0 there
because a local broker tolerates idle connections, so E2a's result lives in
broker load and the attacker's established/refused counts, not in PDR (see 3.5).

### 3.4 Copy results to Windows so they open in the slides

```bash
cp -r ~/plane-b/results "/mnt/c/Uni/KSU CoEIA/testbed/plane-b/"
```

### 3.5 Write the half-page (one short paragraph per sub-experiment)

E2a and E2b report different headline metrics. E2a is a **load** result:
patient delivery stays about 1.0 in every cell (a local broker tolerates idle
connections), so reporting E2a as a delivery experiment would make that flat
PDR look like a null finding. E2b is a **delivery and block** result. Read each
quantity off `summary.csv` as the median with its `_lo`-`_hi` 95% interval, and
pair the two headline comparisons with the p-values from 3.3:

| Quantity | E2a (load) | E2b (delivery / block) |
|---|---|---|
| **Attack effect** | attacker `established` count (the `attack` column, e.g. `400,0,400`) and broker `cpu_med`, vs baseline; PDR stays ~1.0 | forged reading delivered and malformed frame reaching the parser (`attack` = `accepted,reached-parser`) |
| **Mitigation efficacy** | table bounded and source throttled: the `established`/`refused` shift (e.g. ~400 opened in ~1s, down to ~160 over the window with refusals) and lower broker load, vs attack | both refused at the TLS layer (`blocked-by-tls`), with PDR unaffected |
| **Residual harm** | `attack_mitig` vs `baseline`: broker load still above calm | `attack_mitig` vs `baseline`: should be essentially none |
| **Cost of the defence** | `mitig` vs `baseline` on `cpu_med` (cap and rate-limit overhead) | `mitig` vs `baseline` on `lat_ms_med` and `cpu_med` (the TLS cost from day 1) |

Report PDR for E2a only to show that patient service held. Quote the broker
connection counts directionally (peak table under attack versus bounded under
mitigation), not as exact ceilings: under the firewall hook the sampler
undercounts simultaneous sockets, so `recv.csv`/PDR is the authoritative
measure of patient service.

Then one honest sentence of caveats: single host (every client, patient and
attacker alike, binds its own loopback source so the per-source rule sees them
as distinct network sources, which on a real ward they would be), WSL2 timing
is not hard-real-time so latency is indicative, and, if 2.1 gave `staying
cap-only`, that E2a ran with the connection cap but without the firewall rate
limit.

**End of day 3 you can state:** E2a and E2b each have a result with dispersion
and a significance test, plus a figure, ready for the day-4 slides where the
**Insert:** markers are.

---

## Day 4 — Demonstration and mapping to the diagram

**Goal:** show it running and place it on the architecture figure, so the
meeting sees E2 as the first realized piece of plane B.

### The live demo (about 5 minutes)

1. One terminal: `python3 run.py --exp e2b --condition attack --scale 10
   --duration 30` — show the collector receiving a forged `bed-2` reading
   (grep `recv.csv` for `rogue` or `bed-2`).
2. Same command with `--condition attack_mitig` — show `attack.csv` now says
   `blocked-by-tls`, and the forged reading is gone from `recv.csv`.
3. Show `e2b_summary.png`: delivery stays high and the forged publish is
   refused once the control is on, at the TLS latency cost from day 1.

### Mapping back to the architecture figure

Point at plane B in Figure 1 (the three-plane diagram) and connect each box to
what you built. This is the paragraph to rehearse:

- **MQTT broker (plane B).** The Mosquitto instance. In the baseline it is
  plain MQTT; the E2 mitigation adds the connection cap, mutual TLS and the
  per-topic ACL. This is the box labelled with the E2 mitigation on the right
  of plane B in the figure.
- **Attacker container (E2, E3).** In the diagram the attacker sits below the
  ward components with a dashed arrow into the broker. In this build it is the
  two harnesses (`attack_conn_exhaust.py`, `attack_malformed.py`); the dashed
  arrow is their traffic into the broker.
- **Ward clients / patients.** The `patient.py` publishers are the legitimate
  ward traffic; the **CoAP--MQTT bridge** above them in the figure is not part
  of E2 and is drawn but not yet built (it arrives with plane A and E7).
- **Measurement points (italic, left of plane B).** "flow latency, capture,
  rule counts, broker load" in the figure are exactly `recv.csv` (latency and
  delivery), `broker.csv` (broker load), and `attack.csv` (what the control
  refused). Say that the italic measurement labels in the figure are these
  CSVs.
- **What is deliberately not here yet.** Open vSwitch, the SDN controller and
  the MQTT--DDS adapter are in the plane B drawing but belong to E3 and E5;
  E2 needs none of them, which is why it is the first brick. Running E2 on a
  plain broker now and moving it behind Open vSwitch later does not change the
  broker config or the scripts, so the work carries forward.

### One honest slide on limits

- Single host: every client is on loopback, so to keep the per-source rate
  limit meaningful each patient binds its own loopback address (127.0.0.3+),
  the collector uses 127.0.0.1, and the attacker uses 127.0.0.2. On a real
  ward each device already has a distinct IP, so this mapping stands in for it.
- WSL2 timing is not hard-real-time, so latency figures are indicative; this
  is the same real-time caveat the paper already accepts for the emulated
  planes.
- E2 is plane-local. It does not yet show anything crossing a plane boundary;
  that is E3, E5 and E7.

### Progress-report framing

Done: plane B / E2 built, run under the four-condition design at three scales
with ten repetitions, one published result (TLS cost) replicated, attack
effect and mitigation efficacy measured with significance tests, and mapped to
the architecture figure. Next: put the broker behind Open vSwitch in GNS3 for
E3, and begin plane A / E1 in Cooja.
