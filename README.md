# IoMT Attack and Mitigation Evaluation Environment

A non-learning evaluation environment for Internet of Medical Things (IoMT)
attacks and the mitigations against them. The environment is organised as three
planes — sensor, ward and clinical — and each experiment measures two things for
one security control: its **cost** when the system is calm, and its **efficacy**
when the system is under attack.

Every experiment uses the same four-condition, mitigation-first design:

| Condition | Attack | Mitigation |
|---|---|---|
| `baseline` | no | no |
| `mitig` | no | yes |
| `attack` | yes | no |
| `attack_mitig` | yes | yes |

From which: **cost** = `mitig` − `baseline`, **efficacy** = `attack_mitig` −
`attack`, and **residual risk** = `attack_mitig` − `baseline`. Results are
reported as medians over repeated runs with bootstrap 95 % confidence intervals
and Mann–Whitney *U* tests. Both planes import one implementation of those
statistics (`plane-b/analyze.py`), so figures from different planes are directly
comparable.

---

## Status

> **This repository reflects a single-host implementation.** Every component
> runs as a local process on one machine, with roles separated by distinct
> loopback addresses. The migration to a GNS3-emulated network is planned and
> will change the scripts — see [Planned migration to GNS3](#planned-migration-to-gns3).

| Experiment | Plane | Control evaluated | Status |
|---|---|---|---|
| E1 | A — sensor | Trust-based isolation | Not implemented |
| **E2** | **B — ward** | **Connection limits, mutual TLS, ACLs** | **Complete** (E2a–E2d) |
| E3 | B — ward | SDN IP–MAC binding | Not implemented — requires the GNS3 topology |
| E4 | C — clinical | Tiered DDS Security | Not implemented — requires OpenICE/DDS |
| E5 | B → C | Ward segmentation, lateral movement | Not implemented — requires the GNS3 topology |
| **E6** | **C — clinical** | **Allow-list, mutual TLS on MLLP, per-peer cap** | **Complete** (E6a, E6b) |
| E7 | A — sensor | OSCORE, identity binding at the bridge | Not implemented |

The ward → clinical boundary run is implemented and has a first preliminary
result (3 repetitions; the completed experiments use 10).

---

## Results

### E2 — ward MQTT broker (60 patients, 10 repetitions)

| Sub-exp. | Condition | PDR | Latency (ms) | Broker CPU (%) | Attack outcome |
|---|---|---|---|---|---|
| E2c | baseline | 1.00 | 0.34 | 0.81 | — |
| E2c | mitig | 1.00 | 0.40 | 1.15 | — |
| E2d | baseline | 1.00 | 0.37 | 0.84 | — |
| E2d | attack | **0.00** | — | 0.16 | 400 established, 0 refused |
| E2d | attack_mitig | **0.63** | 0.37 | 0.58 | 337 established, 63 refused |

- The combined hardened posture (E2c) costs about **0.06 ms** of latency and
  0.34 points of broker CPU at 60 patients (*p* = 0.00018). At 10 patients the
  difference is not significant (*p* = 0.47), so the cost figure is
  scale-sensitive.
- **E2d is the early-flood variant.** In E2a–E2c the patients connect before the
  attack and hold their connections, so delivery never falls and the efficacy
  test has no variance to work with. E2d starts the flood 10 s ahead of the
  patients so delivery can fall, and it does: **0.00 → 0.63** with the
  per-source rate limit, *p* = 2.43 × 10⁻⁵. The connection cap is present in
  both attack conditions, so efficacy isolates the rate limit alone.
- Recovery is partial, not total: a per-source rate limit slows new connection
  attempts, so a persistent flood retains part of the connection table.

### E6 — clinical HL7 v2 over MLLP (30 patients, 10 repetitions, 80 runs)

**E6a — result tampering.** A peer forges a physiologically plausible vital sign
for a real bed as a well-formed `ORU^R01` message. Mitigations: an nftables
allow-list so only the gateway's address can reach the MLLP port, plus mutual
TLS on the MLLP channel.

| Condition | ACK latency (ms) | Delivery | Forged accepted | Forged persisted |
|---|---|---|---|---|
| baseline | 0.186 | 1.00 | — | — |
| mitig | 0.237 | 1.00 | — | — |
| attack | 0.188 | 1.00 | **1.000** | **300** |
| attack_mitig | 0.239 | 1.00 | **0.000** | **0** |

Cost **+0.051 ms** (*p* = 0.00018); forged acceptance **1.000 → 0.000**.
Legitimate delivery is unaffected in all four conditions, so efficacy is read on
forged acceptance rather than on delivery — the appropriate metric for an
integrity attack, which adds false data rather than removing true data. The
forged value is deliberately plausible: validation is not the defence against
tampering and is not presented as one.

**E6b — connection exhaustion.** A connection flood attempts to starve the
listener. Mitigation: a per-peer connection cap above the listener's bounded
global pool.

| Condition | Delivery | ACK latency (ms) | Peak connections |
|---|---|---|---|
| baseline | 1.00 | 0.435 | 1 |
| mitig | 1.00 | 0.435 | 1 |
| attack | **0.00** | — | 100 (pool full) |
| attack_mitig | **1.00** | 0.416 | 21 |

Efficacy is total: **0.00 → 1.00** (*p* = 1.59 × 10⁻⁵), and the cap costs
nothing measurable when calm (*p* = 0.97). Under attack the flood fills all 100
global slots and the gateway is locked out; with the cap the flood's source is
confined to 20 slots and all legitimate readings are delivered. Note that
listener CPU *falls* under attack (1.43 % → 0.78 %) — that is the outage, not
efficiency, since the listener holds idle sockets and processes almost no
messages.

### Ward → clinical boundary (30 patients, 3 repetitions — preliminary)

| Posture | End-to-end PDR | End-to-end (ms) | Ward leg | Bridge leg |
|---|---|---|---|---|
| plain | 1.00 | 0.493 | 0.400 | 0.091 |
| hardened | 1.00 | 0.491 | 0.400 | 0.089 |

No measurable difference between postures at 3 repetitions; the confidence
intervals overlap, so this supports no claim in either direction. The clinical
consumer here is a stub, not OpenICE/DDS: it establishes the boundary and the
measurement path, nothing about clinical middleware.

### Across protocols

Mutual TLS costs **+0.06 ms on MQTT** and **+0.051 ms on HL7/MLLP** — same
machine, same certificate authority, same statistics — which suggests the cost
is a property of the control rather than of the protocol. This comparison is
indicative rather than controlled: the runs differ in scale (60 against 30
patients) and the plane-B figure bundles the connection cap, rate limit and ACL
together with TLS.

---

## Layout

```
plane-a/          Sensor plane — documented setup procedure only
  GUIDE.md

plane-b/          Ward plane — MQTT over Mosquitto (E2), and the B→C boundary
  run.py              Per-cell orchestrator (E2a–E2d)
  analyze.py          Metrics, bootstrap CI, Mann–Whitney (shared by plane C)
  sweep.sh            Full E2 sweep driver
  e2c_matrix.sh       Combined hardened posture across the matrix
  e2d_early.sh        Early-flood variant — the efficacy measurement
  run_bc.py           Ward→clinical boundary run
  analyze_bc.py       Boundary metrics
  setup.sh            Environment setup
  requirements.txt
  mosquitto/          Broker configs: baseline, e2a_mitig, e2b_mitig, hardened, tls, acl
  certs/make-certs.sh CA + server + per-client certificates
  src/                patient, collector, monitor, adapter, clinical_stub,
                      ratelimit.sh, attack_conn_exhaust, attack_malformed,
                      attack_distributed
  results/            Aggregated results and plots
  E2-implementation-report.md, THREAT-MODEL.md, GUIDE.md

plane-c/          Clinical plane — HL7 v2 over MLLP (E6)
  run_e6.py           Per-cell orchestrator (E6a, E6b)
  analyze_e6.py       Metrics; imports the statistics from plane-b/analyze.py
  sweep_e6.sh         80-run sweep driver
  certs/make-certs.sh CA + listener + gateway certificates
  src/                hl7util, hl7_listener, hl7_gateway,
                      attack_hl7_tamper, attack_hl7_exhaust, hl7_allowlist.sh
  results/            Aggregated results
  E6-PLAN.md, E6-BUILD-STATUS.md
```

### What is not in the repository, and why

- **Raw per-repetition data.** The E2 and E6 sweeps produce several thousand
  per-run CSV files. These are regenerable from the sweep scripts and are
  excluded; the aggregated summaries and plots are kept. If the raw data is
  needed for a data-availability statement it should be archived separately with
  a DOI rather than held here.
- **TLS material.** Private keys and certificates are excluded. Each plane's
  `certs/make-certs.sh` regenerates them, so a fresh clone remains reproducible.
- **Virtual environments and caches.**

---

## Running it

Requires Python 3, Mosquitto, OpenSSL and nftables on a Linux host. Developed
and run on Kali under WSL 2.

```bash
cd plane-b
bash setup.sh
source .venv/bin/activate
bash certs/make-certs.sh
```

Plane B — the full E2 sweep, and the early-flood variant that carries the
efficacy result:

```bash
cd plane-b
bash sweep.sh                      # E2a–E2c across 10/30/60 patients
bash e2d_early.sh 10 60 60 10      # E2d: reps, duration, scale, attack lead
python3 analyze.py                 # writes results/summary.csv and the plots
```

Plane C — E6:

```bash
cd plane-c
bash certs/make-certs.sh
bash sweep_e6.sh 10 60 30          # 80 runs, approx. 90 minutes
python3 analyze_e6.py              # writes results/e6_summary.csv
```

A single cell, for a quick check rather than a full sweep:

```bash
cd plane-c
E6_RESULTS_DIR=results_demo python3 run_e6.py \
  --exp e6a --condition attack --scale 10 --rep 1 --duration 20
```

`E6_RESULTS_DIR` (and `E2_RESULTS_DIR` in plane B) redirects output to a
throwaway directory, so an ad-hoc run cannot overwrite recorded results.

---

## Current limitations

These are deliberate simplifications of the present implementation, recorded so
they are not mistaken for oversights.

1. **Single host, loopback interfaces.** All components run on one machine, each
   role bound to its own loopback address — in plane C the gateway at
   `127.0.0.2`, the attacking peer at `127.0.0.3`, patients from `127.0.0.4`
   upward. This is what makes the source-based controls measurable at all: an
   allow-list, a per-source rate limit and a per-peer cap all key on the source
   address, and without distinct addresses attacker and patient traffic would be
   indistinguishable on one host. Three consequences follow:
   - Absolute latencies are kernel-loopback figures and should be read as a
     floor. They contain no propagation delay, no link capacity limit, no switch
     queuing and no packet loss. The quantity the results rely on is the
     *difference* between conditions measured under identical circumstances.
   - The attacker is not bandwidth-limited as a remote attacker would be, and
     all components contend for the same CPU.
   - The source separation is cleaner than a real deployment's, so the efficacy
     figures for source-based controls are best read as an **upper bound** on
     what those controls achieve where traffic shares an address behind NAT.
2. **No emulated network.** Open vSwitch and an SDN controller are part of the
   design but are not yet stood up, so the results cover host- and
   application-layer controls only — broker configuration, mutual TLS, nftables
   packet filtering, listener connection limits — and no traffic traverses a
   switch. E3 and E5 depend on this and cannot run until it exists.
3. **Reporting cadence.** The HL7 gateway reports one message per reading rather
   than in 60 s charting-style batches, which would yield too few messages per
   run to support a median with a confidence interval. Batching changes the
   connection duty cycle and can be added as a factor.
4. **Validation is split and kept out of the timing path.** HL7 conformance
   validation costs roughly 3.4 ms, about 30 times the cost of mutual TLS, so
   including it in the acknowledgment path would bury the effect being measured.
   The listener validates structurally by default and conformance validation is
   a separate factor. The library does not range-check values, so the
   physiological plausibility check is implemented here.
5. **Consequence boundary.** Claims extend to "a forged value was accepted and
   persisted" and no further. No physiology model is coupled in, so nothing is
   claimed about clinical outcome.
6. **Clinical middleware.** The clinical consumer is the HL7 listener line, not
   OpenICE over DDS. E6 establishes the HL7 precedent for plane C
   independently of that dependency.

---

## Planned migration to GNS3

The next substantial step is to move the environment onto a GNS3-emulated
network with Open vSwitch and an SDN controller. This is the prerequisite that
gates five of the seven experiments, and it addresses limitations 1 and 2 above.

**This migration will change the scripts.** The experiment design, metrics and
analysis are intended to stay fixed so that results before and after remain
comparable, but the harness that places and drives the components changes
substantially:

- **Addressing.** Role separation by loopback address is replaced by one node
  per role with its own interface. The `--bind` arguments, the `GW_BIND` /
  `ATK_BIND` constants in `plane-c/run_e6.py`, and the sequential
  `127.0.0.{i+3}` patient allocation in `plane-b/run.py`, `plane-b/run_bc.py`
  and `plane-c/run_e6.py` all give way to per-node addressing.
- **Process placement.** The orchestrators currently spawn every component as a
  local subprocess and measure resource use by PID (`src/monitor.py --pid`).
  With components on separate nodes this becomes remote launch and per-node
  measurement, and the teardown ordering changes accordingly.
- **Where the controls live.** `src/ratelimit.sh` and
  `plane-c/src/hl7_allowlist.sh` apply nftables rules on the loopback path of a
  single host. These move onto the individual nodes, while the controls E3 and
  E5 evaluate become Open vSwitch flow rules and controller policy rather than
  host firewall rules.
- **What the measurements mean.** Once traffic crosses emulated links, the
  absolute latency figures will shift to include propagation, link capacity,
  queuing and loss. The differential results should remain the comparable
  quantity across the migration, and re-running E2 and E6 on the emulated
  network is the intended way to confirm that.

Planned order of work:

1. Take the ward → clinical boundary run from 3 repetitions to 10, so it carries
   the same weight as E2 and E6. The code already exists.
2. Stand up the GNS3 topology with Open vSwitch and an SDN controller, and
   migrate the harness as described above.
3. E3 (SDN IP–MAC binding) and E5 (ward segmentation and lateral movement),
   which depend on that topology.
4. E4 (tiered DDS Security), which depends on an OpenICE/DDS deployment.
5. E1 and E7 on the sensor plane, which require the Contiki-NG / Cooja
   simulation to be brought up beyond its documented setup.
