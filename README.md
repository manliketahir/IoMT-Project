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

> **E2 and E6 run on a GNS3-emulated network**, with one container per role on
> emulated Ethernet, at 10 patients. This is the platform for all further work.
> The original single-host loopback harness is **retired**; its results (at
> 10/30/60 patients) are kept below as the earlier-stage results. See
> [E2 and E6 on GNS3](#e2-and-e6-on-gns3) and [GNS3-NODE-ACCESS.md](GNS3-NODE-ACCESS.md).

**Current work**

| Experiment | Plane | Control evaluated | Status |
|---|---|---|---|
| **E2** | **B — ward** | **Connection limits, mutual TLS, ACLs** | **Complete**: loopback (E2a–E2d, 10/30/60 patients) and GNS3 (E2a, E2b, 10 patients) |
| **E6** | **C — clinical** | **Allow-list, mutual TLS on MLLP, per-peer cap** | **Complete**: loopback (E6a, E6b, 30 patients) and GNS3 (E6a, E6b, 10 patients) |

**Future work**

| Experiment | Plane | Control evaluated | Depends on |
|---|---|---|---|
| E1 | A — sensor | Trust-based isolation | The Contiki-NG / Cooja sensor plane |
| E3 | B — ward | SDN IP–MAC binding | Open vSwitch + SDN controller in the GNS3 network |
| E4 | C — clinical | Tiered DDS Security | An OpenICE/DDS deployment |
| E5 | B → C | Ward segmentation, lateral movement | Open vSwitch + SDN controller in the GNS3 network |
| E7 | A — sensor | OSCORE, identity binding at the bridge | The sensor plane |

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

## E2 and E6 on GNS3

Both experiments also run on a GNS3-emulated network, at 10 patients and 10
repetitions per condition. Every role is a Docker container with its own
address on emulated Ethernet. The design, conditions, mitigations and statistics
are the same as on loopback. The loopback harness is retired, and the loopback
results above are kept as the earlier-stage results. [GNS3-NODE-ACCESS.md](GNS3-NODE-ACCESS.md) explains how to reach and
inspect every node; [GNS3-GUIDE.md](GNS3-GUIDE.md) explains how the GNS3 setup
was built and why.

**Topologies** (one GNS3 project, two separate labelled networks):

- **E2**: one switched segment, `10.0.0.0/24`. Broker `.10`, collector `.20`,
  attacker `.100`, patients `.101`–`.110`.
- **E6**: the proposal's planes, without the DDS stage. The ward (plane B,
  `10.0.6.0/24`) holds the broker and patients; the clinical segment (plane C,
  `10.0.7.0/24`) holds the HL7 listener, the gateway and the attacker; a router
  joins them. Only the gateway's MQTT subscription crosses the router, standing
  in for the MQTT→DDS link. The MLLP hop under test, and the attacker, are
  inside plane C.

**Platform, and a clock correction you need to know about.** On the development
host WSL 2 keeps the Windows hypervisor on.
- VirtualBox's GNS3 VM froze for minutes at a time there (kernel soft lockups
  of 45–239 s), even at 2 vCPUs with nested virtualization off, and was
  rejected.
- The VMware Workstation GNS3 VM is stable, but its virtual clock runs at a
  measured, steady **0.900** of real time (0.89987–0.90013 over 151 minutes,
  against Windows' NTP-synced clock).
- Counts, delivery ratios, attack outcomes, CPU % and Mann–Whitney p-values are
  unaffected by that factor.
- **Absolute latencies read 10 % low.** The GNS3 latencies below are corrected
  (measured ÷ 0.900), and `analyze_gns3.py` writes both values.
- Every run is also checked, and repeated, if a node restarted, a patient's log
  is short, the VM kernel logged a stall, or any patient went more than 3 s
  between readings.

### E2 on GNS3 (10 patients, 10 repetitions, all 80 runs valid)

| Sub-exp. | Condition | PDR | Latency, ms (as measured) | Attack outcome |
|---|---|---|---|---|
| E2a | baseline | 1.00 | 0.811 (0.73) | — |
| E2a | mitig | 1.00 | 0.822 (0.74) | — |
| E2a | attack | 1.00 | 0.822 (0.74) | flood 400/400 connected |
| E2a | attack_mitig | 1.00 | 0.811 (0.73) | flood 311–312 connected, 60 refused |
| E2b | baseline | 1.00 | 0.789 (0.71) | — |
| E2b | mitig | 1.00 | 0.922 (0.83) | — |
| E2b | attack | 1.00 | 0.822 (0.74) | unauthorised publish accepted; malformed frame parsed |
| E2b | attack_mitig | 1.00 | 0.911 (0.82) | both blocked at TLS (300 of 300 attempts) |

- **Cost:** E2a +0.011 ms (*p* = 0.031); E2b +0.133 ms (*p* = 0.00018).
- **Efficacy:** delivery stays at 1.00, as on loopback, because the patients
  connect before the attack. E2d is what measures efficacy on delivery, and it
  has not yet been re-run on GNS3. The attack outcomes above were identical in
  all ten repetitions.
- **What the network adds:** about 0.8 ms end to end, roughly twice the
  0.36–0.52 ms loopback floor at the same scale.

### E6 on GNS3 (10 patients, 10 repetitions, all 80 runs valid)

| Sub-exp. | Condition | Delivery | ACK latency, ms (as measured) | Attack outcome |
|---|---|---|---|---|
| E6a | baseline | 1.00 | 0.451 (0.406) | — |
| E6a | mitig | 1.00 | 0.554 (0.499) | — |
| E6a | attack | 1.00 | 0.477 (0.429) | 299 forged results, all accepted and stored |
| E6a | attack_mitig | 1.00 | 0.571 (0.514) | forger never connects; 0 accepted |
| E6b | baseline | 1.00 | 0.857 (0.771) | — |
| E6b | mitig | 1.00 | 0.863 (0.777) | — |
| E6b | attack | **0.00** | — | flood holds all 100 slots; 800 refused, incl. all 600 gateway attempts |
| E6b | attack_mitig | **1.00** | 0.872 (0.785) | flood capped at 20 slots, 280 refused |

- **Cost:** E6a (allow-list + mutual TLS) +0.103 ms (*p* = 0.00018), against
  +0.051 ms on loopback. E6b's per-peer cap costs nothing measurable
  (+0.006 ms, *p* = 0.17).
- **Efficacy:** the same as loopback. Forged-result acceptance falls from 1.000
  to 0.000; gateway delivery under the flood goes from 0.00 to 1.00
  (*p* = 1.59×10⁻⁵). Every count above was identical in all ten repetitions.
- **What the network adds:** the MLLP round trip is about 0.45 ms on a
  persistent connection (E6a) and 0.86 ms with one connection per message
  (E6b), roughly 2.4× and 2.0× loopback. Indicative only: loopback E6 ran at
  30 patients.
- The single TLS failure the listener logs in each mutual-TLS run is the
  orchestrator's readiness probe (a plain TCP connect from inside the listener
  container), not an attack.
- The clock factor held at 0.89986–0.90010 over the 120-minute E6 sweep.

### What the migration exposed

- **TLS version.** The GNS3 broker (Debian's Mosquitto 2.0.11) negotiates
  **TLS 1.3** even with `tls_version tlsv1.2`; the loopback broker used TLS 1.2.
  Mutual-TLS costs from the two environments are therefore not like for like.
- **`attack_malformed.py` mislabelled its outcome under TLS 1.3.** It took a
  completed client-side handshake to mean its bytes reached the MQTT parser.
  It also sent before reading, which raced the server's certificate-required
  alert and lost it in 52 of 300 attempts. Under TLS it now reads before
  sending, and it writes `attack_tally.csv` with every attempt's outcome. The
  TLS 1.2 path is unchanged, so the loopback results are unaffected.
- **AppArmor.** The GNS3 VM confines Mosquitto to `/etc/mosquitto/`, so the
  orchestrator stages the broker's config, certificates and ACL there for each
  run.

---

## Layout

```
GNS3-NODE-ACCESS.md  Reaching and inspecting every GNS3 node (consoles, SSH, captures)
GNS3-GUIDE.md        How GNS3 was set up and the testbed migrated (VMware, clock, design)

plane-a/          Sensor plane — documented setup procedure only
  GUIDE.md

plane-b/          Ward plane — MQTT over Mosquitto (E2), and the B→C boundary
  Dockerfile          GNS3 node image (iomt-node:1.0), built inside the GNS3 VM
  gns3_build_e2.py    Builds the E2 topology through the GNS3 API (idempotent)
  run_gns3.py         GNS3 per-cell orchestrator (docker exec; validity checks)
  sweep_gns3.sh       GNS3 E2 sweep: resume, retry invalid runs, stop if the topology is down
  analyze_gns3.py     Runs a plane's analyser on GNS3 results + clock correction
  gns3_clock_e2.csv   VM clock vs Windows clock, sampled during the E2 sweep
  results-gns3/       GNS3 E2 summaries, clock-corrected summary, loopback comparison
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
  Dockerfile          GNS3 E6 image (iomt-node:1.1 = 1.0 + plane-c + hl7apy 1.3.5)
  .dockerignore       Keeps TLS material out of that image
  gns3_build_e6.py    Builds the E6 topology (ward + clinical segments, router)
  run_gns3_e6.py      GNS3 E6 orchestrator (reuses plane-b/run_gns3.py's checks)
  sweep_gns3_e6.sh    GNS3 E6 sweep
  gns3_clock_e6.csv   VM clock log for the E6 sweep
  results-gns3/       GNS3 E6 summaries
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
  per-run CSV files, on loopback and on GNS3 alike. These are regenerable from
  the sweep scripts and are excluded; the aggregated summaries, plots and clock
  logs are kept. If the raw data is
  needed for a data-availability statement it should be archived separately with
  a DOI rather than held here.
- **TLS material.** Private keys and certificates are excluded. Each plane's
  `certs/make-certs.sh` regenerates them, so a fresh clone remains reproducible.
- **Virtual environments and caches.**

---

## Running it

The loopback harness is retired; the steps below reproduce its earlier-stage
results only. New runs use GNS3 ([On GNS3](#on-gns3)). It requires Python 3,
Mosquitto, OpenSSL and nftables on a Linux host, and was run on Kali under
WSL 2.

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

### On GNS3

You need GNS3 2.2 with a GNS3 VM (VMware was used; see the platform note
above), and this repository copied into the VM: `plane-b` as `~/testbed`, a link
`~/plane-b → ~/testbed`, and `plane-c` as `~/plane-c`, with the HL7 certificates
in `~/plane-c/certs`.

1. On the GNS3 VM, build the node images:

   ```bash
   cd ~/testbed && docker build -t iomt-node:1.0 .
   ```

   ```bash
   cd ~/plane-c && docker build -t iomt-node:1.1 .
   ```

2. On the Windows host, with GNS3 open, build the topologies and start the nodes:

   ```bash
   python plane-b/gns3_build_e2.py
   ```

   ```bash
   python plane-c/gns3_build_e6.py
   ```

3. On the GNS3 VM, run the sweeps. Each is resumable and is best started
   detached, for example with `nohup setsid … &`:

   ```bash
   cd ~/testbed && bash sweep_gns3.sh 10 60 e2a e2b
   ```

   ```bash
   cd ~/plane-c && bash sweep_gns3_e6.sh 10 60 e6a e6b
   ```

4. Copy each `results/` folder back as `results-gns3/`, log the VM clock during
   the sweep (see `gns3_clock_e2.csv` for the format), and analyse:

   ```bash
   python3 plane-b/analyze_gns3.py e2
   ```

   ```bash
   python3 plane-b/analyze_gns3.py e6
   ```

---

## Current limitations

These are deliberate simplifications of the present implementation, recorded so
they are not mistaken for oversights.

1. **The GNS3 network is switched, but not software-defined.** The switches are
   plain learning switches; Open vSwitch and the SDN controller are not yet stood
   up. The results therefore still cover host- and application-layer controls
   only — broker configuration, mutual TLS, nftables packet filtering, listener
   connection limits. E3 and E5 cannot run until that layer exists. On GNS3, E2
   and E6 run at 10 patients only, and E2c and E2d have not been re-run there.
   - The emulated links are not bandwidth-limited, so the floods are not
     constrained as a remote attacker's would be, and every node shares the
     GNS3 VM's two CPUs.
   - The source separation is cleaner than a real deployment's: every node has
     its own address and there is no NAT. The efficacy figures for source-based
     controls (allow-list, per-source rate limit, per-peer cap) are therefore
     best read as an **upper bound**. The shared-address case is testable on
     GNS3 but has not been tested yet.
2. **GNS3 timing depends on the host.** On a host where WSL 2 keeps the Windows
   hypervisor on, the VMware GNS3 VM's clock runs at 0.900 of real time. GNS3
   latencies are corrected for it, using the clock log recorded during each
   sweep.
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
   independently of that dependency. On GNS3 the gateway subscribes to the ward
   broker across the plane boundary, in place of the MQTT→DDS link.

---

## How the GNS3 harness differs from the loopback one

The experiment design, metrics and analysis are unchanged, so results from the
two environments stay comparable. The harness that places and drives the
components is new, in `run_gns3.py` and `run_gns3_e6.py`. The loopback scripts
are untouched, apart from the `attack_malformed.py` fix described above.

- **Addressing.** One container per role, with its own interface and address.
  The `--bind` loopback aliases are gone.
- **Process placement.** Components are launched with `docker exec` into their
  containers, and results collected with `docker cp`. Resource use is still
  measured by PID, inside the container that runs the target.
- **Where the controls live.** The E2a rate limit and the E6a allow-list run
  inside the broker and listener containers and key on real source addresses.
  The controls E3 and E5 will evaluate become Open vSwitch flow rules and
  controller policy, once that layer exists.
- **Validity.** Every run is checked for node restarts, truncated patient logs,
  VM kernel stalls and send gaps, and is repeated if any is found. A sweep
  resumes from where it stopped.

## Future work

The current work is E2 and E6. In rough order:

1. Re-run E2d (the efficacy measurement on delivery) and E2c on GNS3.
2. Take the ward → clinical boundary run from 3 repetitions to 10. The E6
   topology now provides a real boundary to run it across.
3. Add Open vSwitch and an SDN controller to the GNS3 network, then build E3
   (SDN IP–MAC binding) and E5 (ward segmentation and lateral movement).
4. E4 (tiered DDS Security), which depends on an OpenICE/DDS deployment. That
   deployment would also let E6 run through the DDS stage.
5. E1 and E7 on the sensor plane, which require the Contiki-NG / Cooja
   simulation to be brought up beyond its documented setup.

Two infrastructure improvements would strengthen every later result. A GNS3
server that doesn't go through the Windows hypervisor would remove the clock
correction. And a shared-address test, with attacker and patients behind one
address, would measure what source-based controls achieve when they cannot
cleanly separate the two.
