# Technical implementation report: experiment E2 (MQTT broker availability and access control)

November 3, 2026

## 1. Environment setup

Experiment E2 was conducted on a single Windows 11 machine running Kali Linux under WSL 2. All traffic stays on the loopback interface, and every component targets our own broker only; no GNS3 topology or Docker container is needed at this stage. Linux treats the whole 127.0.0.0/8 range as loopback, so separate source addresses were assigned to each role. This allows the firewall to tell attack traffic apart from patient traffic.

| Role | Address | Port |
|---|---|---|
| Collector (ward subscriber) | 127.0.0.1 | 1883 or 8883 |
| Single attacker host | 127.0.0.2 | 1883 or 8883 |
| Patient monitors (bed-1 to bed-60) | 127.0.0.3 to 127.0.0.62 | 1883 or 8883 |
| Distributed attacker sources | 127.0.2.1 to 127.0.2.8 | 1883 |

## 2. Software and tools used

| Component | Tool and version | Purpose |
|---|---|---|
| Broker | Eclipse Mosquitto 2.1.2 | MQTT broker under test |
| Clients | Python 3 with paho-mqtt | Simulated patients and collector |
| Measurement | psutil, numpy, scipy, matplotlib | Broker CPU and memory, statistics, plots |
| Certificates | OpenSSL 3.5.4 | A local CA, a server certificate, and 61 client certificates |
| Firewall | nftables | Per-source connection-rate limit |

The harness consists of `run.py` (runs one cell), `sweep.sh` (runs the full sweep), and `analyze.py` (creates the summary CSV and plots).

## 3. Experimental workflow

Each sub-experiment pairs an attack with the control that is meant to stop it, and is run under four conditions so that the cost of a control is measured separately from its benefit.

```
                  no attack        under attack
no mitigation     baseline         attack
mitigation on     mitig            attack_mitig

cost      = mitig - baseline
efficacy  = attack_mitig - attack
```

Every cell was run at 10, 30, and 60 patients, 10 times each, with a 60-second window. A single run proceeds as follows:

```
start broker -> start CPU/memory monitor -> start collector
     -> start attacker (attack cells only) -> start patients
     -> wait 60 s -> stop all processes -> write CSVs
```

Results are reported as the median with a bootstrap 95% confidence interval. A Mann-Whitney U test was used for latency cost (baseline vs mitig) and for delivery efficacy (attack vs attack_mitig).

## 4. Attack scenarios

| Scenario | Sub-experiment | Description |
|---|---|---|
| Connection exhaustion | E2a | A single host opens 400 MQTT connections and holds them open to fill the broker's connection table. |
| Malformed frames and unauthorized publishing | E2b | Invalid MQTT frames are sent, and a client publishes to topics belonging to other patients. |
| Half-open flood | Review probe | TCP sockets are opened and nothing is sent, so the MQTT CONNECT step never takes place. |
| Distributed flood | Review probe | The connection flood is sent from 8 source addresses at once instead of 1. |

The last two scenarios were added in response to supervisor review. The threat model covers a single attacker host with the patients already connected; the distributed probe was run to show where that model stops holding.

## 5. Mitigation mechanisms

| Configuration | Controls | Port |
|---|---|---|
| `e2a_mitig.conf` | Global connection cap (`max_connections 100`) and a per-source rate limit of 5 new connections per second (burst of 10) in nftables | 1883 |
| `e2b_mitig.conf` | Mutual TLS (`require_certificate`), the certificate name used as the username, and a per-topic ACL | 8883 |
| `hardened.conf` (E2c) | All of the above on one TLS listener | 8883 |

The cap of 100 sits above the largest legitimate population (60 patients and 1 collector) and below the volume of the flood. Mosquitto has no per-source rate limit of its own, which is why that control is applied in the firewall. E2a and E2b were first tested one at a time; E2c was added because a real ward broker would combine them.

## 6. Generated outputs and metrics

Each run writes its own folder of CSV files: `sent_*.csv` and `recv.csv` (per-message send and receive times), `broker.csv` (broker CPU and memory), `attack.csv` (connections established, refused, and attempted), and `attack_liveness.csv` (sockets still open over time). `analyze.py` combines these into `results/summary.csv` and one plot per sub-experiment. The metrics are packet delivery ratio (PDR), median end-to-end latency, and mean broker CPU.

Results at the largest scale (60 patients, 10 runs each), taken from `results/summary-final.csv` and `results/summary.csv`:

| Sub-experiment | Condition | PDR | Latency (ms) | Broker CPU (%) | Attack outcome |
|---|---|---|---|---|---|
| E2a | attack | 1.0 | 0.37 | 0.94 | 400 established, 0 refused |
| E2a | attack_mitig | 1.0 | 0.37 | 0.87 | 306 established, 56 refused |
| E2b | attack | 1.0 | 0.36 | 0.82 | Frames reached the MQTT parser |
| E2b | attack_mitig | 1.0 | 0.40 | 1.19 | Blocked at the TLS layer |
| E2c | baseline | 1.0 | 0.34 | 0.81 | None |
| E2c | mitig | 1.0 | 0.40 | 1.15 | None |
| E2c | attack_mitig | 1.0 | 0.40 | 1.21 | 305 established, 39 still open at 60 s |

Patient delivery stayed at 1.0 in every cell. The combined configuration costs about 0.06 ms of latency and 0.34 points of CPU at 60 patients (p = 0.00018); at 10 patients the latency difference is not significant (p = 0.47).

The two review probes produced the following results (`results/noconnect/` and `results/distributed/`):

| Probe | Setup | Result |
|---|---|---|
| Half-open flood, 300 sockets, 30 s | No connection cap | All 300 sockets remained open for the full 30 s |
| Half-open flood, 300 sockets, 30 s | Cap of 100 | Exactly 100 sockets were held for the full 30 s |
| Distributed flood, rate limit on | 1 source | 158 established |
| Distributed flood, rate limit on | 8 sources | 1,259 established |

This indicates that Mosquitto does not close a silent connection on its own within 30 seconds, so the connection cap is the control that bounds it. It also demonstrates that the per-source rate limit slows a single host but not a group of hosts; only the global cap still applies in that case.

## 7. Challenges encountered and how they were addressed

| Challenge | Resolution |
|---|---|
| The rate limit cannot separate attacker and patient traffic that share one address. | Each role was bound to its own loopback address (Section 1). |
| The virtual environment and certificates had been deleted after the main sweep. | Both were rebuilt from `requirements.txt` and `make-certs.sh` before the review runs; the regenerated E2a and E2b results matched `summary-final.csv` exactly. |
| The review noted three gaps: distributed attackers, half-open sockets, and controls tested in isolation. | A written threat model was added, the two probes were run, and the combined E2c configuration was tested across the full matrix (3 scales, 10 runs, 60 s). |
| The efficacy test returned no p-value (open problem). | PDR was 1.0 in both attack and attack_mitig, so the test had no variance to compare. The patients connect before the flood and hold their slots, so the attack never reduced delivery and PDR cannot show the effect of the defense. This will be addressed in future work by starting the flood before the patients connect, or by setting the cap below the patient population, so that delivery can drop without the defense. |

All experiments were run on our own machine against our own broker. The distributed sources are separate loopback addresses on one host rather than separate machines, so that probe shows how the per-source logic behaves but not real network conditions.
