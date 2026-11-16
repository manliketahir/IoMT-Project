# E6 — build status

Built and verified end to end on 2026-11-07 in Kali WSL, Python 3.14.7, on the
plane-B `.venv`. This records what exists, what it produced in verification, and
the two design decisions taken *during* the build that change the written draft.

See [E6-PLAN.md](E6-PLAN.md) for the rationale and the time plan; this file is
the as-built record.

## Status: functional. Not yet run at full scale.

All nine planned files plus two added during the build exist, compile, and pass
a four-condition verification for both sub-experiments. What remains is the full
sweep (10 reps) and the write-up — the code is done.

## Files

| File | Role |
|---|---|
| `src/hl7util.py` | MLLP framing, IEEE 11073 codes, ORU^R01 / ACK builders, range table |
| `src/hl7_listener.py` | The E6 target: MLLP server, validation, ACK, mutual TLS, per-peer + global caps, in-process allow-list |
| `src/hl7_gateway.py` | The legitimate peer (IHE PCD-01 reporter): MQTT → ORU^R01 → MLLP, persistent or per-message |
| `src/attack_hl7_tamper.py` | E6a: forges a plausible vital for a real bed |
| `src/attack_hl7_exhaust.py` | E6b: holds many MLLP connections open |
| `src/hl7_allowlist.sh` | E6a network-layer allow-list (nftables), graceful fallback |
| `run_e6.py` | Orchestrator, four conditions per sub-experiment |
| `sweep_e6.sh` | 80-run sweep driver |
| `analyze_e6.py` | Metrics, medians, bootstrap CI, Mann–Whitney (imports plane B's) |
| `certs/make-certs.sh` | CA + hl7-server + hl7-gateway (the forger gets no cert, by design) |
| `requirements.txt` (plane B) | `hl7apy>=1.3.5` added |

## Verification (scale 10, 2 reps, 12 s — a correctness check, not the result)

**E6a — result tampering**

| condition | gateway PDR | ACK ms | forged acceptance | forged persisted |
|---|---|---|---|---|
| baseline | 1.0 | 0.171 | — | — |
| mitig (allow-list + mTLS) | 1.0 | 0.226 | — | — |
| attack | 1.0 | 0.184 | **1.000** | **60** |
| attack_mitig | 1.0 | 0.222 | **0.000** | **0** |

- TLS cost = mitig − baseline = **+0.055 ms**, within noise of E2c's +0.05 ms
  MQTT TLS cost. Same CA, machine and workload, second protocol — the
  directly-comparable cross-protocol figure the plan predicted.
- Forged acceptance 1.000 → 0.000. Under `attack_mitig` the forger logs
  `conn_refused` with zero messages sent: the nftables allow-list drops it at
  the TCP layer, exactly the "never completes a TCP connection" of the draft.
- Gateway PDR is 1.0 in all four conditions: neither the attack nor the
  mitigations disturb legitimate flow. (So E6a's efficacy is read on forged
  acceptance, not on PDR — analyze_e6.py reports both, and the PDR Mann–Whitney
  is correctly undefined here because PDR is constant.)

**E6b — connection exhaustion**

| condition | gateway PDR | ACK ms | listener CPU | peak conns |
|---|---|---|---|---|
| baseline | 1.0 | 0.430 | 0.45 | 1 |
| mitig (per-peer cap) | 1.0 | 0.418 | 0.40 | 1 |
| attack | **0.0** | — | 0.90 | 100 (full) |
| attack_mitig | **1.0** | 0.405 | 0.62 | 21 |

- Cap cost ≈ 0 (0.430 → 0.418).
- Gateway fully starved (PDR 0.0) then fully recovered (1.0). Efficacy is total
  at this scale.
- The flood fills all 100 global slots; the per-peer cap confines one source to
  20, leaving the gateway served.

These are n=2 correctness numbers. The 10-rep sweep is what gets reported.

## Decisions taken during the build (both change the draft)

### 1. E6b needed a global connection ceiling and a non-persistent gateway

The first E6b build could not starve the gateway. A persistent MLLP connection
already holds its one slot and cannot be evicted, and with no global ceiling a
connection flood exhausts nothing. The draft's E6b threat is explicitly
"exhaustion by an allowed peer," which only bites when:

- the listener has a **bounded connection pool** (real interface engines do;
  an unbounded `ThreadingTCPServer` is not a realistic target), and
- the gateway **re-acquires a slot per message**, which is the draft's own
  "charting-style batches" pattern — between batches it holds nothing.

So the listener gained `--max-conns` (global ceiling, set to 100 to match the
`max_connections=100` of E2c's broker), present in **every** E6b condition as
the environment, and the gateway gained `--per-message-conn`, used in E6b. The
per-peer cap is the mitigation toggled on top. This is the same binding-
constraint structure as E2d (the cap is the environment, the finer control is
the toggled mitigation), so it is consistent with the rest of the testbed.

**Draft consequence:** §`sec:bridges`/§E6 should state the listener's bounded
pool and that E6b uses per-reading (non-persistent) connections. The persistent
path still exists and is used by E6a.

### 2. Validation is split, and kept out of the ACK timing path

hl7apy's schema validation costs 3.4 ms median, 5.9 ms p95 — measured on this
machine. That variance alone is ~30× the mutual-TLS cost E6 is trying to
measure, so schema validation in the ACK path would bury the signal. The
listener therefore validates **structurally** by default (0.001 ms: required
segments, known 11073 code, numeric range) and takes `--validate schema` as a
separate factor. The difference between the two is itself a reportable result:
HL7 conformance validation costs ~30× what encrypting the channel costs.

hl7apy also does **not** range-check values (OBX-5 = 9999 for a heart rate
passes schema validation), so a physiological range check is ours. This is why
E6a's forged value is a *plausible* 72 bpm, not an absurd one: validation is not
the defence against tampering and must not be presented as one. The allow-list
and mutual TLS are.

**Draft consequence:** "the listener validates each message" should read as two
things — structural/schema conformance (hl7apy) and physiological plausibility
(ours) — and the write-up should name which validation mode the reported sweep
used (structural).

## Known limits to state in the write-up

- **Batching.** The gateway reports per reading, not in 60 s batches. 60 s
  batching would give one message per patient per run — too few for a median
  with a CI. Per-reading gives ~1800 messages per run at scale 30. Batching
  changes the connection duty cycle (it matters to the per-peer cap) and can be
  added as a factor later; it is a stated simplification, not a silent one.
- **`tls_fail` of 1 in TLS conditions** is a teardown artefact: the gateway's
  socket is closed mid-read when the orchestrator sends SIGTERM. Gateway PDR of
  1.0 in those conditions confirms TLS itself works. If it is ever not exactly
  1, investigate.
- **Consequence boundary.** "Forged value accepted and persisted" is as far as
  the claim goes. No physiology model is coupled in, so nothing is claimed about
  clinical outcome — the same boundary the draft already sets.
- **Scale.** E6b efficacy is total at scale 10 with a 300-connection flood
  against a 100-slot ceiling. Confirm the ceiling and flood size give a clean,
  non-saturated signal at scale 30/60 in the real sweep.

## To run the real sweep

```bash
cd ~/plane-b/plane-c
source ~/plane-b/plane-b/.venv/bin/activate
bash sweep_e6.sh 10 60 30      # 80 runs, ~1.5 h
python3 analyze_e6.py          # writes results/e6_summary.csv
```

The nftables allow-list needs `sudo -n nft` (the testbed sudoers already grants
it). If it is ever unavailable the orchestrator falls back to the weaker
in-listener `--allow` and drops a `NOTE_allowlist_fallback` in the cell — check
for those before reporting E6a as a network-layer result.

## Location

Master on Windows: `C:\Uni\KSU CoEIA\testbed\plane-c`.
Runnable copy in WSL: `~/plane-b/plane-c` (sibling of `~/plane-b/plane-b`, which
`run_e6.py` reaches as `../plane-b` for the broker config and `patient.py`).
Both are plain files; nothing is committed. plane-c sits outside the plane-B git
repo — whether it joins that repo or gets its own is a question for you.
