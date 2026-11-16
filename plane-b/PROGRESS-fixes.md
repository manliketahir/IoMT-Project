# E2 progress report: the three review fixes, with results

This reports the work done in response to the three review points on the E2
(MQTT) testbed, and cites the CSVs the numbers come from. The existing sweep
behind `results/summary-final.csv` was not re-run; it is untouched. The
regenerated `results/summary.csv` reproduces every `e2a` and `e2b` row of
`summary-final.csv` byte for byte, which confirms the raw per-repetition data
is intact and the added work did not disturb it. The new rows are the
combined-defence sub-experiment `e2c`.

Note on environment: the `.venv` and the TLS certificates had been deleted
since the original sweep, so both were rebuilt (paho-mqtt, psutil, numpy,
scipy, matplotlib; CA + server + collector + 60 bed certificates) before any
run. All runs are inside Kali WSL over loopback, on the author's own broker.

## The three review points and how each was answered

1. *A per-source limit is bypassed by many sources; state whether the threat
   model is a single host or distributed.* — Answered in writing
   (`THREAT-MODEL.md`) and demonstrated by a run (`results/distributed/`).
2. *Sockets that open TCP but never send CONNECT may still hold a slot; check
   how long Mosquitto holds them.* — Measured directly
   (`results/noconnect/`), with a `--no-connect` mode added to the harness.
3. *The listener is still unauthenticated/unencrypted; E2a and E2b are tested
   one at a time; a real deployment combines them.* — Combined config built
   (`mosquitto/hardened.conf`) and run as `e2c` (`results/summary.csv`).

---

## Fix 1 — threat model (writing)

`THREAT-MODEL.md` now states the scope the results hold under:

- **Single attacker host.** Every attack in `summary-final.csv` comes from one
  source address (`127.0.0.2`); the E2a headline is a single-source result.
- **Patients already connected.** `run.py` starts the attacker ~0.5 s before
  the patients, so the cap protects slots the patients already hold.
- **Global cap vs per-source rate limit.** `max_connections` bounds the table
  regardless of source count; the nftables rate limit is per-source and is
  bypassed by many sources. Fixes 2 and 4 give the evidence for this sentence.

## Fix 2 — combined (defence-in-depth) config, sub-experiment `e2c`

`mosquitto/hardened.conf` puts every control on one TLS listener: mutual TLS
(`require_certificate`), `use_identity_as_username` + the ACL, `max_connections
100`, and the per-source nftables rate limit around the run. It was run as the
**full matrix** — three scales (10, 30, 60 patients), 10 repetitions, 60 s per
run — matching the main `e2a`/`e2b` sweep. From `results/summary.csv` (median
of 10 reps; PDR is 1.0 in every one of the twelve cells):

| scale | latency ms: `baseline` → `mitig` | broker CPU %: `baseline` → `mitig` | cost p (baseline vs mitig) | `attack_mitig` attacker (est.,ref.,att.) |
|---|---|---|---|---|
| 10 | 0.40 → 0.38 | 0.14 → 0.19 | 0.47 (not significant) | `303,59,362` |
| 30 | 0.33 → 0.38 | 0.41 → 0.58 | 0.00018 | `306,57,363` |
| 60 | 0.34 → 0.40 | 0.81 → 1.15 | 0.00018 | `305,57,362` |

Reading:
- **Cost when calm** (`mitig` − `baseline`): the TLS work costs about +0.05 ms
  median latency and a broker-CPU rise that grows with scale (+0.05, +0.17,
  +0.34 points at 10/30/60). Delivery is unchanged at 1.0. The latency cost is
  statistically detectable at scales 30 and 60 (`analyze.py`:
  `baseline vs mitig p=0.00018`) but not at scale 10 (p=0.47), and is
  negligible in absolute terms at every scale.
- **Efficacy under fire** (`attack_mitig`): patient delivery stays at PDR 1.0
  at every scale. The Mann-Whitney efficacy test reports `p=nan` because PDR is
  at the 1.0 ceiling in both `attack` and `attack_mitig` — there is no variance
  to separate, which is the point: the combined defence leaves patient delivery
  perfect. The half-open flood opened ~305 TCP sockets but only **39 were still
  alive** at the end of the 60 s window at scale 60
  (`results/e2c/attack_mitig/s60/r1/attack.csv` = `305,57,362`;
  `attack_liveness.csv` final row `39`): the TLS-handshake requirement drops
  sockets that send no valid handshake, and the cap bounds the rest (60 patient
  slots + ~39 ≈ under the cap of 100). So the combined posture keeps patients
  fully served against the same flood the plain E2b listener (no cap) would
  have had to hold open — see Fix 3.

## Fix 3 — half-open / pre-CONNECT flood (`results/noconnect/`)

A `--no-connect` mode was added to `src/attack_conn_exhaust.py`: it opens TCP
sockets and sends nothing, and samples how many stay alive. Two brokers, 300
sockets, 30 s:

| broker | established (TCP) | alive, t=1 s … t=30 s |
|---|---|---|
| `baseline.conf` (no cap) | 300 | **300 for the whole 30 s** |
| `hardened.conf` (cap 100) | 300 | **100, flat for the whole 30 s** |

This answers the reviewer directly. Mosquitto 2.1.2 does **not** close a
silent pre-CONNECT peer on its own within 30 s: on the uncapped listener all
300 sockets persist (`baseline_liveness.csv`). So a socket that never sends
CONNECT does hold a slot. `max_connections` is the control that bounds it:
on the capped listener exactly 100 are held no matter that 300 were opened
(`hardened_liveness.csv`). The practical consequence is that the original E2b
listener, which had no cap, was exposed to a half-open flood; `hardened.conf`
closes that by adding the cap to the TLS listener.

## Fix 4 — distributed per-source rate-limit bypass (`results/distributed/`)

`src/attack_distributed.py` runs the flood from several loopback sources at
once, against the E2a broker (cap 100) with the per-source nftables rate limit
on. From `results/distributed/summary.csv`:

| sources | attempted | established | refused |
|---|---|---|---|
| 1 | 188 | 158 | 30 |
| 8 | 1494 | 1259 | 235 |

With the rate limit on, eight sources established **1259** connections against
**158** for one source — roughly eight times as many, and the refused fraction
is the same (~16 %) in both. The per-source meter gives each source its own
budget, so it throttles one host and not a botnet: the rate limit is bypassed
by many sources, exactly as the threat model now states. (These `established`
counts are TCP-level; the global connection cap, the control that actually
bounds the live broker table, is the one shown holding at 100 in Fix 3.)

---

## Honest limitations

- `e2c` now uses the full matrix — 3 scales (10/30/60), 10 repetitions, 60 s —
  matching `e2a`/`e2b`. The earlier focused run (scale 60, 5 reps, 30 s) has
  been replaced. The main `e2a`/`e2b` results are untouched (still 10 reps; the
  regenerated rows match `summary-final.csv` byte for byte).
- Everything is loopback on one host; the "distributed" sources are distinct
  loopback addresses, not separate machines. This shows the per-source logic
  being bypassed, not real botnet network conditions.
- `established` in the attacker CSVs is a TCP-level count (connect succeeded);
  it is not the broker's live client count, which the cap bounds.

## Files added or changed (all local, under testbed/plane-b)

- `THREAT-MODEL.md` — new (Fix 1)
- `mosquitto/hardened.conf` — new (Fix 2)
- `src/attack_distributed.py` — new (Fix 4)
- `src/attack_conn_exhaust.py` — `--no-connect` + liveness sampling (Fix 3)
- `run.py`, `analyze.py` — `e2c` sub-experiment wired in
- `run_fixes.sh` — driver for the no-connect and distributed probes (Fixes 3, 4)
- `e2c_matrix.sh` — driver for the full `e2c` matrix (Fix 2)
- `results/e2c/`, `results/noconnect/`, `results/distributed/`, regenerated
  `results/summary.csv` and `results/{e2a,e2b,e2c}_summary.png`
