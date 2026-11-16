# E6 — HL7 result tampering and connection exhaustion at the clinical boundary

Plan of work. E6 is the first experiment of plane C and the one that opens the
tier at the lowest risk: it depends only on HL7 v2 over MLLP, so it needs no
DDS implementation, no OpenICE, and no commercial licence.

From Draft-5, Table `tab:experiments`:

> E6 — HL7 result tampering and connection exhaustion against the clinical
> listener — plane C — Network-layer allow-list, mutual TLS on MLLP, and
> per-peer connection cap — *Forged-result acceptance; listener availability*

And from §`sec:experiments`:

> In E6, the allow-list is placed at the network layer, so a peer that is not
> on the list never completes a TCP connection. Mutual TLS on MLLP is added
> against tampering, and a per-peer connection cap against exhaustion by an
> allowed peer. [...] The legitimate peer is the HL7 gateway.

---

## 1. Why E6 and not E4

Both are plane C. E6 is the cheaper and safer of the two:

| | E6 | E4 |
|---|---|---|
| Dependency | HL7 v2 over MLLP (plain TCP framing) | A DDS stack with working Security plugins |
| Licence risk | none | T4 (origin authentication) is commercial-only on RTI; absent from Fast DDS docs; was unimplemented in OpenDDS 3.13 |
| Matrix | 2 sub-experiments × 4 conditions × 1 scale | 5 levels × 3 topic classes × 4 attackers + 3-part cost decomposition |
| Mitigation shapes | allow-list, mutual TLS, per-peer cap — all three already proven in E2 | tiered DDS Security policy, new ground |
| Role in the draft | the **independent second precedent** that keeps plane C standing if OpenICE proves impractical (§`sec:threats`) | the ICE/DDS line, which is the riskier of the two |

The draft explicitly names the HL7 line as the fallback that makes plane C
realistic without OpenICE. Building it first means the clinical tier exists
whatever happens to the DDS question.

E6 is **plane-local** (§`sec:experiments`: "E4 and E6 in the clinical plane").
Keeping plane B as the data source does not change that — both the attack and
all three mitigations sit on the MLLP hop.

## 2. What already exists and carries over

This is most of the reason E6 is affordable.

| Needed for E6 | Already have |
|---|---|
| A TCP listener that records arrivals and writes a CSV on SIGTERM | `plane-b/src/clinical_stub.py` — becomes the MLLP listener |
| A consumer of `ward/#` that maps metric → IEEE 11073 code and forwards downstream | `plane-b/src/adapter.py` — becomes the HL7 gateway |
| A connection-exhaustion harness with a separate bind address, half-open mode and a liveness sampler | `plane-b/src/attack_conn_exhaust.py` — strip the MQTT CONNECT, keep everything else |
| Per-source firewall control with graceful degradation on WSL | `plane-b/src/ratelimit.sh` — same shape, different rule |
| CA + per-identity client certificates | `plane-b/certs/make-certs.sh` — add two CNs |
| Broker-process CPU and RSS sampling | `plane-b/src/monitor.py` — unchanged, point it at the listener pid |
| Four-condition orchestration, newest-first teardown, per-cell progress line | `plane-b/run.py` / `run_bc.py` — same skeleton |
| Medians, bootstrap 95% CI, Mann–Whitney U | `plane-b/analyze.py` — `boot_ci()` and `mann_whitney()` import directly |
| The workload itself (30 patient monitors, 1 Hz, sequence-numbered) | `plane-b/src/patient.py` — unchanged |

Nothing in that right-hand column needs redesign. E6 is new protocol code
wrapped around a harness that already works.

## 3. The chain under test

```
patient.py ×30  ──MQTT──>  mosquitto  ──MQTT──>  hl7_gateway.py
   (plane B, unchanged)                               │
                                                      │ MLLP  (the hop under test)
                                                      v
                                              hl7_listener.py
                                                      │
                                              hl7_recv.csv  (what was accepted)

                     attack_hl7_tamper.py   ──MLLP──> ┤   (E6a)
                     attack_hl7_exhaust.py ──TCP───>  ┤   (E6b)
```

The gateway is the device observation reporter of IHE PCD-01: it subscribes to
the ward topics, batches per patient, and sends `ORU^R01` with IEEE 11073 codes
in the OBX segments. The listener validates and returns an ACK. Both halves are
described in Draft-5 §`sec:bridges`.

### Message shape

MLLP framing is three bytes around the payload: `0x0B <message> 0x1C 0x0D`.

```
MSH|^~\&|IOMT-GW|WARD-B|CLIN-LIS|CLIN-C|20261107120000||ORU^R01|<seq>|P|2.5
PID|1||bed-7
OBR|1||<seq>|147842^MDC_ECG_HEART_RATE^MDC
OBX|1|NM|147842^MDC_ECG_HEART_RATE^MDC||72|264864^MDC_DIM_BEAT_PER_MIN^MDC|||||F
```

`147842` is already in `adapter.py`'s `NOM_CODE` map, with SpO2 and
respiration rate alongside it. The sequence number in `MSH-10` is the same
`seq` the patient published, which is what lets end-to-end delivery be computed
against `sent_*.csv` — the identity-carrying requirement of §`sec:bridges`.

## 4. Sub-experiments

Scale is **one stated value** for E6, per §`sec:experiments` ("E5 and E6 are run
at 1 stated scale, since their size is set by the number of clinical hosts and
HL7 peers"). Use 30 patients, 1 gateway, 1 attacking peer — the middle E2 scale,
which also matches the 30-node ward of Monteiro and Granjal.

### E6a — result tampering

A rogue peer connects to the MLLP port and sends `ORU^R01` messages for a real
bed with a falsified OBX value. This is the LIS02-A laboratory-result attack of
Dupont et al. moved to HL7 v2.

Use a clinically meaningful forgery, not a malformed one: a plausible normal
heart rate for a patient whose real readings are critical. The question is
whether the listener accepts and stores it, not whether it survives a parser.

- **Mitigations:** network-layer allow-list, then mutual TLS on MLLP.
- **Primary metric:** forged-result acceptance ratio — forged messages
  returning `MSA|AA` ÷ forged messages sent.
- **Secondary:** *persistence* — forged observations present in `hl7_recv.csv`,
  i.e. whether a fabricated value reached the record a clinician would read.
  This is the "accepted and displayed" consequence boundary of §`sec:scope`,
  and the limit of what may be claimed: no physiology model is coupled in.

### E6b — connection exhaustion

Many concurrent MLLP connections, held open. Run both variants, mirroring the
E2a/E2c pair that is already validated:

- full-frame: complete MLLP messages, so the listener parses
- half-open: TCP connect and then silence, or a partial frame with no `0x1C`
  trailer — the slow-MLLP case, which probes whether the listener holds a
  thread per peer. This is `--no-connect` from `attack_conn_exhaust.py`.

- **Mitigation:** per-peer connection cap.
- **Primary metric:** listener availability — delivery ratio of the gateway's
  legitimate observations, and ACK round-trip latency (median and p95).
- **Secondary:** listener CPU and peak RSS from `monitor.py`; attacker sockets
  still alive over the hold window.

### The four conditions

Unchanged from the mitigation-first design, so `analyze.py`'s arithmetic applies
without modification:

| condition | attack | mitigation | yields |
|---|---|---|---|
| `baseline` | — | — | reference |
| `mitig` | — | on | **cost** = mitig − baseline |
| `attack` | on | — | unmitigated harm |
| `attack_mitig` | on | on | **efficacy** = attack_mitig − attack; **residual** = attack_mitig − baseline |

## 5. Run matrix

2 sub-experiments × 4 conditions × 1 scale × 10 repetitions = **80 runs**.

Ten repetitions is the stated method for emulated planes (§`sec:experiments`) —
do not trim this; it is a commitment in the draft, and the bootstrap CIs depend
on it.

At 60 s per run plus teardown: **~85 min**, unattended.

> **Run length is a decision to make before the final sweep.** The draft says
> 600 s per run. The E2 sweep that produced the current results actually ran at
> 60 s. At 600 s this sweep is ~13.5 h — fine overnight, but one bug then costs
> a day. Develop at 60 s; if the draft's 600 s has to hold, run the final sweep
> overnight once the pipeline is proven. Either way, say in the write-up which
> was used. Do not leave 600 s in the draft and 60 s in the results.

## 6. What to build

| # | File | What it does | Est. |
|---|---|---|---|
| 1 | `src/hl7_listener.py` | Subclass `hl7apy.mllp.MLLPServer`: override `get_request()` for mutual TLS, `verify_request()` for the per-peer cap; handler validates, range-checks, ACKs `MSA\|AA`/`AE`, records to `hl7_recv.csv`. | 40–50 min |
| 2 | `src/hl7_gateway.py` | From `adapter.py`: subscribe `ward/#`, build `ORU^R01`, send over MLLP, await ACK, log `t_send`/`t_ack`/ack code to `hl7_sent.csv`. | 30–40 min |
| 3 | `src/attack_hl7_tamper.py` | Rogue peer, forged OBX for a real bed, logs whether `AA` came back. | 20 min |
| 4 | `src/attack_hl7_exhaust.py` | From `attack_conn_exhaust.py`, MQTT CONNECT removed; full-frame and half-open modes; liveness sampler kept. | 15 min |
| 5 | `src/hl7_allowlist.sh` | nftables: accept the gateway source to the MLLP port, drop others. Same graceful-degradation contract as `ratelimit.sh`. | 15 min |
| 6 | `run_e6.py` | Orchestrator on the `run_bc.py` skeleton. | 30–40 min |
| 7 | `sweep_e6.sh` | 80 cells, mitigation toggled around each run. Honour `E6_RESULTS_DIR`. | 15 min |
| 8 | `analyze_e6.py` | Acceptance ratio, availability, ACK latency; imports `boot_ci` and `mann_whitney`. | 30 min |
| 9 | certs | `make-certs.sh` + CNs `hl7-gateway`, `hl7-server`. | 5 min |
| 10 | range check | Per-code plausibility bounds (hl7apy does **not** range-check; see below). | 15 min |

**Build subtotal: 3.5–4 h** — item 1 came down after the `MLLPServer` finding,
item 10 is new, so the total is unchanged.

### Decisions — both settled 2026-11-07

#### 1. HL7 library: hl7apy. Settled, with one limit.

Draft-5 §`sec:bridges` says the listener is "created with the HAPI HL7 v2
library" — HAPI is Java, so that puts a JVM in the loop for no experimental
gain. `python-hl7` was the other candidate but is a parser and MLLP *client*;
its receive side needs the separate `twisted-hl7` package, and its own docs
have warned it does not fully follow the specification.

`hl7apy` **1.3.5 installs and works on this testbed** — Python 3.14.7, in the
existing plane-b `.venv`. Added to `requirements.txt` as `hl7apy>=1.3.5`, so
`setup.sh` picks it up. Tested, all on the real venv:

| Check | Result |
|---|---|
| `import hl7apy.core / .parser / .validation / .mllp` | all pass |
| Parse a gateway `ORU^R01`, STRICT level | passes |
| Schema validation of a complete message | passes |
| Read back `MSH-10`, `OBX-3`, `OBX-5`, `PID-3` | all readable |
| Reject a malformed message | rejects, naming the fault: `Missing required child ORU_R01_ORDER_OBSERVATION.OBR` — so `MSA\|AE` is reachable and can cite a reason |
| Build an `ACK` with `MSA\|AA` | works |

Two things learned that change the build:

**`hl7apy.mllp` ships an `MLLPServer`,** built on `socketserver.ThreadingTCPServer`,
with `MLLPRequestHandler` and an `AbstractHandler`/`AbstractErrorHandler` pair.
So the server loop does *not* need hand-rolling — subclass it instead:

- **mutual TLS:** the module does not mention `ssl` at all, so wrap the socket
  by overriding `get_request()` on the subclass with an `SSLContext`
  (`verify_mode=CERT_REQUIRED`, the plane-b CA).
- **per-peer cap:** there is no real connection cap — the `max`/`limit` hit in
  the source is the listen backlog (`request_queue_size`), not a cap. Implement
  it in `verify_request()`, counting live connections per peer address. This is
  correct anyway: the cap is the *mitigation under test*, so it has to be ours
  and it has to be switchable between the four conditions.
- **thread-per-connection is the E6b target.** `ThreadingTCPServer` spawns a
  thread per peer with no ceiling, which is exactly the exhaustion surface the
  per-peer cap is evaluated against. Convenient: the vulnerability is
  idiomatic, not contrived.

**Schema validation does not range-check values.** `OBX-5 = 9999` for a heart
rate was **accepted**. So "the listener validates each message" splits in two,
and the write-up must say which is which:

- *structural / schema* — hl7apy, free
- *physiological plausibility* — a numeric range check per 11073 code, ours,
  ~15 min

This matters for E6a's design and confirms the choice already made: the forgery
must be a **plausible** value (HR 72 for a critical patient), not an absurd one.
Verified directly — a well-formed forged `ORU^R01` with a plausible value is
**accepted** by validation, exactly as it must be for the attack to land. HL7 v2
carries no authentication, so validation is not the defence and must not be
presented as one. The allow-list and mutual TLS are the defences; the range
check only stops a clumsy forger.

#### 2. Network-layer allow-list: available. Settled.

`nft` is at `/usr/sbin/nft`, and **the real E6 allow-list rule applies on this
kernel** (6.6.87.2-microsoft-standard-WSL2):

```
nft add rule ip e6 input tcp dport 2575 ip saddr != 127.0.0.1 counter drop
```

Applied, listed back, and cleaned up. So E6 gets the allow-list *the draft
describes* — an unlisted peer never completes a TCP connection — and the weaker
in-listener fallback is not needed. Port 2575 is the IANA-registered MLLP port.

Root is reachable without a prompt: sudoers carries `(root) NOPASSWD:
/usr/sbin/nft`, scoped to that one binary. That is why `sudo -n true` is refused
while `sudo -n nft …` succeeds — worth knowing before writing another
`sudo -n`-gated script. `iptables` is **absent** entirely, so `nft` is the only
option; there is no legacy fallback.

> **This corrects a standing assumption about E2a.** The notes carried a caveat
> that this WSL kernel lacks `nf_tables`, so E2a's per-source rate limit may not
> apply and E2a "runs cap-only". That is not what the kernel does. The exact
> meter rule from `src/ratelimit.sh` — `meter e2a-m { ip saddr limit rate over
> 5/second burst 10 packets }` — **applies**, and `nft` listed back the dynamic
> set it created. Nor is there any evidence it ever degraded: every
> `[ratelimit]` line found under `results/` reads `on via nft (port 1883; >
> 5/second per source is dropped)`, 20 of them, each with a matching `off`, and
> there is not one `cap only` / `not applied` trace anywhere in the tree.
>
> So E2a's mitigation was the **full two-control mitigation** (connection cap
> *plus* per-source rate limit), as designed — not a weakened one. The
> cap-only caveat should come out of the E2 write-up.
>
> Honest limit on that claim: the sweep's own stdout was not captured to a file,
> so those 20 logged attempts are not all 60 rate-limited cells. What is
> established is that the capability is present on this kernel and that nothing
> under `results/` records a degradation. If the write-up needs to assert it for
> every cell, have `run.py` record the `ratelimit.sh` outcome into the cell
> directory — ~10 min, and worth it, since a mitigation's identity is currently
> not in the data.

## 7. Time

| Phase | Hands-on | Unattended |
|---|---|---|
| ~~Decisions (hl7apy check, `nft` check)~~ | **done** | |
| Build items 1–10 | 3.5–4 h | |
| Smoke and debug | 1 h | |
| Full sweep (80 × 60 s) | | ~1.5 h |
| Analysis, plots, numbers | 45 min | |
| Write-up (`E6-REPORT.md`) | 1 h | |
| **Total** | **6–6.5 h** | **1.5 h** |

**About 1.5 working days** — still more than the 5–6 h that plane B's closeout
took, but the 20 min of decision risk is now spent and both answers came back
favourable, so nothing in the estimate is waiting on an unknown.

The 1 h for smoke and debug is not padding. Both bugs that surfaced in the B→C
work produced *clean-looking numbers from nothing*: the adapter's client-ID
collision gave PDR 0.0 that read as a legitimate negative result, and the
smoke run silently overwrote sweep data. The MLLP ACK handshake is exactly that
kind of trap — a listener that never ACKs and a gateway that never checks look
identical to a working pair until you read `hl7_sent.csv`. Budget the hour.

### If it has to fit one day

Build items 1, 2, 3, 5, 6, 8, 9 and run **E6a only**: 4–4.5 h hands-on, 40 min
of sweep. E6a is the headline — forged-result acceptance is the novel claim and
the one that ties to Dupont et al. and Brüggemann et al. E6b is then a
half-day follow-on, because item 4 is a near-copy of a harness that already
works and the orchestrator and analysis already handle it.

Do not instead cut repetitions to 5, or run a single scale badly. The method
commitments in the draft are worth more than a second sub-experiment.

## 8. Checks before trusting any of it

The same silent-zero discipline as `PROGRESS-fixes.md`:

- [ ] `hl7_sent.csv` shows `MSA|AA` for the baseline. No ACK means nothing
      downstream is meaningful, however good the PDR looks.
- [ ] Gateway and listener use **distinct** identities. The MQTT client-ID
      collision in `adapter.py` cost a full debugging cycle; the MLLP analogue
      is two peers sharing a certificate CN under a per-peer cap.
- [ ] In `attack` with no mitigation, forged acceptance is **high**. If it is
      low, the attack is not landing and efficacy is measuring nothing.
- [ ] In `attack_mitig`, the legitimate gateway still delivers. If both the
      attacker and the gateway are blocked, the mitigation is just an outage.
- [ ] `E6_RESULTS_DIR` is honoured by `run_e6.py` and `analyze_e6.py` before
      the first smoke run, not after.
- [ ] Record whether `nft` applied, **into the cell directory**. The rule is
      confirmed available on this kernel, so a failure now means something
      broke rather than something is missing — and right now a mitigation's
      actual identity is not in the data at all (see the E2a note in §6).
- [ ] Listener CPU and RSS are non-zero in `broker.csv` — i.e. `monitor.py` is
      pointed at the right pid.

### Environment note found while settling the decisions

The WSL working copy at `~/plane-b/plane-b` **does not have its own venv**. Its
`.venv/bin/activate` carries the path baked in at creation time:

```
export VIRTUAL_ENV='/mnt/c/Uni/KSU CoEIA/testbed/plane-b/.venv'
```

So activating it in WSL uses the venv on the Windows filesystem. That is why
`hl7apy` installed to `/mnt/c/Uni/KSU CoEIA/testbed/plane-b/.venv/lib/python3.14/`
— which is convenient (one venv serves both locations, and `requirements.txt`
on the Windows master is the one that matters), but it has three consequences:

- the WSL copy is **not self-contained**; move or rename the Windows directory
  and it breaks
- package imports cross the `/mnt/c` boundary on every run, which is slow
- a `python3 -m venv .venv` inside WSL would silently shadow it and give a
  second, diverging dependency set

Leave it as it is for now — it works and both copies see the same packages. But
it belongs in the reproducibility notes, because `setup.sh` creates a venv
wherever it is run, so a clean WSL checkout will *not* reproduce this layout.

## 9. A side benefit worth reporting

`mitig − baseline` on the MLLP ACK round trip is a mutual-TLS cost measurement
on a second protocol, with the same CA, the same machine and the same workload
as E2c's MQTT measurement (+0.05 ms at s30). Two protocols, one methodology,
directly comparable. Seoane et al. are the replication precedent for the MQTT
figure; the HL7 figure is an extension of it, and it comes free with E6's
`mitig` condition.

## 10. Open questions for the supervisor

1. **HAPI → hl7apy.** §`sec:bridges` names HAPI (Java). hl7apy is tested
   working on the testbed and avoids a JVM for no experimental loss, so the
   recommendation is to amend the text. It is still a change to written text —
   confirm before revising. Alongside it, §`sec:bridges` says the listener
   "validates each message": that now needs splitting into schema validation
   (hl7apy) and physiological range checking (ours), because the library does
   not do the second.
2. **600 s vs 60 s.** The draft says 600 s; E2's results are 60 s. One of the
   two has to move. This affects every plane, not just E6.
3. **Is plane C now the committed tier?** E6 opens it on the HL7 line only. If
   E4 is also wanted, the RTI Connext licence question gates T4 and should be
   started now, because procurement is slower than code.
4. **Does E6b need a second attacking peer?** The per-peer cap is only properly
   tested if one peer can be capped while another legitimate peer continues.
   With a single gateway, the cap and a total cap are indistinguishable.
   Adding a second gateway is ~20 min and makes the claim sharper.
