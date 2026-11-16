# Plane A build guide: the sensor tier, E1 and the A–B boundary

This is the plan for the second tier of the environment. Plane B exists: E2 is
built, swept and reported (`../plane-b`, sub-experiments `e2a`–`e2d`, results in
`../plane-b/results/summary.csv`, written up in `../plane-b/PROGRESS-fixes.md`).
Plane A is the next brick, and finishing it is what closes the A–B boundary that
Section 4 of Draft-5 calls the minimum viable configuration: *planes A and B with
a stub clinical consumer, supporting E1, E2, E7 and E3*.

Everything here is your own simulated network on your own machine. The attacker
motes are stimulus for measuring the defence, exactly as the two attack harnesses
are in plane B.

---

## 0. What "complete plane A" means, and where to stop

Plane A carries two experiments (Draft-5, Table 5):

| | Attack | Mitigation | Plane |
|---|---|---|---|
| **E1** | RPL decreased-rank and blackhole, separately and combined, configurable onset, static or mobile | Trust-based isolation with rank validation, following SRF-IoT, inside Contiki-NG's RPL | A (B in coupled form) |
| **E7** | Falsified readings injected through the bridge by a rogue or compromised mote | OSCORE mote↔bridge, identity-to-topic binding, per-sender rate limit, plausible-range check | A, B |

Split the tier into three deliverables and treat them as separate stopping lines:

- **A-I — E1, Cooja-only.** The replication plus the trust mitigation, measured
  entirely inside Cooja. This is the tier's core and it stands on its own.
- **A-II — the A–B bridge, and E1 coupled.** `tunslip6` plus the CoAP–MQTT
  bridge, then re-run E1 with plane B attached so delivery is also measured at
  the Mosquitto broker. This is what actually makes the boundary exist.
- **A-III — E7.** The second experiment of the plane. It depends on A-II (the
  mitigation is enforced *at the bridge*, not on the mote) and on a third-party
  OSCORE port, so it carries its own risk.

Do A-I, then A-II. **Take A-III to your supervisor as a scope question before
starting it**, because A-I + A-II already give a complete plane and a complete
boundary, and E7 is closer to a third tier of work than a finishing touch.

---

## 1. Replication before extension

The rule the paper sets for every plane (Draft-5, §"Replication"): at least one
published result is reproduced before anything new is claimed. For plane A:

- **E1 replicates Ioulianou et al. (SRF-IoT)** — delivery, drops, parent
  switches and overhead under rank and blackhole attacks.
- **Monteiro and Granjal is the native-Cooja reference** for the decreased-rank
  variant and the mobile scenario.
- **E7 replicates the relative cost of OSCORE against TinyDTLS** from Gunnarsson
  et al.

One honesty point you must state in writing, because it is already a stated
threat to validity in Draft-5: **the SRF-IoT numbers were obtained on Whitefield,
not Cooja.** Both run Contiki-NG, so the attack and countermeasure code
transfers, but radio models differ and absolute figures will not match. Judge the
replication on **qualitative behaviour**: delivery falls under attack, parent
switches rise, the mitigation recovers delivery, and the overhead it costs is
measurable. Monteiro and Granjal covers decreased-rank natively in Cooja but not
blackhole and not the combined attack, and it runs RPL over TSCH, which is why
plane A uses TSCH as its link layer.

Write this paragraph into `THREAT-MODEL.md` on day one, the way plane B's was
written for the single-host question. It is the thing a reviewer will ask first.

---

## 2. Environment setup

### 2.1 Toolchain

Use the maintained Docker image rather than fighting a native toolchain:

```bash
git clone --recursive https://github.com/contiki-ng/contiki-ng.git ~/contiki-ng
docker pull contiker/contiki-ng
```

Run from inside the container with the tree bind-mounted. Cooja needs a JDK and
Gradle; the image already has them. If you build Cooja natively instead, you need
a JDK (17 or newer) and the msp430/arm cross-compilers.

Keep plane A in **Kali WSL alongside plane B**, so the two planes share one host
clock when you get to the coupled runs. WSLg gives you the Cooja GUI when you
need it for debugging, but every measured run must be headless.

### 2.2 Headless Cooja

The whole harness depends on launching Cooja with no GUI and reading its log.
The flag spelling changed between releases, so check yours once and write the
working form into `run.py`:

```bash
cd ~/contiki-ng/tools/cooja
./gradlew run --args="--no-gui --contiki=$HOME/contiki-ng sim.csc"
# older releases: java -jar build/libs/cooja.jar -nogui=sim.csc -contiki=...
```

A headless run needs a termination condition inside the `.csc` file itself (a
timeout in the simulation script), otherwise it never exits. Set it to the run
duration plus a margin, and make the script print a known final line so the
parser can tell a complete run from a truncated one.

### 2.3 Platform and link layer choices

Three decisions, each of which changes what you can claim:

1. **Mote type.** `cooja` motes (native-compiled) scale to 60 nodes
   comfortably. Emulated MSP430 motes give finer energy accounting but are far
   slower and may not ship in your Contiki-NG release — check
   `ls ~/contiki-ng/arch/platform` before planning around them. Recommendation:
   `cooja` motes for the whole matrix.
2. **Energy.** With `cooja` motes, report **Energest radio on-time**
   (`ENERGEST_TYPE_TRANSMIT`, `ENERGEST_TYPE_LISTEN`) as the energy proxy, not a
   joule figure derived from a CPU cycle count. Draft-5 already concedes that
   Cooja motes are not cycle-accurate and that CPU energy is only indicative, so
   radio duty cycle is both defensible and sufficient for "per-mote radio
   energy".
3. **MAC and routing.** TSCH, to match the native reference:
   ```
   MAKE_MAC = MAKE_MAC_TSCH
   MAKE_WITH_ORCHESTRA = 1
   ```
   Leave routing at the default **RPL-Lite** unless the trust mitigation needs
   storing mode, in which case switch to `MAKE_ROUTING = MAKE_ROUTING_RPL_CLASSIC`.
   Decide this *before* you write the attack patches, because the DIO handling
   code you patch differs between the two.

### 2.4 Version control

`../plane-b` is its own git repository with no remote, which is the right pattern
for this work. Do the same here: `git init` in `testbed/plane-a`, no remote.
Commit the `.csc` templates and the generator script, not the generated `.csc`
files or `results/`.

Also write `setup.sh` on day one — toolchain check, Cooja build, firmware build,
one smoke run. Plane B lost its venv and certificates once and had to rebuild
them mid-analysis; a one-command rebuild stops that happening twice.

---

## 3. The application: a patient monitor over CoAP

Start from `~/contiki-ng/examples/coap`. Each mote is one bedside monitor that
sends readings to the border router; the border router forwards them out of the
simulation in A-II.

- **Payload: SenML (RFC 8428).** Keep it minimal on a mote — a hand-built JSON
  or CBOR SenML record with base name, time, value and unit. The bridge in A-II
  needs the mote identity, a sequence number and a timestamp to carry through to
  the broker, so put all three in the record from the start, even though nothing
  reads them yet.
- **Rate: 1 reading per second per mote**, matching plane B's patient model, so
  the two planes' numbers are comparable and the coupled run is a continuation
  of the same workload rather than a new one.
- **Scales: 10, 30, 60 motes**, 600 s per run. 30 is the scale that matches the
  hospital-ward network of Monteiro and Granjal, so it is the one to run first
  and the one every reduced sweep keeps.
- **Topology.** UDGM radio medium, a fixed grid or a seeded random placement with
  a sink at one edge, so routes are multi-hop. A single-hop star has no rank to
  decrease and would make E1 vacuous — check the hop count in the baseline before
  you build any attack.

---

## 4. The attacks (E1)

Three variants, all on the same firmware tree behind compile flags, so one source
tree builds both honest and malicious motes:

```c
#if MALICIOUS_RANK
  /* advertise a falsely low rank in outgoing DIOs */
#endif
#if MALICIOUS_BLACKHOLE
  /* accept packets for forwarding, then drop them */
#endif
```

- **Decreased rank.** Patch the DIO output path in RPL (`rpl-icmp6.c` /
  `rpl-dag.c` in rpl-lite) to advertise a rank far below the node's real one.
  This attracts children, which is the point: it is the variant Monteiro and
  Granjal also cover.
- **Blackhole.** Drop packets the node is asked to forward, while keeping its own
  traffic and its RPL control messages normal, so it stays attractive as a parent.
- **Combined.** Both on one mote. The decreased rank pulls traffic in and the
  blackhole destroys it; this is the variant with the largest effect and the one
  to use for the full three-scale sweep.

**Configurable onset** is a requirement from the experiment table, not an extra:
a `ctimer` that flips the malicious flag at *t = onset* (say 120 s into a 600 s
run), so each run contains its own before-and-after. Record the onset timestamp
in the log; the analysis needs it to compute time to first effect.

Number of attackers: 1 at scale 10, and scale it in proportion at 30 and 60 (so
roughly 1 in 10 motes), stated explicitly in the run metadata. Do not leave it
implicit — it is the first parameter a reviewer will ask for.

---

## 5. The mitigation: trust-based isolation with rank validation

**This is the one piece of real engineering in the tier.** Budget most of your
time here; everything else is configuration, scripting and waiting.

Two non-learning mechanisms, following SRF-IoT:

1. **Rank validation.** Reject a DIO whose advertised rank is inconsistent with
   the sender's position: a rank below the parent's rank plus the minimum hop
   rank increase is impossible and the DIO is discarded. This alone defeats the
   naive decreased-rank attack and costs almost nothing.
2. **Per-neighbour trust from forwarding evidence.** Each node watches whether a
   chosen parent actually forwards what it was given (overhearing the
   retransmission, or an absent end-to-end acknowledgement), keeps a score per
   neighbour, and blacklists a neighbour whose score crosses a threshold,
   triggering a parent switch. No learned detector, no model: a counter and a
   threshold, both compile-time constants you report.

Keep the thresholds and the observation window as `#define`s and list their
values in the report. They are the knobs a reviewer will want to see, and they
are also the honest limit of the defence: state what an attacker who stays just
inside the threshold can still do.

**Measure what it costs**, since cost is half of every claim in this
environment:

- control-message count (DIO/DIS/DAO) per mote per run,
- radio on-time per mote (Energest),
- RAM and ROM footprint, from `size` on the two firmware builds, with and without
  the mitigation. This is a cost axis plane B does not have, and it is worth a
  row of its own in the report.

---

## 6. The run matrix

The same four conditions as plane B, so the analysis carries over unchanged:

```
                 no attack            under attack
no mitigation    baseline             attack
mitigation       mitig                attack_mitig

cost     = mitig        - baseline
efficacy = attack_mitig - attack
residual = attack_mitig - baseline
```

The attack variants apply only to the two attack conditions, which gives eight
condition-variant combinations:

`baseline`, `mitig`, and then `attack` / `attack_mitig` × {`rank`, `blackhole`,
`combined`}.

Cooja is deterministic for a given seed, so **5 seeds**, not 10 repetitions
(Draft-5 sets this, and it matches Monteiro and Granjal's 5 runs per scenario).

A full factorial including mobility is more than you need. Run this instead:

| Block | Combos | Scales | Mobility | Seeds | Runs |
|---|---|---|---|---|---|
| Main sweep | 8 | 10, 30, 60 | static | 5 | 120 |
| Mobility factor | 8 | 30 only | mobile | 5 | 40 |
| **Total** | | | | | **160** |

At 600 s each that is about 27 hours of simulated time. Headless Cooja without
the GUI runs faster than real time at these scales, so plan on well under that
in wall clock — but **measure it on a single scale-60 run before you commit to
the sweep.** Draft-5 promises exactly this feasibility check, and it is also the
check that tells you whether the coupled runs in A-II are viable.

For the mobility block, follow the published scenario: about a quarter of the
nodes (7 of 30) moving under Random Waypoint, traces generated with BonnMotion
and fed to Cooja through its mobility plugin.

---

## 7. The harness: mirror plane B exactly

Copy the shape, not just the spirit. Plane B's analysis already does bootstrap
confidence intervals and Mann-Whitney tests over a directory tree of per-cell
CSVs, so if plane A writes the same tree, `analyze.py` needs only a new
`cell_metrics`.

```
plane-a/
  firmware/            the Contiki-NG app, attack patches, trust mitigation
  sim/                 .csc templates + generator (motes, seed, duration, placement)
  src/parse_log.py     Cooja log -> recv.csv, energest.csv, rpl.csv, attack.csv
  run.py               one cell: --exp e1 --condition ... --variant ... --scale ... --seed ...
  sweep.sh             the matrix above
  analyze.py           copied from ../plane-b, cell_metrics replaced
  results/e1/<condition>_<variant>/s<N>/seed<K>/
  THREAT-MODEL.md
  setup.sh
```

Two things to get right early, because they are what breaks silently:

- **Generate the `.csc` from a template per cell.** Mote count, seed, duration,
  placement and which motes are malicious all come from `run.py` arguments. Never
  hand-edit a `.csc` for a measured run.
- **Make the parser fail loudly.** Plane B's early trouble was a harness that
  recorded nothing and looked like a clean result. Have `parse_log.py` refuse a
  log with no final marker line, fewer motes than requested, or a simulated time
  short of the duration, and have `run.py` write a non-empty `attack.csv` even
  when the attack did nothing. A missing row must be an error, never a zero.

Per-cell CSV contents, mirroring plane B's columns where they mean the same thing:

| File | Columns |
|---|---|
| `recv.csv` | mote, seq, send_time, recv_time, latency_ms |
| `energest.csv` | mote, cpu, lpm, tx, rx, period |
| `rpl.csv` | mote, time, event (parent switch, rank change, DIO/DAO sent) |
| `attack.csv` | variant, onset_s, attacker motes, packets dropped, first effect time |
| `meta.json` | condition, variant, scale, seed, duration, sim vs wall clock, flags |

---

## 8. A-II: the A–B bridge, and E1 coupled

This is the part that makes the tier count as a boundary rather than a second
isolated experiment.

1. **Border router.** One mote runs the Contiki-NG RPL border router. Cooja's
   serial socket plugin exposes its serial line on a TCP port.
2. **tunslip6.** On the border host, `~/contiki-ng/tools/serial-io/tunslip6`
   against that port, carrying `fd00::/64` into the host. Keep Cooja and the
   border host on a separate management link so the serial stream is not part of
   the measured network.
3. **CoAP–MQTT bridge.** On the same host: a CoAP server (aiocoap is fine) that
   receives the SenML records and a `paho-mqtt` publisher that republishes each
   one to `ward/bed-N/vitals/<metric>`. Carry the mote identity, sequence number
   and bridge timestamp through into the MQTT payload, so end-to-end latency is
   measurable from mote to collector.
4. **Reuse plane B's collector.** `../plane-b/src/collector.py` already records
   receipts in the format `analyze.py` expects. Point it at the broker and you
   have delivery measured on the far side of the boundary with no new code.
5. **Coupled runs must be real-time.** Cooja in real-time mode, and every run
   logs simulated time against wall-clock time, with runs where the simulator
   falls behind flagged and excluded. This is a stated requirement in Draft-5 and
   the first thing to verify at scale 60.

Then re-run E1 with plane B attached, at scale 30, all eight condition-variant
combinations, 5 seeds (40 runs, real-time, about 7 hours). The new result is the
one the Cooja-only form cannot give: **a routing attack in the sensor plane
showing up as lost patient data at the ward broker**, and the trust mitigation
recovering it. That sentence is the deliverable of this tier.

---

## 9. A-III: E7, if it is in scope

Only after A-II works.

- OSCORE between each mote and the bridge, using Gunnarsson et al.'s open-source
  Contiki-NG implementation; TinyDTLS as the comparison, which is also the
  replication target (relative cost of the two, not absolute energy).
- The mitigation lives **at the bridge**: bind each OSCORE sender identity to
  exactly one MQTT topic, apply a per-sender rate limit, and reject readings
  outside a plausible physiological range.
- Two attacker variants: (a) a rogue, unprovisioned mote impersonating another
  mote; (b) a provisioned but compromised mote publishing for other patients, at
  a high rate.
- The claim to make: identity-to-topic binding holds the **blast radius at 1** —
  a compromised mote can falsify its own patient's stream and no other. Report
  the falsification of that one stream as the limit of the mitigation, not as a
  failure of it. Follow the forged readings downstream to the consumer, but make
  the containment claim at the bridge.

---

## 10. Write these down as you go

Plane B's strongest artefacts were not its numbers, they were `THREAT-MODEL.md`
and `PROGRESS-fixes.md` — the documents that answered reviewers before they
asked. Produce the equivalents here:

- **`THREAT-MODEL.md`.** The attacker is an insider mote inside the mesh. State
  for each variant whether it holds key material (compromised) or not (rogue),
  that PHY-layer jamming and radio-level attacks are out of scope, that the UDGM
  radio model bounds what the interference results mean, and that the SRF-IoT
  reference was Whitefield rather than Cooja.
- **A scope note on the sensor tier.** Plane A is 802.15.4/6LoWPAN, so Bluetooth
  wearables are out of scope, and 6LoWPAN meshes are less common on real wards
  than Wi-Fi and Bluetooth. Draft-5 already says this; say it again in the
  testbed's own documentation so the code and the paper agree.
- **A progress report per block**, in the shape of `../plane-b/PROGRESS-fixes.md`:
  the question, the change, the CSV the number came from. It made the plane B
  meeting straightforward and it will do the same here.

---

## 11. Sequence and rough budget

| Phase | Work | Rough effort |
|---|---|---|
| A0 | Toolchain, headless Cooja, 10-mote CoAP app, log parser, first baseline PDR | 2 days |
| A1 | Three attack variants with configurable onset; confirm each bites at s30 | 2 days |
| A2 | Rank validation + trust-based isolation; footprint and overhead measurement | 4–6 days |
| A3 | `.csc` generator, `run.py`, `sweep.sh`, `analyze.py`; feasibility run at s60; the 160-run sweep | 1–2 days of building, then runtime |
| A4 | Border router, `tunslip6`, CoAP–MQTT bridge, coupled E1 at s30 | 2–3 days |
| A5 | E7 (only if scoped into this tier) | about a week |

Gate A3 on A1: do not start the long sweep until every cell has been shown to
behave at a single scale. That gate is what saved plane B's day-3 sweep, where a
single-host rate-limit defect would otherwise have invalidated every scale-60
run.

---

## 12. Decisions to settle before writing code

Four of these, and the first two should go to your supervisor now:

1. **Is E7 part of this tier or the next one?** A-I + A-II is already a complete
   plane and a complete boundary.
2. **Is plane C still the tier after this, and does RTI Connext licensing need
   starting now?** A licence can take weeks, and E4 at level T4 (origin
   authentication) may depend on it. Ask early even if plane C is months away.
3. **RPL-Lite or RPL-Classic.** Changes which DIO code you patch and whether
   storing mode is available to the trust mechanism.
4. **Is mobility in scope for this tier?** It is a published scenario worth
   matching, but it adds a 40-run block and a BonnMotion dependency.

---

## 13. The first commands

```bash
git clone --recursive https://github.com/contiki-ng/contiki-ng.git ~/contiki-ng
```

```bash
docker pull contiker/contiki-ng
```

```bash
cd ~/contiki-ng/examples/coap && ls
```

```bash
cd ~/contiki-ng/tools/cooja && ./gradlew build
```

Then build the CoAP example for the `cooja` platform, open the example `.csc` in
the GUI once to confirm motes boot and the sink receives, and immediately switch
to headless for everything after that.
