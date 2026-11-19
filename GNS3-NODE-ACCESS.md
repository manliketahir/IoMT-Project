# Seeing inside the GNS3 testbed: E2 and E6 node by node

How to get into every node of the two GNS3 topologies, what is running there
during a run, and how to watch it. Everything here is read-only unless a step
says otherwise.

Written 18 November 2026 for GNS3 2.2.61 with the **VMware** GNS3 VM
(`192.168.89.128`, on VMware's host-only network VMnet1). If that address
changes, GNS3's **Topology Summary** pane always shows the current one, in the
Console column.

---

## 1. What is where

Both topologies are in the GNS3 project **CoEIA IoMT**. On the canvas they sit
side by side in labelled boxes: E2 on the left, and E6's two planes on the right.

### E2: MQTT ward broker (plane B), `10.0.0.0/24`, one switch `ward-sw`

| Node | Address | Role in a run | Console |
|---|---|---|---|
| broker | 10.0.0.10 | Mosquitto broker: the target and the control point (connection cap, rate limit, mutual TLS, ACL) | `192.168.89.128:5001` |
| collector | 10.0.0.20 | Ward collector: subscribes to `ward/#` and records every reading | `:5003` |
| attacker | 10.0.0.100 | Connection flood (E2a) or malformed / unauthorised publishes (E2b) | `:5005` |
| patient-1 … patient-10 | 10.0.0.101 … .110 | One simulated patient monitor each, publishing 1 reading/s | `:5007`, `:5009` … `:5025` (odd ports, in order) |

### E6: HL7 v2 over MLLP, two planes joined by `e6-router`

| Node | Plane | Address | Role in a run |
|---|---|---|---|
| e6-broker | B (ward) | 10.0.6.10 | Plain Mosquitto broker feeding the gateway |
| e6-patient-1 … 10 | B (ward) | 10.0.6.101 … .110 | Patient monitors, as in E2 |
| e6-router | boundary | 10.0.6.1 and 10.0.7.1 | Forwards between the planes. The only traffic crossing it is the gateway's MQTT subscription (the stand-in for the proposal's MQTT→DDS link; E6 is built without the DDS stage) |
| e6-gateway | C (clinical) | 10.0.7.20 | HL7 gateway (IHE PCD-01): turns each reading into an `ORU^R01` and delivers it over MLLP |
| e6-listener | C (clinical) | 10.0.7.10 | HL7 v2 listener: the target and the control point (allow-list, mutual TLS, per-peer cap) |
| e6-attacker | C (clinical) | 10.0.7.100 | Forged results (E6a) or connection flood (E6b), from inside plane C as in the proposal diagram |

E6 console ports are listed in section 9, and live in GNS3's Topology Summary.

---

## 2. Three ways in

### a) The node's console in GNS3: the everyday way
Double-click a node, or right-click it and choose **Console**. GNS3 opens
**Solar-PuTTY** (bundled with GNS3) on the node's telnet console. Press
**Enter** at `… console is now available... Press RETURN to get started.` and
you get a **root shell inside that node**:

```
root@collector:/opt/testbed#
```

Any telnet client works too, for example `telnet 192.168.89.128 5001` for the broker.

### b) SSH into the GNS3 VM, then into a container
Use this when you want several nodes in one window, or to copy files out.

```bash
ssh gns3@192.168.89.128
```

The password is `gns3`. If the GNS3 VM's blue menu appears, choose **Shell**. Then:

```bash
docker ps --format '{{.Names}}'
```

```bash
docker exec -it GNS3.broker.47cea970-52a0-4033-9fe0-0faa878f6e92 bash
```

Container names are `GNS3.<node name>.<project id>`.

### c) Watch the wire: packet capture on a link
Right-click any **link** on the canvas and choose **Start capture**. GNS3
streams it into **Wireshark** (installed at `C:\Program Files\Wireshark`)
live. The most useful links:

| Capture on | What you see |
|---|---|
| broker ↔ ward-sw (E2) | Every MQTT packet to and from the broker: patient publishes, the collector's subscription, the attacker's flood |
| e6-router ↔ e6-clin-sw (E6) | Exactly what crosses the plane B → C boundary: only the gateway's MQTT session |
| e6-listener ↔ e6-clin-sw (E6) | All MLLP traffic: gateway deliveries and ACKs, and the attacker's forged messages or flood |

Useful display filters are `mqtt`, `tcp.port == 1883`, `tcp.port == 8883`
(TLS, so payloads are encrypted) and `tcp.port == 2575` (MLLP). On a 2575
stream, use **Follow → TCP Stream** to read the HL7 segments (`MSH|…`,
`OBX|…`, and the `MSA|AA` acknowledgement).

---

## 3. What is inside every node

Every node runs the same image, so the layout is identical. What differs is
which program runs in it during a run.

| Path | Contents |
|---|---|
| `/opt/testbed/` | The plane-B code (`src/patient.py`, `collector.py`, `monitor.py`, the attack scripts), the broker configs in `mosquitto/`, and the certificates in `certs/` |
| `/opt/plane-c/` | E6 nodes only: the plane-C code (`src/hl7_gateway.py`, `hl7_listener.py`, `attack_hl7_*.py`, `hl7_allowlist.sh`). The HL7 certificates are copied into `certs/` at the start of each run |
| `/opt/testbed/out/` | **The live run directory.** Each node writes its outputs here during a run. It is emptied at the start of the next run |
| `/etc/mosquitto/` | Brokers only: the config, certificates and ACL for the current run, staged here because the Mosquitto security profile on the GNS3 VM (AppArmor) only lets the broker read this directory |
| `/etc/network/interfaces` | The node's static address |

Handy commands in any node:

| Command | Shows |
|---|---|
| `ip -br addr` | The node's addresses |
| `ip route` | Its routes (E6 nodes route to the other plane via 10.0.6.1 or 10.0.7.1) |
| `ps -eo pid,etime,args` | What is running: one testbed program per node during a run, nothing between runs |
| `ss -tn` | Open TCP connections |
| `ls -l /opt/testbed/out` | This run's files so far |

Some files are written as the run goes (the patients' `sent_*.csv`, the
monitors' resource CSVs and every `*.log`). Others are written only when the
run ends: the collector's `recv.csv`, the gateway's `hl7_sent.csv`, the
listener's `hl7_recv.csv`, and the attackers' results.

---

## 4. E2 node by node

**broker** (`192.168.89.128:5001`)
- The broker log: `tail -f /opt/testbed/out/broker.log`
- Its CPU and memory, sampled twice a second: `tail -f /opt/testbed/out/broker.csv`
- Which configuration is in force: `ps -eo args | grep [m]osquitto` shows the config file; `cat` it. `baseline.conf` is plain and anonymous; `e2a_mitig.conf` adds `max_connections 100`; `e2b_mitig.conf` is mutual TLS plus the ACL on port 8883
- How many clients are connected: `ss -tn state established '( sport = :1883 or sport = :8883 )' | tail -n +2 | wc -l`. That's 11 (10 patients plus the collector) in a calm run, and many more under the E2a flood
- The per-source rate limit (E2a mitigation): `nft list ruleset`. During `mitig` and `attack_mitig` a table `ip e2a` exists, with a meter that drops new connections above 5 per second from any one source, and a `counter` showing how many it dropped
- The traffic itself: `tcpdump -ni eth0 -c 20 tcp port 1883 -A`. In plain conditions the JSON readings are readable; on 8883 they are TLS-encrypted

**collector** (`:5003`)
- `tail -f /opt/testbed/out/collector.log`
- To watch readings arrive yourself, on a plain broker: `mosquitto_sub -h 10.0.0.10 -t 'ward/#' -v`
- On the mutual-TLS broker:
  `mosquitto_sub -h 10.0.0.10 -p 8883 --cafile certs/ca.crt --cert certs/collector.crt --key certs/collector.key -t 'ward/#' -v`
- `recv.csv` appears in `out/` when the run ends

**patient-N** (`:5007`, `:5009` … `:5025`)
- `tail -f /opt/testbed/out/sent_bed-N.csv`: one row per reading, with sequence number, send time, and whether the client accepted it
- `cat /opt/testbed/out/patient.log` shows connection errors, for example when the broker refuses a patient under a flood

**attacker** (`:5005`)
- E2a: `ss -tn | grep -c ':1883'` shows how many flood connections it is holding; `attack.csv` (established / refused / attempted) appears when the run ends
- E2b: `attack.csv` records whether the unauthorised publish was accepted, and whether the malformed frame reached the MQTT parser or was stopped at TLS

---

## 5. E6 node by node

**e6-listener**, the target
- `tail -f /opt/testbed/out/listener.log`: its start line states TLS on/off, the per-peer cap and the global ceiling, for example
  `hl7-listener: 0.0.0.0:2575 validate=structural tls=True peer_cap=none max_conns=none allow=any`.
  `allow=any` is expected even in E6a's mitigated runs. That field is the listener's own (weaker) fallback allow-list; the real one is the nftables rule below, which sits outside the listener
- Connections into it: `ss -tn sport = :2575`. Under the E6b flood without the cap, the global ceiling of 100 fills with the attacker's connections; with the cap, the attacker is held to 20
- The allow-list (E6a mitigation): `nft list table ip e6allow`. It accepts the gateway (10.0.7.20) and drops everyone else on port 2575, with a drop counter
- The HL7 traffic: `tcpdump -ni eth0 -A tcp port 2575`. In plain conditions you can read `MSH|^~\&|…`, the `OBX` observation and the `MSA|AA` acknowledgement; with mutual TLS on, it is encrypted
- `hl7_recv.csv` (every stored observation) and `hl7_listener_stat.csv` (accepted / blocked counters) appear when the run ends. In the stats, `blocked_global` counts connections turned away by the ceiling of 100, and `blocked_cap` those turned away by the per-peer cap of 20. A single `tls_fail` in TLS runs is the orchestrator's own "is the port up?" check, not an attack
- Its CPU and memory: `tail -f /opt/testbed/out/listener_resource.csv`

**e6-gateway**
- `tail -f /opt/testbed/out/gateway.log`
- Its MQTT session to the ward broker, across the router: `ss -tn dport = :1883`
- Its MLLP deliveries: `ss -tn dport = :2575`. There is one long-lived connection in E6a, and one connection per message in E6b (which is what lets a flood starve it)
- `hl7_sent.csv` (each delivery, its ACK, and the ACK time) appears when the run ends

**e6-router**
- `ip -br addr` shows both legs; `sysctl net.ipv4.ip_forward` should be 1
- To watch the boundary: `tcpdump -ni eth1 tcp port 1883` shows the gateway's MQTT session as it crosses from plane C to the ward broker. Nothing on port 2575 ever crosses the router, because the MLLP hop and the attacker are both inside plane C

**e6-attacker**
- E6a: `tail -f /opt/testbed/out/attack.log`. `tamper.csv` (each forged result for bed-1, and the acknowledgement it got) appears when the attacker's window ends. The forged value is a plausible heart rate of 72, on purpose
- E6b: `ss -tn | grep -c ':2575'` shows how many connections the flood holds; `exhaust.csv` and `exhaust_liveness.csv` appear at the end

**e6-broker**, **e6-patient-N**: the same as their E2 counterparts above.

---

## 6. Watching one run end to end

Runs are started from the GNS3 VM, not from the node consoles. To watch a
single E6a attack run with consoles open on e6-listener and e6-attacker:

```bash
ssh gns3@192.168.89.128
```

```bash
cd ~/plane-c && python3 run_gns3_e6.py --exp e6a --condition attack --scale 10 --rep 99 --duration 60
```

An E2 run is the same from `~/testbed`, for example
`python3 run_gns3.py --exp e2a --condition attack_mitig --scale 10 --rep 99 --duration 60`.

Each run prints one line on success, for example:

```
done -> results/e6a/attack/s10/r99  gateway delivered 600/600  forged accepted 300/300
```

or `INVALID` with the reason. A run is rejected if a node restarted, a
patient's log is short, the VM's kernel logged a stall, or any patient went
more than 3 s between readings. Use a high `--rep` number such as 99 for
manual runs, so they never overwrite a sweep's cells.

---

## 7. Where results go

| | On the GNS3 VM | Copied to Windows |
|---|---|---|
| E2 sweep | `~/testbed/results/e2{a,b}/<condition>/s10/r<rep>/`, log `~/testbed/sweep_e2.log` | `testbed/plane-b/results-gns3/` |
| E6 sweep | `~/plane-c/results/e6{a,b}/…`, log `~/plane-c/sweep_e6.log` | `testbed/plane-c/results-gns3/` |
| Rejected attempts | `results_invalid/…`, next to each `results/`, kept for inspection and never analysed | not copied |
| VM clock factor | — | `plane-b/gns3_clock_e2.csv`, `plane-c/gns3_clock_e6.csv` |

Every valid cell holds a `DONE` file. `analyze_gns3.py e2` or `… e6` runs the
plane's own analyser on these folders, then applies the VM clock correction
(next section).

---

## 8. Things to know before touching anything

- **Don't start, stop or reload nodes while a sweep is running.** The
  orchestrator detects it and discards the run, but the run is lost and has to
  be repeated. Consoles, `cat`, `tail`, `ss` and `nft list` are all harmless.
- **Avoid packet captures and `mosquitto_sub` during a measured sweep.** They
  add load to the VM that the measurement would include. Use them on manual
  runs (section 6).
- **The VM's clock runs at 0.900 of real time.** VMware on this host has to go
  through the Windows hypervisor, which WSL2 keeps on. Timestamps inside the
  VM, and so the latencies, read 10 % low. Counts, delivery ratios, attack
  outcomes and p-values are unaffected. The factor is logged during every
  sweep, and the analysis divides latencies by it.
- **Starting from cold:** open GNS3 and it boots the GNS3 VM itself. Then open
  the CoEIA IoMT project and start all nodes with the green ▶. "Virtualize
  AMD-V" must stay off in the VM settings, because VMware can't run the VM with
  it on under the Windows hypervisor. GNS3 leaves it off once it has been
  turned off.
- **If the GNS3 VM is replaced**, re-run `plane-b/gns3_build_e2.py` and
  `plane-c/gns3_build_e6.py`. The static addresses are stored on the VM's
  disk, not in the project.

---

## 9. E6 console ports

All on the GNS3 VM at `192.168.89.128`, as of 18 November 2026. GNS3's
Topology Summary always shows the live values.

| Node | Console | Node | Console |
|---|---|---|---|
| e6-broker | `:5029` | e6-router | `:5051` |
| e6-patient-1 … 10 | `:5031` … `:5049` (odd ports, in order) | e6-gateway | `:5053` |
| | | e6-listener | `:5055` |
| | | e6-attacker | `:5057` |

E2's are in section 1: broker `:5001`, collector `:5003`, attacker `:5005`,
patient-1 … 10 `:5007` … `:5025`.
