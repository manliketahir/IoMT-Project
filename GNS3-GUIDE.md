# GNS3 setup and migration guide

How GNS3 was brought up on this machine, and how the loopback testbed was moved
onto an emulated topology. The scope is **migration only**. E3 and E5 come
after it, and §9 says where they attach.

First written 16 November 2026 for GNS3 2.2.61 with the VirtualBox GNS3 VM.
**Updated 19 November 2026** with what actually happened.

> **What changed since the first version**
>
> - **The GNS3 VM runs under VMware Workstation, not VirtualBox.** On this
>   host VirtualBox froze for minutes at a time (§2). The VMware VM is stable,
>   but its clock runs at 0.900 of real time, and every GNS3 latency is
>   corrected for that.
> - **The loopback harness is retired.** GNS3 is the platform for all further
>   work, and the loopback results are kept as the earlier-stage results.
> - **The migration is done.** E2 (E2a, E2b) and E6 (E6a, E6b) both run on
>   GNS3 at 10 patients, with all 80 runs of each sweep valid. The steps below
>   are now scripted (`gns3_build_e2.py`, `gns3_build_e6.py`, `run_gns3.py`,
>   `run_gns3_e6.py`, `sweep_gns3*.sh`). The manual steps remain for
>   understanding and for rebuilding by hand.
> - **For day-to-day use, read [GNS3-NODE-ACCESS.md](GNS3-NODE-ACCESS.md)**,
>   which covers addresses, consoles, how to get into each node, what each one
>   runs, and where results go. This guide is the *why* and the *how it was
>   built*.

---

## 1. The setup wizard

On the wizard's first page, choose:

> ○ **Run appliances in a virtual machine (GNS3 VM)**

not "Run appliances on my local computer". **Why it matters:** on Windows, the
GNS3 *local* server can only run Dynamips (Cisco IOS), VPCS and Qemu. **Docker
containers and Open vSwitch are Linux-only**, so they run inside the GNS3 VM.
The whole testbed is Linux (mosquitto, Python, nftables), and the ward plane
needs Open vSwitch for E3 and E5.

If the wizard shows the local-server page anyway, its values are correct as
they stand (`localhost`, port `3080 TCP`, the default server path). Leave them
and continue.

On the **GNS3 VM** page (later: *Edit → Preferences → GNS3 VM*), the settings
in use are:

| Setting | Value | Reason |
|---|---|---|
| Virtualization engine | **VMware Workstation / Player** | VirtualBox was rejected (§2) |
| VM name | `GNS3 VM` | The VMware build of the GNS3 VM, imported into VMware Workstation |
| vCPUs | 2 | Enough for E2 and E6 at 10 patients |
| RAM | 4096 MB | |
| Action when closing GNS3 | **keep the GNS3 VM running** | Sweeps run for hours on the VM; closing the GUI must not stop them |

---

## 2. The WSL2 conflict, and why VirtualBox was dropped

This machine runs the testbed in WSL2, and **WSL2 keeps the Windows
hypervisor (Hyper-V) on**. Neither VirtualBox nor VMware can then use the CPU's
virtualisation extensions directly. Both fall back to running through the
Windows Hypervisor Platform. Do **not** disable Hyper-V or WSL2 to get around
this: the analysis environment (`analyze_gns3.py` and its Python venv) lives in
WSL2.

**VirtualBox under that fallback was unusable.** The GNS3 VM froze repeatedly.
The guest kernel logged soft lockups of 45–239 s, and VirtualBox recorded 76
"guest unresponsive" events and 709 s of lost time in 20 minutes. Seven of eight
60 s test runs were rejected, even at 2 vCPUs with nested virtualisation off.
GNS3 also turns VirtualBox's nested virtualisation back on every time it starts
the VM. A first E2 sweep was silently corrupted, with runs reporting a delivery
ratio of 1.000 over 19 of 600 expected messages. That is why every run is now
validity-checked (§7.3).

**VMware Workstation under the same fallback is stable, but its clock runs
slow.** Eight of eight test runs, all 80 E2 runs and all 80 E6 runs were valid
at the first attempt. Its virtual clock, however, runs at a steady **0.900** of
real time, measured against Windows' NTP-synced clock: 0.89986–0.90013 over
both sweeps. What that does and does not affect:

- **Unaffected:** counts, delivery ratios, attack outcomes, CPU % and every
  Mann–Whitney p-value, since a rank test does not change under a uniform scale
  factor.
- **Affected:** absolute latencies read 10 % low. `plane-b/analyze_gns3.py`
  divides them by the factor taken from the clock log the sweep records
  (`gns3_clock_e2.csv`, `gns3_clock_e6.csv`), and keeps both values.

Two VMware-specific notes:

- GNS3 adds `vhv.enable` (nested virtualisation) to the VM's `.vmx` only if
  the key is missing. Setting it explicitly to `"FALSE"` therefore persists.
  Docker containers do not need nested virtualisation; Qemu appliances would.
- After the import, the VM's network adapters were disabled in VMware and had
  to be enabled by hand. GNS3 also had to be restarted once after VMware was
  installed before it found `vmrun`.

If Qemu appliances or uncorrected timing become necessary, the options are a
GNS3 VM native to Hyper-V or a GNS3 server inside WSL2 (§11). Removing Hyper-V
is not one of them.

---

## 3. Finish the wizard and verify

- **Servers Summary** (right-hand pane) should list **GNS3 VM** in green.
- *Help → GNS3 Doctor* should report no errors.

If the VM stays grey, check in this order:
1. Is the VM imported into the hypervisor GNS3 is set to use?
2. Is there enough free RAM?
3. Are the VM's network adapters enabled, and is the host-only network
   present? Under VirtualBox, a missing host-only adapter showed up as
   `VERR_INTNET_FLT_IF_NOT_FOUND`, and recreating the adapter fixed it.

The VM's address is shown on its console. It is currently `192.168.89.128`,
and the login is `gns3` / `gns3`.

---

## 4. Get the testbed into container images

Images must be built **inside the GNS3 VM**. An image built in WSL2 or Docker
Desktop is invisible to GNS3, because they are separate Docker daemons.

### 4.1 Reach the GNS3 VM

```bash
ssh gns3@192.168.89.128
```

### 4.2 Copy the trees over

The plane-B tree goes to `~/testbed` on the VM, without `results*`, `.venv` and
caches. A `~/plane-b` symlink points to it, so the E6 harness finds plane B
where it expects it. The plane-C tree goes to `~/plane-c`, and its HL7
certificates go into `~/plane-c/certs` separately. A tar pipe over SSH is the
simplest way to do this:

```bash
tar -C ~/plane-b --exclude='./results*' --exclude='./.venv' --exclude='__pycache__' -czf - . \
  | ssh gns3@192.168.89.128 'mkdir -p ~/testbed && tar -C ~/testbed -xzf - && ln -sfn ~/testbed ~/plane-b'
```

The E2 broker certificate on the VM was re-issued from the same CA with
`IP:10.0.0.10` and `DNS:broker` added to its SANs, because clients now reach the
broker by address rather than on `127.0.0.1`.

### 4.3 The Dockerfiles

These are now in the repository:

- `plane-b/Dockerfile` → **`iomt-node:1.0`**. Debian bookworm-slim with python3,
  mosquitto, nftables, iproute2, ping, tcpdump, netcat, openssl, procps, plus
  `paho-mqtt` and `psutil`. It contains only what a node needs: numpy, scipy
  and matplotlib stay out, because the analysis runs in WSL, not in the
  topology.
- `plane-c/Dockerfile` → **`iomt-node:1.1`**. This is 1.0 plus the plane-C code
  and `hl7apy==1.3.5`. The HL7 listener imports `hl7apy` at start-up, even for
  structural validation. `plane-c/.dockerignore` keeps keys and certificates
  out of the image, and the E6 orchestrator copies them in for each run.

### 4.4 Build them

```bash
cd ~/testbed  && docker build -t iomt-node:1.0 .
cd ~/plane-c  && docker build -t iomt-node:1.1 .
```

One image serves every role in a topology. Which role a node plays is decided
by the command run in it, so every host is identically provisioned.

---

## 5. GNS3 templates

The builders create these through the GNS3 REST API, so there is nothing to
click. They do the equivalent of *Edit → Preferences → Docker → Docker
containers → New*:

| Field | E2 | E6 |
|---|---|---|
| Server | GNS3 VM | GNS3 VM |
| Image | `iomt-node:1.0` | `iomt-node:1.1` |
| Template name | `iomt-node` | `iomt-node-e6` |
| Adapters | 1 | 1 (the router: 2) |
| Console | telnet | telnet |

Each node gets a static address through the node-files API, which writes
`/etc/network/interfaces`:

```
auto eth0
iface eth0 inet static
    address 10.0.0.10
    netmask 255.255.255.0
```

E6 nodes also get a `gateway` line pointing at their side of the router. These
files live on the **GNS3 VM's disk**, not in the controller's project copy, so
rerun the builders after replacing the VM.

---

## 6. The topologies

Both live in the one GNS3 project, **CoEIA IoMT**, as separate labelled
networks. Run the builders on Windows with GNS3 open:

```powershell
python plane-b\gns3_build_e2.py
python plane-c\gns3_build_e6.py
```

Both are idempotent: they reuse the template, nodes and links by name, and only
rewrite the address files.

**E2: one switched segment, `10.0.0.0/24`**, behind the Ethernet switch
`ward-sw`.

```
   patient-1 ──┐
      ...      ├── [ ward-sw ] ── broker    (10.0.0.10)
   patient-10 ─┤        │
   attacker ───┘        └──────── collector (10.0.0.20)
   (10.0.0.100)          patients 10.0.0.101–110
```

**E6: the proposal's planes B and C, without the DDS stage.**

```
 plane B (ward) 10.0.6.0/24             plane C (clinical) 10.0.7.0/24
 e6-patient-1..10 (.101–.110) ┐       ┌ e6-gateway  (.20)
                              ├ e6-ward-sw ─ e6-router ─ e6-clin-sw ┼ e6-listener (.10)
 e6-broker (.10) ─────────────┘   (.1 / .1)           └ e6-attacker (.100)
```

The only traffic crossing the router is the gateway's MQTT subscription to the
ward broker, standing in for the proposal's MQTT→DDS link. The MLLP hop that E6
attacks and defends, and the attacker itself, are inside plane C.

| Role | Loopback | GNS3 |
|---|---|---|
| E2 broker | `127.0.0.1` | `10.0.0.10` |
| E2 collector | `127.0.0.1` | `10.0.0.20` |
| E2 attacker | `127.0.0.2` | `10.0.0.100` |
| E2 patients | `127.0.0.3`… | `10.0.0.101`… |
| E6 HL7 listener | `127.0.0.1` | `10.0.7.10` |
| E6 gateway | `127.0.0.2` | `10.0.7.20` |
| E6 attacker | `127.0.0.3` | `10.0.7.100` |
| E6 broker / patients | `127.0.0.1` / `127.0.0.4`… | `10.0.6.10` / `10.0.6.101`… |

The switches are plain GNS3 **Ethernet switches**. Swap them for **Open
vSwitch** when E3/E5 start: it behaves as a learning switch until a controller
is attached.

---

## 7. The migration work, as done

### 7.1 `--bind` disappeared

On loopback each role bound its own `127.0.0.x`, so source-based controls could
tell the attacker from the patients. On GNS3 every node has its own address:
`--bind` is dropped and clients connect to the broker's or listener's real
address. As a result, the E2a per-source rate limit and the E6a allow-list now
run **inside the broker and listener containers**, as nftables rules keyed on
real source addresses, instead of in the WSL host's firewall. GNS3 runs
containers privileged, so nftables works inside them.

The clean separation is still there: distinct addresses, with no NAT. The
harder case is now testable but not yet tested: attacker and patients behind
one address, where a rate limit *cannot* separate them. That case would turn the
"upper bound" caveat into a measured result.

### 7.2 Orchestration became multi-host

`plane-b/run_gns3.py` (E2) and `plane-c/run_gns3_e6.py` (E6, which reuses the
E2 orchestrator's helpers and checks) run **on the GNS3 VM**. They keep `run.py`'s sequence: broker, collector,
attacker, patients, wait out the window, stop. Only the launch and collect
primitives change:

| Loopback | GNS3 |
|---|---|
| `subprocess.Popen([...])` | `docker exec -d GNS3.<node>.<project-id> ...` |
| read `results/<cell>/*.csv` | `docker cp <container>:/opt/testbed/out/. results/<cell>/` |

Containers are found by their `GNS3.<role>.<project-id>` names, so no node IDs
are hard-coded. Results are collected **before** anything is stopped or reset,
because a GNS3 reset discards the container filesystem.

### 7.3 Validity checks

A run is rejected, moved to `results_invalid/` and repeated, up to three times,
if:
- any node restarted during it;
- any patient's log covers less than 90 % of the window;
- the VM's kernel logged a stall;
- any patient went more than 3 s between readings.

The last check matters most: on VirtualBox the longest freezes stopped the guest
clock too, so they left no trace in the kernel log. The sweeps resume from the
last completed run, stop if the topology goes down (exit code 4), and are
started detached (`nohup setsid`) so that a dropped SSH session does not kill
them.

### 7.4 What the move exposed

- **AppArmor confines the broker.** The VM enforces Debian's Mosquitto profile,
  which lets the broker read only `/etc/mosquitto/` (one level deep, plus
  `certs/`). The orchestrator therefore stages each run's config and
  certificates there, with the broker key readable.
- **The GNS3 broker negotiates TLS 1.3**, even with `tls_version tlsv1.2`. The
  loopback broker used TLS 1.2, so E2b's mutual-TLS costs are not like for
  like.
- **`attack_malformed.py` mislabelled its outcome under TLS 1.3.** It treated a
  finished client-side handshake as proof its bytes reached the MQTT parser,
  and it sent before reading, which raced the server's certificate-required
  alert. Under TLS it now reads before it sends and tallies every attempt. The
  TLS 1.2 path, and so the loopback results, are unchanged.

---

## 8. Scale: GNS3 runs at 10 patients

Sixty Docker nodes in a GNS3 topology is unmanageable: the canvas becomes
unreadable, start-up takes minutes, and the VM will not hold it comfortably.
GNS3 therefore runs at **scale 10**, with real interfaces, real switching and,
in E6, real routing.

The single-host loopback harness is **retired**. Its 10/30/60 scaling results
are kept as the earlier-stage results, and all further work runs on GNS3.

More beds inside GNS3 without more nodes would mean several `patient.py` per
container. Beds that share a container also share one IP, which changes what
source-based controls see. That is an experimental variable, so decide it
deliberately.

---

## 9. Order of work

1. ✅ **GNS3 VM green in Servers Summary.** (§1–3)
2. ✅ **Images built inside the VM; one node proven.** (§4–5)
3. ✅ **Three nodes: broker, one patient, collector**, the chain working off
   loopback.
4. ✅ **Ten patients plus the attacker; orchestrator ported.** (§6–7)
5. ✅ **E2a and E2b re-run at scale 10 and compared with loopback.** The
   latency on a switched network is about 0.8 ms, roughly twice the loopback
   floor.
6. ✅ **E6 on a two-segment, routed topology.** It reproduces the loopback
   efficacy exactly.
7. ⬜ **E2c and E2d on GNS3.** E2d carries E2's efficacy result on delivery,
   and the harness already supports both.
8. ⬜ **Open vSwitch plus a controller, then E3/E5.** There are two realistic
   controller choices. **Faucet** is YAML-configured and maps cleanly onto
   IP–MAC binding and segmentation ACLs. **Ryu** means writing the logic
   yourself, and it is poorly maintained on recent Python. The E6 topology
   already separates the ward and clinical segments that E5's lateral movement
   must cross.

---

## 10. Things to be careful about

- **The loopback harness is retired**, but its scripts and results stay in the
  repository, because the earlier-stage results in the report come from them.
- **Build images on the GNS3 VM**, never in WSL2 or Docker Desktop.
- **Collect results before stopping or resetting nodes** (§7.2).
- **A VM restart closes the project**, and GNS3 recreates the containers when
  the project is opened again. Open the project and start all nodes before a
  sweep; the sweep refuses to run if the topology is down.
- **Certificates:** TLS verification now cares about addresses. The E2 broker
  certificate on the VM carries `IP:10.0.0.10`. E6 verifies the listener by
  name (`--server-name localhost`). If TLS fails after a topology change, check
  the SANs before suspecting the network.
- **nftables inside containers.** If a rule seems to do nothing, check
  `nft list ruleset` in that node rather than trusting a script's exit code.
- **Timing is the VM's clock.** Correct latencies with `analyze_gns3.py`, and
  keep the clock sampler running alongside any new sweep.
- **Never commit TLS keys or certificates.** `.gitignore` excludes them, and
  each plane's `certs/make-certs.sh` regenerates them.
- **Take a GNS3 snapshot** before changing a working topology.

---

## 11. If GNS3 fights you

The experiment design needs *a real switched topology with separate network
stacks*. GNS3 is how the draft specifies getting that, and it now works on this
host under VMware. If the clock factor or the Windows-hypervisor path ever
becomes a problem, the alternatives, in order, are:

1. a **GNS3 VM native to Hyper-V**, since Hyper-V is already on;
2. a **GNS3 server inside WSL2**;
3. as a last resort, **Linux network namespaces plus Open vSwitch**, scripted
   inside WSL2. First check that the WSL2 kernel exposes the `openvswitch`
   module. This option gives up the visual topology and the appliance
   ecosystem, which are part of why GNS3 was chosen.
