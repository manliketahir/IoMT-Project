#!/usr/bin/env python3
"""E2 orchestrator for the GNS3 topology (multi-host).

This is the GNS3 counterpart of run.py. run.py spawns every role as a local
process on one machine over loopback; here each role is a Docker container in
the GNS3 'CoEIA IoMT' topology with its own real address, so the orchestrator
drives them with `docker exec` instead of subprocess.Popen and collects each
container's CSVs with `docker cp`.

It is meant to run ON the GNS3 VM (where the Docker daemon that GNS3 uses
lives). It discovers the GNS3 containers by their `GNS3.<role>.<project>`
names, so it needs no node IDs.

Addressing (also in GNS3-NODE-ACCESS.md section 1):
    broker     10.0.0.10        collector  10.0.0.20
    attacker   10.0.0.100       patient-i  10.0.0.(100+i)

Two deliberate differences from run.py:

  * --bind is gone. On loopback every role shared one host and each patient
    bound a distinct 127.0.0.x so the per-source rate limit could tell them
    apart. Here each node genuinely has its own address, so patients just
    connect from their own IP and the attacker from 10.0.0.100.

  * The E2a per-source rate limit moves from the WSL host firewall into the
    broker container (nft, hook prerouting), keyed on real source IP. The
    attacker is a single source (throttled); the ten patients are ten
    distinct sources (untouched). That is the honest version of the control
    the loopback run could only approximate.

Results land in results/<exp>/<cond>/s<scale>/r<rep>/ exactly as run.py's do,
so analyze.py consumes them without change.

Usage (on the VM):
    python3 run_gns3.py --exp e2a --condition baseline --scale 10 --rep 1 --duration 60
"""
import argparse
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))

# Filled in at runtime from `docker ps`: role name -> full container name.
CONTAINERS = {}

BROKER_IP = "10.0.0.10"
COLLECTOR_IP = "10.0.0.20"
ATTACKER_IP = "10.0.0.100"

# Path INSIDE every container where the testbed tree was COPYed by the image.
TB = "/opt/testbed"

# The GNS3 VM host loads the Debian mosquitto AppArmor profile in enforce mode,
# and Docker containers inherit host AppArmor, so the mosquitto BINARY can only
# read files under /etc/mosquitto/ (the profile allows /etc/mosquitto/** r). It
# cannot read a config or certs under /opt/testbed. We therefore stage the
# broker's config tree + certs + acl under /etc/mosquitto inside the broker
# container and launch from there. The clients are Python (paho / raw sockets),
# which AppArmor does not confine, so they keep reading /opt/testbed/certs.
ETC = "/etc/mosquitto"


def sh(cmd, check=True, capture=False, timeout=None):
    """Run a local command (we are on the VM)."""
    return subprocess.run(cmd, check=check, timeout=timeout,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.STDOUT if capture else None,
                          text=True)


def discover(project_hint=None):
    """Map role -> container name from the running GNS3 containers.

    GNS3 names a node's container GNS3.<node-name>.<project-id>. We key by the
    middle field (broker, collector, attacker, patient-1 ...).
    """
    out = subprocess.run(["docker", "ps", "--format", "{{.Names}}"],
                         check=True, stdout=subprocess.PIPE, text=True).stdout
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("GNS3."):
            continue
        parts = line.split(".")
        if len(parts) < 3:
            continue
        role = parts[1]
        if project_hint and parts[-1] != project_hint:
            continue
        CONTAINERS[role] = line
    return CONTAINERS


def dexec(role, argv, detach=False, check=True, capture=False):
    name = CONTAINERS[role]
    cmd = ["docker", "exec"]
    if detach:
        cmd.append("-d")
    cmd.append(name)
    cmd += argv
    return sh(cmd, check=check, capture=capture)


def dexec_sh(role, script, detach=False, check=True, capture=False):
    return dexec(role, ["sh", "-c", script], detach=detach,
                 check=check, capture=capture)


def broker_for(exp, condition):
    """(conf, port, tls) for this cell -- identical policy to run.py."""
    mitig = condition in ("mitig", "attack_mitig")
    if exp == "e2a":
        conf = "mosquitto/e2a_mitig.conf" if mitig else "mosquitto/baseline.conf"
        return conf, 1883, False
    if exp == "e2c":
        if mitig:
            return "mosquitto/hardened.conf", 8883, True
        return "mosquitto/baseline.conf", 1883, False
    if exp == "e2d":
        if condition == "baseline":
            return "mosquitto/baseline.conf", 1883, False
        return "mosquitto/e2a_mitig.conf", 1883, False
    # e2b
    if mitig:
        return "mosquitto/e2b_mitig.conf", 8883, True
    return "mosquitto/baseline.conf", 1883, False


def tls_args(name):
    return ["--cafile", f"{TB}/certs/ca.crt",
            "--certfile", f"{TB}/certs/{name}.crt",
            "--keyfile", f"{TB}/certs/{name}.key"]


# ---- the per-source rate limit, now inside the broker container ------------
# This is ratelimit.sh's job expressed as the control under test for E2a/E2c.
# It limits NEW connections per source IP to the broker port; a single flooding
# source (the attacker, 10.0.0.100) is throttled while ten distinct patient
# sources are not. If nft is unavailable it is a no-op, exactly like the
# loopback script, so the cell degrades to cap-only rather than aborting.
RATE = "5/second"
BURST = 10


def ratelimit(port, on):
    if on:
        script = (
            "nft delete table ip e2a 2>/dev/null; "
            "nft add table ip e2a && "
            "nft 'add chain ip e2a pre { type filter hook prerouting priority -300 ; policy accept ; }' && "
            f"nft 'add rule ip e2a pre tcp dport {port} tcp flags & (syn|ack) == syn "
            f"meter e2a-m {{ ip saddr limit rate over {RATE} burst {BURST} packets }} counter drop' "
            "&& echo RATELIMIT_ON || echo RATELIMIT_SKIP"
        )
    else:
        script = "nft delete table ip e2a 2>/dev/null; echo RATELIMIT_OFF"
    r = dexec_sh("broker", script, check=False, capture=True)
    print("  [ratelimit]", (r.stdout or "").strip().splitlines()[-1:] or "?")


def wait_broker(port, timeout=15.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        r = dexec_sh("broker",
                     f"nc -z 127.0.0.1 {port} && echo UP || true",
                     check=False, capture=True)
        if "UP" in (r.stdout or ""):
            return True
        time.sleep(0.3)
    return False


def collect(role, cell_dir, remote_glob):
    """docker cp <container>:/opt/testbed/out/<file> into the cell dir."""
    name = CONTAINERS[role]
    # Copy the whole out/ dir then let the caller sort files; simplest & atomic.
    sh(["docker", "cp", f"{name}:{TB}/out/.", cell_dir], check=False)


def reset_out(role):
    dexec_sh(role, f"rm -rf {TB}/out && mkdir -p {TB}/out", check=False)


PROC_PAT = ("patient.py|collector.py|monitor.py|"
            "attack_conn_exhaust.py|attack_malformed.py|mosquitto")


def cleanup_all(scale):
    """Kill any processes a previous cell left behind, in every container, and
    clear the rate-limit table. Detached `docker exec -d` processes survive an
    interrupted orchestrator run (a held connection flood, a still-bound
    broker), and would poison the next cell; this makes each cell start from a
    clean slate regardless of how the last one ended."""
    roles = ["broker", "collector", "attacker"] + \
            [f"patient-{i}" for i in range(1, scale + 1)]
    for r in roles:
        if r in CONTAINERS:
            dexec_sh(r, f"pkill -9 -f '{PROC_PAT}' 2>/dev/null; true", check=False)
    if "broker" in CONTAINERS:
        dexec_sh("broker", "nft delete table ip e2a 2>/dev/null; true", check=False)


# ---- cell validity ----------------------------------------------------------
# A first GNS3 sweep produced "PDR=1.000 (19/19)" cells: the topology had been
# stopped underneath the run, patients were cut off after two seconds, and the
# orchestrator reported the remnant as a valid measurement. These guards make
# that impossible: a cell either measures the full window on a topology that
# stayed up, or it is marked INVALID and the sweep re-runs it.
EXIT_INVALID = 3        # cell ran but its data is incomplete -> retry the cell
EXIT_TOPOLOGY_DOWN = 4  # containers not running / unreachable -> stop the sweep


def started_at(roles):
    """Container start timestamps; a change between the start and the end of a
    cell means GNS3 restarted a node mid-measurement."""
    names = [CONTAINERS[r] for r in roles]
    out = subprocess.run(
        ["docker", "inspect", "-f", "{{.Name}} {{.State.Running}} {{.State.StartedAt}}"]
        + names, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True).stdout
    info = {}
    for line in out.splitlines():
        parts = line.strip().lstrip("/").split()
        if len(parts) == 3:
            info[parts[0]] = (parts[1] == "true", parts[2])
    return info


def preflight(roles):
    """Every container this cell needs must be running, and the collector and a
    patient must reach the broker across the switch, before anything starts."""
    info = started_at(roles)
    down = [r for r in roles if not info.get(CONTAINERS[r], (False, ""))[0]]
    if down:
        return f"containers not running: {down}"
    probe = [r for r in roles if r == "collector" or r == "patient-1"]
    for r in probe:
        ok = dexec_sh(r, f"ping -c1 -W2 {BROKER_IP} >/dev/null 2>&1 && echo OK",
                      check=False, capture=True)
        if "OK" not in (ok.stdout or ""):
            return f"{r} cannot reach the broker at {BROKER_IP} (links down?)"
    return None


# ---- VM freeze detection ----------------------------------------------------
# On this host the GNS3 VM runs under VirtualBox's Hyper-V (NEM) backend, which
# was observed to freeze the guest for 1-4 minutes (kernel soft lockups, RCU
# stalls). A freeze inside a cell corrupts its timing even if every file is
# complete, so a cell hit by one is INVALID. All containers share the VM's one
# kernel, so the kernel log read from the privileged broker container sees it.
STALL_RE = re.compile(r"^\[\s*(\d+\.\d+)\]\s.*(soft lockup|rcu_preempt detected stall"
                      r"|rcu: INFO: .*stall|self-detected stall|Watchdog timeout)")
MAX_SEND_GAP_S = 3.0   # patients send every 1/rate s; a 3 s hole means a freeze


def kernel_uptime():
    out = dexec("broker", ["cat", "/proc/uptime"], check=False, capture=True).stdout
    try:
        return float(out.split()[0])
    except (ValueError, IndexError, AttributeError):
        return None


def kernel_stalls_since(t0):
    if t0 is None:
        return ["could not read kernel uptime at cell start"]
    out = dexec("broker", ["dmesg"], check=False, capture=True).stdout or ""
    hits = []
    for line in out.splitlines():
        m = STALL_RE.match(line)
        if m and float(m.group(1)) >= t0:
            hits.append(line.strip()[:120])
    return hits


def send_gaps(cell, scale):
    """Largest gap between consecutive sends, per patient, from the senders'
    own timestamps."""
    import csv
    worst = []
    for i in range(1, scale + 1):
        try:
            with open(os.path.join(cell, f"sent_bed-{i}.csv")) as f:
                ts = [float(r["t_send"]) for r in csv.DictReader(f)]
        except (OSError, ValueError, KeyError):
            continue
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        if gaps and max(gaps) > MAX_SEND_GAP_S:
            worst.append((f"bed-{i}", round(max(gaps), 1)))
    return worst


def validate_cell(cell, scale, duration, rate, attack, before, roles, t0=None):
    """Return a list of reasons the cell is not a complete measurement."""
    import csv
    reasons = []
    stalls = kernel_stalls_since(t0)
    if stalls:
        reasons.append(f"VM kernel stall during the cell ({len(stalls)} log lines), "
                       f"first: {stalls[0]}")
    gaps = send_gaps(cell, scale)
    if gaps:
        reasons.append(f"send gaps > {MAX_SEND_GAP_S:.0f} s (VM freeze?): {gaps[:4]}")
    after = started_at(roles)
    restarted = [r for r in roles
                 if after.get(CONTAINERS[r]) != before.get(CONTAINERS[r])]
    if restarted:
        reasons.append(f"containers restarted or stopped during the cell: {restarted}")
    # each patient must have logged (almost) the whole window
    need_rows = int(0.9 * duration * rate)
    for i in range(1, scale + 1):
        path = os.path.join(cell, f"sent_bed-{i}.csv")
        try:
            with open(path) as f:
                n = sum(1 for _ in csv.reader(f)) - 1
        except OSError:
            reasons.append(f"sent_bed-{i}.csv missing")
            continue
        if n < need_rows:
            reasons.append(f"sent_bed-{i}.csv has {n} rows, expected >= {need_rows}")
    for fname in ["recv.csv", "broker.csv"] + (["attack.csv"] if attack else []):
        if not os.path.exists(os.path.join(cell, fname)):
            reasons.append(f"{fname} missing")
    return reasons


def wait_patients_done(scale, duration):
    """Patients run exactly `duration`; wait that long, then confirm every one
    has exited. The pattern is anchored on the exec'd command line so it cannot
    match the `sh -c` wrapper that runs pgrep itself."""
    time.sleep(duration + 2)
    end = time.monotonic() + 20
    pending = [f"patient-{i}" for i in range(1, scale + 1)]
    while pending and time.monotonic() < end:
        still = []
        for r in pending:
            out = dexec_sh(r, "pgrep -f '^python3 src/patient.py' >/dev/null "
                              "&& echo RUN || echo DONE", check=False, capture=True)
            if "RUN" in (out.stdout or ""):
                still.append(r)
        pending = still
        if pending:
            time.sleep(1.0)
    return pending


def stage_broker_configs(conf):
    """Stage the chosen broker config + the broker's certs + the acl FLAT under
    /etc/mosquitto -- the only tree the AppArmor-confined mosquitto binary may
    read -- and rewrite the config's relative paths to absolute /etc/mosquitto
    paths. The Canonical mosquitto profile allows /etc/mosquitto/* (one level
    only) plus /etc/mosquitto/certs/** and /etc/mosquitto/ca_certificates/**
    (recursive), so: config -> /etc/mosquitto/<name>.conf, certs ->
    /etc/mosquitto/certs/, acl -> /etc/mosquitto/acl. The staged key is made
    world-readable because mosquitto, started as root, drops to the 'mosquitto'
    user and could not otherwise read a 600 root-owned key. Returns the
    absolute config path to launch."""
    name = os.path.basename(conf)  # e.g. baseline.conf
    script = (
        "mkdir -p /etc/mosquitto/certs && "
        "rm -f /etc/mosquitto/*.conf /etc/mosquitto/acl && "
        f"cp {TB}/certs/ca.crt {TB}/certs/server.crt {TB}/certs/server.key "
        "/etc/mosquitto/certs/ && chmod 644 /etc/mosquitto/certs/* && "
        f"cp {TB}/mosquitto/acl /etc/mosquitto/acl && chmod 644 /etc/mosquitto/acl && "
        "sed -e 's# certs/# /etc/mosquitto/certs/#g' "
        "-e 's#mosquitto/acl#/etc/mosquitto/acl#g' "
        f"{TB}/{conf} > /etc/mosquitto/{name}"
    )
    dexec_sh("broker", script, check=True)
    return f"/etc/mosquitto/{name}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exp", choices=["e2a", "e2b", "e2c", "e2d"], required=True)
    ap.add_argument("--condition",
                    choices=["baseline", "mitig", "attack", "attack_mitig"],
                    required=True)
    ap.add_argument("--scale", type=int, default=10)
    ap.add_argument("--rep", type=int, default=1)
    ap.add_argument("--duration", type=float, default=60.0)
    ap.add_argument("--rate", type=float, default=1.0)
    ap.add_argument("--attack-lead", type=float, default=0.5)
    ap.add_argument("--count", type=int, default=400,
                    help="attacker connection count")
    ap.add_argument("--project", default=None,
                    help="GNS3 project id to disambiguate containers")
    args = ap.parse_args()

    discover(args.project)
    need = ["broker", "collector"] + [f"patient-{i}" for i in range(1, args.scale + 1)]
    attack = args.condition in ("attack", "attack_mitig")
    if attack:
        need.append("attacker")
    missing = [r for r in need if r not in CONTAINERS]
    if missing:
        sys.exit(f"missing containers (are the nodes started?): {missing}")

    conf, port, tls = broker_for(args.exp, args.condition)
    mitig = args.condition in ("mitig", "attack_mitig")

    res_root = os.environ.get("E2_RESULTS_DIR", "results")
    cell = os.path.join(ROOT, res_root, args.exp, args.condition,
                        f"s{args.scale}", f"r{args.rep}")
    # a re-run of a cell must never mix with files from an earlier attempt
    import shutil
    shutil.rmtree(cell, ignore_errors=True)
    os.makedirs(cell, exist_ok=True)

    print(f"[{args.exp}/{args.condition}/s{args.scale}/r{args.rep}] "
          f"broker={conf} port={port} tls={tls} attack={attack} mitig={mitig}",
          flush=True)

    problem = preflight(need)
    if problem:
        print(f"  TOPOLOGY DOWN: {problem}", flush=True)
        with open(os.path.join(cell, "INVALID"), "w") as f:
            f.write(f"topology down: {problem}\n")
        sys.exit(EXIT_TOPOLOGY_DOWN)
    before = started_at(need)
    t0 = kernel_uptime()   # VM kernel clock at cell start, for stall detection

    # clear any stragglers left by an interrupted previous cell, then give
    # every participating container a fresh out/ dir
    cleanup_all(args.scale)
    for r in need:
        reset_out(r)

    # --- per-source rate limit (E2a/E2c half of the mitigation) -------------
    rl_on = mitig and args.exp in ("e2a", "e2c", "e2d")
    if rl_on:
        ratelimit(port, on=True)

    try:
        # 1. broker (detached, inside broker container). The config, certs and
        # acl are staged flat under /etc/mosquitto with absolute paths (see
        # stage_broker_configs) so the AppArmor-confined binary can read them.
        # broker.log goes to the testbed out/ dir; the shell opens that file,
        # not the confined binary.
        etc_conf = stage_broker_configs(conf)
        dexec_sh("broker",
                 f"exec mosquitto -c {etc_conf} > {TB}/out/broker.log 2>&1",
                 detach=True)
        if not wait_broker(port):
            print("  INVALID: broker did not come up; see broker.log", flush=True)
            collect("broker", cell, None)
            with open(os.path.join(cell, "INVALID"), "w") as f:
                f.write("broker did not come up\n")
            sys.exit(EXIT_INVALID)

        # 2. resource monitor on the mosquitto pid, inside the broker container
        pid = dexec_sh("broker", "pidof mosquitto | awk '{print $1}'",
                       capture=True).stdout.strip()
        if pid:
            dexec_sh("broker",
                     f"cd {TB} && exec python3 src/monitor.py --pid {pid} "
                     f"--outfile out/broker.csv > out/monitor.log 2>&1",
                     detach=True)

        # 3. collector (detached, inside collector container)
        coll = (f"cd {TB} && exec python3 src/collector.py "
                f"--host {BROKER_IP} --port {port} --outfile out/recv.csv")
        if tls:
            coll += " " + " ".join(tls_args("collector"))
        coll += " > out/collector.log 2>&1"
        dexec_sh("collector", coll, detach=True)
        time.sleep(1.5)

        # 4. attacker, --attack-lead before the patients
        if attack:
            if args.exp in ("e2a", "e2c", "e2d"):
                a = (f"cd {TB} && exec python3 src/attack_conn_exhaust.py "
                     f"--host {BROKER_IP} --port {port} --source {ATTACKER_IP} "
                     f"--count {args.count} "
                     f"--duration {args.duration + args.attack_lead} "
                     f"--outfile out/attack.csv")
                if args.exp == "e2c":
                    a += " --no-connect --liveness out/attack_liveness.csv"
            else:  # e2b malformed
                a = (f"cd {TB} && exec python3 src/attack_malformed.py "
                     f"--host {BROKER_IP} --port {port} "
                     f"--duration {args.duration} --outfile out/attack.csv")
                if tls:
                    a += f" --tls --cafile {TB}/certs/ca.crt"
            a += " > out/attack_run.log 2>&1"
            dexec_sh("attacker", a, detach=True)
            time.sleep(args.attack_lead)

        # 5. patients (detached, each in its own container)
        for i in range(1, args.scale + 1):
            name = f"bed-{i}"
            role = f"patient-{i}"
            p = (f"cd {TB} && exec python3 src/patient.py --id {name} "
                 f"--host {BROKER_IP} --port {port} --rate {args.rate} "
                 f"--duration {args.duration} --outdir out")
            if tls:
                p += " " + " ".join(tls_args(name))
            p += " > out/patient.log 2>&1"
            dexec_sh(role, p, detach=True)

        # 6. wait out the window, then confirm every patient has exited
        stuck = wait_patients_done(args.scale, args.duration)
        if stuck:
            print(f"  warning: patients still running after the window: {stuck}",
                  flush=True)
        time.sleep(1.5)

        # stop collector + monitor + attacker (patients have exited)
        for r in ("attacker", "collector", "broker"):
            if r in CONTAINERS:
                dexec_sh(r, "pkill -TERM -f 'collector.py|monitor.py|"
                            "attack_conn_exhaust.py|attack_malformed.py' "
                            "2>/dev/null; true", check=False)
        time.sleep(1.5)

    finally:
        if rl_on:
            ratelimit(port, on=False)
        # stop the broker last, AFTER collecting below would be ideal, but the
        # monitor already wrote broker.csv incrementally; collect then stop.
        pass

    # 7. collect every container's out/ into the cell dir (before any reset)
    collect("broker", cell, None)       # broker.log, broker.csv, monitor.log
    collect("collector", cell, None)    # recv.csv, collector.log
    if attack:
        collect("attacker", cell, None)  # attack.csv, (liveness), attack_run.log
    for i in range(1, args.scale + 1):
        collect(f"patient-{i}", cell, None)  # sent_bed-i.csv, patient.log

    # now the broker process can go
    dexec_sh("broker", "pkill -TERM mosquitto 2>/dev/null; true", check=False)

    # quick delivery figure so a sweep shows progress (analyze.py is authority)
    pdr = cell_summary(cell, args.scale)
    reasons = validate_cell(cell, args.scale, args.duration, args.rate,
                            attack, before, need, t0)
    if reasons:
        with open(os.path.join(cell, "INVALID"), "w") as f:
            f.write("\n".join(reasons) + "\n")
        print(f"  INVALID -> {os.path.relpath(cell, ROOT)}  {pdr}", flush=True)
        for r in reasons[:5]:
            print(f"    - {r}", flush=True)
        sys.exit(EXIT_INVALID)
    with open(os.path.join(cell, "DONE"), "w") as f:
        f.write("valid\n")
    print(f"  done -> {os.path.relpath(cell, ROOT)}  {pdr}", flush=True)


def cell_summary(cell, scale):
    import csv
    import glob
    offered = set()
    connected = 0
    for path in glob.glob(os.path.join(cell, "sent_*.csv")):
        try:
            with open(path) as f:
                rows = list(csv.DictReader(f))
        except OSError:
            continue
        if any(r.get("accepted") == "1" for r in rows):
            connected += 1
        for r in rows:
            offered.add((r["pub_id"], r["seq"]))
    delivered = set()
    recv = os.path.join(cell, "recv.csv")
    if os.path.exists(recv):
        try:
            with open(recv) as f:
                for r in csv.DictReader(f):
                    key = (r["pub_id"], r["seq"])
                    if key in offered:
                        delivered.add(key)
        except OSError:
            pass
    pdr = len(delivered) / len(offered) if offered else float("nan")
    return (f"PDR={pdr:.3f} ({len(delivered)}/{len(offered)}) "
            f"connected={connected}/{scale}")


if __name__ == "__main__":
    main()
