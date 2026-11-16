#!/usr/bin/env python3
"""E2 orchestrator.

Runs one cell of the experiment: one sub-experiment (e2a or e2b), one of the
four conditions, one scale, one repetition. It starts the right broker, the
resource monitor, the collector and the patient publishers, optionally the
attack harness, waits out the window, stops everything in order, and leaves
all CSVs in results/<exp>/<condition>/s<scale>/r<rep>/.

The four conditions follow the mitigation-first design:
  baseline      legitimate traffic only, no mitigation
  mitig         legitimate traffic only, mitigation on   (cost = mitig - baseline)
  attack        attack + legitimate traffic, no mitigation
  attack_mitig  attack + legitimate traffic, mitigation on (efficacy vs attack)

Run many cells with: bash sweep.sh
"""
import argparse
import csv
import glob
import os
import signal
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, "src")
CERTS = os.path.join(ROOT, "certs")


def wait_port(host, port, timeout=10.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def broker_for(exp, condition):
    """Return (conf, port, tls) for this cell."""
    mitig = condition in ("mitig", "attack_mitig")
    if exp == "e2a":
        conf = "mosquitto/e2a_mitig.conf" if mitig else "mosquitto/baseline.conf"
        return conf, 1883, False
    if exp == "e2c":
        # combined defense-in-depth: mutual TLS + ACL + cap on 8883, with the
        # per-source rate limit applied around the run as in E2a
        if mitig:
            return "mosquitto/hardened.conf", 8883, True
        return "mosquitto/baseline.conf", 1883, False
    if exp == "e2d":
        # Early-flood variant of E2a, used with --attack-lead so the flood
        # arrives before the patients. The connection cap is the control under
        # test's environment: it is present in BOTH attack and attack_mitig, so
        # it is the binding constraint and the flood can take the slots the
        # patients need. The mitigation that is toggled between attack and
        # attack_mitig is the per-source rate limit (applied by the driver),
        # so efficacy = attack_mitig - attack isolates the rate limit alone.
        # Only the plain baseline is uncapped.
        if condition == "baseline":
            return "mosquitto/baseline.conf", 1883, False
        return "mosquitto/e2a_mitig.conf", 1883, False
    # e2b: mitigation is mutual TLS + ACL on 8883; otherwise plain anon
    if mitig:
        return "mosquitto/e2b_mitig.conf", 8883, True
    return "mosquitto/baseline.conf", 1883, False


def tls_args(name):
    return ["--cafile", os.path.join(CERTS, "ca.crt"),
            "--certfile", os.path.join(CERTS, f"{name}.crt"),
            "--keyfile", os.path.join(CERTS, f"{name}.key")]


def cell_summary(outdir):
    """Delivery figures for a finished cell, so a long sweep shows progress.

    analyze.py remains the authority for the reported numbers; this is the same
    arithmetic done once per cell purely so the terminal shows whether the
    attack is actually biting while the sweep is still running.
    """
    offered = set()
    connected = 0
    for path in glob.glob(os.path.join(outdir, "sent_*.csv")):
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
    recv = os.path.join(outdir, "recv.csv")
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
    return pdr, len(delivered), len(offered), connected


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exp", choices=["e2a", "e2b", "e2c", "e2d"], required=True)
    ap.add_argument("--condition",
                    choices=["baseline", "mitig", "attack", "attack_mitig"],
                    required=True)
    ap.add_argument("--scale", type=int, default=30)
    ap.add_argument("--rep", type=int, default=1)
    ap.add_argument("--duration", type=float, default=60.0)
    ap.add_argument("--rate", type=float, default=1.0)
    ap.add_argument("--attack-lead", type=float, default=0.5,
                    help="seconds the attacker runs before the patients start; "
                         "raise it (e.g. 10) so the flood fills the table first")
    args = ap.parse_args()

    conf, port, tls = broker_for(args.exp, args.condition)
    attack = args.condition in ("attack", "attack_mitig")
    # E2_RESULTS_DIR redirects a throwaway run (e.g. the setup.sh smoke test)
    # away from the real sweep's results/ tree. See analyze.py.
    res_root = os.environ.get("E2_RESULTS_DIR", "results")
    outdir = os.path.join(ROOT, res_root, args.exp, args.condition,
                          f"s{args.scale}", f"r{args.rep}")
    os.makedirs(outdir, exist_ok=True)

    procs = []

    def spawn(cmd, **kw):
        p = subprocess.Popen(cmd, **kw)
        procs.append(p)
        return p

    print(f"[{args.exp}/{args.condition}/s{args.scale}/r{args.rep}] "
          f"broker={conf} port={port} tls={tls} attack={attack}")

    # 1. broker
    broker = spawn(["mosquitto", "-c", conf], cwd=ROOT,
                   stdout=open(os.path.join(outdir, "broker.log"), "w"),
                   stderr=subprocess.STDOUT)
    if not wait_port("127.0.0.1", port):
        print("broker did not come up; see broker.log")
        broker.terminate()
        sys.exit(1)

    # 2. resource monitor on the broker pid
    spawn([sys.executable, os.path.join(SRC, "monitor.py"),
           "--pid", str(broker.pid),
           "--outfile", os.path.join(outdir, "broker.csv")])

    # 3. collector
    coll = [sys.executable, os.path.join(SRC, "collector.py"),
            "--host", "127.0.0.1", "--port", str(port),
            "--outfile", os.path.join(outdir, "recv.csv")]
    if tls:
        coll += tls_args("collector")
    spawn(coll)
    time.sleep(1.5)

    # 4. attacker, started --attack-lead seconds before the patients so its
    # effect overlaps them (and, with a large lead, precedes them). The flood
    # runs for the lead plus the patient window so it holds throughout.
    if attack:
        if args.exp in ("e2a", "e2c", "e2d"):
            cmd = [sys.executable, os.path.join(SRC, "attack_conn_exhaust.py"),
                   "--host", "127.0.0.1", "--port", str(port),
                   "--duration", str(args.duration + args.attack_lead),
                   "--outfile", os.path.join(outdir, "attack.csv")]
            # On the hardened TLS listener the flood is TCP-level only: it opens
            # sockets and never completes the TLS handshake, so it probes the
            # connection cap rather than the MQTT parser.
            if args.exp == "e2c":
                cmd += ["--no-connect",
                        "--liveness", os.path.join(outdir, "attack_liveness.csv")]
            spawn(cmd)
        else:
            cmd = [sys.executable, os.path.join(SRC, "attack_malformed.py"),
                   "--host", "127.0.0.1", "--port", str(port),
                   "--duration", str(args.duration),
                   "--outfile", os.path.join(outdir, "attack.csv")]
            if tls:
                cmd += ["--tls", "--cafile", os.path.join(CERTS, "ca.crt")]
            spawn(cmd)
        time.sleep(args.attack_lead)

    # 5. patient publishers
    pubs = []
    for i in range(1, args.scale + 1):
        name = f"bed-{i}"
        cmd = [sys.executable, os.path.join(SRC, "patient.py"),
               "--id", name, "--host", "127.0.0.1", "--port", str(port),
               "--rate", str(args.rate), "--duration", str(args.duration),
               "--outdir", outdir,
               # Each patient binds a distinct loopback source so the E2a
               # per-source rate limit treats it as its own client; the
               # collector keeps 127.0.0.1 and the attacker uses 127.0.0.2.
               "--bind", f"127.0.0.{i + 2}"]
        if tls:
            cmd += tls_args(name)
        pubs.append(spawn(cmd))

    # 6. wait out the window, then stop everything newest-first
    for p in pubs:
        p.wait()
    time.sleep(1.0)
    for p in reversed(procs):
        if p.poll() is None:
            p.send_signal(signal.SIGTERM)
    time.sleep(1.5)
    for p in procs:
        if p.poll() is None:
            p.kill()
    pdr, delivered, offered, connected = cell_summary(outdir)
    print(f"  done -> {os.path.relpath(outdir, ROOT)}  "
          f"PDR={pdr:.3f} ({delivered}/{offered})  "
          f"connected={connected}/{args.scale}")


if __name__ == "__main__":
    main()
