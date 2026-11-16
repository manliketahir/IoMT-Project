#!/usr/bin/env python3
"""B->C boundary run: patient -> ward broker -> adapter -> clinical stub.

This exercises the ward->clinical boundary in stub form and measures delivery
and end-to-end latency all the way to the clinical consumer. It reuses the E2
broker configs and the same patient monitors, so the workload is identical to
the E2 sweep and the two sets of numbers are directly comparable.

Two postures:
  --posture plain      plain MQTT on 1883 (the E2 baseline broker)
  --posture hardened   mutual TLS + ACL + cap on 8883 (the deployable posture,
                       the e2c broker); patients, collector and adapter all
                       present client certificates

Results go to results/bc/<posture>/s<scale>/r<rep>/. clinical_recv.csv is the
new artefact; analyze_bc.py reads it against sent_*.csv.
"""
import argparse
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


def tls_args(name):
    return ["--cafile", os.path.join(CERTS, "ca.crt"),
            "--certfile", os.path.join(CERTS, f"{name}.crt"),
            "--keyfile", os.path.join(CERTS, f"{name}.key")]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--posture", choices=["plain", "hardened"], default="plain")
    ap.add_argument("--scale", type=int, default=30)
    ap.add_argument("--rep", type=int, default=1)
    ap.add_argument("--duration", type=float, default=60.0)
    ap.add_argument("--rate", type=float, default=1.0)
    ap.add_argument("--clinical-port", type=int, default=9009)
    args = ap.parse_args()

    if args.posture == "hardened":
        conf, port, tls = "mosquitto/hardened.conf", 8883, True
    else:
        conf, port, tls = "mosquitto/baseline.conf", 1883, False

    outdir = os.path.join(ROOT, "results", "bc", args.posture,
                          f"s{args.scale}", f"r{args.rep}")
    os.makedirs(outdir, exist_ok=True)
    procs = []

    def spawn(cmd, **kw):
        p = subprocess.Popen(cmd, **kw)
        procs.append(p)
        return p

    print(f"[bc/{args.posture}/s{args.scale}/r{args.rep}] "
          f"broker={conf} port={port} tls={tls}")

    # 1. ward broker
    broker = spawn(["mosquitto", "-c", conf], cwd=ROOT,
                   stdout=open(os.path.join(outdir, "broker.log"), "w"),
                   stderr=subprocess.STDOUT)
    if not wait_port("127.0.0.1", port):
        print("broker did not come up; see broker.log")
        broker.terminate()
        sys.exit(1)

    # 2. broker resource monitor
    spawn([sys.executable, os.path.join(SRC, "monitor.py"),
           "--pid", str(broker.pid),
           "--outfile", os.path.join(outdir, "broker.csv")])

    # 3. clinical stub consumer (plane C stub)
    spawn([sys.executable, os.path.join(SRC, "clinical_stub.py"),
           "--host", "127.0.0.1", "--port", str(args.clinical_port),
           "--outfile", os.path.join(outdir, "clinical_recv.csv")])
    if not wait_port("127.0.0.1", args.clinical_port):
        print("clinical stub did not come up")
        sys.exit(1)

    # 4. ward collector (so the ward leg is still measured, as in E2)
    coll = [sys.executable, os.path.join(SRC, "collector.py"),
            "--host", "127.0.0.1", "--port", str(port),
            "--outfile", os.path.join(outdir, "recv.csv")]
    if tls:
        coll += tls_args("collector")
    spawn(coll)

    # 5. the B->C adapter (the pivot attached to both segments)
    adp = [sys.executable, os.path.join(SRC, "adapter.py"),
           "--broker-host", "127.0.0.1", "--broker-port", str(port),
           "--clinical-host", "127.0.0.1", "--clinical-port",
           str(args.clinical_port)]
    if tls:
        adp += ["--cafile", os.path.join(CERTS, "ca.crt"),
                "--certfile", os.path.join(CERTS, "collector.crt"),
                "--keyfile", os.path.join(CERTS, "collector.key")]
    spawn(adp)
    time.sleep(1.5)

    # 6. patient publishers (same workload as E2)
    pubs = []
    for i in range(1, args.scale + 1):
        name = f"bed-{i}"
        cmd = [sys.executable, os.path.join(SRC, "patient.py"),
               "--id", name, "--host", "127.0.0.1", "--port", str(port),
               "--rate", str(args.rate), "--duration", str(args.duration),
               "--outdir", outdir, "--bind", f"127.0.0.{i + 2}"]
        if tls:
            cmd += tls_args(name)
        pubs.append(spawn(cmd))

    # 7. wait, then stop newest-first so the stub flushes last
    for p in pubs:
        p.wait()
    time.sleep(2.0)   # let in-flight samples reach the consumer
    for p in reversed(procs):
        if p.poll() is None:
            p.send_signal(signal.SIGTERM)
    time.sleep(1.5)
    for p in procs:
        if p.poll() is None:
            p.kill()
    print(f"  done -> {os.path.relpath(outdir, ROOT)}")


if __name__ == "__main__":
    main()
