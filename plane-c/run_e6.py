#!/usr/bin/env python3
"""E6 orchestrator: HL7 result tampering (e6a) and connection exhaustion (e6b).

Runs one cell: one sub-experiment, one of the four conditions, one repetition,
at the single stated scale. It starts the plane-B ward (broker + patient
monitors, reused unchanged), the HL7 gateway and the HL7 listener, optionally
the attacker, waits out the window, stops everything newest-first, and leaves
all CSVs under results/<exp>/<condition>/s<scale>/r<rep>/.

The chain is:

    patient.py x N  --MQTT-->  mosquitto  --MQTT-->  hl7_gateway.py
                                                          |
                                                          |  MLLP (the hop)
                                                          v
                                                    hl7_listener.py

The MQTT leg is plain throughout: E6 is not about MQTT hardening (that is E2),
it is about the MLLP hop. The TLS under test is the mutual TLS between the
gateway and the listener.

MITIGATION MAPPING (mitigation-first, four conditions)
------------------------------------------------------
e6a (tampering), mitigations = network-layer allow-list + mutual TLS on MLLP:
    baseline      gateway only, plain MLLP
    mitig         gateway only, allow-list + mutual TLS  (cost)
    attack        gateway + forging peer, plain MLLP     (forged accepted)
    attack_mitig  gateway + forging peer, allow-list + mutual TLS
                                                         (forged rejected)

e6b (exhaustion), mitigation = per-peer connection cap:
    baseline      gateway only, no cap
    mitig         gateway only, cap on                   (cost ~ nil)
    attack        gateway + connection flood, no cap     (gateway starved)
    attack_mitig  gateway + connection flood, cap on     (gateway served)

E6_RESULTS_DIR redirects a throwaway run away from the real results/ tree, the
same guard analyze.py and run.py use in plane B.
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
PLANE_B = os.path.normpath(os.path.join(ROOT, "..", "plane-b"))
PB_SRC = os.path.join(PLANE_B, "src")

MLLP_PORT = 2575
MQTT_PORT = 1883
GW_BIND = "127.0.0.2"
ATK_BIND = "127.0.0.3"


def wait_port(host, port, timeout=10.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def hl7_tls_args_listener():
    return ["--tls",
            "--cafile", os.path.join(CERTS, "ca.crt"),
            "--certfile", os.path.join(CERTS, "hl7-server.crt"),
            "--keyfile", os.path.join(CERTS, "hl7-server.key")]


def hl7_tls_args_gateway():
    return ["--tls",
            "--cafile", os.path.join(CERTS, "ca.crt"),
            "--certfile", os.path.join(CERTS, "hl7-gateway.crt"),
            "--keyfile", os.path.join(CERTS, "hl7-gateway.key"),
            "--server-name", "localhost"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exp", choices=["e6a", "e6b"], required=True)
    ap.add_argument("--condition",
                    choices=["baseline", "mitig", "attack", "attack_mitig"],
                    required=True)
    ap.add_argument("--scale", type=int, default=30)
    ap.add_argument("--rep", type=int, default=1)
    ap.add_argument("--duration", type=float, default=60.0)
    ap.add_argument("--rate", type=float, default=1.0)
    ap.add_argument("--validate", choices=["structural", "schema"],
                    default="structural")
    ap.add_argument("--peer-cap", type=int, default=20,
                    help="per-peer connection cap used in e6b mitig/attack_mitig")
    ap.add_argument("--max-conns", type=int, default=100,
                    help="listener global connection ceiling for e6b (the "
                         "environment; present in every e6b condition). Matches "
                         "the mosquitto max_connections=100 used in E2c.")
    ap.add_argument("--attack-lead", type=float, default=5.0,
                    help="seconds the exhaustion flood runs before the patients")
    args = ap.parse_args()

    mitig = args.condition in ("mitig", "attack_mitig")
    attack = args.condition in ("attack", "attack_mitig")

    res_root = os.environ.get("E6_RESULTS_DIR", "results")
    outdir = os.path.join(ROOT, res_root, args.exp, args.condition,
                          f"s{args.scale}", f"r{args.rep}")
    os.makedirs(outdir, exist_ok=True)

    use_tls = (args.exp == "e6a" and mitig)
    use_cap = (args.exp == "e6b" and mitig)
    use_allowlist = (args.exp == "e6a" and mitig)

    procs = []

    def spawn(cmd, **kw):
        p = subprocess.Popen(cmd, **kw)
        procs.append(p)
        return p

    print(f"[{args.exp}/{args.condition}/s{args.scale}/r{args.rep}] "
          f"tls={use_tls} cap={args.peer_cap if use_cap else 'none'} "
          f"allowlist={use_allowlist} attack={attack} validate={args.validate}")

    # 1. ward broker (plane B, plain)
    broker = spawn(["mosquitto", "-c", "mosquitto/baseline.conf"], cwd=PLANE_B,
                   stdout=open(os.path.join(outdir, "broker.log"), "w"),
                   stderr=subprocess.STDOUT)
    if not wait_port("127.0.0.1", MQTT_PORT):
        print("broker did not come up; see broker.log")
        broker.terminate()
        sys.exit(1)

    # 2. network-layer allow-list (e6a mitig): only the gateway source may
    #    reach the MLLP port. Applied before the listener binds.
    allowlist_on = False
    if use_allowlist:
        rc = subprocess.run(["bash", os.path.join(SRC, "hl7_allowlist.sh"),
                             "on", GW_BIND, str(MLLP_PORT)])
        allowlist_on = (rc.returncode == 0)

    # 3. HL7 listener
    listener_cmd = [sys.executable, os.path.join(SRC, "hl7_listener.py"),
                    "--host", "0.0.0.0", "--port", str(MLLP_PORT),
                    "--validate", args.validate,
                    "--outfile", os.path.join(outdir, "hl7_recv.csv"),
                    "--statfile", os.path.join(outdir, "hl7_listener_stat.csv")]
    if use_tls:
        listener_cmd += hl7_tls_args_listener()
    if args.exp == "e6b":
        # the global ceiling is the environment: present in all e6b conditions
        listener_cmd += ["--max-conns", str(args.max_conns)]
    if use_cap:
        listener_cmd += ["--peer-cap", str(args.peer_cap)]
    if use_allowlist and not allowlist_on:
        # nft unavailable: fall back to the weaker in-listener allow-list so the
        # mitigation still exists, and record that it was the weaker form.
        listener_cmd += ["--allow", f"{GW_BIND},127.0.0.1"]
        with open(os.path.join(outdir, "NOTE_allowlist_fallback"), "w") as f:
            f.write("nft allow-list unavailable; used in-listener --allow "
                    "(weaker: TCP connection completes before rejection)\n")
    listener = spawn(listener_cmd,
                     stdout=open(os.path.join(outdir, "listener.log"), "w"),
                     stderr=subprocess.STDOUT)
    if not wait_port("127.0.0.1", MLLP_PORT):
        print("listener did not come up; see listener.log")

    # 4. resource monitor on the listener pid (it is the E6 target)
    spawn([sys.executable, os.path.join(PB_SRC, "monitor.py"),
           "--pid", str(listener.pid),
           "--outfile", os.path.join(outdir, "listener_resource.csv")])

    # 5. HL7 gateway (subscribes before the patients publish)
    gw_cmd = [sys.executable, os.path.join(SRC, "hl7_gateway.py"),
              "--mqtt-host", "127.0.0.1", "--mqtt-port", str(MQTT_PORT),
              "--client-id", "hl7-gateway",
              "--hl7-host", "127.0.0.1", "--hl7-port", str(MLLP_PORT),
              "--bind", GW_BIND,
              "--outfile", os.path.join(outdir, "hl7_sent.csv"),
              "--statfile", os.path.join(outdir, "hl7_gateway_stat.csv")]
    if use_tls:
        gw_cmd += hl7_tls_args_gateway()
    if args.exp == "e6b":
        # per-message connections: the gateway must re-acquire a listener slot
        # for each reading, so a connection flood that fills the global ceiling
        # can lock it out. A persistent connection cannot be starved.
        gw_cmd += ["--per-message-conn"]
    spawn(gw_cmd, stdout=open(os.path.join(outdir, "gateway.log"), "w"),
          stderr=subprocess.STDOUT)
    time.sleep(1.5)

    # 6. attacker
    if attack:
        if args.exp == "e6a":
            cmd = [sys.executable, os.path.join(SRC, "attack_hl7_tamper.py"),
                   "--host", "127.0.0.1", "--port", str(MLLP_PORT),
                   "--bind", ATK_BIND, "--duration", str(args.duration),
                   "--rate", "5", "--target-bed", "bed-1",
                   "--forged-value", "72",
                   "--outfile", os.path.join(outdir, "tamper.csv")]
            # The forging peer presents no client certificate, so on the TLS
            # listener its handshake is refused -- which is the point.
            spawn(cmd, stdout=open(os.path.join(outdir, "attack.log"), "w"),
                  stderr=subprocess.STDOUT)
        else:
            cmd = [sys.executable, os.path.join(SRC, "attack_hl7_exhaust.py"),
                   "--host", "127.0.0.1", "--port", str(MLLP_PORT),
                   "--bind", ATK_BIND, "--conns", "300",
                   "--duration", str(args.duration + args.attack_lead),
                   "--mode", "full", "--open-rate", "150",
                   "--outfile", os.path.join(outdir, "exhaust.csv"),
                   "--liveness", os.path.join(outdir, "exhaust_liveness.csv")]
            spawn(cmd, stdout=open(os.path.join(outdir, "attack.log"), "w"),
                  stderr=subprocess.STDOUT)
            time.sleep(args.attack_lead)

    # 7. patient publishers (plane B, unchanged)
    pubs = []
    for i in range(1, args.scale + 1):
        cmd = [sys.executable, os.path.join(PB_SRC, "patient.py"),
               "--id", f"bed-{i}", "--host", "127.0.0.1",
               "--port", str(MQTT_PORT), "--rate", str(args.rate),
               "--duration", str(args.duration),
               "--outdir", outdir, "--bind", f"127.0.0.{i + 3}"]
        pubs.append(spawn(cmd))

    # 8. wait out the window, then stop everything newest-first
    for p in pubs:
        p.wait()
    time.sleep(2.0)   # let in-flight readings reach the listener and be ACKed
    for p in reversed(procs):
        if p.poll() is None:
            p.send_signal(signal.SIGTERM)
    time.sleep(1.5)
    for p in procs:
        if p.poll() is None:
            p.kill()

    if allowlist_on:
        subprocess.run(["bash", os.path.join(SRC, "hl7_allowlist.sh"),
                        "off", str(MLLP_PORT)])

    print(f"  done -> {os.path.relpath(outdir, ROOT)}")


if __name__ == "__main__":
    main()
