#!/usr/bin/env python3
"""E6 orchestrator for the GNS3 topology (HL7 v2 / MLLP, plane C).

GNS3 counterpart of run_e6.py. run_e6.py runs every role as a local process
over loopback; here each role is a container in the E6 topology built by
gns3_build_e6.py, driven with `docker exec` and collected with `docker cp`.
It runs ON the GNS3 VM, next to plane-b/run_gns3.py, whose hardened machinery
it reuses (AppArmor-safe broker staging, container-restart detection, VM
kernel-stall and send-gap checks, DONE / INVALID markers and exit codes).

Topology (gns3_build_e6.py):
    plane B ward      10.0.6.0/24  e6-broker .10, e6-patient-i .100+i
    boundary                       e6-router 10.0.6.1 | 10.0.7.1
    plane C clinical  10.0.7.0/24  e6-listener .10, e6-gateway .20, e6-attacker .100

The gateway subscribes to the ward broker across the router (the stand-in for
the proposal's MQTT->DDS link; E6 is built without the DDS stage) and delivers
each reading over MLLP to the listener. The attacker sits inside plane C, as in
the proposal diagram. Mitigations are the listener's, as in run_e6.py:

  e6a (tampering)    mitig = nftables allow-list on the listener (only the
                     gateway's address may reach MLLP) + mutual TLS on MLLP
  e6b (exhaustion)   mitig = per-peer connection cap (20) on the listener,
                     over a global ceiling of 100 present in every e6b cell

Differences from run_e6.py, all forced by the move off loopback:
  * no --bind aliases: each role has its own address, so the allow-list keys on
    the gateway's real IP (10.0.7.20) and the flood on the attacker's (.100);
  * the allow-list runs inside the listener container, not on the host;
  * the HL7 certificates are copied into the gateway and listener at run time
    (they are not baked into the image).

Results land in results/<exp>/<cond>/s<scale>/r<rep>/ exactly as run_e6.py's,
so analyze_e6.py reads them unchanged.

    python3 run_gns3_e6.py --exp e6a --condition attack --scale 10 --rep 1
"""
import argparse
import os
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
PLANE_B = os.environ.get("GNS3_PLANE_B", os.path.join(ROOT, "..", "plane-b"))
sys.path.insert(0, os.path.abspath(PLANE_B))
import run_gns3 as R  # noqa: E402  (shared GNS3 orchestration helpers)

TB = R.TB                     # /opt/testbed in the image: plane-b tree (patients, broker conf, monitor)
PC = "/opt/plane-c"           # plane-c tree in the image
OUT = f"{TB}/out"             # every container writes here; reset per cell
CERT_SRC = os.path.join(ROOT, "certs")   # on the VM: ca.crt, hl7-server.*, hl7-gateway.*

BROKER_IP, LISTENER_IP, GATEWAY_IP, ATTACKER_IP = "10.0.6.10", "10.0.7.10", "10.0.7.20", "10.0.7.100"
WARD_NET, CLIN_NET, WARD_GW, CLIN_GW = "10.0.6.0/24", "10.0.7.0/24", "10.0.6.1", "10.0.7.1"
MLLP_PORT, MQTT_PORT = 2575, 1883

E6_PAT = ("patient.py|monitor.py|hl7_listener.py|hl7_gateway.py|"
          "attack_hl7_tamper.py|attack_hl7_exhaust.py|mosquitto")


def discover(scale):
    """Map E6 node names onto the role names the shared helpers use."""
    out = subprocess.run(["docker", "ps", "--format", "{{.Names}}"],
                         check=True, stdout=subprocess.PIPE, text=True).stdout
    alias = {"e6-broker": "broker", "e6-gateway": "gateway", "e6-listener": "listener",
             "e6-attacker": "attacker", "e6-router": "router"}
    alias.update({f"e6-patient-{i}": f"patient-{i}" for i in range(1, scale + 1)})
    for line in out.split():
        parts = line.split(".")
        if len(parts) >= 3 and parts[0] == "GNS3" and parts[1] in alias:
            R.CONTAINERS[alias[parts[1]]] = line


def ward(roles):
    return [r for r in roles if r == "broker" or r.startswith("patient-")]


def preflight(roles):
    info = R.started_at(roles + ["router"])
    down = [r for r in roles + ["router"] if not info.get(R.CONTAINERS[r], (False, ""))[0]]
    if down:
        return f"containers not running: {down}"
    # the router forwards between the planes; both sides route via it
    R.dexec_sh("router", "sysctl -qw net.ipv4.ip_forward=1", check=False)
    for r in roles:
        if r in ward(roles):
            R.dexec_sh(r, f"ip route replace {CLIN_NET} via {WARD_GW}", check=False)
        else:
            R.dexec_sh(r, f"ip route replace {WARD_NET} via {CLIN_GW}", check=False)
    probes = [("gateway", BROKER_IP, "gateway -> ward broker, across the router"),
              ("gateway", LISTENER_IP, "gateway -> listener"),
              ("patient-1", BROKER_IP, "patient-1 -> broker")]
    if "attacker" in roles:
        probes.append(("attacker", LISTENER_IP, "attacker -> listener"))
    for r, ip, what in probes:
        ok = R.dexec_sh(r, f"ping -c1 -W2 {ip} >/dev/null 2>&1 && echo OK",
                        check=False, capture=True)
        if "OK" not in (ok.stdout or ""):
            return f"no path: {what} ({ip})"
    return None


def cleanup(roles):
    for r in roles:
        R.dexec_sh(r, f"pkill -9 -f '{E6_PAT}' 2>/dev/null; true", check=False)
    R.dexec_sh("listener", "nft delete table ip e6allow 2>/dev/null; true", check=False)


def stage_certs():
    for role, names in (("listener", ["ca.crt", "hl7-server.crt", "hl7-server.key"]),
                        ("gateway", ["ca.crt", "hl7-gateway.crt", "hl7-gateway.key"])):
        R.dexec_sh(role, f"mkdir -p {PC}/certs", check=False)
        for n in names:
            R.sh(["docker", "cp", os.path.join(CERT_SRC, n),
                  f"{R.CONTAINERS[role]}:{PC}/certs/{n}"], check=True)


def wait_port(role, port, timeout=15.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        r = R.dexec_sh(role, f"nc -z 127.0.0.1 {port} && echo UP || true",
                       check=False, capture=True)
        if "UP" in (r.stdout or ""):
            return True
        time.sleep(0.3)
    return False


def wait_gone(role, pattern, timeout):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        r = R.dexec_sh(role, f"pgrep -f '{pattern}' >/dev/null && echo RUN || echo DONE",
                       check=False, capture=True)
        if "DONE" in (r.stdout or ""):
            return True
        time.sleep(1.0)
    return False


def summary(cell, scale):
    import csv
    def rows(n):
        try:
            with open(os.path.join(cell, n)) as f:
                return list(csv.DictReader(f))
        except OSError:
            return []
    offered = sum(len(rows(f"sent_bed-{i}.csv")) for i in range(1, scale + 1))
    delivered = sum(1 for r in rows("hl7_sent.csv") if r.get("ok") == "1")
    s = f"gateway delivered {delivered}/{offered}"
    tam = rows("tamper.csv")
    if tam:
        s += f"  forged accepted {sum(1 for r in tam if r.get('ack_code') == 'AA')}/{len(tam)}"
    ex = {r["key"]: r["value"] for r in rows("exhaust.csv") if "key" in r}
    if ex:
        s += f"  flood established {ex.get('established')}/{ex.get('requested')}"
    return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exp", choices=["e6a", "e6b"], required=True)
    ap.add_argument("--condition", choices=["baseline", "mitig", "attack", "attack_mitig"],
                    required=True)
    ap.add_argument("--scale", type=int, default=10)
    ap.add_argument("--rep", type=int, default=1)
    ap.add_argument("--duration", type=float, default=60.0)
    ap.add_argument("--rate", type=float, default=1.0)
    ap.add_argument("--validate", choices=["structural", "schema"], default="structural")
    ap.add_argument("--peer-cap", type=int, default=20)
    ap.add_argument("--max-conns", type=int, default=100)
    ap.add_argument("--attack-lead", type=float, default=5.0)
    args = ap.parse_args()

    mitig = args.condition in ("mitig", "attack_mitig")
    attack = args.condition in ("attack", "attack_mitig")
    use_tls = args.exp == "e6a" and mitig
    use_allowlist = args.exp == "e6a" and mitig
    use_cap = args.exp == "e6b" and mitig

    discover(args.scale)
    need = (["broker", "gateway", "listener"]
            + [f"patient-{i}" for i in range(1, args.scale + 1)]
            + (["attacker"] if attack else []))
    missing = [r for r in need + ["router"] if r not in R.CONTAINERS]
    if missing:
        print(f"  TOPOLOGY DOWN: E6 containers not running: {missing}", flush=True)
        sys.exit(R.EXIT_TOPOLOGY_DOWN)

    cell = os.path.join(ROOT, os.environ.get("E6_RESULTS_DIR", "results"), args.exp,
                        args.condition, f"s{args.scale}", f"r{args.rep}")
    shutil.rmtree(cell, ignore_errors=True)
    os.makedirs(cell, exist_ok=True)
    print(f"[{args.exp}/{args.condition}/s{args.scale}/r{args.rep}] tls={use_tls} "
          f"cap={args.peer_cap if use_cap else 'none'} allowlist={use_allowlist} "
          f"attack={attack}", flush=True)

    problem = preflight(need)
    if problem:
        print(f"  TOPOLOGY DOWN: {problem}", flush=True)
        with open(os.path.join(cell, "INVALID"), "w") as f:
            f.write(f"topology down: {problem}\n")
        sys.exit(R.EXIT_TOPOLOGY_DOWN)
    watched = need + ["router"]   # a router restart would cut the gateway's ward feed
    before = R.started_at(watched)
    t0 = R.kernel_uptime()

    cleanup(need)
    for r in need:
        R.reset_out(r)
    stage_certs()

    def bail(msg):
        print(f"  INVALID: {msg}", flush=True)
        for r in need:
            R.collect(r, cell, None)
        with open(os.path.join(cell, "INVALID"), "w") as f:
            f.write(msg + "\n")
        cleanup(need)
        sys.exit(R.EXIT_INVALID)

    allowlist_on = False
    try:
        # 1. ward broker (plain; E6 is about the MLLP hop, not MQTT hardening)
        conf = R.stage_broker_configs("mosquitto/baseline.conf")
        R.dexec_sh("broker", f"exec mosquitto -c {conf} > {OUT}/broker.log 2>&1", detach=True)
        if not R.wait_broker(MQTT_PORT):
            bail("broker did not come up")

        # 2. network-layer allow-list on the listener (e6a mitig)
        listener_extra = ""
        if use_allowlist:
            r = R.dexec_sh("listener", f"bash {PC}/src/hl7_allowlist.sh on {GATEWAY_IP} {MLLP_PORT}"
                                       f" && nft list table ip e6allow >/dev/null && echo NFT_OK",
                           check=False, capture=True)
            allowlist_on = "NFT_OK" in (r.stdout or "")
            note = "NOTE_allowlist_nft" if allowlist_on else "NOTE_allowlist_fallback"
            with open(os.path.join(cell, note), "w") as f:
                f.write((r.stdout or "") + ("" if allowlist_on else
                        "nft allow-list unavailable; used in-listener --allow (weaker)\n"))
            if not allowlist_on:
                listener_extra += f" --allow {GATEWAY_IP},127.0.0.1"

        # 3. HL7 listener (the E6 target)
        lc = (f"cd {PC} && exec python3 src/hl7_listener.py --host 0.0.0.0 --port {MLLP_PORT}"
              f" --validate {args.validate} --outfile {OUT}/hl7_recv.csv"
              f" --statfile {OUT}/hl7_listener_stat.csv")
        if use_tls:
            lc += (f" --tls --cafile {PC}/certs/ca.crt --certfile {PC}/certs/hl7-server.crt"
                   f" --keyfile {PC}/certs/hl7-server.key")
        if args.exp == "e6b":
            lc += f" --max-conns {args.max_conns}"
        if use_cap:
            lc += f" --peer-cap {args.peer_cap}"
        lc += listener_extra + f" > {OUT}/listener.log 2>&1"
        R.dexec_sh("listener", lc, detach=True)
        if not wait_port("listener", MLLP_PORT):
            bail("listener did not come up")

        # 4. resource monitor on the listener pid
        pid = R.dexec_sh("listener", "pgrep -f 'hl7_listener.py' | head -1",
                         check=False, capture=True).stdout.strip()
        if pid:
            R.dexec_sh("listener", f"cd {TB} && exec python3 src/monitor.py --pid {pid}"
                                   f" --outfile {OUT}/listener_resource.csv > {OUT}/monitor.log 2>&1",
                       detach=True)

        # 5. HL7 gateway: MQTT from the ward (across the router), MLLP to the listener
        gc = (f"cd {PC} && exec python3 src/hl7_gateway.py --mqtt-host {BROKER_IP}"
              f" --mqtt-port {MQTT_PORT} --client-id hl7-gateway --hl7-host {LISTENER_IP}"
              f" --hl7-port {MLLP_PORT} --outfile {OUT}/hl7_sent.csv"
              f" --statfile {OUT}/hl7_gateway_stat.csv")
        if use_tls:
            gc += (f" --tls --cafile {PC}/certs/ca.crt --certfile {PC}/certs/hl7-gateway.crt"
                   f" --keyfile {PC}/certs/hl7-gateway.key --server-name localhost")
        if args.exp == "e6b":
            gc += " --per-message-conn"
        R.dexec_sh("gateway", gc + f" > {OUT}/gateway.log 2>&1", detach=True)
        time.sleep(1.5)

        # 6. attacker, inside plane C
        if attack:
            if args.exp == "e6a":
                ac = (f"cd {PC} && exec python3 src/attack_hl7_tamper.py --host {LISTENER_IP}"
                      f" --port {MLLP_PORT} --duration {args.duration} --rate 5"
                      f" --target-bed bed-1 --forged-value 72 --outfile {OUT}/tamper.csv")
            else:
                ac = (f"cd {PC} && exec python3 src/attack_hl7_exhaust.py --host {LISTENER_IP}"
                      f" --port {MLLP_PORT} --bind {ATTACKER_IP} --conns 300"
                      f" --duration {args.duration + args.attack_lead} --mode full"
                      f" --open-rate 150 --outfile {OUT}/exhaust.csv"
                      f" --liveness {OUT}/exhaust_liveness.csv")
            R.dexec_sh("attacker", ac + f" > {OUT}/attack.log 2>&1", detach=True)
            if args.exp == "e6b":
                time.sleep(args.attack_lead)

        # 7. patients (plane B)
        for i in range(1, args.scale + 1):
            R.dexec_sh(f"patient-{i}",
                       f"cd {TB} && exec python3 src/patient.py --id bed-{i} --host {BROKER_IP}"
                       f" --port {MQTT_PORT} --rate {args.rate} --duration {args.duration}"
                       f" --outdir {OUT} > {OUT}/patient.log 2>&1", detach=True)

        # 8. window, then let in-flight readings reach the listener and be ACKed
        stuck = R.wait_patients_done(args.scale, args.duration)
        if stuck:
            print(f"  warning: patients still running after the window: {stuck}", flush=True)
        time.sleep(2.0)
        if attack and args.exp == "e6a":
            # the tamper peer has no SIGTERM handler and writes tamper.csv only
            # when its own window ends, so let it finish rather than stop it
            wait_gone("attacker", "attack_hl7_tamper.py", 15)

        # 9. stop newest-first: attacker, gateway, monitor, listener, broker
        for role, pat in (("attacker", "attack_hl7_tamper.py|attack_hl7_exhaust.py"),
                          ("gateway", "hl7_gateway.py"), ("listener", "monitor.py"),
                          ("listener", "hl7_listener.py"), ("broker", "mosquitto")):
            if role in need:
                R.dexec_sh(role, f"pkill -TERM -f '{pat}' 2>/dev/null; true", check=False)
        time.sleep(1.5)
        for r in need:
            R.dexec_sh(r, f"pkill -9 -f '{E6_PAT}' 2>/dev/null; true", check=False)
    finally:
        if allowlist_on:
            R.dexec_sh("listener", f"bash {PC}/src/hl7_allowlist.sh off {MLLP_PORT}", check=False)

    # 10. collect every container's out/
    for r in need:
        R.collect(r, cell, None)

    reasons = R.validate_cell(cell, args.scale, args.duration, args.rate,
                              False, before, watched, t0)
    required = ["hl7_sent.csv", "hl7_recv.csv", "listener_resource.csv"]
    if attack:
        required.append("tamper.csv" if args.exp == "e6a" else "exhaust.csv")
    reasons += [f"{f} missing" for f in required if not os.path.exists(os.path.join(cell, f))]
    # validate_cell also demands E2's recv.csv/broker.csv; E6 has neither
    reasons = [x for x in reasons if x not in ("recv.csv missing", "broker.csv missing")]
    line = summary(cell, args.scale)
    if reasons:
        with open(os.path.join(cell, "INVALID"), "w") as f:
            f.write("\n".join(reasons) + "\n")
        print(f"  INVALID -> {os.path.relpath(cell, ROOT)}  {line}", flush=True)
        for x in reasons[:5]:
            print(f"    - {x}", flush=True)
        sys.exit(R.EXIT_INVALID)
    with open(os.path.join(cell, "DONE"), "w") as f:
        f.write("valid\n")
    print(f"  done -> {os.path.relpath(cell, ROOT)}  {line}", flush=True)


if __name__ == "__main__":
    main()
