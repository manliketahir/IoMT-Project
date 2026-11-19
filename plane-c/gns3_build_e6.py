#!/usr/bin/env python3
"""Build the E6 (HL7 v2 / MLLP) topology in the GNS3 project 'CoEIA IoMT'.

Run on the Windows host while GNS3 is open (it talks to the local GNS3
controller on 127.0.0.1:3080 with the credentials in gns3_server.ini):

    python gns3_build_e6.py            # SCALE=10 patients by default

E6 gets its own nodes, separate from the E2 topology in the same project, so
the two experiments can be seen and run independently. The layout follows the
proposal's planes, without the DDS stage (E6 is designed to stand without
OpenICE/DDS; the gateway subscribes to the ward broker directly):

    plane B, ward      10.0.6.0/24   e6-broker (.10), e6-patient-1..N (.101..)
                                     e6-ward-sw
    boundary                         e6-router  10.0.6.1 | 10.0.7.1
    plane C, clinical  10.0.7.0/24   e6-listener (.10)  HL7 v2 listener, the target
                                     e6-gateway  (.20)  HL7 gateway (IHE PCD-01)
                                     e6-attacker (.100) HL7 attacker, inside plane C
                                     e6-clin-sw

The only traffic crossing the router is the gateway's MQTT subscription to the
ward broker -- the stand-in for the proposal's MQTT->DDS link. The MLLP hop
that E6 attacks and defends (gateway -> listener) and the attacker are both
inside plane C, as in the proposal diagram.

Idempotent: re-running reuses template, nodes, links and drawings by name and
only rewrites the static address files (which live on the GNS3 VM's disk, so
re-run this after replacing the VM). The image iomt-node:1.1 (the E2 image plus
the plane-c code) must already exist on the GNS3 VM.
"""
import base64, json, os, re, sys, urllib.error, urllib.request

CTRL = "http://127.0.0.1:3080/v2"
PROJECT_NAME = "CoEIA IoMT"
COMPUTE = "vm"
IMAGE = "iomt-node:1.1"
TEMPLATE_NAME = "iomt-node-e6"
SCALE = int(os.environ.get("SCALE", "10"))
X0 = 760          # E6 sits to the right of the E2 topology on the canvas

INI = os.path.join(os.environ["APPDATA"], "GNS3", "2.2", "gns3_server.ini")


def auth_header():
    txt = open(INI, encoding="utf-8", errors="replace").read()
    user = re.search(r"^user\s*=\s*(.+)$", txt, re.M).group(1).strip()
    pw = re.search(r"^password\s*=\s*(.+)$", txt, re.M).group(1).strip()
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()}


HDR = auth_header()


def call(method, path, body=None, raw=None):
    headers = dict(HDR)
    data = None
    if raw is not None:
        data = raw.encode()
        headers["Content-Type"] = "application/octet-stream"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(CTRL + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            txt = r.read().decode("utf-8", "replace")
            return json.loads(txt) if txt.strip().startswith(("{", "[")) else txt
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{method} {path} -> {e.code}: "
                           f"{e.read().decode('utf-8', 'replace')[:400]}") from None


# ---------------------------------------------------------------- project
proj = next((p for p in call("GET", "/projects") if p["name"] == PROJECT_NAME), None)
if not proj:
    sys.exit(f"project {PROJECT_NAME!r} not found")
PID = proj["project_id"]
if proj["status"] != "opened":
    call("POST", f"/projects/{PID}/open")
print(f"project {PROJECT_NAME} = {PID}")

# ---------------------------------------------------------------- template
tpl = next((t for t in call("GET", "/templates") if t.get("name") == TEMPLATE_NAME), None)
if tpl:
    print(f"template exists: {TEMPLATE_NAME}")
else:
    call("POST", "/templates", {
        "name": TEMPLATE_NAME, "template_type": "docker", "compute_id": COMPUTE,
        "image": IMAGE, "adapters": 1, "start_command": "", "console_type": "telnet",
        "console_auto_start": False, "category": "guest",
        "symbol": ":/symbols/docker_guest.svg", "environment": "",
        "usage": "E6 node: broker / patient / HL7 gateway / HL7 listener / HL7 "
                 "attacker / router. Role is chosen by the command run inside it."})
    print(f"template created: {TEMPLATE_NAME}")

existing = {n["name"]: n for n in call("GET", f"/projects/{PID}/nodes")}

# ---------------------------------------------------------------- switches
def ensure_switch(name, nports, x, y):
    if name in existing:
        return existing[name]
    node = call("POST", f"/projects/{PID}/nodes", {
        "name": name, "node_type": "ethernet_switch", "compute_id": COMPUTE,
        "x": x, "y": y,
        "properties": {"ports_mapping": [
            {"name": f"Ethernet{p}", "port_number": p, "type": "access", "vlan": 1}
            for p in range(nports)]}})
    existing[name] = node
    print(f"switch created: {name} ({nports} ports)")
    return node


ward_sw = ensure_switch("e6-ward-sw", SCALE + 6, X0 + 220, -20)
clin_sw = ensure_switch("e6-clin-sw", 8, X0 + 720, -20)

# ---------------------------------------------------------------- docker nodes
WARD_GW, CLIN_GW = "10.0.6.1", "10.0.7.1"

def iface_block(dev, ip, gw=None):
    s = f"auto {dev}\niface {dev} inet static\n\taddress {ip}\n\tnetmask 255.255.255.0\n"
    return s + (f"\tgateway {gw}\n" if gw else "")

HEADER = "# E6 GNS3 topology -- static addressing (plane B ward / plane C clinical)\n"

# name, adapters, interfaces file, x, y, [(adapter, switch)]
PLAN = [("e6-broker", 1, iface_block("eth0", "10.0.6.10", WARD_GW), X0 + 420, -260, [(0, ward_sw)])]
for i in range(1, SCALE + 1):
    PLAN.append((f"e6-patient-{i}", 1, iface_block("eth0", f"10.0.6.{100 + i}", WARD_GW),
                 X0, -330 + (i - 1) * 62, [(0, ward_sw)]))
PLAN += [
    ("e6-router", 2, iface_block("eth0", "10.0.6.1") + iface_block("eth1", "10.0.7.1"),
     X0 + 470, -20, [(0, ward_sw), (1, clin_sw)]),
    ("e6-gateway", 1, iface_block("eth0", "10.0.7.20", CLIN_GW), X0 + 920, -260, [(0, clin_sw)]),
    ("e6-listener", 1, iface_block("eth0", "10.0.7.10", CLIN_GW), X0 + 920, 60, [(0, clin_sw)]),
    ("e6-attacker", 1, iface_block("eth0", "10.0.7.100", CLIN_GW), X0 + 920, 280, [(0, clin_sw)]),
]

nodes = {}
for name, nad, ifaces, x, y, _ in PLAN:
    if name in existing:
        node = existing[name]
        print(f"  node exists: {name}")
    else:
        node = call("POST", f"/projects/{PID}/nodes", {
            "name": name, "node_type": "docker", "compute_id": COMPUTE, "x": x, "y": y,
            "properties": {"image": IMAGE, "adapters": nad, "start_command": "",
                           "console_type": "telnet", "environment": ""}})
        existing[name] = node
        print(f"  node created: {name}")
    nodes[name] = node
    call("POST", f"/projects/{PID}/nodes/{node['node_id']}/files/etc/network/interfaces",
         raw=HEADER + ifaces)

# ---------------------------------------------------------------- links
links = call("GET", f"/projects/{PID}/links")
linked = {(n["node_id"], n["adapter_number"]) for l in links for n in l["nodes"]}
used = {}
for l in links:
    for n in l["nodes"]:
        used.setdefault(n["node_id"], set()).add(n["port_number"])

def free_port(sw):
    nports = len(sw["properties"]["ports_mapping"])
    for p in range(nports):
        if p not in used.setdefault(sw["node_id"], set()):
            used[sw["node_id"]].add(p)
            return p
    raise RuntimeError(f"no free port on {sw['name']}")

for name, _, _, _, _, wires in PLAN:
    node = nodes[name]
    for adapter, sw in wires:
        if (node["node_id"], adapter) in linked:
            continue
        port = free_port(sw)
        call("POST", f"/projects/{PID}/links", {"nodes": [
            {"node_id": node["node_id"], "adapter_number": adapter, "port_number": 0},
            {"node_id": sw["node_id"], "adapter_number": 0, "port_number": port}]})
        print(f"  link created: {name} eth{adapter} <-> {sw['name']}:{port}")

# ---------------------------------------------------------------- labels
# Boxes and captions so E2 and E6, and E6's two planes, read separately on the
# canvas. Matched by caption text, so re-running does not duplicate them.
drawings = call("GET", f"/projects/{PID}/drawings")
have = " ".join(d.get("svg", "") for d in drawings)

def box(x, y, w, h, colour):
    return {"x": x, "y": y, "z": 0, "svg":
            f'<svg height="{h}" width="{w}"><rect height="{h}" width="{w}" fill="{colour}" '
            f'fill-opacity="0.08" stroke="{colour}" stroke-width="2"/></svg>'}

def caption(x, y, text):
    return {"x": x, "y": y, "z": 2, "svg":
            f'<svg height="24" width="{9 * len(text)}"><text fill="#222222" fill-opacity="1.0" '
            f'font-family="TypeWriter" font-size="11.0" font-weight="bold">{text}</text></svg>'}

LABELS = [
    ("E2 | MQTT ward broker | plane B | 10.0.0.0/24",
     box(-440, -400, 830, 790, "#3b6ea5"), caption(-430, -395, "E2 | MQTT ward broker | plane B | 10.0.0.0/24")),
    ("E6 | plane B (ward) | 10.0.6.0/24",
     box(X0 - 60, -400, 600, 790, "#3b6ea5"), caption(X0 - 50, -395, "E6 | plane B (ward) | 10.0.6.0/24")),
    ("E6 | plane C (clinical) | 10.0.7.0/24",
     box(X0 + 640, -400, 420, 790, "#a5503b"), caption(X0 + 650, -395, "E6 | plane C (clinical) | 10.0.7.0/24")),
]
for text, b, c in LABELS:
    if text in have:
        continue
    call("POST", f"/projects/{PID}/drawings", b)
    call("POST", f"/projects/{PID}/drawings", c)
    print(f"  label added: {text}")

print("\nE6 topology ready:")
for name, *_ in PLAN:
    print(f"  {name:<14} {nodes[name]['node_id']}")
