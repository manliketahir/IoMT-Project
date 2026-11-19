#!/usr/bin/env python3
"""Build the E2 scale-10 topology in the GNS3 project 'CoEIA IoMT' via the REST API.

Run on the Windows host while GNS3 is open (it talks to the local GNS3
controller on 127.0.0.1:3080 with the credentials in gns3_server.ini):

    python gns3_build_e2.py            # SCALE=10 by default

It creates (or reuses) the Docker template `iomt-node` on the GNS3 VM, an
Ethernet switch `ward-sw`, and the nodes broker 10.0.0.10, collector
10.0.0.20, attacker 10.0.0.100 and patient-1..N 10.0.0.101.., links each to
the switch, and writes every node's static address into
/etc/network/interfaces through the node-files API.

Idempotent: re-running reuses the template, nodes and links by name and only
rewrites the address files. Run it again after the GNS3 VM is replaced: the
address files live on the VM's disk, not in the controller's project copy.
The image iomt-node:1.0 must already exist on the GNS3 VM (build it inside the
VM with plane-b/Dockerfile, as its header explains), or GNS3 cannot create the containers.
"""
import base64, json, os, re, sys, urllib.error, urllib.request

CTRL = "http://127.0.0.1:3080/v2"
PROJECT_NAME = "CoEIA IoMT"
COMPUTE = "vm"
IMAGE = "iomt-node:1.0"
TEMPLATE_NAME = "iomt-node"
SCALE = int(os.environ.get("SCALE", "10"))

INI = os.path.join(os.environ["APPDATA"], "GNS3", "2.2", "gns3_server.ini")


def auth_header():
    txt = open(INI, encoding="utf-8", errors="replace").read()
    user = re.search(r"^user\s*=\s*(.+)$", txt, re.M).group(1).strip()
    pw = re.search(r"^password\s*=\s*(.+)$", txt, re.M).group(1).strip()
    tok = base64.b64encode(f"{user}:{pw}".encode()).decode()
    return {"Authorization": "Basic " + tok}


HDR = auth_header()


def call(method, path, body=None, raw=None, expect=(200, 201, 204)):
    url = CTRL + path
    data = None
    headers = dict(HDR)
    if raw is not None:
        data = raw.encode() if isinstance(raw, str) else raw
        headers["Content-Type"] = "application/octet-stream"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            txt = r.read().decode("utf-8", "replace")
            if r.status not in expect:
                raise RuntimeError(f"{method} {path} -> {r.status}: {txt[:300]}")
            return json.loads(txt) if txt.strip().startswith(("{", "[")) else txt
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")
        raise RuntimeError(f"{method} {path} -> {e.code}: {detail[:400]}") from None


# ---------------------------------------------------------------- project
projects = call("GET", "/projects")
proj = next((p for p in projects if p["name"] == PROJECT_NAME), None)
if not proj:
    sys.exit(f"project {PROJECT_NAME!r} not found")
PID = proj["project_id"]
if proj["status"] != "opened":
    call("POST", f"/projects/{PID}/open")
print(f"project {PROJECT_NAME} = {PID}")

# ---------------------------------------------------------------- template
templates = call("GET", "/templates")
tpl = next((t for t in templates if t.get("name") == TEMPLATE_NAME), None)
if tpl:
    print(f"template exists: {tpl['template_id']}")
else:
    tpl = call("POST", "/templates", {
        "name": TEMPLATE_NAME,
        "template_type": "docker",
        "compute_id": COMPUTE,
        "image": IMAGE,
        "adapters": 1,
        "start_command": "",
        "console_type": "telnet",
        "console_auto_start": False,
        "category": "guest",
        "symbol": ":/symbols/docker_guest.svg",
        "environment": "",
        "usage": "E2 testbed node: broker / collector / patient / attacker. "
                 "Role is chosen by the command run inside it.",
    })
    print(f"template created: {tpl['template_id']}")

# ---------------------------------------------------------------- nodes
existing = {n["name"]: n for n in call("GET", f"/projects/{PID}/nodes")}

PLAN = [("broker", "10.0.0.10", 320, -140),
        ("collector", "10.0.0.20", 320, 120),
        ("attacker", "10.0.0.100", -360, 300)]
for i in range(1, SCALE + 1):
    PLAN.append((f"patient-{i}", f"10.0.0.{100 + i}", -360, -330 + (i - 1) * 62))

NPORTS = SCALE + 6


def ensure_switch():
    if "ward-sw" in existing:
        return existing["ward-sw"]
    node = call("POST", f"/projects/{PID}/nodes", {
        "name": "ward-sw",
        "node_type": "ethernet_switch",
        "compute_id": COMPUTE,
        "x": 0, "y": -20,
        "properties": {"ports_mapping": [
            {"name": f"Ethernet{p}", "port_number": p, "type": "access", "vlan": 1}
            for p in range(NPORTS)]},
    })
    print("switch created with", NPORTS, "ports")
    existing[node["name"]] = node
    return node


sw = ensure_switch()

INTERFACES = """# E2 GNS3 topology -- static addressing (see GNS3-NODE-ACCESS.md section 1)
auto eth0
iface eth0 inet static
\taddress {ip}
\tnetmask 255.255.255.0
"""

created = []
for name, ip, x, y in PLAN:
    if name in existing:
        node = existing[name]
        print(f"  node exists: {name}")
    else:
        node = call("POST", f"/projects/{PID}/nodes", {
            "name": name,
            "node_type": "docker",
            "compute_id": COMPUTE,
            "x": x, "y": y,
            "properties": {
                "image": IMAGE,
                "adapters": 1,
                "start_command": "",
                "console_type": "telnet",
                "environment": "",
            },
        })
        existing[name] = node
        print(f"  node created: {name} ({ip})")
    created.append((node, ip))
    # static address file inside the node
    call("POST", f"/projects/{PID}/nodes/{node['node_id']}/files/etc/network/interfaces",
         raw=INTERFACES.format(ip=ip))

# ---------------------------------------------------------------- links
links = call("GET", f"/projects/{PID}/links")
linked_nodes = set()
for l in links:
    for n in l["nodes"]:
        linked_nodes.add(n["node_id"])

used_ports = set()
for l in links:
    for n in l["nodes"]:
        if n["node_id"] == sw["node_id"]:
            used_ports.add(n["port_number"])

free = (p for p in range(NPORTS) if p not in used_ports)
for node, ip in created:
    if node["node_id"] in linked_nodes:
        print(f"  link exists: {node['name']}")
        continue
    port = next(free)
    call("POST", f"/projects/{PID}/links", {
        "nodes": [
            {"node_id": node["node_id"], "adapter_number": 0, "port_number": 0},
            {"node_id": sw["node_id"], "adapter_number": 0, "port_number": port},
        ]
    })
    print(f"  link created: {node['name']} <-> ward-sw:{port}")

print("\nTopology ready. Nodes:")
for node, ip in created:
    print(f"  {node['name']:<12} {ip:<12} {node['node_id']}")
