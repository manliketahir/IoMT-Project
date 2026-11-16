#!/usr/bin/env python3
"""E6 target: the HL7 v2 listener at the clinical IT boundary.

This is the MLLP server of Draft-5 section "Clinical middleware to clinical IT
(inside C)": it receives IHE PCD-01 style ORU^R01 observations from the HL7
gateway, validates each one, returns an acknowledgment, and stores what it
accepted for the clinical consumer.

It is also the thing E6 attacks. Three mitigations are evaluated against it:

  network-layer allow-list   applied OUTSIDE this process with nftables
                             (src/hl7_allowlist.sh), so an unlisted peer never
                             completes a TCP connection. --allow is a weaker
                             in-process variant, kept for comparison only.
  mutual TLS on MLLP         --tls with --cafile/--certfile/--keyfile; a peer
                             without a certificate signed by our CA never gets
                             its bytes to the HL7 parser.
  per-peer connection cap    --peer-cap N; the Nth+1 concurrent connection
                             from one source address is refused.

WHY THIS IS NOT hl7apy's MLLPServer, quite
------------------------------------------
It subclasses it for the handler-dispatch plumbing, but replaces the request
handler, because hl7apy's MLLPRequestHandler closes the connection after a
single message. Real HL7 interfaces hold a persistent connection and stream
many messages down it, and more importantly E6b is *about* holding connections
open -- a one-message-per-connection listener would make the per-peer
connection cap meaningless, because every message would be its own connection
and the legitimate gateway would trip the cap first.

TLS handshakes also run in the worker thread, not the accept loop. With
do_handshake_on_connect left at its default, one peer that completes a TCP
connection and then stalls would block accept() for every other peer, so the
E6b attack would succeed against the TLS listener for an uninteresting reason
(an artefact of this implementation) instead of the reason under test.

VALIDATION: TWO MODES, AND WHY
------------------------------
  --validate structural  (default)  hand-rolled: required segments present,
                                    OBX-3 a known IEEE 11073 code, OBX-5
                                    numeric and within physiological range.
                                    Measured at 0.001 ms per message.
  --validate schema                 the above plus hl7apy parse + schema
                                    validation. Measured at 3.4 ms median,
                                    5.9 ms p95, on this machine.

The default is structural because E6 measures sub-millisecond effects: mutual
TLS on MQTT cost +0.05 ms in E2c, and hl7apy's *variance* alone is ~2.5 ms. Run
schema mode in the ACK path and the mitigation cost disappears into library
noise. Schema mode is therefore its own factor, and the difference between the
two modes is itself a result worth reporting: HL7 conformance validation costs
roughly 30x what encrypting the channel costs.

Both modes reject a malformed message with MSA|AE, so the acknowledgment
semantics the draft describes hold either way.
"""
import argparse
import csv
import os
import signal
import socket
import ssl
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hl7util as H  # noqa: E402

try:
    from hl7apy.mllp import MLLPServer
except ImportError:
    print("hl7apy missing: pip install -r requirements.txt", file=sys.stderr)
    raise

from socketserver import StreamRequestHandler  # noqa: E402

HANDSHAKE_TIMEOUT = 5.0


# --------------------------------------------------------------------------
# validation
# --------------------------------------------------------------------------
def validate_structural(msg):
    """Hand-rolled checks. Returns (ok, reason, code, value, pub_id, mid).

    Deliberately cheap: this sits in the ACK path, which E6 is timing.
    """
    segs = msg.split(H.SEG)
    kinds = {s[:3] for s in segs}
    for need in ("MSH", "PID", "OBR", "OBX"):
        if need not in kinds:
            return False, f"missing {need}", None, None, "", ""

    mid = pub = ""
    code = val = None
    try:
        msh = next(s for s in segs if s.startswith("MSH"))
        mid = msh.split("|")[9]
    except (StopIteration, IndexError):
        return False, "bad MSH-10", None, None, "", ""
    try:
        pid = next(s for s in segs if s.startswith("PID"))
        pub = pid.split("|")[3]
    except (StopIteration, IndexError):
        return False, "bad PID-3", None, None, "", mid

    try:
        obx = next(s for s in segs if s.startswith("OBX"))
        f = obx.split("|")
        code = int(f[3].split("^")[0])
        val = float(f[5])
    except (StopIteration, IndexError, ValueError):
        return False, "bad OBX", code, val, pub, mid

    if code not in H.RANGE:
        return False, f"unknown code {code}", code, val, pub, mid
    lo, hi = H.RANGE[code]
    if not (lo <= val <= hi):
        return False, f"out of range {val}", code, val, pub, mid
    return True, "", code, val, pub, mid


_schema_bits = None


def validate_schema(msg):
    """Structural checks plus hl7apy schema validation."""
    global _schema_bits
    if _schema_bits is None:
        from hl7apy.parser import parse_message
        from hl7apy.consts import VALIDATION_LEVEL
        from hl7apy.validation import Validator
        _schema_bits = (parse_message, VALIDATION_LEVEL, Validator)
    parse_message, VALIDATION_LEVEL, Validator = _schema_bits

    ok, reason, code, val, pub, mid = validate_structural(msg)
    if not ok:
        return ok, reason, code, val, pub, mid
    try:
        m = parse_message(msg, validation_level=VALIDATION_LEVEL.TOLERANT)
        Validator.validate(m)
    except Exception as e:
        return False, f"schema: {type(e).__name__}", code, val, pub, mid
    return True, "", code, val, pub, mid


# --------------------------------------------------------------------------
# server
# --------------------------------------------------------------------------
class E6Handler(StreamRequestHandler):
    """One thread per connection, many messages per connection."""

    def setup(self):
        srv = self.server
        if isinstance(self.request, ssl.SSLSocket):
            # Handshake here, in the worker thread, so a stalled peer cannot
            # block the accept loop (see the module docstring).
            self.request.settimeout(HANDSHAKE_TIMEOUT)
            try:
                self.request.do_handshake()
                srv.bump("tls_ok")
            except Exception as e:
                srv.bump("tls_fail")
                srv.log_reject(self.client_address, f"tls: {type(e).__name__}")
                raise
        self.request.settimeout(1.0)
        StreamRequestHandler.setup(self)

    def handle(self):
        srv = self.server
        srv.bump("conns")
        buf = b""
        while not srv.stopping:
            try:
                chunk = self.request.recv(65536)
            except socket.timeout:
                # Idle but open. Held deliberately: persistent MLLP is the
                # real pattern, and holding is what E6b exploits.
                continue
            except OSError:
                break
            if not chunk:
                break
            t_recv = time.time()
            buf += chunk
            msgs, buf = H.deframe(buf)
            for m in msgs:
                ack = srv.process(m, t_recv, self.client_address[0])
                try:
                    self.request.sendall(H.frame(ack))
                except OSError:
                    return

    def handle_error(self, request, client_address):
        # A failed TLS handshake is an expected outcome in attack_mitig, not a
        # crash. Counted, never dumped to stderr.
        pass


class E6Listener(MLLPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, host, port, validate, ssl_ctx=None, peer_cap=0,
                 max_conns=0, allow=None):
        self.validate = validate
        self.ssl_ctx = ssl_ctx
        self.peer_cap = peer_cap
        # Global connection ceiling. This is the environment, not a mitigation:
        # a real HL7 listener (HAPI, a vendor interface engine) has a bounded
        # connection pool, so an unbounded ThreadingTCPServer would be an
        # unrealistic target that no attacker could ever exhaust. It is present
        # in every E6b condition. The per-peer cap is the mitigation that is
        # toggled on top of it -- the same structure as E2d, where the
        # connection cap is the binding constraint and the rate limit is the
        # toggled control. Without this ceiling, "exhaustion by an allowed
        # peer" (the draft's E6b threat) has nothing to exhaust.
        self.max_conns = max_conns
        self.total_conns = 0
        self.allow = allow
        self.stopping = False
        self.lock = threading.Lock()
        self.rows = []
        self.rejects = []
        self.peer_conns = {}
        self.counted = {}
        self.stat = {
            "conns": 0, "accepted": 0, "rejected": 0,
            "blocked_allowlist": 0, "blocked_cap": 0, "blocked_global": 0,
            "peak_conns": 0, "tls_ok": 0, "tls_fail": 0,
        }
        # handlers={} -- dispatch is unused; E6Handler does the routing.
        MLLPServer.__init__(self, host, port, handlers={}, timeout=1.0,
                            request_handler_class=E6Handler)

    # -- counters ---------------------------------------------------------
    def bump(self, k, n=1):
        with self.lock:
            self.stat[k] = self.stat.get(k, 0) + n

    def log_reject(self, addr, why):
        with self.lock:
            self.rejects.append((time.time(), addr[0], why))

    # -- TLS --------------------------------------------------------------
    def get_request(self):
        sock, addr = socket.socket.accept(self.socket)
        if self.ssl_ctx is not None:
            try:
                sock = self.ssl_ctx.wrap_socket(
                    sock, server_side=True, do_handshake_on_connect=False)
            except OSError:
                sock.close()
                raise
        return sock, addr

    # -- allow-list and per-peer cap --------------------------------------
    def verify_request(self, request, client_address):
        ip = client_address[0]
        if self.allow is not None and ip not in self.allow:
            self.bump("blocked_allowlist")
            self.log_reject(client_address, "allowlist")
            return False
        with self.lock:
            # global ceiling first (the environment)
            if self.max_conns and self.total_conns >= self.max_conns:
                self.stat["blocked_global"] += 1
                self.rejects.append((time.time(), ip, "global-cap"))
                return False
            # per-peer cap second (the mitigation)
            live = self.peer_conns.get(ip, 0)
            if self.peer_cap and live >= self.peer_cap:
                self.stat["blocked_cap"] += 1
                self.rejects.append((time.time(), ip, "peer-cap"))
                return False
            self.peer_conns[ip] = live + 1
            self.total_conns += 1
            if self.total_conns > self.stat["peak_conns"]:
                self.stat["peak_conns"] = self.total_conns
            self.counted[request] = ip
        return True

    def shutdown_request(self, request):
        with self.lock:
            ip = self.counted.pop(request, None)
            if ip is not None:
                self.total_conns = max(0, self.total_conns - 1)
                n = self.peer_conns.get(ip, 1) - 1
                if n > 0:
                    self.peer_conns[ip] = n
                else:
                    self.peer_conns.pop(ip, None)
        MLLPServer.shutdown_request(self, request)

    # -- the ACK path -----------------------------------------------------
    def process(self, msg, t_recv, peer):
        ok, reason, code, val, pub, mid = self.validate(msg)
        if not mid:
            mid = "?"
        _, seq = H.split_msg_id(mid)
        with self.lock:
            self.rows.append((mid, pub, seq, f"{t_recv:.6f}",
                              code if code is not None else "",
                              val if val is not None else "",
                              "AA" if ok else "AE", reason, peer))
            self.stat["accepted" if ok else "rejected"] += 1
        return H.build_ack(mid, "AA" if ok else "AE", reason)

    # -- output -----------------------------------------------------------
    def dump(self, outfile, statfile):
        with self.lock:
            rows, rejects, stat = list(self.rows), list(self.rejects), dict(self.stat)
        with open(outfile, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["msg_id", "pub_id", "seq", "t_recv", "code", "value",
                        "ack", "reason", "peer"])
            w.writerows(rows)
        with open(statfile, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["key", "value"])
            for k in sorted(stat):
                w.writerow([k, stat[k]])
            w.writerow(["reject_events", len(rejects)])
        base = os.path.splitext(outfile)[0]
        with open(base + "_rejects.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["t", "peer", "why"])
            w.writerows((f"{t:.6f}", p, why) for t, p, why in rejects)
        print(f"hl7-listener: {len(rows)} messages "
              f"(accepted={stat['accepted']} rejected={stat['rejected']} "
              f"peer_cap_blocked={stat['blocked_cap']} "
              f"global_blocked={stat['blocked_global']} "
              f"peak_conns={stat['peak_conns']} tls_fail={stat['tls_fail']}) "
              f"-> {os.path.basename(outfile)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=H.MLLP_PORT)
    ap.add_argument("--outfile", default="hl7_recv.csv")
    ap.add_argument("--statfile", default="hl7_listener_stat.csv")
    ap.add_argument("--validate", choices=["structural", "schema"],
                    default="structural",
                    help="structural: 0.001 ms/msg. schema: adds hl7apy, "
                         "3.4 ms/msg -- enough to swamp the effects E6 "
                         "measures, so it is a factor, not the default.")
    ap.add_argument("--peer-cap", type=int, default=0,
                    help="max concurrent connections per source address "
                         "(0 = unlimited). The E6b mitigation.")
    ap.add_argument("--max-conns", type=int, default=0,
                    help="global concurrent-connection ceiling (0 = unlimited). "
                         "The realistic listener environment for E6b; present "
                         "in every condition, not a mitigation.")
    ap.add_argument("--allow", default="",
                    help="comma-separated source IPs. WEAKER than the "
                         "nftables allow-list: the TCP connection completes "
                         "before this rejects it. For comparison only; E6a "
                         "uses src/hl7_allowlist.sh.")
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--cafile")
    ap.add_argument("--certfile")
    ap.add_argument("--keyfile")
    args = ap.parse_args()

    ctx = None
    if args.tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.certfile, args.keyfile)
        ctx.load_verify_locations(args.cafile)
        ctx.verify_mode = ssl.CERT_REQUIRED      # mutual TLS
        ctx.check_hostname = False

    validate = validate_schema if args.validate == "schema" else validate_structural
    allow = set(x.strip() for x in args.allow.split(",") if x.strip()) or None

    srv = E6Listener(args.host, args.port, validate, ssl_ctx=ctx,
                     peer_cap=args.peer_cap, max_conns=args.max_conns,
                     allow=allow)

    def stop(*_):
        srv.stopping = True
        threading.Thread(target=srv.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    print(f"hl7-listener: {args.host}:{args.port} validate={args.validate} "
          f"tls={bool(ctx)} peer_cap={args.peer_cap or 'none'} "
          f"max_conns={args.max_conns or 'none'} "
          f"allow={sorted(allow) if allow else 'any'}", flush=True)
    try:
        srv.serve_forever(poll_interval=0.2)
    finally:
        srv.stopping = True
        time.sleep(0.3)
        srv.dump(args.outfile, args.statfile)


if __name__ == "__main__":
    main()
