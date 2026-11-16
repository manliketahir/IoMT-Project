#!/usr/bin/env python3
"""E6b stimulus: connection exhaustion against the HL7 listener.

Research test harness for the author's own local listener only. It opens many
MLLP connections and holds them open, to measure whether the listener keeps
acknowledging the legitimate gateway while its per-connection thread pool
fills. It is the stimulus the E6b mitigation (the per-peer connection cap) is
evaluated against; it defaults to loopback and is not a general-purpose tool.

It is the MLLP analogue of src/attack_conn_exhaust.py from plane B, with the
MQTT CONNECT removed. The listener is a ThreadingTCPServer, so each held
connection costs the listener one thread; the per-peer cap is what bounds that.

To let the per-peer cap and the allow-list tell this traffic apart from the
gateway, the harness binds its connections to a separate loopback source
address (127.0.0.3 by default) while the gateway uses 127.0.0.2. All of
127.0.0.0/8 is loopback on Linux, so both stay on the local host.

MODES
-----
  --mode full       complete a minimal MLLP frame on each socket, so the
                    listener parses and ACKs, then the socket is held open
                    idle. Exercises the real request path.
  --mode half-open  open the TCP (and, with --tls, complete the handshake)
                    and then send nothing. The slow-peer case: it measures
                    whether the listener holds a thread for a silent peer and
                    for how long before it times out and closes.

--liveness <file> samples how many of the sockets are still alive over the
hold window and writes time_s,alive rows, so the mitigation's effect is
visible as the attacker's own sockets being dropped.
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

running = True


def stop(*_):
    global running
    running = False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=H.MLLP_PORT)
    ap.add_argument("--bind", default="127.0.0.3")
    ap.add_argument("--conns", type=int, default=200,
                    help="number of connections to try to hold open")
    ap.add_argument("--duration", type=float, default=60.0)
    ap.add_argument("--mode", choices=["full", "half-open"], default="full")
    ap.add_argument("--open-rate", type=float, default=100.0,
                    help="new connections opened per second")
    ap.add_argument("--outfile", default="exhaust.csv")
    ap.add_argument("--liveness", default="")
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--cafile")
    ap.add_argument("--certfile")
    ap.add_argument("--keyfile")
    ap.add_argument("--server-name", default="localhost")
    args = ap.parse_args()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    ctx = None
    if args.tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if args.cafile:
            ctx.load_verify_locations(args.cafile)
        if args.certfile and args.keyfile:
            ctx.load_cert_chain(args.certfile, args.keyfile)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED if args.cafile else ssl.CERT_NONE

    socks = []
    established = refused = 0
    interval = 1.0 / args.open_rate if args.open_rate > 0 else 0.0

    # A tiny valid ORU so "full" mode gets past the listener's framing. The
    # value is in range; this harness is about holding connections, not about
    # the content.
    probe = H.frame(H.build_oru("bed-1", "X0", 72))

    for i in range(args.conns):
        if not running:
            break
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind((args.bind, 0))
            s.settimeout(3.0)
            s.connect((args.host, args.port))
            if ctx is not None:
                s = ctx.wrap_socket(s, server_hostname=args.server_name)
            if args.mode == "full":
                s.sendall(probe)
            established += 1
            socks.append(s)
        except OSError:
            refused += 1
            try:
                s.close()
            except OSError:
                pass
        if interval:
            time.sleep(interval)

    # hold, sampling liveness
    live_rows = []
    t_start = time.monotonic()
    end = t_start + args.duration

    def alive(s):
        try:
            s.setblocking(False)
            data = s.recv(1, socket.MSG_PEEK)
            # empty read means the peer closed; data or EAGAIN means alive
            return data != b""
        except (BlockingIOError, ssl.SSLWantReadError):
            return True
        except OSError:
            return False
        finally:
            try:
                s.setblocking(True)
            except OSError:
                pass

    while running and time.monotonic() < end:
        n = sum(1 for s in socks if alive(s))
        live_rows.append((f"{time.monotonic() - t_start:.2f}", n))
        time.sleep(1.0)

    for s in socks:
        try:
            s.close()
        except OSError:
            pass

    with open(args.outfile, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["key", "value"])
        w.writerow(["mode", args.mode])
        w.writerow(["requested", args.conns])
        w.writerow(["established", established])
        w.writerow(["refused", refused])
    if args.liveness:
        with open(args.liveness, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["time_s", "alive"])
            w.writerows(live_rows)
    print(f"exhaust[{args.mode}]: established={established} refused={refused} "
          f"of {args.conns} -> {os.path.basename(args.outfile)}")


if __name__ == "__main__":
    main()
