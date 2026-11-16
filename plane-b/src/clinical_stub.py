#!/usr/bin/env python3
"""Stub clinical consumer (plane C, stub form).

This is the "stub clinical consumer" of the minimum-viable configuration in
the paper: planes A and B with a stub standing in for the full clinical tier.
It is NOT OpenICE or DDS; it is the smallest thing that lets the B->C boundary
be exercised and measured end to end. The MQTT->DDS adapter (src/adapter.py)
forwards each ward reading to this consumer over a plain TCP socket, which
stands in for the ward->clinical segment hop. The consumer records every
sample it receives, with the time it arrived, so delivery and end-to-end
latency from the patient monitor all the way to the clinical consumer can be
computed against what the patients recorded as sent (sent_*.csv).

One JSON object per line is expected on the socket:
  {"pub": "bed-3", "seq": 12, "t_send": 1699.., "t_adapter": 1699.., "code": 147842, "value": 72}

Writes <outfile> (default clinical_recv.csv) on SIGTERM.
"""
import argparse
import csv
import json
import signal
import socket
import threading
import time

rows = []
stop = {"f": False}


def handle(conn):
    buf = b""
    with conn:
        conn.settimeout(1.0)
        while not stop["f"]:
            try:
                chunk = conn.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                t_recv = time.time()
                if not line.strip():
                    continue
                try:
                    d = json.loads(line)
                    rows.append((d.get("pub"), d.get("seq"), d.get("t_send"),
                                 d.get("t_adapter"), t_recv, d.get("code"),
                                 d.get("value")))
                except Exception:
                    rows.append(("?", -1, "", "", t_recv, "", ""))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9009,
                    help="TCP port the adapter forwards clinical samples to")
    ap.add_argument("--outfile", default="clinical_recv.csv")
    args = ap.parse_args()

    signal.signal(signal.SIGTERM, lambda *_: stop.update(f=True))
    signal.signal(signal.SIGINT, lambda *_: stop.update(f=True))

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(8)
    srv.settimeout(1.0)
    print(f"clinical-stub: listening on {args.host}:{args.port}")

    threads = []
    while not stop["f"]:
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        t = threading.Thread(target=handle, args=(conn,), daemon=True)
        t.start()
        threads.append(t)

    srv.close()
    with open(args.outfile, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["pub_id", "seq", "t_send", "t_adapter", "t_recv",
                    "code", "value"])
        w.writerows(rows)
    print(f"clinical-stub: wrote {len(rows)} samples to {args.outfile}")


if __name__ == "__main__":
    main()
