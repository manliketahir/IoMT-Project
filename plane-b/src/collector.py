#!/usr/bin/env python3
"""The ward collector.

Subscribes to ward/# and records every message it receives, with the receive
time, so delivery ratio and end-to-end latency can be computed against what
the publishers recorded as sent. Writes <outdir>/recv.csv until SIGTERM.

Over mutual TLS the collector presents the "collector" certificate, which the
ACL grants read on ward/#.
"""
import argparse
import csv
import json
import signal
import ssl
import time

import paho.mqtt.client as mqtt

rows = []


def on_message(client, userdata, msg):
    t_recv = time.time()
    try:
        d = json.loads(msg.payload)
        rows.append((d.get("pub"), d.get("seq"), d.get("t"), t_recv))
    except Exception:
        rows.append(("?", -1, "", t_recv))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--qos", type=int, default=1)
    ap.add_argument("--outfile", default="recv.csv")
    ap.add_argument("--cafile")
    ap.add_argument("--certfile")
    ap.add_argument("--keyfile")
    args = ap.parse_args()

    stop = {"f": False}
    signal.signal(signal.SIGTERM, lambda *_: stop.update(f=True))
    signal.signal(signal.SIGINT, lambda *_: stop.update(f=True))

    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="collector")
    c.on_message = on_message
    if args.cafile:
        c.tls_set(ca_certs=args.cafile, certfile=args.certfile,
                  keyfile=args.keyfile, tls_version=ssl.PROTOCOL_TLSv1_2)
    c.connect(args.host, args.port, keepalive=30)
    c.subscribe("ward/#", qos=args.qos)
    c.loop_start()

    while not stop["f"]:
        time.sleep(0.2)

    c.loop_stop()
    c.disconnect()
    with open(args.outfile, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["pub_id", "seq", "t_send", "t_recv"])
        w.writerows(rows)


if __name__ == "__main__":
    main()
