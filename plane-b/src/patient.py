#!/usr/bin/env python3
"""One simulated patient monitor.

Publishes a vital-sign reading at a fixed rate to ward/<id>/vitals/heartrate.
Each message is JSON carrying the publisher id, a monotonic sequence number
and the send time, so the collector can compute delivery ratio and latency.
A per-publisher CSV of what was sent is written to <outdir>/sent_<id>.csv.

Plain or TLS is chosen by whether --cafile is given. For mutual TLS the
client also passes --certfile and --keyfile; the certificate common name is
the publisher id, which the broker turns into the MQTT username.
"""
import argparse
import csv
import json
import os
import signal
import ssl
import time

import paho.mqtt.client as mqtt

running = True


def stop(*_):
    global running
    running = False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--rate", type=float, default=1.0, help="messages/second")
    ap.add_argument("--duration", type=float, default=60.0)
    ap.add_argument("--qos", type=int, default=1)
    ap.add_argument("--outdir", default=".")
    ap.add_argument("--bind", default="",
                    help="source address to bind, e.g. a per-client loopback")
    ap.add_argument("--cafile")
    ap.add_argument("--certfile")
    ap.add_argument("--keyfile")
    args = ap.parse_args()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=args.id)
    if args.cafile:
        c.tls_set(ca_certs=args.cafile, certfile=args.certfile,
                  keyfile=args.keyfile, tls_version=ssl.PROTOCOL_TLSv1_2)
    # Connect may fail if the broker is full or rejects us; record that.
    connected = False
    try:
        c.connect(args.host, args.port, keepalive=30, bind_address=args.bind)
        c.loop_start()
        connected = True
    except Exception as e:
        print(f"{args.id}: connect failed: {e}")

    topic = f"ward/{args.id}/vitals/heartrate"
    period = 1.0 / args.rate if args.rate > 0 else 1.0
    os.makedirs(args.outdir, exist_ok=True)
    path = os.path.join(args.outdir, f"sent_{args.id}.csv")

    seq = 0
    end = time.monotonic() + args.duration
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["pub_id", "seq", "t_send", "accepted"])
        while running and time.monotonic() < end:
            t = time.time()
            accepted = 0
            if connected:
                payload = json.dumps({"pub": args.id, "seq": seq, "t": t,
                                      "hr": 60 + (seq % 40)})
                info = c.publish(topic, payload, qos=args.qos)
                accepted = 1 if info.rc == mqtt.MQTT_ERR_SUCCESS else 0
            w.writerow([args.id, seq, f"{t:.6f}", accepted])
            seq += 1
            time.sleep(period)

    if connected:
        try:
            c.loop_stop()
        except Exception:
            pass
        try:
            c.disconnect()
        except Exception:
            pass


if __name__ == "__main__":
    main()
