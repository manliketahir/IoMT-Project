#!/usr/bin/env python3
"""MQTT->clinical adapter (B->C bridge, stub form).

This is the ward->clinical bridge of the paper's architecture, in the smallest
form that realizes the boundary. In the full environment this is the MQTT->DDS
adapter that reads the ward broker and republishes onto OpenICE's DDS topics.
Here it does the same job without DDS: it subscribes to ward/# on the ward
broker (plane B), maps each reading onto its IEEE 11073-10101 nomenclature code
and the bed's identity, and forwards it over a plain TCP socket to the stub
clinical consumer (src/clinical_stub.py, plane C stub). The TCP hop stands in
for the ward->clinical segment crossing.

It is the only process attached to both sides: an MQTT client on the ward side
and a socket client on the clinical side. That is the pivot the paper describes,
and it is the point where the B->C end-to-end measurement is taken: each sample
carries the patient's original send time and a timestamp added here, so the
consumer can separate the ward leg (patient->adapter) from the bridge leg
(adapter->consumer).

Over the hardened (mutual-TLS) broker, pass --cafile/--certfile/--keyfile so the
adapter authenticates as "collector", which the ACL grants read on ward/#.
"""
import argparse
import json
import signal
import socket
import ssl
import time

import paho.mqtt.client as mqtt

# IEEE 11073-10101 nomenclature codes for the vital signs the ward publishes.
# heartrate -> MDC_ECG_HEART_RATE. Extend as more metrics are added.
NOM_CODE = {
    "heartrate": 147842,   # MDC_ECG_HEART_RATE
    "spo2": 150456,        # MDC_PULS_OXIM_SAT_O2
    "resp": 151562,        # MDC_RESP_RATE
}

state = {"sock": None, "fwd": 0, "drop": 0, "stop": False}


def connect_clinical(host, port, retries=20):
    for _ in range(retries):
        try:
            s = socket.create_connection((host, port), timeout=2.0)
            return s
        except OSError:
            time.sleep(0.25)
    return None


def on_message(client, userdata, msg):
    if state["stop"] or state["sock"] is None:
        return
    # ward/<bed>/vitals/<metric>
    parts = msg.topic.split("/")
    bed = parts[1] if len(parts) > 1 else "?"
    metric = parts[-1] if parts else "?"
    try:
        d = json.loads(msg.payload)
    except Exception:
        state["drop"] += 1
        return
    sample = {
        "pub": d.get("pub", bed),
        "seq": d.get("seq"),
        "t_send": d.get("t"),
        "t_adapter": time.time(),
        "code": NOM_CODE.get(metric, 0),
        "value": d.get("hr", d.get("value")),
    }
    line = (json.dumps(sample) + "\n").encode()
    try:
        state["sock"].sendall(line)
        state["fwd"] += 1
    except OSError:
        state["drop"] += 1
        # try one reconnect so a brief consumer hiccup is not fatal
        state["sock"] = connect_clinical(userdata["chost"], userdata["cport"],
                                         retries=4)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--broker-host", default="127.0.0.1")
    ap.add_argument("--broker-port", type=int, default=1883)
    ap.add_argument("--clinical-host", default="127.0.0.1")
    ap.add_argument("--clinical-port", type=int, default=9009)
    # Must differ from the collector's client id: MQTT client ids are unique
    # per broker, and a duplicate makes the broker evict the other session
    # ("session taken over"), so neither client stays subscribed. The ACL
    # username comes from the certificate CN (use_identity_as_username), not
    # from this id, so the adapter still authenticates as "collector".
    ap.add_argument("--client-id", default="adapter")
    ap.add_argument("--cafile")
    ap.add_argument("--certfile")
    ap.add_argument("--keyfile")
    args = ap.parse_args()

    signal.signal(signal.SIGTERM, lambda *_: state.update(stop=True))
    signal.signal(signal.SIGINT, lambda *_: state.update(stop=True))

    sock = connect_clinical(args.clinical_host, args.clinical_port)
    if sock is None:
        print("adapter: could not reach clinical stub; exiting")
        return
    state["sock"] = sock

    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=args.client_id,
                    userdata={"chost": args.clinical_host,
                              "cport": args.clinical_port})
    c.on_message = on_message
    if args.cafile:
        c.tls_set(ca_certs=args.cafile, certfile=args.certfile,
                  keyfile=args.keyfile, tls_version=ssl.PROTOCOL_TLSv1_2)
    c.connect(args.broker_host, args.broker_port, keepalive=30)
    c.subscribe("ward/#", qos=1)
    c.loop_start()
    print(f"adapter: ward {args.broker_host}:{args.broker_port} "
          f"-> clinical {args.clinical_host}:{args.clinical_port}")

    while not state["stop"]:
        time.sleep(0.2)

    c.loop_stop()
    c.disconnect()
    try:
        state["sock"].close()
    except Exception:
        pass
    print(f"adapter: forwarded {state['fwd']} samples, dropped {state['drop']}")


if __name__ == "__main__":
    main()
