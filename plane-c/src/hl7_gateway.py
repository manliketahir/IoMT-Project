#!/usr/bin/env python3
"""E6 legitimate peer: the HL7 gateway (IHE PCD-01 device observation reporter).

Subscribes to the plane-B ward topics, turns each reading into an ORU^R01 with
IEEE 11073 codes in the OBX segment, sends it to the clinical HL7 listener over
MLLP, and waits for the acknowledgment. This is the "legitimate peer" that
Draft-5 section on E6 refers to, and the thing whose availability E6b measures.

DEVIATION FROM THE DRAFT, STATED DELIBERATELY
---------------------------------------------
Draft-5 describes vitals being sent "in charting-style batches (for example,
every 60 seconds for each patient)". This gateway sends one ORU^R01 per
reading instead. In a 60 s run, 60 s batching would produce exactly one
message per patient -- 30 data points in total, which cannot support a median
ACK latency with a confidence interval, let alone a Mann-Whitney test. Per-
reading reporting gives ~1800 messages per run at scale 30.

Batching is a factor that could be added later (it changes the connection
duty cycle, which matters to the per-peer cap). It is not dropped silently:
the write-up must say per-reading reporting was used and why.

WHY A QUEUE AND A SENDER THREAD
-------------------------------
MLLP is synchronous: send, then wait for the ACK. If the listener is slow --
which is precisely what E6b induces -- doing that inside the MQTT callback
would stall MQTT consumption and silently lose readings in paho's buffers.
Instead the callback only enqueues, and one sender thread drains the queue.
Queue overflow is then counted explicitly as `dropped`, so back-pressure
appears in the data as a number instead of as an unexplained gap.

CLIENT IDENTITY
---------------
--client-id defaults to "hl7-gateway", which must differ from the plane-B
collector's "collector". MQTT client ids are unique per broker and a duplicate
makes the broker evict the other session ("session taken over"), leaving
neither subscribed -- a failure that reads as a legitimate PDR of 0.0. That
cost a debugging cycle once already in this testbed.
"""
import argparse
import csv
import json
import os
import queue
import signal
import socket
import ssl
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hl7util as H  # noqa: E402

import paho.mqtt.client as mqtt  # noqa: E402

TOPIC_METRIC = {
    "heartrate": "heartrate",
    "spo2": "spo2",
    "resp": "resp",
}

stop = {"f": False}
rows = []
rows_lock = threading.Lock()
stat = {
    "queued": 0, "dropped": 0, "sent": 0, "ack_aa": 0, "ack_ae": 0,
    "ack_timeout": 0, "send_fail": 0, "reconnects": 0, "connect_fail": 0,
}
stat_lock = threading.Lock()


def bump(k, n=1):
    with stat_lock:
        stat[k] = stat.get(k, 0) + n


class MllpClient:
    """Persistent MLLP connection with reconnect, and framed ACK reads."""

    def __init__(self, host, port, bind, ssl_ctx, ack_timeout, server_name,
                 per_message=False):
        self.host, self.port = host, port
        self.bind = bind
        self.ssl_ctx = ssl_ctx
        self.ack_timeout = ack_timeout
        self.server_name = server_name
        self.per_message = per_message
        self.sock = None
        self.buf = b""

    def connect(self):
        self.close()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if self.bind:
                s.bind((self.bind, 0))
            s.settimeout(self.ack_timeout)
            s.connect((self.host, self.port))
            if self.ssl_ctx is not None:
                s = self.ssl_ctx.wrap_socket(s, server_hostname=self.server_name)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            try:
                s.close()
            except OSError:
                pass
            bump("connect_fail")
            return False
        self.sock = s
        self.buf = b""
        return True

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def send_and_ack(self, msg):
        """Returns (t_sent, t_ack, ack_code) -- t_ack/ack_code None on failure.

        In per_message mode a fresh connection is opened for this one message
        and closed after the ACK. That is the connection pattern that makes the
        gateway vulnerable to E6b exhaustion: between messages it holds no slot,
        so a flood that has filled the listener's connection ceiling can lock it
        out. A persistent connection (the default) cannot be starved this way,
        because it already holds its slot -- which is why E6b uses per_message.
        """
        if self.per_message:
            self.close()
            if not self.connect():
                return None, None, None
        if self.sock is None and not self.connect():
            return None, None, None
        try:
            t_sent = time.time()
            self.sock.sendall(H.frame(msg))
        except OSError:
            bump("send_fail")
            self.close()
            return None, None, None
        bump("sent")

        deadline = time.monotonic() + self.ack_timeout
        while True:
            msgs, self.buf = H.deframe(self.buf)
            if msgs:
                code, _ = H.ack_code(msgs[0])
                t_ack = time.time()
                if self.per_message:
                    # release the slot immediately, so the gateway holds no
                    # connection between messages (the E6b-vulnerable pattern)
                    self.close()
                return t_sent, t_ack, code
            if time.monotonic() > deadline:
                bump("ack_timeout")
                self.close()
                return t_sent, None, None
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                bump("send_fail")
                self.close()
                return t_sent, None, None
            if not chunk:
                self.close()
                return t_sent, None, None
            self.buf += chunk


def sender(q, client, retry_wait):
    while not stop["f"] or not q.empty():
        try:
            item = q.get(timeout=0.25)
        except queue.Empty:
            continue
        pub_id, seq, value, metric, t_send, t_mqtt = item
        msg = H.build_oru(pub_id, seq, value, metric)
        mid = H.msg_id(pub_id, seq)

        t_sent, t_ack, code = client.send_and_ack(msg)
        if t_sent is None:
            # could not even connect; count a reconnect attempt and move on
            bump("reconnects")
            time.sleep(retry_wait)
        if code == "AA":
            bump("ack_aa")
        elif code:
            bump("ack_ae")

        with rows_lock:
            rows.append((
                mid, pub_id, seq, f"{t_send:.6f}", f"{t_mqtt:.6f}",
                f"{t_sent:.6f}" if t_sent else "",
                f"{t_ack:.6f}" if t_ack else "",
                code or "", 1 if code == "AA" else 0,
            ))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mqtt-host", default="127.0.0.1")
    ap.add_argument("--mqtt-port", type=int, default=1883)
    ap.add_argument("--client-id", default="hl7-gateway",
                    help="must differ from the collector's id; see module docs")
    ap.add_argument("--topic", default="ward/#")
    ap.add_argument("--hl7-host", default="127.0.0.1")
    ap.add_argument("--hl7-port", type=int, default=H.MLLP_PORT)
    ap.add_argument("--bind", default="",
                    help="source address for the MLLP connection; the "
                         "nftables allow-list keys on this")
    ap.add_argument("--outfile", default="hl7_sent.csv")
    ap.add_argument("--statfile", default="hl7_gateway_stat.csv")
    ap.add_argument("--ack-timeout", type=float, default=5.0)
    ap.add_argument("--per-message-conn", action="store_true",
                    help="open and close a fresh MLLP connection per message "
                         "(the E6b-vulnerable, draft per-batch pattern); "
                         "default is one persistent connection")
    ap.add_argument("--queue-max", type=int, default=20000)
    ap.add_argument("--retry-wait", type=float, default=0.25)
    # MLLP TLS (to the listener)
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--cafile")
    ap.add_argument("--certfile")
    ap.add_argument("--keyfile")
    ap.add_argument("--server-name", default="localhost")
    # MQTT TLS (to the broker) -- kept plain for E6, see run_e6.py
    ap.add_argument("--mqtt-tls", action="store_true")
    ap.add_argument("--mqtt-cafile")
    ap.add_argument("--mqtt-certfile")
    ap.add_argument("--mqtt-keyfile")
    args = ap.parse_args()

    signal.signal(signal.SIGTERM, lambda *_: stop.update(f=True))
    signal.signal(signal.SIGINT, lambda *_: stop.update(f=True))

    ctx = None
    if args.tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(args.cafile)
        ctx.load_cert_chain(args.certfile, args.keyfile)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED

    q = queue.Queue(maxsize=args.queue_max)
    client = MllpClient(args.hl7_host, args.hl7_port, args.bind, ctx,
                        args.ack_timeout, args.server_name,
                        per_message=args.per_message_conn)
    if not args.per_message_conn:
        client.connect()

    th = threading.Thread(target=sender, args=(q, client, args.retry_wait),
                          daemon=True)
    th.start()

    def on_connect(c, u, flags, rc, props=None):
        c.subscribe(args.topic, qos=0)

    def on_message(c, u, m):
        t_mqtt = time.time()
        try:
            d = json.loads(m.payload.decode())
        except Exception:
            return
        parts = m.topic.split("/")
        metric = parts[-1] if parts else "heartrate"
        metric = TOPIC_METRIC.get(metric, "heartrate")
        # patient.py publishes {"pub","seq","t","hr"}
        value = d.get("hr", d.get("value", d.get(metric)))
        if value is None:
            return
        item = (d.get("pub", parts[1] if len(parts) > 1 else "?"),
                d.get("seq", -1), value, metric,
                float(d.get("t", t_mqtt)), t_mqtt)
        try:
            q.put_nowait(item)
            bump("queued")
        except queue.Full:
            bump("dropped")

    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=args.client_id)
    if args.mqtt_tls:
        c.tls_set(ca_certs=args.mqtt_cafile, certfile=args.mqtt_certfile,
                  keyfile=args.mqtt_keyfile)
        c.tls_insecure_set(True)
    c.on_connect = on_connect
    c.on_message = on_message
    c.connect(args.mqtt_host, args.mqtt_port, keepalive=30)
    c.loop_start()
    print(f"hl7-gateway: mqtt {args.mqtt_host}:{args.mqtt_port} id={args.client_id} "
          f"-> mllp {args.hl7_host}:{args.hl7_port} tls={bool(ctx)} "
          f"bind={args.bind or 'default'}", flush=True)

    while not stop["f"]:
        time.sleep(0.2)

    c.loop_stop()
    try:
        c.disconnect()
    except Exception:
        pass
    # let the sender drain what is already queued, bounded so teardown is
    # predictable (run_e6.py SIGKILLs 1.5 s after SIGTERM)
    th.join(timeout=1.0)
    client.close()

    with rows_lock:
        out = list(rows)
    with open(args.outfile, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["msg_id", "pub_id", "seq", "t_send", "t_mqtt", "t_sent",
                    "t_ack", "ack_code", "ok"])
        w.writerows(out)
    with stat_lock:
        st = dict(stat)
    st["queue_left"] = q.qsize()
    with open(args.statfile, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["key", "value"])
        for k in sorted(st):
            w.writerow([k, st[k]])
    print(f"hl7-gateway: {len(out)} messages "
          f"(AA={st['ack_aa']} AE={st['ack_ae']} timeout={st['ack_timeout']} "
          f"dropped={st['dropped']} connect_fail={st['connect_fail']}) "
          f"-> {os.path.basename(args.outfile)}")


if __name__ == "__main__":
    main()
