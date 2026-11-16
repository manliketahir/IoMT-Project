#!/usr/bin/env python3
"""E2b load generator: malformed frames and unauthorized publishing.

Research test harness for the author's own local broker only; it defaults to
the loopback address. It exercises two things the E2b mitigation (mutual TLS
plus per-topic ACL) is meant to stop:

  1. Unauthorized publish. The harness connects and publishes to another
     bed's topic (ward/bed-2/...). On the plain anonymous broker this is
     accepted and the collector sees the forged value. On the mutual-TLS
     broker the harness has no client certificate, so the TLS handshake
     never completes and the publish never happens.

  2. Malformed frame. The harness sends a few junk bytes where an MQTT
     packet is expected, to see whether they reach the broker's parser. On
     the plain broker they reach the parser and the connection is dropped;
     on the mutual-TLS broker the TLS layer rejects the peer first, so the
     parser is never exposed.

The point measured is not damage but whether each layer refuses the traffic,
so the harness only records outcomes.
"""
import argparse
import socket
import ssl
import time

import paho.mqtt.client as mqtt


def try_unauth_publish(host, port, tls, cafile):
    """Return 'accepted', 'refused', or 'blocked-by-tls'."""
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="rogue")
    if tls:
        # no client certificate on purpose: mutual TLS should reject us
        c.tls_set(ca_certs=cafile, tls_version=ssl.PROTOCOL_TLSv1_2)
    try:
        c.connect(host, port, keepalive=10)
    except Exception:
        return "blocked-by-tls"
    c.loop_start()
    info = c.publish("ward/bed-2/vitals/heartrate",
                     '{"pub":"rogue","seq":0,"t":0,"hr":0}', qos=1)
    try:
        info.wait_for_publish(timeout=3)
        out = "accepted" if info.is_published() else "refused"
    except Exception:
        out = "refused"
    c.loop_stop()
    c.disconnect()
    return out


def try_malformed(host, port, tls, cafile):
    """Return 'reached-parser' or 'blocked-by-tls'."""
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(3.0)
    try:
        raw.connect((host, port))
        if tls:
            ctx = ssl.create_default_context(cafile=cafile)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_REQUIRED
            s = ctx.wrap_socket(raw, server_hostname="localhost")
        else:
            s = raw
    except (ssl.SSLError, OSError):
        return "blocked-by-tls"
    try:
        s.sendall(b"\xff\xff\xff\xffnot-an-mqtt-packet")
        s.recv(16)  # broker closes the connection on a bad frame
    except OSError:
        pass
    finally:
        s.close()
    return "reached-parser"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--cafile")
    ap.add_argument("--duration", type=float, default=60.0)
    ap.add_argument("--outfile", default="attack.csv")
    args = ap.parse_args()

    end = time.monotonic() + args.duration
    unauth = malformed = None
    while time.monotonic() < end:
        unauth = try_unauth_publish(args.host, args.port, args.tls, args.cafile)
        malformed = try_malformed(args.host, args.port, args.tls, args.cafile)
        time.sleep(2.0)

    with open(args.outfile, "w") as f:
        f.write("unauthorized_publish,malformed_frame\n")
        f.write(f"{unauth},{malformed}\n")
    print(f"malformed/unauth: publish={unauth} frame={malformed}")


if __name__ == "__main__":
    main()
