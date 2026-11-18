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
import os
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
    """Return 'reached-parser' or 'blocked-by-tls'.

    How a broker that requires a client certificate refuses this peer depends
    on the TLS version. Under TLS 1.2 it aborts the handshake itself, so
    wrap_socket raises. Under TLS 1.3 the client's side of the handshake
    completes first, and the server's certificate_required alert arrives
    afterwards, followed by the server closing the connection.

    So under TLS this reads BEFORE sending anything. An alert, a close or a
    reset at that point happens before a single MQTT byte has been sent, so the
    peer was stopped at TLS. Only if the session stays open is the junk sent,
    and then the parser is what rejects it. Sending first would race the
    server's alert: junk arriving at the already-closed socket draws a TCP
    reset, which discards the unread alert and looks like a parser rejection.
    That race mislabelled about 17 % of attempts when it was measured (GNS3, 18
    November 2026). An earlier version also treated any completed client-side
    handshake as reaching the parser, which only holds under TLS 1.2.
    """
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(3.0)
    try:
        raw.connect((host, port))
        if tls:
            ctx = ssl.create_default_context(cafile=cafile)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_REQUIRED
            s = ctx.wrap_socket(raw, server_hostname="localhost")
            print(f"malformed: client-side handshake completed ({s.version()})", flush=True)
        else:
            s = raw
    except (ssl.SSLError, OSError) as e:
        print(f"malformed: handshake refused ({getattr(e, 'reason', None) or e})", flush=True)
        return "blocked-by-tls"
    if tls:
        # Nothing sent yet: does the server keep the TLS session open?
        s.settimeout(1.5)
        try:
            early = s.recv(16)
            if early == b"":
                print("malformed: server closed the TLS session before any MQTT byte "
                      "-> stopped at TLS", flush=True)
                s.close()
                return "blocked-by-tls"
        except ssl.SSLError as e:
            reason = getattr(e, "reason", None) or str(e)
            print(f"malformed: server sent TLS alert {reason} -> stopped at TLS", flush=True)
            s.close()
            return "blocked-by-tls"
        except socket.timeout:
            pass  # session accepted and quiet: the server is waiting for MQTT
        except OSError as e:
            print(f"malformed: connection reset before any MQTT byte ({e}) "
                  f"-> stopped at TLS", flush=True)
            s.close()
            return "blocked-by-tls"
        s.settimeout(3.0)
    try:
        s.sendall(b"\xff\xff\xff\xffnot-an-mqtt-packet")
        s.recv(16)  # broker closes the connection on a bad frame
    except OSError:
        pass
    finally:
        s.close()
    print("malformed: junk sent on an open session -> reached the parser", flush=True)
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
    tally = {}
    while time.monotonic() < end:
        unauth = try_unauth_publish(args.host, args.port, args.tls, args.cafile)
        malformed = try_malformed(args.host, args.port, args.tls, args.cafile)
        for k in (f"unauthorized_publish={unauth}", f"malformed_frame={malformed}"):
            tally[k] = tally.get(k, 0) + 1
        time.sleep(2.0)

    # attack.csv keeps its original one-row format (the last attempt), which
    # analyze.py reads; every attempt's outcome is tallied alongside it.
    with open(args.outfile, "w") as f:
        f.write("unauthorized_publish,malformed_frame\n")
        f.write(f"{unauth},{malformed}\n")
    tally_path = os.path.join(os.path.dirname(os.path.abspath(args.outfile)), "attack_tally.csv")
    with open(tally_path, "w") as f:
        f.write("outcome,attempts\n")
        for k in sorted(tally):
            f.write(f"{k},{tally[k]}\n")
    print(f"malformed/unauth: publish={unauth} frame={malformed}  all attempts: {tally}")


if __name__ == "__main__":
    main()
