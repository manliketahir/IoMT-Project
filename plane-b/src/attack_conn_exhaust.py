#!/usr/bin/env python3
"""E2a load generator: connection exhaustion.

Research test harness for the author's own local broker only. It opens many
MQTT connections and holds them open, to measure whether the broker keeps
serving legitimate publishers while its connection table fills. It is the
stimulus that the E2a mitigation (connection cap plus per-source rate limit)
is evaluated against; it is not a general-purpose tool and defaults to the
loopback address.

To let the per-source rate limit tell this traffic apart from the patients,
the harness binds its connections to a separate loopback source address
(127.0.0.2 by default) while the patients use 127.0.0.1. All of 127.0.0.0/8
is loopback on Linux, so both stay on the local host.

By default a minimal MQTT CONNECT is sent on each socket so the broker counts
it as a client rather than dropping an idle TCP peer. With --no-connect the
socket is opened at the TCP level and nothing is ever sent; this is the
half-open / pre-CONNECT variant, used to measure whether the broker still
holds the slot, whether the connection cap counts it, and how long the broker
waits before closing a silent peer. With --liveness <file> the harness samples
how many of its sockets are still alive over the hold window and writes
time_s,alive rows there.
"""
import argparse
import select
import signal
import socket
import time

running = True


def stop(*_):
    global running
    running = False


def connect_packet(client_id: str) -> bytes:
    cid = client_id.encode()
    # variable header: protocol name "MQTT", level 4, clean session, keepalive
    vh = b"\x00\x04MQTT\x04\x02\x00\x3c"
    payload = len(cid).to_bytes(2, "big") + cid
    rem = vh + payload
    return b"\x10" + encode_len(len(rem)) + rem


def encode_len(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n % 128
        n //= 128
        if n > 0:
            b |= 0x80
        out.append(b)
        if n == 0:
            break
    return bytes(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--source", default="127.0.0.2",
                    help="loopback source address for this traffic")
    ap.add_argument("--count", type=int, default=400,
                    help="connections to attempt")
    ap.add_argument("--duration", type=float, default=60.0)
    ap.add_argument("--outfile", default="attack.csv")
    ap.add_argument("--no-connect", action="store_true",
                    help="open TCP but never send CONNECT (pre-CONNECT flood)")
    ap.add_argument("--liveness", default="",
                    help="CSV to record time_s,alive over the hold window")
    args = ap.parse_args()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    socks = []
    established = 0
    refused = 0
    attempted = 0
    t0 = time.time()
    try:
        for i in range(args.count):
            if not running or (time.time() - t0) >= args.duration:
                break
            attempted += 1
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.bind((args.source, 0))
                s.settimeout(1.0)
                s.connect((args.host, args.port))
                if not args.no_connect:
                    s.sendall(connect_packet(f"x{i}"))
                s.setblocking(False)
                socks.append(s)
                established += 1
            except OSError:
                refused += 1
                s.close()
            time.sleep(0.003)

        # Hold the connections open for the rest of the window. A socket the
        # broker has closed becomes readable and recv() returns b""; counting
        # those still alive shows whether the broker drops silent peers (and
        # how fast) and whether the cap bounds pre-CONNECT sockets.
        live_rows = []

        def alive_count():
            n = 0
            for sk in socks:
                try:
                    r, _, _ = select.select([sk], [], [], 0)
                    if r:
                        if sk.recv(1, socket.MSG_PEEK) == b"":
                            continue  # peer closed
                    n += 1
                except OSError:
                    continue
            return n

        next_sample = 0.0
        while running and (time.time() - t0) < args.duration:
            now = time.time() - t0
            if args.liveness and now >= next_sample:
                live_rows.append((round(now, 1), alive_count()))
                next_sample = now + 2.0
            time.sleep(0.1)
        if args.liveness:
            live_rows.append((round(time.time() - t0, 1), alive_count()))
            with open(args.liveness, "w") as lf:
                lf.write("time_s,alive\n")
                for t, n in live_rows:
                    lf.write(f"{t},{n}\n")
    finally:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass
        # Always record the outcome, even if a signal ends the run early,
        # so the mitigation cell never comes back with an empty attack.csv.
        with open(args.outfile, "w") as f:
            f.write("established,refused,attempted\n")
            f.write(f"{established},{refused},{attempted}\n")
        print(f"conn-exhaust: established={established} "
              f"refused={refused} attempted={attempted}")


if __name__ == "__main__":
    main()
