# GNS3 node image for the E2 topology (and the base of the E6 image).
# Build INSIDE the GNS3 VM, from this directory, so GNS3's Docker daemon has it:
#     docker build -t iomt-node:1.0 .
# One image serves every role (broker, collector, attacker, patients); the role
# is chosen by the command run_gns3.py starts in each container.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip mosquitto mosquitto-clients \
      nftables iproute2 iputils-ping tcpdump netcat-openbsd \
      openssl ca-certificates procps \
 && rm -rf /var/lib/apt/lists/*

# The orchestrator launches its own broker per run; the packaged service must not hold 1883.
RUN systemctl disable mosquitto 2>/dev/null || true

# Only what a node needs. numpy/scipy/matplotlib stay out: analysis runs on the host.
RUN pip3 install --no-cache-dir --break-system-packages "paho-mqtt>=2.1.0" "psutil>=5.9.0"

WORKDIR /opt/testbed
COPY . /opt/testbed
CMD ["/bin/bash"]
