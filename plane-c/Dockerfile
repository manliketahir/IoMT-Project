# GNS3 node image for the E6 topology: the E2 image plus the plane-C code.
# Build INSIDE the GNS3 VM after plane-b's image, from this directory:
#     docker build -t iomt-node:1.1 .
# Certificates are NOT baked in: run_gns3_e6.py copies the HL7 certificates
# into the gateway and listener at the start of each run.
FROM iomt-node:1.0
# hl7_listener.py imports hl7apy at start-up, even for structural validation.
# Pinned to the version the loopback E6 sweep used (E6-PLAN.md).
RUN pip3 install --no-cache-dir --break-system-packages "hl7apy==1.3.5"
COPY . /opt/plane-c
