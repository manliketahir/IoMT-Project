#!/usr/bin/env bash
# Throwaway CA plus the two identities the E6 MLLP mutual-TLS path needs:
# the listener (CN=localhost, so the gateway can verify it) and the gateway
# (CN=hl7-gateway). Everything here is local to this machine and exists only
# to exercise the mutual-TLS path; none of it is a real identity.
#
# The forging peer in E6a is deliberately NOT issued a certificate: that is
# why its handshake is refused on the TLS listener.
#
# Usage:  bash make-certs.sh
set -euo pipefail
cd "$(dirname "$0")"

DAYS=825
SUBJ_BASE="/C=PK/O=IoMT-Testbed"

gen_ca() {
  openssl genrsa -out ca.key 2048
  openssl req -x509 -new -nodes -key ca.key -sha256 -days "$DAYS" \
    -subj "${SUBJ_BASE}/CN=IoMT-Testbed-CA" -out ca.crt
}

gen_cert() {
  local name="$1" san="$2"
  openssl genrsa -out "${name}.key" 2048
  openssl req -new -key "${name}.key" \
    -subj "${SUBJ_BASE}/CN=${name}" -out "${name}.csr"
  if [[ -n "$san" ]]; then
    printf 'subjectAltName=%s\n' "$san" > "${name}.ext"
    openssl x509 -req -in "${name}.csr" -CA ca.crt -CAkey ca.key \
      -CAcreateserial -days "$DAYS" -sha256 \
      -extfile "${name}.ext" -out "${name}.crt"
    rm -f "${name}.ext"
  else
    openssl x509 -req -in "${name}.csr" -CA ca.crt -CAkey ca.key \
      -CAcreateserial -days "$DAYS" -sha256 -out "${name}.crt"
  fi
  rm -f "${name}.csr"
}

echo "[*] CA"
gen_ca
echo "[*] hl7-server (CN=localhost)"
# CN is the literal name "hl7-server" but the SAN carries localhost/127.0.0.1,
# which is what the gateway checks are irrelevant here (check_hostname=False),
# yet the SAN keeps the cert usable if hostname checking is ever turned on.
gen_cert hl7-server "DNS:localhost,IP:127.0.0.1"
echo "[*] hl7-gateway"
gen_cert hl7-gateway ""

chmod 600 ./*.key
echo "[*] done. CA + hl7-server + hl7-gateway in $(pwd)"
