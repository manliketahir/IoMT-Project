#!/usr/bin/env bash
# Generate a throwaway CA, a server certificate, and client certificates
# for the E2 testbed. Everything here is local to this machine and exists
# only to exercise the mutual-TLS path; none of it is a real identity.
#
# Usage:  bash make-certs.sh [bed-count]
# Default bed-count is 60, enough for the largest scale.
set -euo pipefail
cd "$(dirname "$0")"

BEDS="${1:-60}"
DAYS=825
SUBJ_BASE="/C=PK/O=IoMT-Testbed"

gen_ca() {
  openssl genrsa -out ca.key 2048
  openssl req -x509 -new -nodes -key ca.key -sha256 -days "$DAYS" \
    -subj "${SUBJ_BASE}/CN=IoMT-Testbed-CA" -out ca.crt
}

# gen_cert <name> <extfile-or-empty>
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
echo "[*] server (CN=localhost)"
gen_cert server "DNS:localhost,IP:127.0.0.1"
echo "[*] collector"
gen_cert collector ""
echo "[*] ${BEDS} beds"
for i in $(seq 1 "$BEDS"); do
  gen_cert "bed-${i}" "" >/dev/null 2>&1
done

chmod 600 ./*.key
echo "[*] done. CA + server + collector + bed-1..bed-${BEDS} in $(pwd)"
