#!/usr/bin/env bash
# Network-layer allow-list for the E6a first mitigation. A peer whose source
# address is not the HL7 gateway's never completes a TCP connection to the
# MLLP port -- the drop happens in the kernel, before the listener's accept(),
# which is the "never completes a TCP connection" the paper describes. This is
# strictly stronger than the listener's in-process --allow, where the TCP
# connection completes and the peer consumes a slot before being rejected.
#
# It mirrors src/ratelimit.sh from plane B: it runs nft as root (directly if
# already root, else via "sudo -n nft", which the testbed sudoers allows with
# NOPASSWD for /usr/sbin/nft), and if root cannot be reached or the kernel
# rejects the rule it warns and exits 0 so the run continues -- there, with the
# weaker in-listener allow-list instead. It never aborts the sweep.
#
# Usage:  bash hl7_allowlist.sh on  <gateway-ip> [port]
#         bash hl7_allowlist.sh off [port]
set -u

action="${1:-}"
TABLE="e6allow"

warn() { echo "[allowlist] $*" >&2; }

NFT="$(command -v nft || true)"
[ -z "$NFT" ] && [ -x /usr/sbin/nft ] && NFT=/usr/sbin/nft
if [ -z "$NFT" ]; then
  warn "nft not found; fall back to the listener --allow (weaker)"
  exit 0
fi

if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo -n"; fi
nft_cmd() { $SUDO "$NFT" "$@"; }

do_off() { nft_cmd delete table ip "$TABLE" 2>/dev/null || true; }

do_on() {
  local gw="$1" port="$2"
  nft_cmd add table ip "$TABLE" || return 1
  nft_cmd "add chain ip $TABLE input { type filter hook input priority -10 ; policy accept ; }" || return 1
  # Allow the loopback base, the gateway, and already-established flows; drop
  # every other source to the MLLP port. Established is allowed so the
  # listener's own ACK path is never caught by the input hook.
  nft_cmd "add rule ip $TABLE input ct state established,related accept" || return 1
  nft_cmd "add rule ip $TABLE input tcp dport $port ip saddr $gw accept" || return 1
  nft_cmd "add rule ip $TABLE input tcp dport $port ip saddr 127.0.0.1 accept" || return 1
  nft_cmd "add rule ip $TABLE input tcp dport $port counter drop" || return 1
}

case "$action" in
  on)
    gw="${2:-}"; port="${3:-2575}"
    if [ -z "$gw" ]; then echo "usage: bash hl7_allowlist.sh on <gateway-ip> [port]"; exit 1; fi
    do_off
    if do_on "$gw" "$port" 2>/dev/null; then
      echo "[allowlist] on via nft (port $port; only $gw and 127.0.0.1 may connect)"
    else
      warn "could not apply nft rule (no root/NOPASSWD, or kernel lacks nf_tables); fall back to listener --allow"
      do_off
      exit 0
    fi
    ;;
  off)
    do_off
    echo "[allowlist] off"
    ;;
  *)
    echo "usage: bash hl7_allowlist.sh on <gateway-ip> [port] | off [port]"
    exit 1
    ;;
esac
