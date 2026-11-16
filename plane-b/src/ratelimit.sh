#!/usr/bin/env bash
# Per-source new-connection rate limit for the E2a mitigation. The connection
# cap is the broker's half of the mitigation; this is the firewall half, which
# Mosquitto cannot do itself. It throttles how fast one source address may open
# new connections to the broker port, so the connection-exhaustion source
# (bound to 127.0.0.2) is limited while the patients on 127.0.0.1 are not.
#
# It runs the nft commands as root: directly if already root, otherwise through
# "sudo -n nft", so it needs either a passwordless-sudo rule for nft (see the
# day-4 notes) or to be launched under sudo. If root cannot be reached, or the
# WSL kernel rejects the rule, it warns and exits 0 so the run continues with
# the connection cap alone. It never aborts the sweep.
#
# Usage:  bash ratelimit.sh on|off [port]        # as your user, with NOPASSWD nft
#     or: sudo bash ratelimit.sh on|off [port]   # as root
set -u

action="${1:-}"
port="${2:-1883}"
RATE="5/second"
BURST=10
TABLE="e2a"

warn() { echo "[ratelimit] $*" >&2; }

NFT="$(command -v nft || true)"
[ -z "$NFT" ] && [ -x /usr/sbin/nft ] && NFT=/usr/sbin/nft
if [ -z "$NFT" ]; then
  warn "nft not found; staying cap-only"
  exit 0
fi

if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo -n"; fi
nft_cmd() { $SUDO "$NFT" "$@"; }

do_off() { nft_cmd delete table ip "$TABLE" 2>/dev/null || true; }

do_on() {
  nft_cmd add table ip "$TABLE" || return 1
  nft_cmd "add chain ip $TABLE input { type filter hook input priority -10 ; policy accept ; }" || return 1
  nft_cmd "add rule ip $TABLE input tcp dport $port tcp flags & (syn|ack) == syn meter ${TABLE}-m { ip saddr limit rate over $RATE burst $BURST packets } counter drop" || return 1
}

case "$action" in
  on)
    do_off
    if do_on 2>/dev/null; then
      echo "[ratelimit] on via nft (port $port; > $RATE per source is dropped)"
    else
      warn "could not apply nft rule (no root / NOPASSWD, or kernel lacks nf_tables); staying cap-only"
      do_off
      exit 0
    fi
    ;;
  off)
    do_off
    echo "[ratelimit] off (port $port)"
    ;;
  *)
    echo "usage: bash ratelimit.sh on|off [port]"
    exit 1
    ;;
esac
