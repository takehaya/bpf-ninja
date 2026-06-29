#!/usr/bin/env bash
# E3 macrobench: tcpdump (AF_PACKET) baseline.
# Output to tmpfs to remove disk I/O.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/common.sh"

FID="$(require_filter_id "${1:-}")"
IFACE="${IFACE:-eth0}"
EXPR="$(filter_pcap "$FID")"
OUT="$TMPFS/${FID}_tcpdump.pcap"

echo "== tcpdump $FID on $IFACE =="
echo "filter: $EXPR"
echo "output: $OUT (tmpfs)"
echo "duration: ${DURATION}s (warmup ${WARMUP}s)"

# Real run: tcpdump -i $IFACE -nn -w $OUT -G $DURATION -W 1 "$EXPR"
echo "(stub) implement when T-Rex generator is online (Week 4-5)"
