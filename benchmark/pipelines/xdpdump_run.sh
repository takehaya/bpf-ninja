#!/usr/bin/env bash
# E3 macrobench: xdpdump (xdp-tools). No filter capability — captures all packets
# at XDP entry/exit. Used as the no-filter baseline for measuring filter overhead
# in the kunai stack.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/common.sh"

FID="$(require_filter_id "${1:-}")"
IFACE="${IFACE:-eth0}"
OUT="$TMPFS/${FID}_xdpdump.pcapng"

echo "== xdpdump $FID on $IFACE (no filter, all-packet baseline) =="
echo "output: $OUT (tmpfs)"
# Real run: xdpdump -i $IFACE -w $OUT --rx-capture entry
echo "(stub)"
