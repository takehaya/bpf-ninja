#!/usr/bin/env bash
# E3 macrobench: xdp-ninja with kunai DSL filter.
# fentry/fexit attach to a target XDP program (set XDP_TARGET=interface or prog ID).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/common.sh"

FID="$(require_filter_id "${1:-}")"
IFACE="${IFACE:-eth0}"
EXPR="$(filter_kunai "$FID")"
OUT="$TMPFS/${FID}_xdpninja.pcapng"

echo "== xdp-ninja $FID on $IFACE =="
echo "DSL: $EXPR"
echo "output: $OUT (tmpfs)"
echo "duration: ${DURATION}s (warmup ${WARMUP}s)"

# Real run:
#   timeout $DURATION ./xdp-ninja -i $IFACE --dsl "$EXPR" -w "$OUT"
echo "(stub) implement when T-Rex generator is online (Week 4-5)"
