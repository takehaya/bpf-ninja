#!/usr/bin/env bash
# E5: kunai library at the tc attach point.
# Loads kunai-emitted SCHED_CLS program via TCX (Linux 6.6+) and captures matched
# packets. Demonstrates kunai's host portability beyond XDP.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/common.sh"

FID="$(require_filter_id "${1:-}")"
IFACE="${IFACE:-eth0}"
EXPR="$(filter_kunai "$FID")"
OUT="$TMPFS/${FID}_kunai-tc.pcapng"

echo "== kunai/tc $FID on $IFACE =="
echo "DSL: $EXPR"
echo "output: $OUT (tmpfs)"
# Approach 1 (TCX): xdp-ninja --mode tc-entry/tc-exit (already wired in scripts/test/run_tests.sh)
echo "(stub) wire to xdp-ninja --mode tc-entry --dsl \"\$EXPR\" -i $IFACE -w $OUT"
