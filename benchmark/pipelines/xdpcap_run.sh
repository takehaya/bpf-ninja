#!/usr/bin/env bash
# E3 macrobench: xdpcap (Cloudflare). Requires the production XDP program to
# embed the xdpcap_hook (invasive deployment); here we use scripts/test/xdp_pass.o
# patched with a hook for sanity comparison only.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/common.sh"

FID="$(require_filter_id "${1:-}")"
IFACE="${IFACE:-eth0}"
EXPR="$(filter_pcap "$FID")"
OUT="$TMPFS/${FID}_xdpcap.pcap"

echo "== xdpcap $FID on $IFACE =="
echo "filter: $EXPR"
echo "output: $OUT (tmpfs)"
echo "(stub) implement when xdpcap binary + hooked target XDP are prepared (Week 4)"
