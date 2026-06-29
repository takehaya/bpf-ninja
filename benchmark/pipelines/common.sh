#!/usr/bin/env bash
# Common utility for bench runners.
# E3 macrobench: each tool reads test packets (T-Rex live or replay from pcap)
# and writes a captured pcap to tmpfs to remove disk I/O from the comparison.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMPFS="${TMPFS:-/dev/shm/xdpninja_bench}"
mkdir -p "$TMPFS"

DURATION="${DURATION:-300}"   # seconds per run
WARMUP="${WARMUP:-30}"        # seconds pre-warmup

filter_kunai() {
    cat "$REPO_ROOT/benchmark/filters/kunai/$1.kunai"
}

filter_pcap() {
    grep -v '^#' "$REPO_ROOT/benchmark/filters/pcap/$1.txt" | tr -d '\n'
}

# Parse "F1" / "F2" / ... from CLI arg, return absolute filter file path.
require_filter_id() {
    local fid="${1:-}"
    if [[ -z "$fid" ]]; then
        echo "usage: $0 <F1..F10>" >&2
        exit 2
    fi
    echo "$fid"
}
