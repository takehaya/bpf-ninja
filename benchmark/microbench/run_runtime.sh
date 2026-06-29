#!/usr/bin/env bash
# Mesobenchmark (E2 / B2): per-packet runtime via BPF_PROG_TEST_RUN.
#
# Walks internal/program::FilterSet via go test -bench=BenchmarkFilterSetRun
# (which loads each filter as a real tracing probe and times Test() calls)
# and reformats the output as ../results/b2_runtime.csv.
#
# Requires root because BPF_PROG_TEST_RUN must load real BPF programs.
#
# Usage:
#   sudo bash benchmark/microbench/run_runtime.sh
#   BENCHTIME=3s sudo bash benchmark/microbench/run_runtime.sh   # longer for stability
#
# Output columns:
#   filter   F1..F10 (matches FilterSet[].ID)
#   path     kunai | cbpfc
#   ns_per_pkt  per-packet end-to-end cost including the BPF_PROG_TEST_RUN
#               syscall overhead (~600 ns on x86 kernels). Same overhead
#               affects both kunai and cbpfc, so the kunai/cbpfc *ratio*
#               on this CSV is the codegen-only signal.
#
# Note: This is the §6.3 "JIT amortization" data source. Companion to
# b1_insns.csv (compile-time codegen) and b3_throughput.csv (line-rate,
# Week 5).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RESULTS_DIR="$REPO_ROOT/benchmark/results"
mkdir -p "$RESULTS_DIR"
OUT="$RESULTS_DIR/b2_runtime.csv"

BENCHTIME="${BENCHTIME:-1s}"

if [[ $EUID -ne 0 ]]; then
    echo "error: this script must run as root (BPF_PROG_TEST_RUN requires CAP_BPF/CAP_SYS_ADMIN)" >&2
    echo "       try: sudo $0" >&2
    exit 2
fi

echo "filter,path,ns_per_pkt" > "$OUT"

cd "$REPO_ROOT"
go test ./internal/program/ \
    -run='^$' \
    -bench=BenchmarkFilterSetRun \
    -benchtime="$BENCHTIME" \
    -timeout=15m \
| awk -v OFS=',' '
    /^BenchmarkFilterSetRun\// {
        n = split($1, parts, "/")
        fid = parts[2]
        sub(/-[0-9]+$/, "", parts[3])
        path = parts[3]

        ns_per_pkt = ""
        for (i = 2; i <= NF; i++) {
            if ($i == "ns/pkt") { ns_per_pkt = $(i-1) }
        }
        print fid, path, ns_per_pkt
    }
' >> "$OUT"

echo
echo "wrote $OUT"
column -s, -t "$OUT"
