#!/usr/bin/env bash
# Microbenchmark (E2 / B1): per-filter compile time + raw-insn count.
#
# Walks internal/program::FilterSet via go test -bench=BenchmarkFilterSet
# and reformats the output as ../results/b1_insns.csv. The CSV is small
# enough (≤ 20 rows) to commit and inspect by eye; downstream plotters
# in benchmark/analysis/ can read it as the canonical §6.3 source.
#
# Usage:
#   bash benchmark/microbench/run.sh                  # default 1s benchtime
#   BENCHTIME=3s bash benchmark/microbench/run.sh     # longer for stability
#
# Output columns:
#   filter   F1..F10 (matches FilterSet[].ID)
#   path     dsl | cbpfc
#   wall_ns  ns/op as reported by go test -bench
#   insns    instruction count (raw, DWord-loads expanded into 2 slots)
#
# Note: wall_ns reflects compile-time only (lex+parse+codegen, not
# verifier load or runtime); the matching B3 macrobench measures
# end-to-end packet processing.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RESULTS_DIR="$REPO_ROOT/benchmark/results"
mkdir -p "$RESULTS_DIR"
OUT="$RESULTS_DIR/b1_insns.csv"

BENCHTIME="${BENCHTIME:-1s}"

echo "filter,path,wall_ns,insns" > "$OUT"

cd "$REPO_ROOT"
# -benchmem is not used; we capture the custom 'insns/op' metric instead.
# -run=^$ skips ordinary tests so only the benchmarks execute.
go test ./internal/program/ \
    -run='^$' \
    -bench=BenchmarkFilterSet \
    -benchtime="$BENCHTIME" \
    -timeout=10m \
| awk -v OFS=',' '
    # Match lines like:
    #   BenchmarkFilterSet/F1/dsl-64    1234   42473 ns/op    197.0 insns/op
    # and emit: F1,dsl,42473,197
    /^BenchmarkFilterSet\// {
        # $1 has the form BenchmarkFilterSet/Fn/<path>-<cpus>; split it.
        n = split($1, parts, "/")
        fid = parts[2]
        sub(/-[0-9]+$/, "", parts[3])
        path = parts[3]

        # Find ns/op and insns/op columns by scanning.
        wall_ns = ""
        insns = ""
        for (i = 2; i <= NF; i++) {
            if ($i == "ns/op")     { wall_ns = $(i-1) }
            if ($i == "insns/op")  { insns = $(i-1); sub(/\.0+$/, "", insns) }
        }
        print fid, path, wall_ns, insns
    }
' >> "$OUT"

echo
echo "wrote $OUT"
column -s, -t "$OUT"
