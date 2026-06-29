#!/usr/bin/env bash
# B2 re-measurement driver: run the per-packet BPF_PROG_TEST_RUN
# mesobench (run_runtime.sh) REPS times, keep each rep CSV, then
# aggregate per (filter,path) into b2_runtime_stats.csv (n, mean, sd).
# b2_runtime.csv is left as the final rep (a single representative run),
# matching the prior artifact layout.
#
# Usage: sudo bash benchmark/microbench/run_runtime_reps.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RESULTS_DIR="$REPO_ROOT/benchmark/results"
REPS="${REPS:-10}"
BENCHTIME="${BENCHTIME:-1s}"

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root (BPF_PROG_TEST_RUN needs CAP_BPF/CAP_SYS_ADMIN)" >&2
    exit 2
fi

for i in $(seq 1 "$REPS"); do
    echo "=== rep $i/$REPS ==="
    BENCHTIME="$BENCHTIME" bash "$REPO_ROOT/benchmark/microbench/run_runtime.sh" >/dev/null
    cp "$RESULTS_DIR/b2_runtime.csv" "$RESULTS_DIR/b2_runtime_rep${i}.csv"
done

# Aggregate: mean and sample sd per (filter,path) across the reps.
python3 - "$RESULTS_DIR" "$REPS" <<'PY'
import csv, sys, math, glob, os
results_dir, reps = sys.argv[1], int(sys.argv[2])
acc = {}
order = []
for i in range(1, reps + 1):
    p = os.path.join(results_dir, f"b2_runtime_rep{i}.csv")
    with open(p) as f:
        for row in csv.DictReader(f):
            key = (row["filter"], row["path"])
            if key not in acc:
                acc[key] = []
                order.append(key)
            acc[key].append(float(row["ns_per_pkt"]))
out = os.path.join(results_dir, "b2_runtime_stats.csv")
with open(out, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["filter", "path", "n", "mean_ns", "sd_ns"])
    for key in order:
        xs = acc[key]
        n = len(xs)
        mean = sum(xs) / n
        sd = math.sqrt(sum((x - mean) ** 2 for x in xs) / (n - 1)) if n > 1 else 0.0
        w.writerow([key[0], key[1], n, f"{mean:.1f}", f"{sd:.1f}"])
print(f"wrote {out}")
PY

echo "=== b2_runtime_stats.csv ==="
column -s, -t "$RESULTS_DIR/b2_runtime_stats.csv"
