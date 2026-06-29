#!/usr/bin/env bash
#
# Non-invasive observability matrix orchestrator. Runs the 5×5×3
# matrix used as the §6.6 main result in the paper:
#
#   behaviors : pass, drop443, tx_reflect, rewrite_dst, redirect_cpumap
#   observers : baseline, tcpdump, xdpdump, ninja-entry, ninja-exit
#   reps      : 1, 2, 3
#
# 5 × 5 × 3 = 75 cells. With 30s tx + 30s rest per cell that's
# ~75 minutes wall-clock. Output:
#   benchmark/results/visibility_matrix.csv
#
# CSV columns match visibility_run.sh stdout:
#   behavior,observer,rep,duration_s,trex_tx_pps,trex_opackets,observer_captured

set -euo pipefail
duration_s="${1:-30}"
rest_s="${2:-30}"
out="benchmark/results/visibility_matrix.csv"

mkdir -p "$(dirname "$out")"
echo "behavior,observer,rep,duration_s,trex_tx_pps,trex_opackets,observer_captured" > "$out"

behaviors=(pass drop443 tx_reflect rewrite_dst redirect_cpumap)
observers=(baseline tcpdump xdpdump ninja-entry ninja-exit)

for behavior in "${behaviors[@]}"; do
    for observer in "${observers[@]}"; do
        for rep in 1 2 3; do
            echo "[$(date +%H:%M:%S)] behavior=$behavior observer=$observer rep=$rep" >&2
            bash benchmark/pipelines/visibility_run.sh \
                "$behavior" "$observer" "$rep" "$duration_s" \
                | tee -a "$out"
            sleep "$rest_s"
        done
    done
done
echo "[$(date +%H:%M:%S)] Done. Result: $out" >&2
