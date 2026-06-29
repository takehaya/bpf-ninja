#!/usr/bin/env bash
#
# B3 Tier 1 master orchestrator. Runs F1 × {tcpdump, xdp-ninja-dsl} ×
# {1%, 100%} match × 3 reps = 12 cells. Output:
# benchmark/results/b3_throughput.csv
#
# Bottom row of CSV is identical to b3_run.sh stdout schema:
#   filter,tool,size,match_pct,rep,duration_s,trex_opackets,trex_tx_pps,
#   tool_captured,tool_pps

set -e
duration_s="${1:-30}"
out="benchmark/results/b3_throughput.csv"

mkdir -p "$(dirname "$out")"
echo "filter,tool,size,match_pct,rep,duration_s,trex_opackets,trex_tx_pps,tool_captured,tool_pps" > "$out"

for tool in tcpdump xdp-ninja-dsl; do
  for match_pct in 1 100; do
    for rep in 1 2 3; do
      echo "[$(date +%H:%M:%S)] tool=$tool match=$match_pct rep=$rep" >&2
      bash benchmark/pipelines/b3_run.sh "$tool" "$match_pct" "$rep" "$duration_s" \
        | tee -a "$out"
      sleep 3  # let DPDK queues drain between runs
    done
  done
done
echo "[$(date +%H:%M:%S)] Done. Result: $out" >&2
