#!/usr/bin/env bash
#
# r5_matrix.sh — orchestrator for the §6.4 multi-source 4-way
# capture-rate matrix. Runs each tool for N reps and collects raw
# CSV into benchmark/results/r5_multi_source.csv.
#
# Usage:
#   bash benchmark/pipelines/r5_matrix.sh [n_reps] [duration_s]
#     n_reps default 10, duration_s default 60.
#
# Tools covered (in run order):
#   1. tcpdump            — AF_PACKET single socket (baseline)
#   2. tcpdump-fanout     — afp_fanout helper (fair PACKET_FANOUT baseline)
#   3. xdpdump            — perf_event_array
#   4. xdpcap             — xdpcap_hook + cBPF + perf_event_array
#   5. xdp-ninja          — per-CPU sharded bpf_ringbuf

set -euo pipefail
n_reps="${1:-10}"
duration_s="${2:-60}"
rest_s="${3:-10}"
out=benchmark/results/r5_multi_source.csv

mkdir -p "$(dirname "$out")"
echo "tool,rep,duration_s,trex_tx_pps,trex_opackets,observer_captured,pps" > "$out"

for tool in tcpdump tcpdump-fanout xdpdump xdpcap xdp-ninja; do
    for rep in $(seq 1 "$n_reps"); do
        echo "[$(date +%H:%M:%S)] tool=$tool rep=$rep" >&2
        bash benchmark/pipelines/r5_multi_source.sh "$tool" "$rep" "$duration_s" \
            | tee -a "$out"
        sleep "$rest_s"
    done
done
echo "[$(date +%H:%M:%S)] Done. Result: $out" >&2
