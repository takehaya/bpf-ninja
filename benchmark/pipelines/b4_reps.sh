#!/bin/bash
# B4 datapath macrobench, N reps for mean±σ (RR1 statistical reporting).
#
# Runs benchmark/pipelines/b4_xdp_drop.sh REPS times, each writing to its
# own b4_xdp_drop_rep{K}.csv, then prints the aggregation command.
#
# Preconditions (same as b4_xdp_drop.sh):
#   - TRex (-c 20, /etc/trex_cfg.yaml) RUNNING on ocxma-trex
#   - DUT iface enp138s0f0np0 UP and linked at 100 GbE
#   - passwordless sudo on the DUT
#
# Existing rep CSVs are archived to results/attic/ first (not overwritten).
#
# Usage:  REPS=5 DURATION=30 bash benchmark/pipelines/b4_reps.sh
set -uo pipefail
cd /home/ocxma/private/xdp-ninja

REPS=${REPS:-5}
B4="$PWD/benchmark/pipelines/b4_xdp_drop.sh"
OUTDIR="$PWD/benchmark/results"
ATTIC="$OUTDIR/attic"

mkdir -p "$ATTIC"
ts=$(date +%Y%m%d_%H%M%S 2>/dev/null || echo prev)
for old in "$OUTDIR"/b4_xdp_drop_rep*.csv; do
    [ -e "$old" ] || continue
    mv "$old" "$ATTIC/$(basename "${old%.csv}")_$ts.csv"
done

for k in $(seq 1 "$REPS"); do
    echo "########################## b4 rep $k / $REPS ##########################"
    if ! CSV="$OUTDIR/b4_xdp_drop_rep${k}.csv" bash "$B4"; then
        echo "rep $k FAILED -- aborting (check TRex running + iface up)" >&2
        exit 1
    fi
    sleep 5
done

echo
echo "done: $REPS reps -> $OUTDIR/b4_xdp_drop_rep{1..$REPS}.csv"
echo "aggregate with:"
echo "  python3 benchmark/analysis/b4_stats.py $OUTDIR/b4_xdp_drop_rep*.csv | tee $OUTDIR/b4_xdp_drop_stats.csv"
