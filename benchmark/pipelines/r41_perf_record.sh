#!/bin/bash
# R41: perf record verification of R12 v2 mechanism (ice driver L1
# dcache warming when observer attached with --observer-prefetch on
# 0%-match filter). Compares baseline vs observer perf data.
#
# Reproduces the perf record finding from
# docs/ja/r12-fentry-prefetch-finding.md §v2 ("ice_alloc_rx_bufs
# L1 miss 35.7% → 0% when observer attached") to confirm the
# mechanism still holds after the R22 sharded-ringbuf hoist.
set -uo pipefail
cd /home/ocxma/private/xdp-ninja
DUT_IFACE=enp138s0f0np0
NINJA_BIN=$PWD/xdp-ninja
TREX_BENCH=/opt/trex/v3.08/scripts/trex_bench_mix.py
DURATION=28
OUTDIR=/var/tmp/r41
sudo mkdir -p "$OUTDIR" && sudo chmod 777 "$OUTDIR"

# attach prod_tx_reflect
sudo ip link set dev $DUT_IFACE xdp off 2>/dev/null || true
sudo rm -rf /sys/fs/bpf/r41 2>/dev/null
sudo bpftool prog loadall ./scripts/test/prod_tx_reflect.o /sys/fs/bpf/r41
sudo ip link set dev $DUT_IFACE xdp pinned /sys/fs/bpf/r41/prod_tx_reflect

run_perf() {
    local label="$1" with_observer="$2"
    local data_file=$OUTDIR/perf_${label}.data
    local stat_file=$OUTDIR/perf_${label}_stat.log
    sudo rm -f "$data_file" "$stat_file"

    local ninja_pid=""
    if [[ "$with_observer" == "yes" ]]; then
        sudo GODEBUG=asyncpreemptoff=1 timeout $((DURATION+10)) "$NINJA_BIN" --mode entry -i $DUT_IFACE \
            --observer-prefetch -w /dev/null "eth/ipv4/udp" \
            > /tmp/r41_ninja.out 2>/tmp/r41_ninja.err &
        ninja_pid=$!
        sleep 3
    fi

    # perf stat (counters) in parallel with TRex
    ssh ocxma-trex "python3 $TREX_BENCH $DURATION" > /tmp/r41_trex.json 2>/dev/null &
    TREX_PID=$!
    sleep 2  # let TRex ramp up

    # perf stat samples
    sudo perf stat -a --no-big-num \
        -e cycles,instructions,L1-dcache-load-misses,branch-misses \
        sleep $((DURATION - 4)) 2>"$stat_file" 1>/dev/null

    wait $TREX_PID 2>/dev/null || true
    [[ -n "$ninja_pid" ]] && wait $ninja_pid 2>/dev/null || true

    # TRex stats
    trex_rx=$(python3 -c 'import sys,json;print(json.load(sys.stdin)["avg_rx_mpps"])' < /tmp/r41_trex.json 2>/dev/null || echo n/a)

    echo "=== $label (observer=$with_observer) ==="
    echo "  TRex avg_rx_mpps: $trex_rx"
    echo "  perf stat (28s system-wide):"
    grep -E "cycles|instructions|L1-dcache-load-misses|branch-misses|IPC" "$stat_file" | head -10
}

run_perf "baseline"  "no"
sleep 3
run_perf "observer"  "yes"

sudo ip link set dev $DUT_IFACE xdp off 2>/dev/null
sudo rm -rf /sys/fs/bpf/r41 2>/dev/null

echo ""
echo "=== Compare (R12 v2 memory expects: L1 -23%, branch-miss -65% with observer) ==="
b_l1=$(grep "L1-dcache-load-misses" $OUTDIR/perf_baseline_stat.log | head -1 | awk '{print $1}' | tr -d ',')
o_l1=$(grep "L1-dcache-load-misses" $OUTDIR/perf_observer_stat.log | head -1 | awk '{print $1}' | tr -d ',')
b_br=$(grep "branch-misses" $OUTDIR/perf_baseline_stat.log | head -1 | awk '{print $1}' | tr -d ',')
o_br=$(grep "branch-misses" $OUTDIR/perf_observer_stat.log | head -1 | awk '{print $1}' | tr -d ',')

if [[ -n "$b_l1" && -n "$o_l1" ]]; then
    delta_l1=$(awk "BEGIN{printf \"%.1f\", ($o_l1 - $b_l1) * 100 / $b_l1}")
    echo "  L1-dcache-load-misses: baseline=$b_l1, observer=$o_l1, delta=${delta_l1}%"
fi
if [[ -n "$b_br" && -n "$o_br" ]]; then
    delta_br=$(awk "BEGIN{printf \"%.1f\", ($o_br - $b_br) * 100 / $b_br}")
    echo "  branch-misses:         baseline=$b_br, observer=$o_br, delta=${delta_br}%"
fi
echo ""
echo "DONE — data at $OUTDIR/"
