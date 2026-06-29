#!/bin/bash
# R36: filter complexity sweep. Same prod_drop_all + 64B TRex,
# vary DSL chain depth from 1 (eth) to 7 (vxlan inner tcp) layers.
# Measures whether kunai's codegen and the new dynamic-scratch
# path scale gracefully with chain depth.
set -uo pipefail
cd /home/ocxma/private/xdp-ninja
DUT_IFACE=enp138s0f0np0
NINJA_BIN=$PWD/xdp-ninja
TREX_BENCH=/opt/trex/v3.08/scripts/trex_bench.py
DURATION=30
OUTDIR=/var/tmp/r36
sudo mkdir -p "$OUTDIR" && sudo chmod 777 "$OUTDIR"
CSV=$PWD/benchmark/results/r36_filter_complexity.csv

echo "depth,filter,captured_pkts,pps_Mpps,nic_rx_delta_Mpps,trex_tx_mpps,file_MB" > "$CSV"

# attach prod_drop_all
sudo ip link set dev $DUT_IFACE xdp off 2>/dev/null || true
sudo rm -rf /sys/fs/bpf/prod_drop_all_r36 2>/dev/null
sudo bpftool prog loadall ./scripts/test/prod_drop_all.o /sys/fs/bpf/prod_drop_all_r36
sudo ip link set dev $DUT_IFACE xdp pinned /sys/fs/bpf/prod_drop_all_r36/prod_drop_all

run_cell() {
    local depth="$1" filter="$2"
    sudo rm -f $OUTDIR/r36.raw* 2>/dev/null
    rx_before=$(ip -s link show $DUT_IFACE | awk '/RX:/{getline; print $2}')

    local args=(--mode entry -i $DUT_IFACE --raw-dump --fast-reader --no-wakeup
                --in-memory-buffer 256 --ringbuf-size 1024 --snaplen 1500
                -w $OUTDIR/r36.raw)
    [[ -n "$filter" ]] && args+=("$filter")

    sudo GODEBUG=asyncpreemptoff=1 timeout 60 "$NINJA_BIN" "${args[@]}" \
        > /tmp/r36.out 2>/tmp/r36.err &
    pid=$!
    sleep 3
    trex_json=$(ssh ocxma-trex "python3 $TREX_BENCH 64 $DURATION" 2>/dev/null)
    wait $pid 2>/dev/null || true

    rx_after=$(ip -s link show $DUT_IFACE | awk '/RX:/{getline; print $2}')
    captured=$(grep -oE '[0-9]+ packets captured' /tmp/r36.err | grep -oE '^[0-9]+' | head -1)
    captured=${captured:-0}
    file_b=$(sudo du -bc $OUTDIR/r36.raw* 2>/dev/null | tail -1 | awk '{print $1}')
    file_b=${file_b:-0}
    sudo rm -f $OUTDIR/r36.raw* 2>/dev/null

    pps_mbps=$(awk "BEGIN{printf \"%.2f\", $captured/$DURATION/1e6}")
    nic_rx=$(awk "BEGIN{printf \"%.2f\", ($rx_after-$rx_before)/$DURATION/1e6}")
    trex_tx=$(echo "$trex_json" | python3 -c 'import sys,json;print(json.load(sys.stdin)["avg_tx_mpps"])' 2>/dev/null || echo 0)
    file_mb=$(awk "BEGIN{printf \"%.1f\", $file_b/1024/1024}")

    echo "$depth,${filter:-<none>},$captured,$pps_mbps,$nic_rx,$trex_tx,$file_mb" | tee -a "$CSV"
}

run_cell 0 ""
run_cell 1 "eth"
run_cell 2 "eth/ipv4"
run_cell 3 "eth/ipv4/udp"
run_cell 4 "eth/ipv4/udp/vxlan"
run_cell 5 "eth/ipv4/udp/vxlan/eth"
run_cell 6 "eth/ipv4/udp/vxlan/eth/ipv4"
run_cell 7 "eth/ipv4/udp/vxlan/eth/ipv4/tcp"

sudo ip link set dev $DUT_IFACE xdp off 2>/dev/null
sudo rm -rf /sys/fs/bpf/prod_drop_all_r36 2>/dev/null

echo ""
echo "DONE — CSV: $CSV"
cat "$CSV"
