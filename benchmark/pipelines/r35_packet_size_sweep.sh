#!/bin/bash
# R35: packet size sweep. xdp-ninja --mode entry on prod_drop_all,
# default flags (no prefetch), varying TRex packet size to see how
# capture rate scales with packet size at fixed NVMe storage ceiling.
set -uo pipefail
cd /home/ocxma/private/xdp-ninja
DUT_IFACE=enp138s0f0np0
NINJA_BIN=$PWD/xdp-ninja
TREX_BENCH=/opt/trex/v3.08/scripts/trex_bench.py
DURATION=30
OUTDIR=/var/tmp/r35
sudo mkdir -p "$OUTDIR" && sudo chmod 777 "$OUTDIR"
CSV=$PWD/benchmark/results/r35_packet_size_sweep.csv

echo "pkt_size,captured_pkts,pps_Mpps,nic_rx_delta_Mpps,trex_tx_mpps,file_MB,bytes_per_pkt" > "$CSV"

# attach prod_drop_all once
sudo ip link set dev $DUT_IFACE xdp off 2>/dev/null || true
sudo rm -rf /sys/fs/bpf/prod_drop_all_r35 2>/dev/null
sudo bpftool prog loadall ./scripts/test/prod_drop_all.o /sys/fs/bpf/prod_drop_all_r35
sudo ip link set dev $DUT_IFACE xdp pinned /sys/fs/bpf/prod_drop_all_r35/prod_drop_all

run_cell() {
    local pkt_label="$1"
    sudo rm -f $OUTDIR/r35.raw* 2>/dev/null

    rx_before=$(ip -s link show $DUT_IFACE | awk '/RX:/{getline; print $2}')

    sudo GODEBUG=asyncpreemptoff=1 timeout 60 "$NINJA_BIN" --mode entry -i $DUT_IFACE \
        --raw-dump --fast-reader --no-wakeup --in-memory-buffer 256 --ringbuf-size 1024 \
        --snaplen 1500 \
        -w $OUTDIR/r35.raw > /tmp/r35.out 2>/tmp/r35.err &
    pid=$!
    sleep 3
    trex_json=$(ssh ocxma-trex "python3 $TREX_BENCH $pkt_label $DURATION" 2>/dev/null)
    wait $pid 2>/dev/null || true

    rx_after=$(ip -s link show $DUT_IFACE | awk '/RX:/{getline; print $2}')

    captured=$(grep -oE '[0-9]+ packets captured' /tmp/r35.err | grep -oE '^[0-9]+' | head -1)
    captured=${captured:-0}
    file_b=$(sudo du -bc $OUTDIR/r35.raw* 2>/dev/null | tail -1 | awk '{print $1}')
    file_b=${file_b:-0}
    sudo rm -f $OUTDIR/r35.raw* 2>/dev/null

    pps_mbps=$(awk "BEGIN{printf \"%.2f\", $captured/$DURATION/1e6}")
    nic_rx=$(awk "BEGIN{printf \"%.2f\", ($rx_after-$rx_before)/$DURATION/1e6}")
    trex_tx=$(echo "$trex_json" | python3 -c 'import sys,json;print(json.load(sys.stdin)["avg_tx_mpps"])' 2>/dev/null || echo 0)
    file_mb=$(awk "BEGIN{printf \"%.1f\", $file_b/1024/1024}")
    bpp=$(awk "BEGIN{if($captured>0){printf \"%.1f\", $file_b/$captured}else{print \"n/a\"}}")

    echo "$pkt_label,$captured,$pps_mbps,$nic_rx,$trex_tx,$file_mb,$bpp" | tee -a "$CSV"
}

run_cell 64
run_cell imix
run_cell 1500

# cleanup
sudo ip link set dev $DUT_IFACE xdp off 2>/dev/null
sudo rm -rf /sys/fs/bpf/prod_drop_all_r35 2>/dev/null

echo ""
echo "DONE — CSV: $CSV"
cat "$CSV"
