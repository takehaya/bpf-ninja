#!/bin/bash
# R28: multi-CPU scaling sweep. Vary NIC RX queue count (ethtool -L
#      combined N) for N ∈ {1, 2, 4, 8, 16, 32, 64}. xdp-ninja
#      always allocates 64 shards; only those backed by an active
#      RX queue see traffic.
#      Target: prod_drop_all loaded, xdp-ninja --mode entry observer,
#      TRex hw -c 20 (117 Mpps offered).
set -uo pipefail
cd /home/ocxma/private/xdp-ninja
DUT_IFACE=enp138s0f0np0
NINJA_BIN=$PWD/xdp-ninja
TREX_BENCH=/opt/trex/v3.08/scripts/trex_bench.py
DURATION=30
OUTDIR=/var/tmp/r28
sudo mkdir -p "$OUTDIR" && sudo chmod 777 "$OUTDIR"
CSV=$PWD/benchmark/results/r28_multi_cpu_scaling.csv

echo "rx_queues,captured_pkts,pps_Mpps,nic_rx_delta_Mpps,nic_drop_delta_Mpps,trex_tx_mpps,file_MB" > "$CSV"

restore=64

run_cell() {
    local n="$1"
    echo ""
    echo "=== Cell N=$n RX queues ==="
    sudo ethtool -L $DUT_IFACE combined "$n" 2>&1 | head -3
    sleep 2

    sudo rm -f $OUTDIR/r28.raw* 2>/dev/null

    rx_before=$(ip -s link show $DUT_IFACE | awk '/RX:/{getline; print $2}')
    nic_drop_before=$(sudo ethtool -S $DUT_IFACE 2>/dev/null | grep -E '^\s*rx_dropped\.nic:' | awk '{print $NF}')
    nic_drop_before=${nic_drop_before:-0}

    sudo GODEBUG=asyncpreemptoff=1 timeout 60 "$NINJA_BIN" --mode entry -i $DUT_IFACE \
        --raw-dump --fast-reader --no-wakeup --in-memory-buffer 256 --ringbuf-size 1024 \
        -w $OUTDIR/r28.raw > /tmp/r28.out 2>/tmp/r28.err &
    pid=$!
    sleep 3
    trex_json=$(ssh ocxma-trex "python3 $TREX_BENCH 64 $DURATION" 2>/dev/null)
    wait $pid 2>/dev/null || true

    rx_after=$(ip -s link show $DUT_IFACE | awk '/RX:/{getline; print $2}')
    nic_drop_after=$(sudo ethtool -S $DUT_IFACE 2>/dev/null | grep -E '^\s*rx_dropped\.nic:' | awk '{print $NF}')
    nic_drop_after=${nic_drop_after:-0}

    captured=$(grep -oE '[0-9]+ packets captured' /tmp/r28.err | grep -oE '^[0-9]+' | head -1)
    captured=${captured:-0}
    file_b=$(sudo du -bc $OUTDIR/r28.raw* 2>/dev/null | tail -1 | awk '{print $1}')
    file_b=${file_b:-0}
    sudo rm -f $OUTDIR/r28.raw* 2>/dev/null

    pps_mbps=$(awk "BEGIN{printf \"%.2f\", $captured/$DURATION/1e6}")
    nic_rx=$(awk "BEGIN{printf \"%.2f\", ($rx_after-$rx_before)/$DURATION/1e6}")
    nic_drop=$(awk "BEGIN{printf \"%.2f\", ($nic_drop_after-$nic_drop_before)/$DURATION/1e6}")
    trex_tx=$(echo "$trex_json" | python3 -c 'import sys,json;print(json.load(sys.stdin)["avg_tx_mpps"])' 2>/dev/null || echo 0)
    file_mb=$(awk "BEGIN{printf \"%.1f\", $file_b/1024/1024}")

    echo "$n,$captured,$pps_mbps,$nic_rx,$nic_drop,$trex_tx,$file_mb" | tee -a "$CSV"
}

for n in 1 2 4 8 16 32 64; do
    run_cell "$n"
done

echo ""
echo "=== restore queues to $restore ==="
sudo ethtool -L $DUT_IFACE combined $restore 2>&1 | head -1
echo ""
echo "DONE — CSV: $CSV"
cat "$CSV"
