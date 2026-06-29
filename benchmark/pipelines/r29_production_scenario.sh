#!/bin/bash
# R29: production-realistic scenario — attach xdp-ninja --mode entry to
#      prod_pass.o (XDP_PASS for every packet). Unlike prod_drop_all
#      (which bypasses the kernel netif path), this exercises the
#      full production path: NIC RX → fentry observer → ringbuf
#      submit → original XDP runs → XDP_PASS → kernel netif → drop
#      at netfilter (default).
#
# Compare against R26 (prod_drop_all bench-isolated) to quantify the
# kernel-netif tax on the same fentry observer.
set -uo pipefail
cd /home/ocxma/private/xdp-ninja
DUT_IFACE=enp138s0f0np0
NINJA_BIN=$PWD/xdp-ninja
TREX_BENCH=/opt/trex/v3.08/scripts/trex_bench.py
DURATION=30
OUTDIR=/var/tmp/r29
sudo mkdir -p "$OUTDIR" && sudo chmod 777 "$OUTDIR"
CSV=$PWD/benchmark/results/r29_production_scenario.csv

echo "target,captured_pkts,pps_Mpps,nic_rx_delta_Mpps,nic_drop_delta_Mpps,trex_tx_mpps,file_MB" > "$CSV"

# Detach any current XDP, attach prod_pass
sudo ip link set dev $DUT_IFACE xdp off 2>/dev/null || true
sudo rm -rf /sys/fs/bpf/prod_pass 2>/dev/null || true
sudo bpftool prog loadall ./scripts/test/prod_pass.o /sys/fs/bpf/prod_pass 2>&1
sudo ip link set dev $DUT_IFACE xdp pinned /sys/fs/bpf/prod_pass/prod_pass 2>&1
sudo ip -d link show $DUT_IFACE | grep "prog/xdp" | head -1

run_cell() {
    local label="$1"
    sudo rm -f $OUTDIR/r29.raw* 2>/dev/null

    rx_before=$(ip -s link show $DUT_IFACE | awk '/RX:/{getline; print $2}')
    nic_drop_before=$(sudo ethtool -S $DUT_IFACE 2>/dev/null | grep -E '^\s*rx_dropped\.nic:' | awk '{print $NF}')
    nic_drop_before=${nic_drop_before:-0}

    sudo GODEBUG=asyncpreemptoff=1 timeout 60 "$NINJA_BIN" --mode entry -i $DUT_IFACE \
        --raw-dump --fast-reader --no-wakeup --in-memory-buffer 256 --ringbuf-size 1024 \
        -w $OUTDIR/r29.raw > /tmp/r29.out 2>/tmp/r29.err &
    pid=$!
    sleep 3
    trex_json=$(ssh ocxma-trex "python3 $TREX_BENCH 64 $DURATION" 2>/dev/null)
    wait $pid 2>/dev/null || true

    rx_after=$(ip -s link show $DUT_IFACE | awk '/RX:/{getline; print $2}')
    nic_drop_after=$(sudo ethtool -S $DUT_IFACE 2>/dev/null | grep -E '^\s*rx_dropped\.nic:' | awk '{print $NF}')
    nic_drop_after=${nic_drop_after:-0}

    captured=$(grep -oE '[0-9]+ packets captured' /tmp/r29.err | grep -oE '^[0-9]+' | head -1)
    captured=${captured:-0}
    file_b=$(sudo du -bc $OUTDIR/r29.raw* 2>/dev/null | tail -1 | awk '{print $1}')
    file_b=${file_b:-0}
    sudo rm -f $OUTDIR/r29.raw* 2>/dev/null

    pps_mbps=$(awk "BEGIN{printf \"%.2f\", $captured/$DURATION/1e6}")
    nic_rx=$(awk "BEGIN{printf \"%.2f\", ($rx_after-$rx_before)/$DURATION/1e6}")
    nic_drop=$(awk "BEGIN{printf \"%.2f\", ($nic_drop_after-$nic_drop_before)/$DURATION/1e6}")
    trex_tx=$(echo "$trex_json" | python3 -c 'import sys,json;print(json.load(sys.stdin)["avg_tx_mpps"])' 2>/dev/null || echo 0)
    file_mb=$(awk "BEGIN{printf \"%.1f\", $file_b/1024/1024}")

    echo "$label,$captured,$pps_mbps,$nic_rx,$nic_drop,$trex_tx,$file_mb" | tee -a "$CSV"
}

echo "=== Cell A: --mode entry observer on prod_pass (XDP_PASS production target) ==="
run_cell "prod_pass_entry"

echo ""
echo "=== Cell B: detach prod_pass, --mode xdp (xdp-ninja IS the XDP) for comparison ==="
sudo ip link set dev $DUT_IFACE xdp off 2>/dev/null
sleep 1
sudo rm -f $OUTDIR/r29.raw* 2>/dev/null

rx_before=$(ip -s link show $DUT_IFACE | awk '/RX:/{getline; print $2}')
nic_drop_before=$(sudo ethtool -S $DUT_IFACE 2>/dev/null | grep -E '^\s*rx_dropped\.nic:' | awk '{print $NF}')
nic_drop_before=${nic_drop_before:-0}

# --mode xdp WITHOUT --bench-drop = XDP_PASS to kernel
sudo GODEBUG=asyncpreemptoff=1 timeout 60 "$NINJA_BIN" --mode xdp -i $DUT_IFACE \
    --raw-dump --fast-reader --no-wakeup --in-memory-buffer 256 --ringbuf-size 1024 \
    -w $OUTDIR/r29.raw > /tmp/r29.out 2>/tmp/r29.err &
pid=$!
sleep 3
trex_json=$(ssh ocxma-trex "python3 $TREX_BENCH 64 $DURATION" 2>/dev/null)
wait $pid 2>/dev/null || true
sudo ip link set dev $DUT_IFACE xdp off 2>/dev/null

rx_after=$(ip -s link show $DUT_IFACE | awk '/RX:/{getline; print $2}')
nic_drop_after=$(sudo ethtool -S $DUT_IFACE 2>/dev/null | grep -E '^\s*rx_dropped\.nic:' | awk '{print $NF}')
nic_drop_after=${nic_drop_after:-0}

captured=$(grep -oE '[0-9]+ packets captured' /tmp/r29.err | grep -oE '^[0-9]+' | head -1)
captured=${captured:-0}
file_b=$(sudo du -bc $OUTDIR/r29.raw* 2>/dev/null | tail -1 | awk '{print $1}')
file_b=${file_b:-0}
sudo rm -f $OUTDIR/r29.raw* 2>/dev/null

pps_mbps=$(awk "BEGIN{printf \"%.2f\", $captured/$DURATION/1e6}")
nic_rx=$(awk "BEGIN{printf \"%.2f\", ($rx_after-$rx_before)/$DURATION/1e6}")
nic_drop=$(awk "BEGIN{printf \"%.2f\", ($nic_drop_after-$nic_drop_before)/$DURATION/1e6}")
trex_tx=$(echo "$trex_json" | python3 -c 'import sys,json;print(json.load(sys.stdin)["avg_tx_mpps"])' 2>/dev/null || echo 0)
file_mb=$(awk "BEGIN{printf \"%.1f\", $file_b/1024/1024}")
echo "xdp_native_pass,$captured,$pps_mbps,$nic_rx,$nic_drop,$trex_tx,$file_mb" | tee -a "$CSV"

echo ""
echo "DONE — CSV: $CSV"
cat "$CSV"
