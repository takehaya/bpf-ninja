#!/bin/bash
# R27: DSL filter cost isolation — capture rate at varying selectivity.
#      prod_drop_all loaded on enp138s0f0np0, xdp-ninja --mode entry
#      fentry observer with optimized raw-dump path + 64-shard ringbuf.
#      TRex hw -c 20 sends UDP 64B at ~117 Mpps offered.
set -uo pipefail
cd /home/ocxma/private/xdp-ninja
DUT_IFACE=enp138s0f0np0
NINJA_BIN=$PWD/xdp-ninja
TREX_BENCH=/opt/trex/v3.08/scripts/trex_bench.py
DURATION=30
OUTDIR=/var/tmp/r27
sudo mkdir -p "$OUTDIR" && sudo chmod 777 "$OUTDIR"
CSV=$PWD/benchmark/results/r27_filter_cost.csv

echo "label,filter,captured_pkts,pps_Mpps,nic_rx_delta_Mpps,nic_drop_delta_Mpps,trex_tx_mpps,file_MB" > "$CSV"

run_cell() {
    local label="$1"; shift
    local filter_args=("$@")

    sudo rm -f $OUTDIR/r27.raw* 2>/dev/null

    rx_before=$(ip -s link show $DUT_IFACE | awk '/RX:/{getline; print $2}')
    nic_drop_before=$(sudo ethtool -S $DUT_IFACE 2>/dev/null | grep -E '^\s*rx_dropped\.nic:' | awk '{print $NF}')
    nic_drop_before=${nic_drop_before:-0}

    sudo GODEBUG=asyncpreemptoff=1 timeout 60 "$NINJA_BIN" --mode entry -i $DUT_IFACE \
        --raw-dump --fast-reader --no-wakeup --in-memory-buffer 256 --ringbuf-size 1024 \
        -w $OUTDIR/r27.raw "${filter_args[@]}" > /tmp/r27.out 2>/tmp/r27.err &
    pid=$!
    sleep 3
    trex_json=$(ssh ocxma-trex "python3 $TREX_BENCH 64 $DURATION" 2>/dev/null)
    wait $pid 2>/dev/null || true

    rx_after=$(ip -s link show $DUT_IFACE | awk '/RX:/{getline; print $2}')
    nic_drop_after=$(sudo ethtool -S $DUT_IFACE 2>/dev/null | grep -E '^\s*rx_dropped\.nic:' | awk '{print $NF}')
    nic_drop_after=${nic_drop_after:-0}

    captured=$(grep -oE '[0-9]+ packets captured' /tmp/r27.err | grep -oE '^[0-9]+' | head -1)
    captured=${captured:-0}
    file_b=$(sudo du -bc $OUTDIR/r27.raw* 2>/dev/null | tail -1 | awk '{print $1}')
    file_b=${file_b:-0}
    sudo rm -f $OUTDIR/r27.raw* 2>/dev/null

    pps_mbps=$(awk "BEGIN{printf \"%.2f\", $captured/$DURATION/1e6}")
    nic_rx=$(awk "BEGIN{printf \"%.2f\", ($rx_after-$rx_before)/$DURATION/1e6}")
    nic_drop=$(awk "BEGIN{printf \"%.2f\", ($nic_drop_after-$nic_drop_before)/$DURATION/1e6}")
    trex_tx=$(echo "$trex_json" | python3 -c 'import sys,json;print(json.load(sys.stdin)["avg_tx_mpps"])' 2>/dev/null || echo 0)
    file_mb=$(awk "BEGIN{printf \"%.1f\", $file_b/1024/1024}")

    filter_str="${filter_args[*]:-<none>}"
    echo "$label,\"$filter_str\",$captured,$pps_mbps,$nic_rx,$nic_drop,$trex_tx,$file_mb" | tee -a "$CSV"
}

echo "=== Cell A: no filter (baseline, R23 equivalent) ==="
run_cell "no_filter"

echo ""
echo "=== Cell B: eth (chain root only, trivial) ==="
run_cell "eth_root" "eth"

echo ""
echo "=== Cell C: eth/ipv4 (L3 match, 100% of UDP traffic) ==="
run_cell "eth_ipv4" "eth/ipv4"

echo ""
echo "=== Cell D: eth/ipv4/udp (L4 match, 100% of UDP) ==="
run_cell "eth_ipv4_udp" "eth/ipv4/udp"

echo ""
echo "=== Cell E: eth/ipv4/tcp (L4 match, 0% — TRex sends UDP) ==="
run_cell "eth_ipv4_tcp_0pct" "eth/ipv4/tcp"

echo ""
echo "=== Cell F: eth/ipv4/udp[dport==80] (predicate, 0% — TRex dport=9) ==="
run_cell "udp_dport80_0pct" "eth/ipv4/udp[dport==80]"

echo ""
echo "=== Cell G: eth/ipv4/udp[dport==9] (predicate, 100% match) ==="
run_cell "udp_dport9_100pct" "eth/ipv4/udp[dport==9]"

echo ""
echo "DONE — CSV: $CSV"
cat "$CSV"
