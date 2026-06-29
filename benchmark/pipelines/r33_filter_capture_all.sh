#!/bin/bash
# R33: filter + capture-all. Same 7-cell matrix as R32 but with
#      --snaplen 1500 so MaxCapLen overrides the R57 filter-min
#      snaplen behaviour. Each captured packet records the full
#      L2 frame (min(pkt_len, 1500)) regardless of which filter
#      decided the match.
#
# Expected: throughput stays at the R32 storage ceiling (14 Mpps)
# for match-100 % filters because TRex sends 64 B packets and the
# per-record byte count (16 metadata + ~56 payload) is unchanged
# from R32 — only the *cap* differs. For a real production
# deployment with larger packets, the storage ceiling drops as
# the payload grows.
set -uo pipefail
cd /home/ocxma/private/xdp-ninja
DUT_IFACE=enp138s0f0np0
NINJA_BIN=$PWD/xdp-ninja
TREX_BENCH=/opt/trex/v3.08/scripts/trex_bench.py
DURATION=30
OUTDIR=/var/tmp/r33
sudo mkdir -p "$OUTDIR" && sudo chmod 777 "$OUTDIR"
CSV=$PWD/benchmark/results/r33_filter_capture_all.csv

echo "label,filter,captured_pkts,pps_Mpps,nic_rx_delta_Mpps,nic_drop_delta_Mpps,trex_tx_mpps,file_MB,bytes_per_pkt" > "$CSV"

run_cell() {
    local label="$1"; shift
    local filter_args=("$@")

    sudo rm -f $OUTDIR/r33.raw* 2>/dev/null

    rx_before=$(ip -s link show $DUT_IFACE | awk '/RX:/{getline; print $2}')
    nic_drop_before=$(sudo ethtool -S $DUT_IFACE 2>/dev/null | grep -E '^\s*rx_dropped\.nic:' | awk '{print $NF}')
    nic_drop_before=${nic_drop_before:-0}

    sudo GODEBUG=asyncpreemptoff=1 timeout 60 "$NINJA_BIN" --mode entry -i $DUT_IFACE \
        --raw-dump --fast-reader --no-wakeup --in-memory-buffer 256 --ringbuf-size 1024 \
        --snaplen 1500 \
        -w $OUTDIR/r33.raw "${filter_args[@]}" > /tmp/r33.out 2>/tmp/r33.err &
    pid=$!
    sleep 3
    trex_json=$(ssh ocxma-trex "python3 $TREX_BENCH 64 $DURATION" 2>/dev/null)
    wait $pid 2>/dev/null || true

    rx_after=$(ip -s link show $DUT_IFACE | awk '/RX:/{getline; print $2}')
    nic_drop_after=$(sudo ethtool -S $DUT_IFACE 2>/dev/null | grep -E '^\s*rx_dropped\.nic:' | awk '{print $NF}')
    nic_drop_after=${nic_drop_after:-0}

    captured=$(grep -oE '[0-9]+ packets captured' /tmp/r33.err | grep -oE '^[0-9]+' | head -1)
    captured=${captured:-0}
    file_b=$(sudo du -bc $OUTDIR/r33.raw* 2>/dev/null | tail -1 | awk '{print $1}')
    file_b=${file_b:-0}
    sudo rm -f $OUTDIR/r33.raw* 2>/dev/null

    pps_mbps=$(awk "BEGIN{printf \"%.2f\", $captured/$DURATION/1e6}")
    nic_rx=$(awk "BEGIN{printf \"%.2f\", ($rx_after-$rx_before)/$DURATION/1e6}")
    nic_drop=$(awk "BEGIN{printf \"%.2f\", ($nic_drop_after-$nic_drop_before)/$DURATION/1e6}")
    trex_tx=$(echo "$trex_json" | python3 -c 'import sys,json;print(json.load(sys.stdin)["avg_tx_mpps"])' 2>/dev/null || echo 0)
    file_mb=$(awk "BEGIN{printf \"%.1f\", $file_b/1024/1024}")
    bpp=$(awk "BEGIN{if($captured>0){printf \"%.1f\", $file_b/$captured}else{print \"n/a\"}}")

    filter_str="${filter_args[*]:-<none>}"
    echo "$label,\"$filter_str\",$captured,$pps_mbps,$nic_rx,$nic_drop,$trex_tx,$file_mb,$bpp" | tee -a "$CSV"
}

run_cell "no_filter"
run_cell "eth_root" "eth"
run_cell "eth_ipv4" "eth/ipv4"
run_cell "eth_ipv4_udp" "eth/ipv4/udp"
run_cell "eth_ipv4_tcp_0pct" "eth/ipv4/tcp"
run_cell "udp_dport80_0pct" "eth/ipv4/udp[dport==80]"
run_cell "udp_dport9_100pct" "eth/ipv4/udp[dport==9]"

echo ""
echo "DONE — CSV: $CSV"
cat "$CSV"
