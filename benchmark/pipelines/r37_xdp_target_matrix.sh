#!/bin/bash
# R37: production XDP target matrix. Attach 5 different prod_*.o
# targets, then measure observer capture rate with both default
# and --observer-prefetch flag. Verifies R34's prefetch effect
# generalises beyond prod_tx_reflect.
set -uo pipefail
cd /home/ocxma/private/xdp-ninja
DUT_IFACE=enp138s0f0np0
NINJA_BIN=$PWD/xdp-ninja
TREX_BENCH=/opt/trex/v3.08/scripts/trex_bench.py
DURATION=30
OUTDIR=/var/tmp/r37
sudo mkdir -p "$OUTDIR" && sudo chmod 777 "$OUTDIR"
CSV=$PWD/benchmark/results/r37_xdp_target_matrix.csv

echo "target,observer,prefetch,captured_pkts,pps_Mpps,nic_rx_delta_Mpps,trex_tx_mpps,trex_rx_mpps,file_MB" > "$CSV"

attach_target() {
    local target="$1"
    sudo ip link set dev $DUT_IFACE xdp off 2>/dev/null || true
    sudo rm -rf /sys/fs/bpf/r37_target 2>/dev/null
    sudo bpftool prog loadall ./scripts/test/${target}.o /sys/fs/bpf/r37_target 2>&1 | head -2
    sudo ip link set dev $DUT_IFACE xdp pinned /sys/fs/bpf/r37_target/${target}
}

run_cell() {
    local target="$1" observer="$2" prefetch="$3"
    sudo rm -f $OUTDIR/r37.raw* 2>/dev/null

    rx_before=$(ip -s link show $DUT_IFACE | awk '/RX:/{getline; print $2}')

    local ninja_pid=""
    if [[ "$observer" == "ninja-entry" ]]; then
        local args=(--mode entry -i $DUT_IFACE --raw-dump --fast-reader --no-wakeup
                    --in-memory-buffer 256 --ringbuf-size 1024 --snaplen 1500
                    -w $OUTDIR/r37.raw)
        [[ "$prefetch" == "yes" ]] && args+=(--observer-prefetch)
        sudo GODEBUG=asyncpreemptoff=1 timeout 60 "$NINJA_BIN" "${args[@]}" \
            > /tmp/r37.out 2>/tmp/r37.err &
        ninja_pid=$!
        sleep 3
    fi

    trex_json=$(ssh ocxma-trex "python3 $TREX_BENCH 64 $DURATION" 2>/dev/null)

    if [[ -n "$ninja_pid" ]]; then
        wait "$ninja_pid" 2>/dev/null || true
    fi

    rx_after=$(ip -s link show $DUT_IFACE | awk '/RX:/{getline; print $2}')
    captured=0
    [[ "$observer" == "ninja-entry" ]] && captured=$(grep -oE '[0-9]+ packets captured' /tmp/r37.err | grep -oE '^[0-9]+' | head -1)
    captured=${captured:-0}
    file_b=$(sudo du -bc $OUTDIR/r37.raw* 2>/dev/null | tail -1 | awk '{print $1}')
    file_b=${file_b:-0}
    sudo rm -f $OUTDIR/r37.raw* 2>/dev/null

    pps_mbps=$(awk "BEGIN{printf \"%.2f\", $captured/$DURATION/1e6}")
    nic_rx=$(awk "BEGIN{printf \"%.2f\", ($rx_after-$rx_before)/$DURATION/1e6}")
    trex_tx=$(echo "$trex_json" | python3 -c 'import sys,json;print(json.load(sys.stdin)["avg_tx_mpps"])' 2>/dev/null || echo 0)
    trex_rx=$(echo "$trex_json" | python3 -c 'import sys,json;print(json.load(sys.stdin)["avg_rx_mpps"])' 2>/dev/null || echo 0)
    file_mb=$(awk "BEGIN{printf \"%.1f\", $file_b/1024/1024}")

    echo "$target,$observer,$prefetch,$captured,$pps_mbps,$nic_rx,$trex_tx,$trex_rx,$file_mb" | tee -a "$CSV"
}

for target in prod_pass prod_drop_all prod_drop443 prod_tx_reflect prod_rewrite_dst; do
    echo ""
    echo "=== target: $target ==="
    attach_target "$target"

    run_cell "$target" "baseline"    "n/a"
    run_cell "$target" "ninja-entry" "no"
    run_cell "$target" "ninja-entry" "yes"
done

sudo ip link set dev $DUT_IFACE xdp off 2>/dev/null
sudo rm -rf /sys/fs/bpf/r37_target 2>/dev/null

echo ""
echo "DONE — CSV: $CSV"
cat "$CSV"
