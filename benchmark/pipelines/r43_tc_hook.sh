#!/bin/bash
# R43: TC hook bench. Attach tc_pass clsact classifier, then
# xdp-ninja --mode tc-entry / tc-exit as fentry/fexit observer.
# TC sees skbs (post-XDP, post-netif), so per-packet cost is
# higher than the XDP path. Paper §6 multi-host claim.
set -uo pipefail
cd /home/ocxma/private/xdp-ninja
DUT_IFACE=enp138s0f0np0
NINJA_BIN=$PWD/xdp-ninja
TC_OBJ=$PWD/scripts/test/tc_pass.o
TREX_BENCH=/opt/trex/v3.08/scripts/trex_bench.py
DURATION=30
OUTDIR=/var/tmp/r43
sudo mkdir -p "$OUTDIR" && sudo chmod 777 "$OUTDIR"
CSV=$PWD/benchmark/results/r43_tc_hook.csv

# build tc_pass.o if missing
if [[ ! -f "$TC_OBJ" ]]; then
    cd scripts/test && clang -O2 -g -target bpf -c tc_pass.c -o tc_pass.o
    cd $PWD
fi

echo "mode,captured_pkts,pps_Mpps,nic_rx_delta_Mpps,trex_tx_mpps,file_MB" > "$CSV"

# detach any prior XDP
sudo ip link set dev $DUT_IFACE xdp off 2>/dev/null || true

# clean clsact + reattach
sudo tc qdisc del dev $DUT_IFACE clsact 2>/dev/null || true
sudo tc qdisc add dev $DUT_IFACE clsact
sudo tc filter add dev $DUT_IFACE ingress bpf direct-action obj $TC_OBJ section classifier
sudo tc filter show dev $DUT_IFACE ingress | head -5

# get prog ID of tc_pass
PROG_ID=$(sudo bpftool prog show -j 2>/dev/null | python3 -c '
import sys,json
for p in json.load(sys.stdin):
    if p.get("name") == "tc_pass":
        print(p["id"]); break
')
echo "tc_pass prog id: $PROG_ID"

run_cell() {
    local mode="$1"
    sudo rm -f $OUTDIR/r43.raw* 2>/dev/null
    rx_before=$(ip -s link show $DUT_IFACE | awk '/RX:/{getline; print $2}')

    sudo GODEBUG=asyncpreemptoff=1 timeout 60 "$NINJA_BIN" --mode "$mode" -p "$PROG_ID" \
        --raw-dump --fast-reader --no-wakeup --in-memory-buffer 256 --ringbuf-size 1024 \
        --snaplen 1500 -w $OUTDIR/r43.raw > /tmp/r43.out 2>/tmp/r43.err &
    pid=$!
    sleep 3
    trex_json=$(ssh ocxma-trex "python3 $TREX_BENCH 64 $DURATION" 2>/dev/null)
    wait $pid 2>/dev/null || true

    rx_after=$(ip -s link show $DUT_IFACE | awk '/RX:/{getline; print $2}')
    captured=$(grep -oE '[0-9]+ packets captured' /tmp/r43.err | grep -oE '^[0-9]+' | head -1)
    captured=${captured:-0}
    file_b=$(sudo du -bc $OUTDIR/r43.raw* 2>/dev/null | tail -1 | awk '{print $1}')
    file_b=${file_b:-0}
    sudo rm -f $OUTDIR/r43.raw* 2>/dev/null

    pps_mbps=$(awk "BEGIN{printf \"%.2f\", $captured/$DURATION/1e6}")
    nic_rx=$(awk "BEGIN{printf \"%.2f\", ($rx_after-$rx_before)/$DURATION/1e6}")
    trex_tx=$(echo "$trex_json" | python3 -c 'import sys,json;print(json.load(sys.stdin)["avg_tx_mpps"])' 2>/dev/null || echo 0)
    file_mb=$(awk "BEGIN{printf \"%.1f\", $file_b/1024/1024}")

    echo "$mode,$captured,$pps_mbps,$nic_rx,$trex_tx,$file_mb" | tee -a "$CSV"
}

run_cell "tc-entry"
run_cell "tc-exit"

# cleanup
sudo tc qdisc del dev $DUT_IFACE clsact 2>/dev/null || true

echo ""
echo "DONE — CSV: $CSV"
cat "$CSV"
