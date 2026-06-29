#!/bin/bash
# R40: xdpcap vs xdp-ninja head-to-head on the same source-level
# instrumented XDP program (prod_pass_xdpcap, which has the
# xdpcap_hook map). xdpcap requires this source-level integration
# to work; xdp-ninja attaches non-invasively as fentry on the same
# binary so the comparison is on-equal-footing.
set -uo pipefail
cd /home/ocxma/private/xdp-ninja
DUT_IFACE=enp138s0f0np0
NINJA_BIN=$PWD/xdp-ninja
XDPCAP_BIN=/home/ocxma/.local/share/mise/installs/go/1.25.5/bin/xdpcap
LOADER=$PWD/scripts/test/prod_xdpcap_loader/prod_xdpcap_loader
TREX_BENCH=/opt/trex/v3.08/scripts/trex_bench.py
DURATION=30
OUTDIR=/var/tmp/r40
PIN_PATH=/sys/fs/bpf/xdpcap_hook
sudo mkdir -p "$OUTDIR" && sudo chmod 777 "$OUTDIR"
CSV=$PWD/benchmark/results/r40_xdpcap_compare.csv

echo "tool,output,captured_pkts,pps_Mpps,nic_rx_delta_Mpps,trex_tx_mpps,file_MB" > "$CSV"

# attach prod_pass_xdpcap via the loader (pins hook map)
sudo ip link set dev $DUT_IFACE xdp off 2>/dev/null || true
sudo rm -rf $PIN_PATH 2>/dev/null
sudo "$LOADER" -i $DUT_IFACE -obj $PWD/scripts/test/prod_pass_xdpcap.o -pin $PIN_PATH > /tmp/r40_loader.out 2>/tmp/r40_loader.err &
LOADER_PID=$!
sleep 3
echo "loader pid: $LOADER_PID"
sudo ip -d link show $DUT_IFACE | grep "prog/xdp" | head -1

run_xdpcap() {
    sudo rm -f $OUTDIR/r40.pcap 2>/dev/null
    rx_before=$(ip -s link show $DUT_IFACE | awk '/RX:/{getline; print $2}')

    sudo timeout 60 "$XDPCAP_BIN" "$PIN_PATH" $OUTDIR/r40.pcap > /tmp/r40_xdpcap.out 2>/tmp/r40_xdpcap.err &
    xpid=$!
    sleep 3
    trex_json=$(ssh ocxma-trex "python3 $TREX_BENCH 64 $DURATION" 2>/dev/null)
    sleep 2
    sudo kill -INT $xpid 2>/dev/null
    wait $xpid 2>/dev/null

    rx_after=$(ip -s link show $DUT_IFACE | awk '/RX:/{getline; print $2}')
    # xdpcap stderr summary: "8388608 captured 0 dropped 0 forwarded"
    captured=$(grep -oE '[0-9]+ captured' /tmp/r40_xdpcap.err | head -1 | grep -oE '[0-9]+')
    captured=${captured:-0}
    file_b=$(sudo du -bc $OUTDIR/r40.pcap 2>/dev/null | tail -1 | awk '{print $1}')
    file_b=${file_b:-0}
    sudo rm -f $OUTDIR/r40.pcap 2>/dev/null

    pps_mbps=$(awk "BEGIN{printf \"%.2f\", $captured/$DURATION/1e6}")
    nic_rx=$(awk "BEGIN{printf \"%.2f\", ($rx_after-$rx_before)/$DURATION/1e6}")
    trex_tx=$(echo "$trex_json" | python3 -c 'import sys,json;print(json.load(sys.stdin)["avg_tx_mpps"])' 2>/dev/null || echo 0)
    file_mb=$(awk "BEGIN{printf \"%.1f\", $file_b/1024/1024}")
    echo "xdpcap,nvme,$captured,$pps_mbps,$nic_rx,$trex_tx,$file_mb" | tee -a "$CSV"
}

run_ninja() {
    local label="$1"; shift
    local args=("$@")
    sudo rm -f $OUTDIR/r40.raw* 2>/dev/null
    rx_before=$(ip -s link show $DUT_IFACE | awk '/RX:/{getline; print $2}')

    sudo GODEBUG=asyncpreemptoff=1 timeout 60 "$NINJA_BIN" --mode entry -i $DUT_IFACE \
        "${args[@]}" > /tmp/r40_ninja.out 2>/tmp/r40_ninja.err &
    npid=$!
    sleep 3
    trex_json=$(ssh ocxma-trex "python3 $TREX_BENCH 64 $DURATION" 2>/dev/null)
    wait $npid 2>/dev/null

    rx_after=$(ip -s link show $DUT_IFACE | awk '/RX:/{getline; print $2}')
    captured=$(grep -oE '[0-9]+ packets captured' /tmp/r40_ninja.err | grep -oE '^[0-9]+' | head -1)
    captured=${captured:-0}
    file_b=$(sudo du -bc $OUTDIR/r40.raw* $OUTDIR/r40.pcapng* 2>/dev/null | tail -1 | awk '{print $1}')
    file_b=${file_b:-0}
    sudo rm -f $OUTDIR/r40.raw* $OUTDIR/r40.pcapng* 2>/dev/null

    pps_mbps=$(awk "BEGIN{printf \"%.2f\", $captured/$DURATION/1e6}")
    nic_rx=$(awk "BEGIN{printf \"%.2f\", ($rx_after-$rx_before)/$DURATION/1e6}")
    trex_tx=$(echo "$trex_json" | python3 -c 'import sys,json;print(json.load(sys.stdin)["avg_tx_mpps"])' 2>/dev/null || echo 0)
    file_mb=$(awk "BEGIN{printf \"%.1f\", $file_b/1024/1024}")
    echo "xdp-ninja,$label,$captured,$pps_mbps,$nic_rx,$trex_tx,$file_mb" | tee -a "$CSV"
}

echo ""
echo "=== Cell A: xdpcap (default flags) ==="
run_xdpcap

echo ""
echo "=== Cell B: xdp-ninja --mode entry pcap-ng (typical user) ==="
run_ninja "nvme_pcapng" -w $OUTDIR/r40.pcapng

echo ""
echo "=== Cell C: xdp-ninja --mode entry optimised (raw-dump + fastrb + inmem) ==="
run_ninja "nvme_raw_opt" --raw-dump --fast-reader --no-wakeup --in-memory-buffer 256 --ringbuf-size 1024 --snaplen 1500 -w $OUTDIR/r40.raw

# cleanup
sudo kill $LOADER_PID 2>/dev/null
sleep 1
sudo ip link set dev $DUT_IFACE xdp off 2>/dev/null
sudo rm -rf $PIN_PATH 2>/dev/null

echo ""
echo "DONE — CSV: $CSV"
cat "$CSV"
