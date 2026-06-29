#!/bin/bash
# R39: default-mode bench. xdp-ninja --mode entry with minimum
# required flags (just -i and -w) — no --raw-dump, no --fast-reader,
# no --no-wakeup, no --in-memory-buffer override, no --snaplen
# override. Measures what an out-of-the-box user experiences.
#
# For context vs the optimised recipe:
#   R26 (raw + fastrb + inmem + snaplen):  14.5 Mpps
#   R30 (pcap-ng + fastrb + NVMe):         10.0 Mpps
#   R31 (--null-output + fastrb):          54.2 Mpps
set -uo pipefail
cd /home/ocxma/private/xdp-ninja
DUT_IFACE=enp138s0f0np0
NINJA_BIN=$PWD/xdp-ninja
TREX_BENCH=/opt/trex/v3.08/scripts/trex_bench.py
DURATION=30
OUTDIR=/var/tmp/r39
sudo mkdir -p "$OUTDIR" && sudo chmod 777 "$OUTDIR"
CSV=$PWD/benchmark/results/r39_default_mode.csv

echo "label,captured_pkts,pps_Mpps,nic_rx_delta_Mpps,trex_tx_mpps,file_MB" > "$CSV"

# attach prod_drop_all
sudo ip link set dev $DUT_IFACE xdp off 2>/dev/null || true
sudo rm -rf /sys/fs/bpf/r39_target 2>/dev/null
sudo bpftool prog loadall ./scripts/test/prod_drop_all.o /sys/fs/bpf/r39_target
sudo ip link set dev $DUT_IFACE xdp pinned /sys/fs/bpf/r39_target/prod_drop_all

run_cell() {
    local label="$1"; shift
    local args=("$@")

    sudo rm -f $OUTDIR/r39.pcapng* $OUTDIR/r39.raw* 2>/dev/null

    rx_before=$(ip -s link show $DUT_IFACE | awk '/RX:/{getline; print $2}')

    sudo GODEBUG=asyncpreemptoff=1 timeout 60 "$NINJA_BIN" --mode entry -i $DUT_IFACE \
        "${args[@]}" > /tmp/r39.out 2>/tmp/r39.err &
    pid=$!
    sleep 3
    trex_json=$(ssh ocxma-trex "python3 $TREX_BENCH 64 $DURATION" 2>/dev/null)
    wait $pid 2>/dev/null || true

    rx_after=$(ip -s link show $DUT_IFACE | awk '/RX:/{getline; print $2}')
    captured=$(grep -oE '[0-9]+ packets captured' /tmp/r39.err | grep -oE '^[0-9]+' | head -1)
    captured=${captured:-0}
    file_b=$(sudo du -bc $OUTDIR/r39.pcapng* $OUTDIR/r39.raw* 2>/dev/null | tail -1 | awk '{print $1}')
    file_b=${file_b:-0}
    sudo rm -f $OUTDIR/r39.pcapng* $OUTDIR/r39.raw* 2>/dev/null

    pps_mbps=$(awk "BEGIN{printf \"%.2f\", $captured/$DURATION/1e6}")
    nic_rx=$(awk "BEGIN{printf \"%.2f\", ($rx_after-$rx_before)/$DURATION/1e6}")
    trex_tx=$(echo "$trex_json" | python3 -c 'import sys,json;print(json.load(sys.stdin)["avg_tx_mpps"])' 2>/dev/null || echo 0)
    file_mb=$(awk "BEGIN{printf \"%.1f\", $file_b/1024/1024}")

    echo "$label,$captured,$pps_mbps,$nic_rx,$trex_tx,$file_mb" | tee -a "$CSV"
}

# Cell A: out-of-the-box default (-w pcap-ng, slow ringbuf reader)
echo "=== Cell A: default (-w pcapng only) ==="
run_cell "default_pcapng" -w $OUTDIR/r39.pcapng

# Cell B: + --fast-reader + --no-wakeup (R30 pcap-ng + fastrb)
echo ""
echo "=== Cell B: pcap-ng + --fast-reader + --no-wakeup ==="
run_cell "pcapng_fastrb" -w $OUTDIR/r39.pcapng --fast-reader --no-wakeup

# Cell C: full optimised raw-dump recipe (R26 baseline)
echo ""
echo "=== Cell C: full recipe (raw + fastrb + inmem + snaplen 1500) ==="
run_cell "optimised_raw" -w $OUTDIR/r39.raw --raw-dump --fast-reader --no-wakeup --in-memory-buffer 256 --ringbuf-size 1024 --snaplen 1500

sudo ip link set dev $DUT_IFACE xdp off 2>/dev/null
sudo rm -rf /sys/fs/bpf/r39_target 2>/dev/null

echo ""
echo "DONE — CSV: $CSV"
cat "$CSV"
