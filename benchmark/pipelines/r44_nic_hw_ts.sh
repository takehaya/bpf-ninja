#!/bin/bash
# R44: NIC hardware timestamp (--rx-hwts) verification. xdp-ninja
# --mode xdp --rx-hwts uses bpf_xdp_metadata_rx_timestamp kfunc to
# pull the ice PHC timestamp instead of bpf_ktime_get_ns. Compares
# capture rate + latency CDF for HW vs SW timestamp paths.
set -uo pipefail
cd /home/ocxma/private/xdp-ninja
DUT_IFACE=enp138s0f0np0
NINJA_BIN=$PWD/xdp-ninja
TREX_BENCH=/opt/trex/v3.08/scripts/trex_bench.py
DURATION=30
OUTDIR=/var/tmp/r44
sudo mkdir -p "$OUTDIR" && sudo chmod 777 "$OUTDIR"
CSV=$PWD/benchmark/results/r44_nic_hw_ts.csv

# clean state
sudo ip link set dev $DUT_IFACE xdp off 2>/dev/null || true
sudo tc qdisc del dev $DUT_IFACE clsact 2>/dev/null || true

echo "label,rx_hwts,captured_pkts,pps_Mpps,nic_rx_delta_Mpps,trex_tx_mpps,latency_p50_us,latency_p99_ms,latency_max_ms,note" > "$CSV"

run_cell() {
    local label="$1" hwts="$2"
    sudo rm -f $OUTDIR/r44.raw* /tmp/r44_latency.tsv 2>/dev/null

    local args=(--mode xdp -i $DUT_IFACE --bench-drop
                --raw-dump --fast-reader --no-wakeup --in-memory-buffer 256 --ringbuf-size 1024
                --snaplen 1500
                --latency-sample-period 1000 --latency-sample-output /tmp/r44_latency.tsv
                -w $OUTDIR/r44.raw)
    [[ "$hwts" == "yes" ]] && args+=(--rx-hwts)

    rx_before=$(ip -s link show $DUT_IFACE | awk '/RX:/{getline; print $2}')

    sudo GODEBUG=asyncpreemptoff=1 timeout 60 "$NINJA_BIN" "${args[@]}" \
        > /tmp/r44.out 2>/tmp/r44.err &
    pid=$!
    sleep 3
    trex_json=$(ssh ocxma-trex "python3 $TREX_BENCH 64 $DURATION" 2>/dev/null)
    wait $pid 2>/dev/null || true

    rx_after=$(ip -s link show $DUT_IFACE | awk '/RX:/{getline; print $2}')
    captured=$(grep -oE '[0-9]+ packets captured' /tmp/r44.err | grep -oE '^[0-9]+' | head -1)
    captured=${captured:-0}
    sudo rm -f $OUTDIR/r44.raw* 2>/dev/null

    # parse latency
    local p50 p99 max
    if [[ -f /tmp/r44_latency.tsv ]]; then
        read -r p50 p99 max < <(python3 - <<EOF
samples = sorted(int(l.strip()) for l in open('/tmp/r44_latency.tsv') if l.strip())
n = len(samples)
print(samples[int((n-1)*0.50)]/1e3, samples[int((n-1)*0.99)]/1e6, samples[-1]/1e6)
EOF
)
    else
        p50=""; p99=""; max=""
    fi

    pps_mbps=$(awk "BEGIN{printf \"%.2f\", $captured/$DURATION/1e6}")
    nic_rx=$(awk "BEGIN{printf \"%.2f\", ($rx_after-$rx_before)/$DURATION/1e6}")
    trex_tx=$(echo "$trex_json" | python3 -c 'import sys,json;print(json.load(sys.stdin)["avg_tx_mpps"])' 2>/dev/null || echo 0)
    note=""
    if grep -q "kfunc unavailable\|falling back" /tmp/r44.err 2>/dev/null; then
        note="hwts_fallback_to_sw"
    fi

    echo "$label,$hwts,$captured,$pps_mbps,$nic_rx,$trex_tx,${p50:-},${p99:-},${max:-},$note" | tee -a "$CSV"
}

run_cell "sw_ts"  "no"
run_cell "hw_ts"  "yes"

sudo ip link set dev $DUT_IFACE xdp off 2>/dev/null

echo ""
echo "DONE — CSV: $CSV"
cat "$CSV"
