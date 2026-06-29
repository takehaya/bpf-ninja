#!/usr/bin/env bash
# R11 mini matrix: 64B-only via kernel pktgen (23.7 Mpps offered).
# Mirrors r10_matrix.csv schema for direct comparison.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

REPS="${1:-3}"
DURATION=60
DUT_IFACE="enp138s0f0np0"
NINJA_BIN="$REPO_ROOT/xdp-ninja"
CAP_FILE="/dev/shm/r11_cap.raw"
GLOB="/dev/shm/r11_cap.raw.W*.cpu*.raw"
CSV="$REPO_ROOT/benchmark/results/r11_pktgen_64B.csv"

echo "mode,packet,rep,duration_s,captured,pps,rx_dropped_delta,offered_mpps_estimate" > "$CSV"

run_cell() {
    local mode="$1" rep="$2"
    local ninja_args=(--mode xdp -i "$DUT_IFACE" --raw-dump --fast-reader --no-wakeup -w "$CAP_FILE")
    local timeout_s=$((DURATION + 7))
    if [[ "$mode" == "inmem" ]]; then
        ninja_args+=(--in-memory-buffer 256)
        timeout_s=$((DURATION + 60))
    fi

    sudo rm -f $GLOB "$CAP_FILE"
    sudo ip link set dev "$DUT_IFACE" xdp off 2>/dev/null || true

    local rx_before rx_drop_before
    rx_before=$(ip -s link show "$DUT_IFACE" | awk '/RX:/{getline; print $2}')
    rx_drop_before=$(ip -s link show "$DUT_IFACE" | awk '/RX:/{getline; print $4}')

    sudo GODEBUG=asyncpreemptoff=1 timeout "$timeout_s" "$NINJA_BIN" "${ninja_args[@]}" \
        > /tmp/r11_ninja.out 2>/tmp/r11_ninja.err &
    local pid=$!
    sleep 3

    ssh ocxma-trex "sudo /opt/trex/v3.08/scripts/pktgen_run.sh 64 $DURATION" >/dev/null 2>&1

    wait "$pid" 2>/dev/null || true

    local rx_after rx_drop_after
    rx_after=$(ip -s link show "$DUT_IFACE" | awk '/RX:/{getline; print $2}')
    rx_drop_after=$(ip -s link show "$DUT_IFACE" | awk '/RX:/{getline; print $4}')
    sudo ip link set dev "$DUT_IFACE" xdp off

    # Read ninja's own "captured X packets" report from stderr
    local captured
    captured=$(grep -oE '[0-9]+ packets captured' /tmp/r11_ninja.err | grep -oE '^[0-9]+' || echo 0)
    sudo rm -f $GLOB "$CAP_FILE"

    local rx_drop_delta=$((rx_drop_after - rx_drop_before))
    local rx_delta=$((rx_after - rx_before))
    local offered_estimate
    offered_estimate=$(awk "BEGIN{printf \"%.2f\", ($rx_delta + $rx_drop_delta)/$DURATION/1e6}")
    local pps
    pps=$(awk "BEGIN{printf \"%.0f\", $captured/$DURATION}")

    echo "$mode,64B,$rep,$DURATION,$captured,$pps,$rx_drop_delta,$offered_estimate" | tee -a "$CSV"
}

for mode in baseline inmem; do
    for rep in $(seq 1 "$REPS"); do
        echo "=== mode=$mode rep=$rep ==="
        run_cell "$mode" "$rep"
    done
done

echo ""
echo "DONE. CSV: $CSV"
echo ""
echo "=== summary (median Mpps over reps) ==="
awk -F, 'NR>1 {key=$1; arr[key]=arr[key]","$6; cnt[key]++} END{for(k in arr){split(arr[k],a,","); n=cnt[k]; sum=0; for(i=2;i<=n+1;i++)sum+=a[i]; printf "  %s 64B: %.2f Mpps (n=%d)\n", k, sum/n/1e6, n}}' "$CSV"
