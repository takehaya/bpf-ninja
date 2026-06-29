#!/usr/bin/env bash
# R12 Round 1: tx_reflect + 3 observer variants @ TRex -c 20 (~94 Mpps offered).
# Measures the observer's effect on the production app's XDP_TX reflection
# rate (= trex RX). Schema includes trex_tx_pps + trex_rx_pps.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

REPS="${1:-3}"
DURATION=60
DUT_IFACE="enp138s0f0np0"
NINJA_BIN="$REPO_ROOT/xdp-ninja"
XDP_OBJ="$REPO_ROOT/scripts/test/prod_tx_reflect.o"
TREX_BENCH="/opt/trex/v3.08/scripts/trex_bench.py"
CSV="$REPO_ROOT/benchmark/results/r12_visibility_round1.csv"

echo "cell,observer,filter,rep,duration_s,trex_tx_mpps,trex_rx_mpps,trex_opackets,trex_ipackets,ninja_captured" > "$CSV"

run_cell() {
    local cell="$1" observer="$2" filter="$3" rep="$4"
    sudo ip link set dev "$DUT_IFACE" xdp off 2>/dev/null || true
    sudo ip link set dev "$DUT_IFACE" xdp obj "$XDP_OBJ" sec xdp

    local ninja_pid=""
    if [[ "$observer" == "ninja-entry" ]]; then
        local args=(--mode entry -i "$DUT_IFACE" -w /dev/null)
        [[ -n "$filter" ]] && args+=("$filter")
        sudo GODEBUG=asyncpreemptoff=1 timeout "$((DURATION + 7))" "$NINJA_BIN" "${args[@]}" \
            > /tmp/r12_ninja.out 2>/tmp/r12_ninja.err &
        ninja_pid=$!
        sleep 3   # warmup
    fi

    local trex_json
    trex_json=$(ssh ocxma-trex "python3 $TREX_BENCH 64 $DURATION" 2>/dev/null)

    if [[ -n "$ninja_pid" ]]; then
        wait "$ninja_pid" 2>/dev/null || true
    fi

    sudo ip link set dev "$DUT_IFACE" xdp off

    local tx rx op ip captured
    tx=$(echo "$trex_json"  | python3 -c 'import sys,json;print(json.load(sys.stdin)["avg_tx_mpps"])' 2>/dev/null || echo 0)
    rx=$(echo "$trex_json"  | python3 -c 'import sys,json;print(json.load(sys.stdin)["avg_rx_mpps"])' 2>/dev/null || echo 0)
    op=$(echo "$trex_json"  | python3 -c 'import sys,json;print(json.load(sys.stdin)["opackets"])'    2>/dev/null || echo 0)
    ip=$(echo "$trex_json"  | python3 -c 'import sys,json;print(json.load(sys.stdin)["ipackets"])'    2>/dev/null || echo 0)
    captured=0
    if [[ "$observer" == "ninja-entry" ]]; then
        captured=$(grep -oE '[0-9]+ packets captured' /tmp/r12_ninja.err 2>/dev/null | grep -oE '^[0-9]+' | head -1 || echo 0)
    fi

    echo "$cell,$observer,${filter:-NONE},$rep,$DURATION,$tx,$rx,$op,$ip,$captured" | tee -a "$CSV"
}

for rep in $(seq 1 "$REPS"); do
    echo "=== rep $rep ==="
    run_cell "A" "baseline"    ""               "$rep"
    run_cell "B" "ninja-entry" ""               "$rep"
    run_cell "C" "ninja-entry" "tcp port 443"   "$rep"
done

echo ""
echo "DONE. CSV: $CSV"
echo ""
echo "=== summary (median RX Mpps per cell) ==="
awk -F, 'NR>1 {key=$1; arr[key]=arr[key]","$7; cnt[key]++}
END {for (k in arr) {split(arr[k],a,","); sum=0; n=cnt[k]; for (i=2;i<=n+1;i++) sum+=a[i]; printf "  cell %s: rx %.2f Mpps (n=%d)\n", k, sum/n, n}}' "$CSV" | sort
