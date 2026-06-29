#!/usr/bin/env bash
# R12 Round 2: tx_reflect + match-rate sweep via fixed 50:50 TCP/443+80 mix.
# 4 cells (filter variants → 0%/50%/100% match) × N reps.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

REPS="${1:-3}"
DURATION=60
DUT_IFACE="enp138s0f0np0"
NINJA_BIN="$REPO_ROOT/xdp-ninja"
XDP_OBJ="$REPO_ROOT/scripts/test/prod_tx_reflect.o"
TREX_BENCH="/opt/trex/v3.08/scripts/trex_bench_mix.py"
CSV="$REPO_ROOT/benchmark/results/r12_visibility_round2.csv"

echo "cell,observer,filter,match_pct,rep,duration_s,trex_tx_mpps,trex_rx_mpps,trex_opackets,trex_ipackets,ninja_captured" > "$CSV"

run_cell() {
    local cell="$1" observer="$2" filter="$3" match_pct="$4" rep="$5"
    sudo ip link set dev "$DUT_IFACE" xdp off 2>/dev/null || true
    sudo ip link set dev "$DUT_IFACE" xdp obj "$XDP_OBJ" sec xdp

    local ninja_pid=""
    if [[ "$observer" == "ninja-entry" ]]; then
        local args=(--mode entry -i "$DUT_IFACE" -w /dev/null)
        # kunai DSL syntax (paper's killer feature — NOT pcap/cBPF)
        [[ -n "$filter" ]] && args+=("$filter")
        sudo GODEBUG=asyncpreemptoff=1 timeout "$((DURATION + 7))" "$NINJA_BIN" "${args[@]}" \
            > /tmp/r12_ninja.out 2>/tmp/r12_ninja.err &
        ninja_pid=$!
        sleep 3
    fi

    local trex_json
    trex_json=$(ssh ocxma-trex "python3 $TREX_BENCH $DURATION" 2>/dev/null)

    if [[ -n "$ninja_pid" ]]; then
        wait "$ninja_pid" 2>/dev/null || true
    fi
    sudo ip link set dev "$DUT_IFACE" xdp off

    local tx rx op ip captured
    tx=$(echo "$trex_json" | python3 -c 'import sys,json;print(json.load(sys.stdin)["avg_tx_mpps"])' 2>/dev/null || echo 0)
    rx=$(echo "$trex_json" | python3 -c 'import sys,json;print(json.load(sys.stdin)["avg_rx_mpps"])' 2>/dev/null || echo 0)
    op=$(echo "$trex_json" | python3 -c 'import sys,json;print(json.load(sys.stdin)["opackets"])'    2>/dev/null || echo 0)
    ip=$(echo "$trex_json" | python3 -c 'import sys,json;print(json.load(sys.stdin)["ipackets"])'    2>/dev/null || echo 0)
    captured=0
    if [[ "$observer" == "ninja-entry" ]]; then
        captured=$(grep -oE '[0-9]+ packets captured' /tmp/r12_ninja.err 2>/dev/null | grep -oE '^[0-9]+' | head -1 || echo 0)
    fi

    echo "$cell,$observer,${filter:-NONE},$match_pct,$rep,$DURATION,$tx,$rx,$op,$ip,$captured" | tee -a "$CSV"
}

for rep in $(seq 1 "$REPS"); do
    echo "=== rep $rep ==="
    run_cell "A" "baseline"    ""                            ""     "$rep"
    run_cell "B" "ninja-entry" "eth/ipv4/udp"                "0"    "$rep"
    run_cell "C" "ninja-entry" "eth/ipv4/tcp[dport==443]"    "50"   "$rep"
    run_cell "D" "ninja-entry" ""                            "100"  "$rep"
done

echo ""
echo "DONE. CSV: $CSV"
echo ""
echo "=== summary (median RX Mpps per cell) ==="
awk -F, 'NR>1 {key=$1"|"$4; arr[key]=arr[key]","$8; cnt[key]++}
END {for (k in arr) {split(arr[k],a,","); sum=0; n=cnt[k]; for (i=2;i<=n+1;i++) sum+=a[i]; printf "  cell %s (match=%s%%): rx %.2f Mpps (n=%d)\n", substr(k,1,1), substr(k,3), sum/n, n}}' "$CSV" | sort
