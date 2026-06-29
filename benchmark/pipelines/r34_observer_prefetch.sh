#!/bin/bash
# R34: verify --observer-prefetch flag preserves the R12 finding.
# Same prod_tx_reflect setup as R12 round 2, but compares with/without
# the new flag. Expected:
#   - WITHOUT --observer-prefetch (R32 default): observer attach has
#     no production-speed effect (baseline ≈ observer ≈ 15.5 Mpps)
#   - WITH --observer-prefetch: observer attach restores R12's
#     +70% production speedup (15.5 → ~26 Mpps).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

REPS="${1:-2}"
DURATION=60
DUT_IFACE="enp138s0f0np0"
NINJA_BIN="$REPO_ROOT/xdp-ninja"
XDP_OBJ="$REPO_ROOT/scripts/test/prod_tx_reflect.o"
TREX_BENCH="/opt/trex/v3.08/scripts/trex_bench_mix.py"
CSV="$REPO_ROOT/benchmark/results/r34_observer_prefetch.csv"

echo "cell,observer,prefetch,filter,rep,duration_s,trex_tx_mpps,trex_rx_mpps,ninja_captured" > "$CSV"

run_cell() {
    local cell="$1" observer="$2" prefetch="$3" filter="$4" rep="$5"
    sudo ip link set dev "$DUT_IFACE" xdp off 2>/dev/null || true
    sudo ip link set dev "$DUT_IFACE" xdp obj "$XDP_OBJ" sec xdp

    local ninja_pid=""
    if [[ "$observer" == "ninja-entry" ]]; then
        local args=(--mode entry -i "$DUT_IFACE" -w /dev/null)
        [[ "$prefetch" == "yes" ]] && args+=(--observer-prefetch)
        [[ -n "$filter" ]] && args+=("$filter")
        sudo GODEBUG=asyncpreemptoff=1 timeout "$((DURATION + 7))" "$NINJA_BIN" "${args[@]}" \
            > /tmp/r34_ninja.out 2>/tmp/r34_ninja.err &
        ninja_pid=$!
        sleep 3
    fi

    local trex_json
    trex_json=$(ssh ocxma-trex "python3 $TREX_BENCH $DURATION" 2>/dev/null)

    if [[ -n "$ninja_pid" ]]; then
        wait "$ninja_pid" 2>/dev/null || true
    fi
    sudo ip link set dev "$DUT_IFACE" xdp off

    local tx rx captured
    tx=$(echo "$trex_json" | python3 -c 'import sys,json;print(json.load(sys.stdin)["avg_tx_mpps"])' 2>/dev/null || echo 0)
    rx=$(echo "$trex_json" | python3 -c 'import sys,json;print(json.load(sys.stdin)["avg_rx_mpps"])' 2>/dev/null || echo 0)
    captured=0
    if [[ "$observer" == "ninja-entry" ]]; then
        captured=$(grep -oE '[0-9]+ packets captured' /tmp/r34_ninja.err 2>/dev/null | grep -oE '^[0-9]+' | head -1 || echo 0)
    fi

    echo "$cell,$observer,$prefetch,${filter:-NONE},$rep,$DURATION,$tx,$rx,$captured" | tee -a "$CSV"
}

for rep in $(seq 1 "$REPS"); do
    echo "=== rep $rep ==="
    run_cell "A" "baseline"    "n/a" "" "$rep"
    run_cell "B" "ninja-entry" "no"  "eth/ipv4/udp" "$rep"
    run_cell "C" "ninja-entry" "yes" "eth/ipv4/udp" "$rep"
done

echo ""
echo "DONE. CSV: $CSV"
echo ""
echo "=== median trex_rx_mpps per cell ==="
awk -F, 'NR>1 {key=$1"|"$3; vals[key]=vals[key]","$8; cnt[key]++}
END {for (k in vals) {
  split(k,p,"|"); split(vals[k],a,",");
  sum=0; for (i=2;i<=cnt[k]+1;i++) sum+=a[i]
  printf "  cell %s (prefetch=%s): rx %.2f Mpps (n=%d)\n", p[1], p[2], sum/cnt[k], cnt[k]
}}' "$CSV" | sort
