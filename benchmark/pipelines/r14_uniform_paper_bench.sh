#!/usr/bin/env bash
# R14: uniform-load paper §6 main table re-bench.
#
# 既存 R5/R7/R10/R11 数字は generator が異なる (TRex sw 22 Mpps / pktgen
# 23 Mpps / TRex hw 117 Mpps) ため paper の main table が不揃い。
# 本 bench で **同 generator (TRex v3.08 hw -c 1) × 全 packet size × 2 variant**
# を統一条件で再測定、 paper §6 main result table の確定値を取る。
#
# Generator: TRex v3.08 hardware mode `-c 1` (single TX core)
#   - 64B:   ~23 Mpps offered (sustainable、 DUT ~9 Mpps kernel recv)
#   - IMIX:  ~22 Mpps offered (= 11.66 Gbps)
#   - 1500B: ~8.5 Mpps offered (= 100 GbE line rate)
#
# Variants:
#   V1 baseline: --raw-dump only (no fast-reader, no inmem)
#   V2 final:    --raw-dump --fast-reader --no-wakeup --in-memory-buffer 256
#
# Total: 2 variants × 3 packet sizes × 3 reps = 18 cells × 60s ≈ 22 min
#
# Usage: ./r14_uniform_paper_bench.sh [reps]
# Output: benchmark/results/r14_uniform_paper.csv

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

REPS="${1:-3}"
DURATION=60
DUT_IFACE="enp138s0f0np0"
NINJA_BIN="$REPO_ROOT/xdp-ninja"
TREX_BENCH="/opt/trex/v3.08/scripts/trex_bench.py"
CAP_FILE="/dev/shm/r14_cap.raw"
GLOB="/dev/shm/r14_cap.raw.W*.cpu*.raw"
CSV="$REPO_ROOT/benchmark/results/r14_uniform_paper.csv"

ensure_trex_running_c1() {
    # Ensure trex is at -c 1 (sustainable rate, paper main config)
    local cores
    cores=$(ssh ocxma-trex 'sed "s/\x1b\[[0-9;]*[a-zA-Z]//g" /tmp/trex_hw*.log /tmp/trex_c*.log 2>/dev/null | grep -oE "max cores for 2 ports[^0-9]*[0-9]+" | tail -1' 2>/dev/null || true)
    if ! ssh ocxma-trex 'pgrep -qx _t-rex-64' || [[ "$cores" != *": 1"* ]]; then
        echo "Starting TRex v3.08 hw mode -c 1..."
        ssh ocxma-trex 'sudo pkill -9 _t-rex-64 2>/dev/null; sleep 3
                        cd /opt/trex/v3.08/scripts && sudo nohup ./t-rex-64 -i -c 1 \
                            --cfg /opt/trex/v3.08/scripts/trex_e810_hw.yaml --no-key --stl \
                            >/tmp/trex_r14.log 2>&1 &'
        sleep 13
        if ! ssh ocxma-trex 'pgrep -qx _t-rex-64'; then
            echo "ERROR: TRex failed to start" >&2; exit 1
        fi
    fi
    echo "trex up (PID $(ssh ocxma-trex 'pgrep -x _t-rex-64'))"
}

echo "variant,packet,rep,duration_s,captured,pps,rx_dropped_delta,trex_tx_mpps,trex_oerrors" > "$CSV"

run_cell() {
    local variant="$1" pkt="$2" rep="$3"
    local pkt_label
    case "$pkt" in
        64B)   pkt_label=64 ;;
        IMIX)  pkt_label=imix ;;
        1500B) pkt_label=1500 ;;
        *) echo "unknown packet $pkt" >&2; return 1 ;;
    esac

    local ninja_args=(--mode xdp -i "$DUT_IFACE" --raw-dump -w "$CAP_FILE")
    local timeout_s=$((DURATION + 7))
    if [[ "$variant" == "final" ]]; then
        ninja_args+=(--fast-reader --no-wakeup --in-memory-buffer 256)
        timeout_s=$((DURATION + 60))   # inmem flush 待ち余裕
    fi

    sudo rm -f $GLOB "$CAP_FILE"
    sudo ip link set dev "$DUT_IFACE" xdp off 2>/dev/null || true

    local rx_before rx_drop_before
    rx_before=$(ip -s link show "$DUT_IFACE" | awk '/RX:/{getline; print $2}')
    rx_drop_before=$(ip -s link show "$DUT_IFACE" | awk '/RX:/{getline; print $4}')

    sudo GODEBUG=asyncpreemptoff=1 timeout "$timeout_s" "$NINJA_BIN" "${ninja_args[@]}" \
        > /tmp/r14_ninja.out 2>/tmp/r14_ninja.err &
    local pid=$!
    sleep 3

    local trex_json
    trex_json=$(ssh ocxma-trex "python3 $TREX_BENCH $pkt_label $DURATION" 2>/dev/null)

    wait "$pid" 2>/dev/null || true

    local rx_after rx_drop_after
    rx_after=$(ip -s link show "$DUT_IFACE" | awk '/RX:/{getline; print $2}')
    rx_drop_after=$(ip -s link show "$DUT_IFACE" | awk '/RX:/{getline; print $4}')
    sudo ip link set dev "$DUT_IFACE" xdp off

    local captured
    captured=$(grep -oE '[0-9]+ packets captured' /tmp/r14_ninja.err | grep -oE '^[0-9]+' | head -1 || echo 0)
    sudo rm -f $GLOB "$CAP_FILE"

    local rx_drop_delta=$((rx_drop_after - rx_drop_before))
    local pps
    pps=$(awk "BEGIN{printf \"%.0f\", $captured/$DURATION}")
    local trex_tx trex_oerr
    trex_tx=$(echo "$trex_json"  | python3 -c 'import sys,json;print(json.load(sys.stdin)["avg_tx_mpps"])' 2>/dev/null || echo 0)
    trex_oerr=$(echo "$trex_json" | python3 -c 'import sys,json;print(json.load(sys.stdin)["oerrors"])'    2>/dev/null || echo 0)

    echo "$variant,$pkt,$rep,$DURATION,$captured,$pps,$rx_drop_delta,$trex_tx,$trex_oerr" | tee -a "$CSV"
}

ensure_trex_running_c1

for rep in $(seq 1 "$REPS"); do
    for variant in baseline final; do
        for pkt in 64B IMIX 1500B; do
            echo "=== rep=$rep variant=$variant pkt=$pkt ==="
            run_cell "$variant" "$pkt" "$rep"
        done
    done
done

echo ""
echo "DONE. CSV: $CSV"
echo ""
echo "=== summary (median Mpps per variant×packet) ==="
awk -F, 'NR>1 {key=$1"|"$2; pps[key]+=$6; cnt[key]++}
END {for (k in pps) {split(k,parts,"|"); printf "  %-10s %s: %.2f Mpps (n=%d)\n", parts[1], parts[2], pps[k]/cnt[k]/1e6, cnt[k]}}' "$CSV" | sort
