#!/usr/bin/env bash
# R11: xdp-ninja capture rate matrix at TRex v3.08 hardware-mode 23 Mpps offered.
# Mirrors R10 (r10_matrix.csv) schema so a side-by-side comparison drops in.
#
# Usage:
#   ./r11_hw_matrix.sh [reps] [duration_s]
#
# Out:  benchmark/results/r11_hw_matrix.csv
# CSV:  mode,packet,rep,duration_s,captured,pps,rx_dropped_delta,trex_tx_pps,trex_oerrors

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)/.."
REPO_ROOT="$(cd "$REPO_ROOT" && pwd)"
REPS="${1:-3}"
DURATION="${2:-60}"

CSV="$REPO_ROOT/benchmark/results/r11_hw_matrix.csv"
DUT_IFACE="enp138s0f0np0"
XDP_OBJ="$REPO_ROOT/scripts/test/prod_pass.o"
NINJA_BIN="$REPO_ROOT/xdp-ninja"
TREX_BENCH="/opt/trex/v3.08/scripts/trex_bench.py"
CAP_FILE="/dev/shm/r11_cap.raw"

echo "mode,packet,rep,duration_s,captured,pps,rx_dropped_delta,trex_tx_pps,trex_oerrors" > "$CSV"

ensure_trex_running() {
    if ! ssh ocxma-trex 'pgrep -q _t-rex-64'; then
        echo "starting TRex v3.08 hardware-mode..."
        ssh ocxma-trex 'cd /opt/trex/v3.08/scripts && sudo nohup ./t-rex-64 -i \
            --cfg ./trex_e810_hw.yaml --no-key --stl >/tmp/trex_hw.log 2>&1 &'
        sleep 12
        if ! ssh ocxma-trex 'pgrep -q _t-rex-64'; then
            echo "ERROR: trex failed to start" >&2; exit 1
        fi
    fi
}

attach_xdp() {
    # R10 matrix used --mode xdp where xdp-ninja itself IS the XDP program
    # (no separate production XDP). Make sure the iface starts clean.
    sudo ip link set dev "$DUT_IFACE" xdp off 2>/dev/null || true
}

detach_xdp() {
    sudo ip link set dev "$DUT_IFACE" xdp off 2>/dev/null || true
}

run_cell() {
    local mode="$1" pkt="$2" rep="$3"
    local pkt_label
    case "$pkt" in
        64B) pkt_label=64 ;;
        IMIX) pkt_label=imix ;;
        1500B) pkt_label=1500 ;;
        *) echo "unknown packet $pkt" >&2; return 1 ;;
    esac

    local ninja_args=(--mode xdp -i "$DUT_IFACE" --raw-dump --fast-reader --no-wakeup -w "$CAP_FILE")
    # 256 MiB × 64 shards = 16 GB total. 512 MiB OOM'd on a 62 GiB box
    # (32 GB total competes with the rest of the system + page cache).
    [[ "$mode" == "inmem" ]] && ninja_args+=(--in-memory-buffer 256)

    sudo rm -f "$CAP_FILE"
    attach_xdp

    local rx_before
    rx_before=$(ip -s link show "$DUT_IFACE" | awk '/RX:/{getline; print $2}')
    local rx_drop_before
    rx_drop_before=$(ip -s link show "$DUT_IFACE" | awk '/RX:/{getline; print $4}')

    # spawn xdp-ninja for (DURATION + 7s) so it overlaps both warmup and trex run
    # inmem mode flushes ~16 GB on Close, give it extra grace
    local timeout_s=$((DURATION + 7))
    [[ "$mode" == "inmem" ]] && timeout_s=$((DURATION + 60))
    sudo GODEBUG=asyncpreemptoff=1 timeout "$timeout_s" "$NINJA_BIN" "${ninja_args[@]}" \
        > /tmp/r11_ninja.out 2>/tmp/r11_ninja.err &
    local pid=$!

    sleep 3  # warmup so xdp-ninja is fully attached before traffic starts

    local trex_json
    trex_json=$(ssh ocxma-trex "python3 $TREX_BENCH $pkt_label $DURATION" 2>/dev/null)

    wait "$pid" 2>/dev/null || true

    local rx_after rx_drop_after
    rx_after=$(ip -s link show "$DUT_IFACE" | awk '/RX:/{getline; print $2}')
    rx_drop_after=$(ip -s link show "$DUT_IFACE" | awk '/RX:/{getline; print $4}')

    detach_xdp

    # captured: parse the raw-dump header; faster than full pcap walk.
    # record header is 8 bytes magic + 8 bytes endian + 16 bytes reserved (?)
    # but simplest: convert and tcpdump count.
    local captured=0
    if compgen -G "${CAP_FILE}.W*.cpu*.raw" >/dev/null; then
        sudo "$NINJA_BIN" convert -r "${CAP_FILE}.W*.cpu*.raw" -o /tmp/r11_cap.pcap 2>/dev/null || true
        captured=$(tcpdump -nnr /tmp/r11_cap.pcap 2>/dev/null | wc -l || echo 0)
        sudo rm -f "${CAP_FILE}".W*.cpu*.raw
    fi

    local rx_drop_delta=$((rx_drop_after - rx_drop_before))
    local pps=$(awk "BEGIN{printf \"%.0f\", $captured/$DURATION}")

    local trex_tx_pps trex_oerr
    trex_tx_pps=$(python3 -c "import sys,json; print(json.loads('''$trex_json''').get('tx_pps',0))" 2>/dev/null || echo 0)
    trex_oerr=$(python3 -c "import sys,json; print(json.loads('''$trex_json''').get('oerrors',0))" 2>/dev/null || echo 0)

    echo "$mode,$pkt,$rep,$DURATION,$captured,$pps,$rx_drop_delta,$trex_tx_pps,$trex_oerr" | tee -a "$CSV"
}

ensure_trex_running

for mode in baseline inmem; do
    for pkt in 64B IMIX 1500B; do
        for rep in $(seq 1 "$REPS"); do
            echo "=== mode=$mode pkt=$pkt rep=$rep ==="
            run_cell "$mode" "$pkt" "$rep" || echo "(cell failed)"
        done
    done
done

echo ""
echo "DONE. CSV: $CSV"
