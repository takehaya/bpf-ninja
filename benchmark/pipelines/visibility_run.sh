#!/usr/bin/env bash
#
# Single-cell runner for the non-invasive observability matrix bench.
# Loads one production XDP variant, attaches one observer (or no
# observer for the baseline), drives 30s of T-Rex traffic, then
# emits one CSV line.
#
# Usage:
#   ./visibility_run.sh <behavior> <observer> <rep> [duration_s]
#     behavior  : pass | drop443 | tx_reflect | rewrite_dst | redirect_cpumap
#     observer  : baseline | tcpdump | xdpdump | ninja-entry | ninja-exit
#     rep       : 1..N
#     duration_s: 30 (default)
#
# CSV (one line on stdout):
#   behavior,observer,rep,duration_s,trex_tx_pps,trex_opackets,observer_captured

set -euo pipefail

behavior="${1:?behavior required}"
observer="${2:?observer required}"
rep="${3:?rep required}"
duration_s="${4:-30}"

dut_iface="enp138s0f0np0"
work_dir="/dev/shm/visibility"
sudo mkdir -p "$work_dir"
sudo chmod 1777 "$work_dir"
dut_pcap="$work_dir/dut.pcap"
sudo rm -f "$dut_pcap"

cleanup() {
    # Kill anything we left around
    [[ -n "${OBS_PID:-}" ]] && sudo kill -TERM "$OBS_PID" 2>/dev/null || true
    [[ -n "${PROD_PID:-}" ]] && sudo kill -TERM "$PROD_PID" 2>/dev/null || true
    sleep 1
    sudo ip link set dev "$dut_iface" xdp off 2>/dev/null || true
}
trap cleanup EXIT

# 1. Load production XDP. Most variants attach via plain `ip link`;
#    redirect_cpumap needs the Go loader (cpumap entries must be
#    populated before the XDP_REDIRECT helper resolves a CPU).
case "$behavior" in
    pass|drop443|tx_reflect|rewrite_dst)
        sudo ip link set dev "$dut_iface" xdp off 2>/dev/null || true
        sudo ip link set dev "$dut_iface" xdp obj "scripts/test/prod_${behavior}.o" sec xdp
        ;;
    redirect_cpumap)
        sudo ip link set dev "$dut_iface" xdp off 2>/dev/null || true
        sudo scripts/test/prod_redirect_loader/prod_redirect_loader -i "$dut_iface" \
            > /tmp/visibility_prod.out 2>&1 &
        PROD_PID=$!
        # loader needs ~0.5s to populate cpumap + attach
        sleep 1
        ;;
    *)
        echo "unknown behavior: $behavior" >&2
        exit 2
        ;;
esac

# 2. Spawn observer. observer=baseline runs the same traffic but
#    with no capture tool — used to measure the production XDP's
#    own throughput as the no-overhead reference for that behavior.
case "$observer" in
    baseline)
        ;;  # nothing to spawn
    tcpdump)
        sudo timeout "$((duration_s + 5))" tcpdump -nni "$dut_iface" \
            -w "$dut_pcap" -B 65536 \
            > /tmp/visibility_obs.out 2>/tmp/visibility_obs.err &
        OBS_PID=$!
        ;;
    xdpdump)
        sudo timeout "$((duration_s + 5))" xdpdump -i "$dut_iface" \
            --rx-capture entry -w "$dut_pcap" \
            > /tmp/visibility_obs.out 2>/tmp/visibility_obs.err &
        OBS_PID=$!
        ;;
    ninja-entry)
        sudo timeout "$((duration_s + 5))" \
            ./xdp-ninja --mode entry -i "$dut_iface" -w "$dut_pcap" \
            > /tmp/visibility_obs.out 2>/tmp/visibility_obs.err &
        OBS_PID=$!
        ;;
    ninja-exit)
        sudo timeout "$((duration_s + 5))" \
            ./xdp-ninja --mode exit -i "$dut_iface" -w "$dut_pcap" \
            > /tmp/visibility_obs.out 2>/tmp/visibility_obs.err &
        OBS_PID=$!
        ;;
    *)
        echo "unknown observer: $observer" >&2
        exit 2
        ;;
esac

# 3. Warmup so the observer is fully attached.
sleep 2

# 4. Drive T-Rex 100% TCP/443 stream for the configured duration.
# trex_visibility_run.py uses explicit sleep+stop (the 'duration='
# arg of c.start() does not bound traffic in software mode; observed
# duration=30 actually ran ~156s).
trex_json=$(ssh ocxma-trex "python3 /tmp/trex_visibility_run.py 100 $duration_s" 2>/dev/null)

# 5. Wait for observer to terminate.
if [[ -n "${OBS_PID:-}" ]]; then
    wait "$OBS_PID" 2>/dev/null || true
fi

# 6. Detach production XDP (and the cpumap loader if applicable).
if [[ -n "${PROD_PID:-}" ]]; then
    sudo kill -TERM "$PROD_PID" 2>/dev/null || true
    wait "$PROD_PID" 2>/dev/null || true
else
    sudo ip link set dev "$dut_iface" xdp off 2>/dev/null || true
fi

# 7. Count captured packets.
captured=0
if [[ "$observer" != "baseline" && -s "$dut_pcap" ]]; then
    captured=$(sudo tcpdump -nnr "$dut_pcap" 2>/dev/null | wc -l)
fi

trex_op=$(echo "$trex_json" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("opackets",0))' 2>/dev/null || echo 0)
trex_pps=$(echo "$trex_json" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(int(d.get("tx_pps",0)))' 2>/dev/null || echo 0)

echo "$behavior,$observer,$rep,$duration_s,$trex_pps,$trex_op,$captured"
