#!/bin/bash
# B4: filter-only XDP drop macrobench (§5.5 datapath cost).
#
# benchmark/xdpdrop attaches a native XDP program that copies the
# packet prefix into the per-CPU scratch window (same window model as
# the production fentry/tc observers), runs the filter, bumps per-CPU
# counters, and returns XDP_DROP. No capture path.
#
# Cells: a floor (no copy, no filter), one accept_all per stream type
# (copy only — window copy length differs with frame size, so each
# filter cell is compared against the accept_all of its own stream),
# and the filter cells. TRex (-c 20, /etc/trex_cfg.yaml) must be
# running on ocxma-trex; streams come from trex_b4_streams.py
# (deployed to /opt/trex/v3.08/scripts/).
#
# Filter cost per cell = accept_<stream>.xdp_mpps − cell.xdp_mpps
# evaluated at saturation (offered > XDP capacity).
set -uo pipefail
cd /home/ocxma/private/xdp-ninja

DUT_IFACE=enp138s0f0np0
XDPDROP=${XDPDROP:-/tmp/xdpdrop}
TREX_SCRIPT=/opt/trex/v3.08/scripts/trex_b4_streams.py
DURATION=${DURATION:-30}
CSV=${CSV:-$PWD/benchmark/results/b4_xdp_drop.csv}

go build -o "$XDPDROP" ./benchmark/xdpdrop/

filter_kunai() { cat "$PWD/benchmark/filters/kunai/$1.kunai"; }
filter_pcap()  { grep -v '^#' "$PWD/benchmark/filters/pcap/$1.txt" | tr -d '\n'; }

echo "cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex_tx_mpps,nic_rx_mpps" > "$CSV"

run_cell() {
    local cell="$1" stream="$2"; shift 2

    local out=/tmp/b4_${cell}.json err=/tmp/b4_${cell}.err
    rm -f "$out" "$err"

    local nic_before nic_after
    nic_before=$(sudo ethtool -S $DUT_IFACE | awk '/rx_unicast.nic:/{print $NF}')

    sudo timeout $((DURATION + 25)) "$XDPDROP" -i $DUT_IFACE "$@" \
        -duration $((DURATION + 10))s > "$out" 2> "$err" &
    local pid=$!
    sleep 3
    if ! grep -q attached "$err"; then
        echo "$cell: attach failed" >&2; cat "$err" >&2
        kill $pid 2>/dev/null; return 1
    fi

    local trex_json
    trex_json=$(ssh ocxma-trex "python3 $TREX_SCRIPT $stream $DURATION" 2>/dev/null)
    wait $pid 2>/dev/null

    nic_after=$(sudo ethtool -S $DUT_IFACE | awk '/rx_unicast.nic:/{print $NF}')

    python3 - "$cell" "$stream" "$DURATION" "$out" "$trex_json" "$nic_before" "$nic_after" "$CSV" <<'PY'
import sys, json
cell, stream, dur, path, trex_json, nb, na, csv = sys.argv[1:9]
d = json.load(open(path))
trex = json.loads(trex_json) if trex_json else {}
dur = float(dur)
# xdpdrop runs longer than the traffic window; its counters only move
# while traffic flows, so rate = total / traffic duration.
xdp_mpps = d["total"] / dur / 1e6
nic_mpps = (int(na) - int(nb)) / dur / 1e6
row = (f'{cell},{d["path"]},{stream},"{d["filter"]}",{dur:.0f},'
       f'{d["total"]},{d["matched"]},{xdp_mpps:.2f},'
       f'{trex.get("avg_tx_mpps", 0)},{nic_mpps:.2f}')
print(row)
open(csv, "a").write(row + "\n")
PY
}

echo "=== floor (no copy, no filter) ==="
run_cell floor udp64 -floor

echo "=== accept_all per stream (window copy only) ==="
run_cell accept_udp64   udp64
run_cell accept_tcp443  tcp443
run_cell accept_tcp80   tcp80
run_cell accept_ipv6tcp ipv6tcp
run_cell accept_vlan    vlan
run_cell accept_qinq    qinq
run_cell accept_icmp    icmp
run_cell accept_gtpu    gtpu
run_cell accept_srv6    srv6
run_cell accept_geneve  geneve
run_cell accept_tcpmss  tcpmss

echo "=== filter cells ==="
run_cell cbpfc_F1  tcp443  -pcap "$(filter_pcap F1)"
run_cell kunai_F1  tcp443  -dsl "$(filter_kunai F1)"
run_cell cbpfc_F2  tcp80   -pcap "$(filter_pcap F2)"
run_cell kunai_F2  tcp80   -dsl "$(filter_kunai F2)"
run_cell cbpfc_F3  ipv6tcp -pcap "$(filter_pcap F3)"
run_cell kunai_F3  ipv6tcp -dsl "$(filter_kunai F3)"
run_cell cbpfc_F4  vlan    -pcap "$(filter_pcap F4)"
run_cell kunai_F4  vlan    -dsl "$(filter_kunai F4)"
run_cell cbpfc_F5  icmp    -pcap "$(filter_pcap F5)"
run_cell kunai_F5  icmp    -dsl "$(filter_kunai F5)"
run_cell kunai_F6  qinq    -dsl "$(filter_kunai F6)"
run_cell kunai_F7  gtpu    -dsl "$(filter_kunai F7)"
run_cell kunai_F8  srv6    -dsl "$(filter_kunai F8)"
run_cell kunai_F9  geneve  -dsl "$(filter_kunai F9)"
run_cell kunai_F10 tcpmss  -dsl "$(filter_kunai F10)"

echo
echo "wrote $CSV"
column -s, -t "$CSV"
