#!/bin/bash
# Full controlled-RSS sweep: run the whole b4 cell set (all F1-F10 + the
# pcap-filter cells) under an EQUALIZED queue distribution (ethtool -X
# equal NQ) so every stream saturates the same NQ cores. Lets us see how
# each filter's per-filter cost% and the kunai-vs-pcap gap move when the
# RSS regime changes, vs the default-RSS main figure.
#
# Uses ethtool -X (RSS table) only; NEVER ethtool -L. RX VLAN offload is
# disabled (F4/F5 read the tag from bytes). Both are restored on exit.
#
# Usage: REPS=3 DURATION=15 NQ=16 bash benchmark/pipelines/b4_rss_sweep.sh
set -uo pipefail
cd /home/ocxma/private/xdp-ninja

IFACE=enp138s0f0np0
NQ=${NQ:-16}
REPS=${REPS:-3}
DURATION=${DURATION:-15}
OUT="$PWD/benchmark/results"

restore() {
    echo ">>> restoring RSS default + RX VLAN offloads"
    sudo ethtool -X "$IFACE" default >/dev/null 2>&1 || true
    sudo ethtool -K "$IFACE" rxvlan on rx-vlan-filter on >/dev/null 2>&1 || true
    sudo ethtool -K "$IFACE" rx-vlan-stag-filter on >/dev/null 2>&1 || true
}
trap restore EXIT

echo ">>> RX VLAN offload off (F4/F5) + RSS -> $NQ queues"
sudo ethtool -K "$IFACE" rxvlan off rx-vlan-filter off
sudo ethtool -K "$IFACE" rx-vlan-stag-filter off >/dev/null 2>&1 || true
sudo ethtool -X "$IFACE" equal "$NQ"
sleep 2
ip -br link show "$IFACE" | grep -q UP || { echo "FATAL: $IFACE down"; exit 1; }

for k in $(seq 1 "$REPS"); do
    echo "########## eq${NQ} rep $k/$REPS ##########"
    if ! CSV="$OUT/b4_eq${NQ}_rep${k}.csv" DURATION="$DURATION" \
         bash "$PWD/benchmark/pipelines/b4_xdp_drop.sh"; then
        echo "rep $k FAILED" >&2; exit 1
    fi
    sleep 3
done
echo ">>> done (trap restores RSS + offloads)"
