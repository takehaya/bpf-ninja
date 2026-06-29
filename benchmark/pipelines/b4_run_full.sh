#!/bin/bash
# Full B4 datapath re-measurement (post-#38 merge): disable RX VLAN
# offloads so F4/F5 see the tag in packet bytes, run REPS reps via
# b4_reps.sh, aggregate to b4_xdp_drop_stats.csv, and ALWAYS restore the
# offloads (trap) so an abort can't leave the NIC reconfigured.
#
# Preconditions: TRex running on ocxma-trex (-c 20), enp138s0f0np0 up at
# 100 GbE, passwordless sudo. ~15 min/rep, so REPS=10 is ~2.5 h.
#
# Usage: REPS=10 DURATION=30 bash benchmark/pipelines/b4_run_full.sh
set -uo pipefail
cd /home/ocxma/private/xdp-ninja

IFACE=enp138s0f0np0
REPS=${REPS:-10}
DURATION=${DURATION:-30}
OUTDIR="$PWD/benchmark/results"

restore_offloads() {
    echo ">>> restoring RX VLAN offloads on $IFACE"
    sudo ethtool -K "$IFACE" rxvlan on rx-vlan-filter on >/dev/null 2>&1 || true
    sudo ethtool -K "$IFACE" rx-vlan-stag-filter on   >/dev/null 2>&1 || true
}
trap restore_offloads EXIT

echo ">>> disabling RX VLAN offloads on $IFACE (F4/F5 need the tag in bytes)"
sudo ethtool -K "$IFACE" rxvlan off rx-vlan-filter off
sudo ethtool -K "$IFACE" rx-vlan-stag-filter off >/dev/null 2>&1 || true
sleep 2
if ! ip -br link show "$IFACE" | grep -q UP; then
    echo "FATAL: $IFACE went down after offload toggle -- aborting" >&2
    exit 1
fi
sudo ethtool -k "$IFACE" | grep -iE "rx-vlan-offload|rx-vlan-filter|rx-vlan-stag-filter"

echo ">>> running $REPS reps (DURATION=$DURATION)"
REPS="$REPS" DURATION="$DURATION" bash "$PWD/benchmark/pipelines/b4_reps.sh"

echo ">>> aggregating"
python3 "$PWD/benchmark/analysis/b4_stats.py" "$OUTDIR"/b4_xdp_drop_rep*.csv \
    | tee "$OUTDIR/b4_xdp_drop_stats.csv"

echo ">>> done"
