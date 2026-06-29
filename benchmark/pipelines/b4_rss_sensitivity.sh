#!/bin/bash
# Controlled-RSS sensitivity check (codex reviewer concern on fig:datapath).
#
# Measure F6 (ICMP) and F1 (TCP) under an EQUALIZED queue distribution
# (ethtool -X equal NQ) so both streams saturate the same set of cores.
# If F6 then shows a small but non-zero cost comparable to / below F1, the
# F6 ~= 0 in the main figure was an RSS-spread artifact (ICMP's 2-tuple
# hash spread 32 flows evenly over 32 queues, never saturating), not a
# free filter.
#
# Uses ethtool -X (RSS redirection table) ONLY; NEVER ethtool -L (an ice
# channel-count change can D-state-deadlock the whole box). RSS is restored
# to default on exit via trap.
#
# Usage: REPS=5 DURATION=20 NQ=16 bash benchmark/pipelines/b4_rss_sensitivity.sh
set -uo pipefail
cd /home/ocxma/private/xdp-ninja

IFACE=enp138s0f0np0
XDPDROP=${XDPDROP:-/tmp/xdpdrop}
TREX_SCRIPT=/opt/trex/v3.08/scripts/trex_b4_streams.py
DURATION=${DURATION:-20}
REPS=${REPS:-5}
NQ=${NQ:-16}
OUT="$PWD/benchmark/results"

restore_rss() { echo ">>> restoring RSS to default"; sudo ethtool -X "$IFACE" default >/dev/null 2>&1 || true; }
trap restore_rss EXIT

go build -o "$XDPDROP" ./benchmark/xdpdrop/
filter_kunai() { cat "$PWD/benchmark/filters/kunai/$1.kunai"; }
filter_pcap()  { grep -v '^#' "$PWD/benchmark/filters/pcap/$1.txt" | tr -d '\n'; }

echo ">>> RSS -> $NQ queues (ethtool -X equal $NQ)"
sudo ethtool -X "$IFACE" equal "$NQ"
ip -br link show "$IFACE" | grep -q UP || { echo "FATAL: $IFACE down"; exit 1; }

run_cell() {  # csv cell stream args...
  local csv="$1" cell="$2" stream="$3"; shift 3
  local out=/tmp/r_${cell}.json err=/tmp/r_${cell}.err nb na
  nb=$(sudo ethtool -S "$IFACE" | awk '/rx_unicast.nic:/{print $NF}')
  sudo timeout $((DURATION + 25)) "$XDPDROP" -i "$IFACE" "$@" -duration $((DURATION + 10))s >"$out" 2>"$err" &
  local pid=$!; sleep 3
  grep -q attached "$err" || { echo "$cell attach fail"; cat "$err"; kill $pid 2>/dev/null; return 1; }
  ssh ocxma-trex "python3 $TREX_SCRIPT $stream $DURATION" >/dev/null 2>&1
  wait $pid 2>/dev/null
  na=$(sudo ethtool -S "$IFACE" | awk '/rx_unicast.nic:/{print $NF}')
  python3 - "$cell" "$stream" "$DURATION" "$out" "$nb" "$na" "$csv" <<'PY'
import sys, json
cell, stream, dur, path, nb, na, csv = sys.argv[1:8]; dur = float(dur)
d = json.load(open(path))
row = (f'{cell},{d["path"]},{stream},{dur:.0f},{d["total"]},{d["matched"]},'
       f'{d["total"]/dur/1e6:.2f},{(int(na)-int(nb))/dur/1e6:.2f}')
print("   " + row); open(csv, "a").write(row + "\n")
PY
}

for k in $(seq 1 "$REPS"); do
  CSV="$OUT/b4_rsseq_rep${k}.csv"
  echo "cell,path,stream,dur,xdp_total,xdp_matched,xdp_mpps,nic_rx_mpps" > "$CSV"
  echo "=== rsseq rep $k/$REPS (NQ=$NQ) ==="
  run_cell "$CSV" accept_icmp   icmp
  run_cell "$CSV" cbpfc_F6      icmp   -pcap "$(filter_pcap F6)"
  run_cell "$CSV" kunai_F6      icmp   -dsl "$(filter_kunai F6)"
  run_cell "$CSV" accept_tcp443 tcp443
  run_cell "$CSV" cbpfc_F1      tcp443 -pcap "$(filter_pcap F1)"
  run_cell "$CSV" kunai_F1      tcp443 -dsl "$(filter_kunai F1)"
  sleep 2
done
echo ">>> done (trap restores RSS to default)"
