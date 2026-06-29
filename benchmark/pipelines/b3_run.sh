#!/usr/bin/env bash
#
# B3 macrobench: drive Gen-side T-Rex + DUT-side capture tool, measure tool throughput.
# Result line (CSV): filter,tool,size,match_pct,rep,duration_s,trex_opackets,trex_tx_pps,tool_captured,tool_pps
#
# Usage: ./b3_run.sh <tool> <match_pct> <rep> <duration_s>
#   tool      : tcpdump | xdp-ninja-cbpf | xdp-ninja-dsl
#   match_pct : 1 | 50 | 100
#   rep       : 1 | 2 | 3
#   duration_s: 30 (default)
#
# Outputs one CSV line on stdout. tmp pcap goes to /tmp/b3_dut.pcap (overwritten).

set -e
tool="${1:?tool required}"
match_pct="${2:?match_pct required}"
rep="${3:?rep required}"
duration_s="${4:-30}"

dut_iface="enp138s0f0np0"
dut_pcap="/dev/shm/b3/dut.pcap"
sudo mkdir -p /dev/shm/b3
sudo rm -f "$dut_pcap"

# Start tool on DUT side, send to background
case "$tool" in
  tcpdump)
    sudo timeout "$((duration_s + 5))" tcpdump -nni "$dut_iface" \
      -w "$dut_pcap" -B 65536 'tcp dst port 443' \
      > /tmp/b3_tool.out 2>/tmp/b3_tool.err &
    ;;
  xdp-ninja-cbpf)
    sudo timeout "$((duration_s + 5))" \
      ./xdp-ninja --mode xdp -i "$dut_iface" --cbpf -w "$dut_pcap" 'tcp dst port 443' \
      > /tmp/b3_tool.out 2>/tmp/b3_tool.err &
    ;;
  xdp-ninja-dsl)
    sudo timeout "$((duration_s + 5))" \
      ./xdp-ninja --mode xdp -i "$dut_iface" -w "$dut_pcap" 'eth/ipv4/tcp where tcp.dport == 443' \
      > /tmp/b3_tool.out 2>/tmp/b3_tool.err &
    ;;
  *)
    echo "unknown tool: $tool" >&2; exit 2 ;;
esac
TOOL_PID=$!

# warmup so the tool is attached before traffic starts
sleep 2

# Start T-Rex traffic on Gen side, blocking until done
trex_json=$(ssh ocxma-trex "python3 /tmp/trex_b3_run.py $match_pct $duration_s" 2>/dev/null)

# Wait for tool to terminate (timeout will SIGTERM it)
wait "$TOOL_PID" 2>/dev/null || true

# Extract counts from tool's own self-reported count
# (tcpdump: "X packets captured" on stderr; xdp-ninja: "N packets captured" on stdout)
tool_captured=$(grep -hoE '[0-9]+ packets? captured' /tmp/b3_tool.err /tmp/b3_tool.out 2>/dev/null \
                | head -1 | awk '{print $1}')
tool_captured="${tool_captured:-0}"
trex_op=$(echo "$trex_json" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("opackets",0))')
trex_pps=$(echo "$trex_json" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(int(d.get("tx_pps",0)))')

tool_pps=$(awk "BEGIN { printf \"%d\", $tool_captured / $duration_s }")

echo "F1,$tool,64,$match_pct,$rep,$duration_s,$trex_op,$trex_pps,$tool_captured,$tool_pps"
