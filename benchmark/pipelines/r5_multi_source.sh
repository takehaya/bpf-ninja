#!/usr/bin/env bash
#
# r5_multi_source.sh — 4-way multi-source 22 Mpps benchmark.
# Compares tcpdump (AF_PACKET single socket) vs tcpdump+PACKET_FANOUT
# (afp_fanout helper) vs xdpdump (perf_event_array) vs xdpcap
# (PROG_ARRAY + perf_event_array) vs xdp-ninja (per-CPU sharded
# bpf_ringbuf) end-to-end pcap throughput.
#
# Used for paper §6.4 multi-source paragraph. Each cell is a
# duration-s window with the Generator driving randomised TCP src
# port at ~22 Mpps via `trex_b3_multi_v2.py`.
#
# Required tools on DUT:
#   - xdp-ninja built at /home/ocxma/private/xdp-ninja/xdp-ninja
#   - tcpdump (any version, 4.99+)
#   - xdpdump (xdp-tools 1.4+)
#   - xdpcap (cloudflare/xdpcap @ /tmp/xdpcap/xdpcap)
#   - afp_fanout helper (built from scripts/test/afp_fanout/)
#   - prod_xdpcap_loader (scripts/test/prod_xdpcap_loader/)
#   - capinfos (wireshark-common)
#
# Required setup on Generator (ssh ocxma-trex):
#   - /tmp/trex_b3_multi_v2.py uploaded (see scripts/trex/)
#   - T-Rex daemon running in software mode
#
# Usage:
#   bash benchmark/pipelines/r5_multi_source.sh <tool> <rep> [duration_s]
#     tool      : tcpdump | tcpdump-fanout | xdpdump | xdpcap | xdp-ninja
#     rep       : 1..N
#     duration_s: default 30
#
# CSV (one line on stdout):
#   tool,rep,duration_s,trex_tx_pps,trex_opackets,observer_captured,pps

set -euo pipefail
tool="${1:?tool required}"
rep="${2:?rep required}"
duration_s="${3:-30}"

iface=enp138s0f0np0
xdpn=/home/ocxma/private/xdp-ninja/xdp-ninja
xdpcap=/tmp/xdpcap/xdpcap
afp=/tmp/afp_fanout/afp_fanout
loader_xdpcap=/home/ocxma/private/xdp-ninja/scripts/test/prod_xdpcap_loader/prod_xdpcap_loader
pin_path=/sys/fs/bpf/xdpcap_hook
work=/dev/shm/r5
sudo mkdir -p "$work"; sudo chmod 1777 "$work"

cleanup() {
    sudo ip link set dev "$iface" xdp off 2>/dev/null || true
    sudo rm -f "$pin_path" 2>/dev/null || true
}
trap cleanup EXIT
cleanup
sudo rm -f "$work"/*.pcap "$work"/*.pcap.cpu* "$work"/fan*.pcap

case "$tool" in
    tcpdump)
        sudo timeout $((duration_s + 5)) tcpdump -nni "$iface" -B 65536 \
            -w "$work/out.pcap" 'tcp dst port 443' \
            >/dev/null 2>/tmp/r5_${tool}.err &
        TOOL=$!
        ;;
    tcpdump-fanout)
        # Fair tcpdump baseline using AF_PACKET PACKET_FANOUT (hash mode).
        # tcpdump CLI does not expose PACKET_FANOUT; afp_fanout is a
        # small Go program that opens N=4 sockets joined to one fanout
        # group and writes per-worker pcaps.
        sudo "$afp" -i "$iface" -n 4 -d "$duration_s" -w "$work/fan" \
            >/tmp/r5_${tool}.out 2>/tmp/r5_${tool}.err &
        TOOL=$!
        ;;
    xdpdump)
        # --perf-wakeup 1024: batch the kernel→userspace wakeups to
        # avoid the default per-packet wake (which throttles xdpdump
        # to ~99 kpps under multi-source).
        sudo timeout $((duration_s + 5)) xdpdump -i "$iface" \
            --rx-capture entry --perf-wakeup 1024 -w "$work/out.pcap" \
            >/dev/null 2>/tmp/r5_${tool}.err &
        TOOL=$!
        ;;
    xdpcap)
        # xdpcap needs the production XDP to embed an xdpcap_hook map
        # pinned at bpffs (see prod_pass_xdpcap.c). The loader does
        # that setup then holds the attach; we capture from the
        # pinned hook map.
        sudo "$loader_xdpcap" -i "$iface" \
            >/tmp/r5_${tool}_loader.out 2>/tmp/r5_${tool}_loader.err &
        LOADER=$!
        for _ in $(seq 30); do
            sudo test -e "$pin_path" && break || sleep 0.2
        done
        sleep 0.5
        sudo timeout $((duration_s + 5)) "$xdpcap" \
            -buffer 16777216 "$pin_path" "$work/out.pcap" \
            'tcp dst port 443' \
            >/dev/null 2>/tmp/r5_${tool}.err &
        TOOL=$!
        ;;
    xdp-ninja)
        # xdp-ninja auto-re-execs with GODEBUG=asyncpreemptoff=1 if
        # not already set. XDP_NINJA_FAST_PCAPNG=1 picks the
        # hand-rolled EPB writer over gopacket/pcapgo for ~3% gain.
        sudo XDP_NINJA_FAST_PCAPNG=1 timeout $((duration_s + 5)) \
            "$xdpn" --mode xdp -i "$iface" -w "$work/out.pcap" \
            'eth/ipv4/tcp where tcp.dport == 443' \
            >/dev/null 2>/tmp/r5_${tool}.err &
        TOOL=$!
        ;;
    *)
        echo "unknown tool: $tool" >&2
        exit 2
        ;;
esac
sleep 2

trex_json=$(ssh ocxma-trex "python3 /tmp/trex_b3_multi_v2.py 100 $duration_s" 2>/dev/null)
wait "$TOOL" 2>/dev/null || true
[[ -n "${LOADER:-}" ]] && {
    sudo kill -INT "$LOADER" 2>/dev/null || true
    wait "$LOADER" 2>/dev/null || true
}
cleanup

case "$tool" in
    xdp-ninja)
        # Per-CPU files: out.pcap.cpu0, out.pcap.cpu1, ...
        captured=0
        shopt -s nullglob
        for f in "$work"/out.pcap.cpu*; do
            [[ -s "$f" ]] || continue
            c=$(capinfos -M -c "$f" 2>/dev/null | awk -F': +' '/Number of packets/{print $2}')
            captured=$((captured + ${c:-0}))
        done
        ;;
    tcpdump-fanout)
        # afp_fanout prints captured count to stdout
        captured=$(grep -oP 'captured=\K\d+' /tmp/r5_${tool}.out 2>/dev/null | tail -1)
        captured=${captured:-0}
        ;;
    *)
        captured=$(capinfos -M -c "$work/out.pcap" 2>/dev/null | awk -F': +' '/Number of packets/{print $2}')
        captured=${captured:-0}
        ;;
esac
trex_pps=$(echo "$trex_json" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(int(d.get("tx_pps",0)))' 2>/dev/null || echo 0)
trex_op=$(echo "$trex_json" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("opackets",0))' 2>/dev/null || echo 0)
pps=$(awk -v c="$captured" -v d="$duration_s" 'BEGIN{printf "%d", c/d}')
echo "$tool,$rep,$duration_s,$trex_pps,$trex_op,$captured,$pps"
