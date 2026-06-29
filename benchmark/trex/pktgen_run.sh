#!/bin/bash
# kernel pktgen: 64B packets, N threads, each thread owns its own TX queue
# Usage: pktgen_run.sh <THREADS> <DURATION>
set -e
THREADS="${1:-8}"
DURATION="${2:-5}"
DEV=enp138s0f0
DST_MAC="40:a6:b7:95:a2:d0"
DST_IP="10.99.0.1"
PKT_SIZE=60

# Stop any prior run
echo "stop" > /proc/net/pktgen/pgctrl 2>/dev/null || true
sleep 0.3

# Configure threads: each on its own CPU + own TX queue
for i in $(seq 0 $((THREADS-1))); do
    echo "rem_device_all" > /proc/net/pktgen/kpktgend_$i
    echo "add_device ${DEV}@$i" > /proc/net/pktgen/kpktgend_$i
done

for i in $(seq 0 $((THREADS-1))); do
    DEVQ="/proc/net/pktgen/${DEV}@${i}"
    echo "flag QUEUE_MAP_CPU"      > $DEVQ
    echo "count 0"                  > $DEVQ
    echo "pkt_size $PKT_SIZE"       > $DEVQ
    echo "delay 0"                  > $DEVQ
    echo "clone_skb 1000000"        > $DEVQ
    echo "burst 32"                 > $DEVQ
    echo "queue_map_min $i"         > $DEVQ
    echo "queue_map_max $i"         > $DEVQ
    echo "dst_mac $DST_MAC"         > $DEVQ
    echo "dst $DST_IP"              > $DEVQ
    echo "flag UDPSRC_RND"          > $DEVQ
    echo "flag UDPDST_RND"          > $DEVQ
    echo "udp_src_min 1024"         > $DEVQ
    echo "udp_src_max 60000"        > $DEVQ
    echo "udp_dst_min 1024"         > $DEVQ
    echo "udp_dst_max 60000"        > $DEVQ
done

# Start (blocks until stop)
( echo "start" > /proc/net/pktgen/pgctrl ) &
PG_PID=$!
sleep "$DURATION"
echo "stop" > /proc/net/pktgen/pgctrl
wait $PG_PID 2>/dev/null || true
sleep 0.3

# Tally per-thread pps using "Result:" line
TOTAL_PPS=0
TOTAL_PKTS=0
for i in $(seq 0 $((THREADS-1))); do
    PPS=$(grep -oP '\d+(?=pps)' /proc/net/pktgen/${DEV}@${i} 2>/dev/null | head -1 || echo 0)
    PKTS=$(grep -oP 'pkts-sofar:\s*\K\d+' /proc/net/pktgen/${DEV}@${i} 2>/dev/null | head -1 || echo 0)
    TOTAL_PPS=$((TOTAL_PPS + PPS))
    TOTAL_PKTS=$((TOTAL_PKTS + PKTS))
done

echo "threads=$THREADS duration=${DURATION}s"
echo "pktgen TX: $TOTAL_PKTS packets, sum-of-thread-pps = $TOTAL_PPS ($(awk "BEGIN{printf \"%.2f\", $TOTAL_PPS/1e6}") Mpps)"
