#!/bin/bash
# R38: observer CPU / RSS overhead. Same as R26 conditions
# (prod_drop_all + xdp-ninja --mode entry + raw + fastrb + inmem),
# pidstat samples the xdp-ninja process every second for the bench
# duration. RSS captured via /proc/<pid>/status VmRSS at start/end.
set -uo pipefail
cd /home/ocxma/private/xdp-ninja
DUT_IFACE=enp138s0f0np0
NINJA_BIN=$PWD/xdp-ninja
TREX_BENCH=/opt/trex/v3.08/scripts/trex_bench.py
DURATION=30
OUTDIR=/var/tmp/r38
sudo mkdir -p "$OUTDIR" && sudo chmod 777 "$OUTDIR"
CSV=$PWD/benchmark/results/r38_observer_overhead.csv
PIDSTAT_LOG=$PWD/benchmark/results/r38_pidstat.log

echo "phase,cpu_pct,rss_kb,user_cpu_pct,system_cpu_pct" > "$CSV"

sudo ip link set dev $DUT_IFACE xdp off 2>/dev/null || true
sudo rm -rf /sys/fs/bpf/r38_target 2>/dev/null
sudo bpftool prog loadall ./scripts/test/prod_drop_all.o /sys/fs/bpf/r38_target
sudo ip link set dev $DUT_IFACE xdp pinned /sys/fs/bpf/r38_target/prod_drop_all
sudo rm -f $OUTDIR/r38.raw* 2>/dev/null

echo "=== Spawning xdp-ninja ==="
sudo GODEBUG=asyncpreemptoff=1 timeout 60 "$NINJA_BIN" --mode entry -i $DUT_IFACE \
    --raw-dump --fast-reader --no-wakeup --in-memory-buffer 256 --ringbuf-size 1024 \
    --snaplen 1500 \
    -w $OUTDIR/r38.raw > /tmp/r38.out 2>/tmp/r38.err &
NINJA_SHELL=$!
sleep 1
NINJA_PID=$(pgrep -f "$NINJA_BIN --mode entry" | head -1)
echo "  ninja pid: $NINJA_PID"

# baseline (no traffic, just xdp-ninja attached + reading idle ringbufs)
sleep 2
echo "=== baseline measurement (no traffic) ==="
pidstat_baseline=$(sudo pidstat -p "$NINJA_PID" -u -r 1 5 2>/dev/null | tail -1)
echo "  $pidstat_baseline"
baseline_cpu=$(echo "$pidstat_baseline" | awk '{print $8}')
baseline_user=$(echo "$pidstat_baseline" | awk '{print $4}')
baseline_sys=$(echo "$pidstat_baseline" | awk '{print $6}')
baseline_rss=$(sudo awk '/VmRSS:/{print $2}' /proc/$NINJA_PID/status 2>/dev/null || echo 0)
echo "idle,$baseline_cpu,$baseline_rss,$baseline_user,$baseline_sys" | tee -a "$CSV"

# start TRex bench in background
echo ""
echo "=== bench measurement (TRex hw -c 20 64B, ${DURATION}s) ==="
ssh ocxma-trex "python3 $TREX_BENCH 64 $DURATION" > /tmp/r38_trex.json 2>/dev/null &
TREX_PID=$!
sleep 3

# pidstat for the duration
sudo pidstat -p "$NINJA_PID" -u -r 1 25 > "$PIDSTAT_LOG" 2>/dev/null
load_cpu=$(awk '/^Average/{print $8}' "$PIDSTAT_LOG" | head -1)
load_user=$(awk '/^Average/{print $4}' "$PIDSTAT_LOG" | head -1)
load_sys=$(awk '/^Average/{print $6}' "$PIDSTAT_LOG" | head -1)
load_rss=$(sudo awk '/VmRSS:/{print $2}' /proc/$NINJA_PID/status 2>/dev/null || echo 0)
echo "loaded,$load_cpu,$load_rss,$load_user,$load_sys" | tee -a "$CSV"

wait $TREX_PID 2>/dev/null || true
wait $NINJA_SHELL 2>/dev/null || true

captured=$(grep -oE '[0-9]+ packets captured' /tmp/r38.err | grep -oE '^[0-9]+' | head -1)
echo ""
echo "captured pkts: $captured"
echo "Mpps:          $(awk "BEGIN{printf \"%.2f\", ${captured:-0}/$DURATION/1e6}")"

# cleanup
sudo ip link set dev $DUT_IFACE xdp off 2>/dev/null
sudo rm -rf /sys/fs/bpf/r38_target 2>/dev/null
sudo rm -f $OUTDIR/r38.raw*

echo ""
echo "DONE — CSV: $CSV  pidstat: $PIDSTAT_LOG"
cat "$CSV"
echo ""
echo "=== pidstat tail (last samples) ==="
tail -10 "$PIDSTAT_LOG"
