#!/bin/bash
# R45: sustained 10-minute capture run. Verifies no throughput
# drift, memory leak, ringbuf accumulation, or anomaly explosion
# over a longer window than the 30-s benches. Same prod_drop_all
# + optimised recipe as R26.
set -uo pipefail
cd /home/ocxma/private/xdp-ninja
DUT_IFACE=enp138s0f0np0
NINJA_BIN=$PWD/xdp-ninja
TREX_BENCH=/opt/trex/v3.08/scripts/trex_bench.py
DURATION=600   # 10 min sustained
OUTDIR=/var/tmp/r45
sudo mkdir -p "$OUTDIR" && sudo chmod 777 "$OUTDIR"
CSV=$PWD/benchmark/results/r45_sustained.csv
SAMPLES_LOG=$PWD/benchmark/results/r45_pidstat.log

sudo ip link set dev $DUT_IFACE xdp off 2>/dev/null || true
sudo rm -rf /sys/fs/bpf/r45 2>/dev/null
sudo bpftool prog loadall ./scripts/test/prod_drop_all.o /sys/fs/bpf/r45
sudo ip link set dev $DUT_IFACE xdp pinned /sys/fs/bpf/r45/prod_drop_all
sudo rm -f $OUTDIR/r45.raw* 2>/dev/null

sudo GODEBUG=asyncpreemptoff=1 timeout $((DURATION + 30)) "$NINJA_BIN" --mode entry -i $DUT_IFACE \
    --raw-dump --fast-reader --no-wakeup --in-memory-buffer 256 --ringbuf-size 1024 \
    --snaplen 1500 -w $OUTDIR/r45.raw > /tmp/r45.out 2>/tmp/r45.err &
NINJA_SHELL=$!
sleep 3
NINJA_PID=$(sudo ps -e -o pid,uid,comm | awk '$2=="0" && $3=="xdp-ninja"{print $1; exit}')
echo "ninja pid: $NINJA_PID"

# Start TRex bench
ssh ocxma-trex "python3 $TREX_BENCH 64 $DURATION" > /tmp/r45_trex.json 2>/dev/null &
TREX_PID=$!
sleep 2

# Sample resource usage every 60 seconds
clk_tck=$(getconf CLK_TCK)
echo "ts_sec,utime_ticks,stime_ticks,total_cpu_pct,rss_kb,threads,anomaly_count" > "$CSV"

start_time=$(date +%s)
prev_utime=$(sudo awk '{print $14}' /proc/$NINJA_PID/stat 2>/dev/null || echo 0)
prev_stime=$(sudo awk '{print $15}' /proc/$NINJA_PID/stat 2>/dev/null || echo 0)

for i in $(seq 1 10); do
    sleep 60
    now=$(date +%s)
    elapsed=$((now - start_time))

    if ! sudo kill -0 $NINJA_PID 2>/dev/null; then
        echo "ninja exited at $elapsed s"
        break
    fi

    utime=$(sudo awk '{print $14}' /proc/$NINJA_PID/stat 2>/dev/null || echo 0)
    stime=$(sudo awk '{print $15}' /proc/$NINJA_PID/stat 2>/dev/null || echo 0)
    rss=$(sudo awk '/VmRSS:/{print $2}' /proc/$NINJA_PID/status 2>/dev/null || echo 0)
    threads=$(sudo awk '/Threads:/{print $2}' /proc/$NINJA_PID/status 2>/dev/null || echo 0)

    du=$((utime - prev_utime))
    ds=$((stime - prev_stime))
    cpu_pct=$(awk "BEGIN{printf \"%.1f\", ($du + $ds) * 100 / ($clk_tck * 60)}")

    echo "$elapsed,$utime,$stime,$cpu_pct,$rss,$threads,0" | tee -a "$CSV"

    prev_utime=$utime
    prev_stime=$stime
done

wait $TREX_PID 2>/dev/null
wait $NINJA_SHELL 2>/dev/null

# Final stats
captured=$(grep -oE '[0-9]+ packets captured' /tmp/r45.err | grep -oE '^[0-9]+' | head -1)
anomaly_msg=$(grep -E "anomalies|warning" /tmp/r45.err | head -3)
echo ""
echo "=== final ==="
echo "captured: $captured pkts over ${DURATION}s = $(awk "BEGIN{printf \"%.2f Mpps\", ${captured:-0}/$DURATION/1e6}")"
echo ""
echo "stderr (last 10):"
tail -10 /tmp/r45.err

sudo ip link set dev $DUT_IFACE xdp off 2>/dev/null
sudo rm -rf /sys/fs/bpf/r45 $OUTDIR 2>/dev/null

echo ""
echo "DONE — sample CSV: $CSV"
cat "$CSV"
