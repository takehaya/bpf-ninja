#!/bin/bash
# R42b: same as R42 but WITHOUT --no-wakeup, to show the
# latency-vs-throughput trade-off cleanly after the F1 fix.
# Expectation: with wakeup ON, eventfd round-trip fires per submit,
# the fastrb reader epoll-wakes immediately, and p50 latency drops
# from the 1ms polling-floor (R42 default) to ~100µs.
set -uo pipefail
cd /home/ocxma/private/xdp-ninja
DUT_IFACE=enp138s0f0np0
NINJA_BIN=$PWD/xdp-ninja
TREX_BENCH=/opt/trex/v3.08/scripts/trex_bench.py
DURATION=30
OUTDIR=/var/tmp/r42b
sudo mkdir -p "$OUTDIR" && sudo chmod 777 "$OUTDIR"
SAMPLE_PATH=$PWD/benchmark/results/r42b_latency_samples.tsv
SUMMARY=$PWD/benchmark/results/r42b_latency_summary.txt

sudo ip link set dev $DUT_IFACE xdp off 2>/dev/null || true
sudo rm -rf /sys/fs/bpf/r42b 2>/dev/null
sudo bpftool prog loadall ./scripts/test/prod_drop_all.o /sys/fs/bpf/r42b
sudo ip link set dev $DUT_IFACE xdp pinned /sys/fs/bpf/r42b/prod_drop_all
sudo rm -f $OUTDIR/r42b.raw* 2>/dev/null

# NB: --no-wakeup deliberately OMITTED (wakeup ON intentionally).
# --fast-reader is fine without --no-wakeup; the slow ringbuf.Reader
# path was the one that required --fast-reader to be present.
sudo GODEBUG=asyncpreemptoff=1 timeout 60 "$NINJA_BIN" --mode entry -i $DUT_IFACE \
    --raw-dump --fast-reader --in-memory-buffer 256 --ringbuf-size 1024 \
    --snaplen 1500 --latency-sample-period 1000 --latency-sample-output $SAMPLE_PATH \
    -w $OUTDIR/r42b.raw > /tmp/r42b.out 2>$SUMMARY &
NPID=$!
sleep 3
ssh ocxma-trex "python3 $TREX_BENCH 64 $DURATION" 2>/dev/null >/dev/null
wait $NPID 2>/dev/null

sudo ip link set dev $DUT_IFACE xdp off 2>/dev/null
sudo rm -rf /sys/fs/bpf/r42b $OUTDIR 2>/dev/null

echo "=== R42b summary ==="
grep -E "captured|latency-sample" "$SUMMARY"
echo ""
python3 - <<EOF
samples = sorted(int(l.strip()) for l in open("$SAMPLE_PATH") if l.strip())
n = len(samples)
def pct(p): return samples[int((n-1) * p)]
print(f"n = {n}")
print(f"p10   = {pct(0.10)/1e3:>8.2f} µs")
print(f"p50   = {pct(0.50)/1e3:>8.2f} µs")
print(f"p90   = {pct(0.90)/1e3:>8.2f} µs")
print(f"p99   = {pct(0.99)/1e6:>8.2f} ms")
print(f"p99.9 = {pct(0.999)/1e6:>8.2f} ms")
print(f"max   = {samples[-1]/1e6:>8.2f} ms")
EOF
