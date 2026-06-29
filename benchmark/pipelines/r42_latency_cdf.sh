#!/bin/bash
# R42: BPF-submit → reader-read latency CDF. Samples every 1000th
# ringbuf record's monotonic-now − record.kernel_ts and prints the
# percentile distribution to a tsv. Same prod_drop_all + optimised
# recipe as R26.
set -uo pipefail
cd /home/ocxma/private/xdp-ninja
DUT_IFACE=enp138s0f0np0
NINJA_BIN=$PWD/xdp-ninja
TREX_BENCH=/opt/trex/v3.08/scripts/trex_bench.py
DURATION=30
OUTDIR=/var/tmp/r42
sudo mkdir -p "$OUTDIR" && sudo chmod 777 "$OUTDIR"
SAMPLE_PATH=$PWD/benchmark/results/r42_latency_samples.tsv
SUMMARY=$PWD/benchmark/results/r42_latency_summary.txt

# attach prod_drop_all
sudo ip link set dev $DUT_IFACE xdp off 2>/dev/null || true
sudo rm -rf /sys/fs/bpf/r42 2>/dev/null
sudo bpftool prog loadall ./scripts/test/prod_drop_all.o /sys/fs/bpf/r42
sudo ip link set dev $DUT_IFACE xdp pinned /sys/fs/bpf/r42/prod_drop_all
sudo rm -f $OUTDIR/r42.raw* 2>/dev/null

sudo GODEBUG=asyncpreemptoff=1 timeout 60 "$NINJA_BIN" --mode entry -i $DUT_IFACE \
    --raw-dump --fast-reader --no-wakeup --in-memory-buffer 256 --ringbuf-size 1024 \
    --snaplen 1500 --latency-sample-period 1000 --latency-sample-output /home/ocxma/private/xdp-ninja/benchmark/results/r42_latency_samples.tsv \
    -w $OUTDIR/r42.raw > /tmp/r42.out 2>$SUMMARY &
NPID=$!
sleep 3
ssh ocxma-trex "python3 $TREX_BENCH 64 $DURATION" 2>/dev/null >/dev/null
wait $NPID 2>/dev/null

sudo ip link set dev $DUT_IFACE xdp off 2>/dev/null
sudo rm -rf /sys/fs/bpf/r42 $OUTDIR 2>/dev/null

echo ""
echo "=== summary (stderr) ==="
grep -E "captured|latency-sample" "$SUMMARY"
echo ""
echo "=== sample count ==="
wc -l "/home/ocxma/private/xdp-ninja/benchmark/results/r42_latency_samples.tsv"
echo ""
echo "=== percentiles + histogram ==="
python3 - <<'EOF'
import sys
samples = []
with open("/home/ocxma/private/xdp-ninja/benchmark/results/r42_latency_samples.tsv") as f:
    for line in f:
        try:
            samples.append(int(line.strip()))
        except ValueError:
            pass
samples.sort()
n = len(samples)
print(f"n = {n}")
def pct(p):
    return samples[int((n-1) * p)]
print(f"p10  = {pct(0.10):>10d} ns ({pct(0.10)/1e3:.1f} µs)")
print(f"p50  = {pct(0.50):>10d} ns ({pct(0.50)/1e3:.1f} µs)")
print(f"p90  = {pct(0.90):>10d} ns ({pct(0.90)/1e3:.1f} µs)")
print(f"p99  = {pct(0.99):>10d} ns ({pct(0.99)/1e3:.1f} µs)")
print(f"p99.9 = {pct(0.999):>9d} ns ({pct(0.999)/1e3:.1f} µs)")
print(f"p99.99 = {pct(0.9999):>8d} ns ({pct(0.9999)/1e3:.1f} µs)")
print(f"max  = {samples[-1]:>10d} ns ({samples[-1]/1e6:.2f} ms)")
print("")
print("=== ascii histogram (log scale ns) ===")
bins = [1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10]
counts = [0]*(len(bins)+1)
for v in samples:
    placed = False
    for i,b in enumerate(bins):
        if v < b:
            counts[i] += 1
            placed = True
            break
    if not placed:
        counts[-1] += 1
labels = ["< 1µs","1-10µs","10-100µs","100µs-1ms","1-10ms","10-100ms","100ms-1s","1-10s",">10s"]
for lbl, c in zip(labels, counts):
    pct_c = 100.0 * c / n if n else 0
    bar = '#' * int(pct_c)
    print(f"  {lbl:<10s} {c:>10d} ({pct_c:5.1f}%) {bar}")
EOF
