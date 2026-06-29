#!/usr/bin/env python3
"""Plot Figure 7: per-tool capture throughput at 1% / 100% match rates.

RETIRED. The end-to-end throughput (B3) benchmark was dropped from the
paper; this script, its data, and fig7 all live under attic/ now. Kept
for reproducibility only. Run from the repo root.

Reads the bpf_ringbuf backend run
benchmark/results/attic/b3_throughput_ringbuf_v1.csv and writes
docs/paper/ebpf_workshop_2026/paper/figures/attic/fig7_throughput.pdf.
The earlier perf-event-array backend lives in
benchmark/results/attic/b3_throughput_perf.csv.
"""
import csv, os, sys
from collections import defaultdict
from statistics import median

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# bpf_ringbuf backend run (retired; both data and output now under attic/).
CSV = "benchmark/results/attic/b3_throughput_ringbuf_v1.csv"
OUT = "docs/paper/ebpf_workshop_2026/paper/figures/attic/fig7_throughput.pdf"

groups = defaultdict(list)  # (tool, match_pct) -> [tool_pps,...]
with open(CSV) as f:
    for row in csv.DictReader(f):
        groups[(row["tool"], int(row["match_pct"]))].append(int(row["tool_pps"]))

tools = ["tcpdump", "xdp-ninja-dsl"]
matches = [1, 100]
labels = {"tcpdump": "tcpdump (AF_PACKET)",
          "xdp-ninja-dsl": "xdp-ninja + kunai (XDP)"}

fig, ax = plt.subplots(figsize=(5.0, 2.8))
x = list(range(len(matches)))
w = 0.35
for i, tool in enumerate(tools):
    medians = [median(groups[(tool, m)]) / 1e6 for m in matches]
    mins    = [min(groups[(tool, m)]) / 1e6 for m in matches]
    maxs    = [max(groups[(tool, m)]) / 1e6 for m in matches]
    err = [[med - mn for med, mn in zip(medians, mins)],
           [mx - med for mx, med in zip(maxs, medians)]]
    ax.bar([xi + (i - 0.5) * w for xi in x], medians,
           width=w, label=labels[tool], yerr=err, capsize=4)

ax.set_xticks(x)
ax.set_xticklabels([f"{m}% match" for m in matches])
ax.set_ylabel("Captured throughput (Mpps)")
ax.set_xlabel("Match rate (production / worst-case)")
ax.legend(frameon=False, loc="upper right", fontsize=8)
ax.grid(True, axis="y", alpha=0.3)

os.makedirs(os.path.dirname(OUT), exist_ok=True)
plt.tight_layout()
plt.savefig(OUT)
print(f"wrote {OUT}")
