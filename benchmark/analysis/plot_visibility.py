#!/usr/bin/env python3
"""Non-invasive observability matrix figure + table.

Run from the repo root. Reads benchmark/results/visibility_matrix.csv,
computes median (visibility %, overhead %) per (behavior, observer)
cell, prints a human-readable Markdown table to stdout, and writes the
grouped bar chart of visibility% per cell to the figures dir under
docs/paper/ebpf_workshop_2026/.

NOTE: this figure and its table are currently archived under
sections/attic/ and are not included in the paper body.

CSV schema (from visibility_run.sh):
  behavior,observer,rep,duration_s,trex_tx_pps,trex_opackets,observer_captured

Derived:
  offered_load = trex_tx_pps * duration_s          (T-Rex opackets is
                                                    accumulator-broken,
                                                    so we recompute)
  visibility_pct = observer_captured / offered_load * 100
  baseline_pps   = median trex_tx_pps for (behavior, observer=baseline)
  overhead_pct   = (1 - tool_pps / baseline_pps) * 100
"""
import csv, os, sys
from collections import defaultdict
from statistics import median

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BASE = "docs/paper/ebpf_workshop_2026/paper"
CSV = "benchmark/results/visibility_matrix.csv"
OUT = BASE + "/figures/fig_visibility_matrix.pdf"
TEX = BASE + "/sections/attic/_visibility_matrix_table.tex"  # \input{}'d by §6.6 (attic)

BEHAVIORS = ["pass", "drop443", "tx_reflect", "rewrite_dst", "redirect_cpumap"]
OBSERVERS = ["baseline", "tcpdump", "xdpdump", "ninja-entry", "ninja-exit"]
BEHAVIOR_LABELS = {
    "pass":            "PASS",
    "drop443":         "DROP",
    "tx_reflect":      "TX",
    "rewrite_dst":     "REWRITE",
    "redirect_cpumap": "REDIRECT",
}
OBSERVER_LABELS = {
    "baseline":    "(baseline)",
    "tcpdump":     "tcpdump",
    "xdpdump":     "xdpdump",
    "ninja-entry": "xdp-ninja entry",
    "ninja-exit":  "xdp-ninja exit",
}

# Load all rows.
rows = []
with open(CSV) as f:
    for row in csv.DictReader(f):
        rows.append({
            "behavior": row["behavior"],
            "observer": row["observer"],
            "rep":      int(row["rep"]),
            "duration_s": int(row["duration_s"]),
            "trex_tx_pps": int(row["trex_tx_pps"]),
            "trex_opackets": int(row["trex_opackets"]),
            "captured":   int(row["observer_captured"]),
        })

# Group raw samples per (behavior, observer). offered_load uses
# trex_opackets directly (the actual packet count delivered in the
# duration); tx_pps is only the end-of-window rate snapshot, which
# can be anomalously low under trex hiccups (observed in tx_reflect
# baselines).
samples = defaultdict(list)  # (behavior, observer) -> [(offered, captured, tx_pps), ...]
for r in rows:
    samples[(r["behavior"], r["observer"])].append(
        (r["trex_opackets"], r["captured"], r["trex_tx_pps"]),
    )

# Per-behavior baseline offered rate (opackets / duration, median).
baseline_pps_offered = {}
for b in BEHAVIORS:
    runs = samples.get((b, "baseline"), [])
    if runs:
        baseline_pps_offered[b] = median(o for o, _, _ in runs) / 30.0
    else:
        baseline_pps_offered[b] = 0

# Compute visibility% (over 3 reps) and observer overhead% per cell.
def cell_stats(behavior, observer):
    runs = samples.get((behavior, observer), [])
    if not runs:
        return None
    if observer == "baseline":
        # offered_pps_med = opackets / duration, the actual
        # delivered rate (more robust than the tx_pps snapshot).
        opackets = [o for o, _, _ in runs]
        return {
            "visibility_pct": None,
            "overhead_pct":   0.0,
            "offered_pps_med": median(opackets) / 30.0,
        }
    vis = []
    for offered, captured, _ in runs:
        if offered > 0:
            vis.append(captured / offered * 100.0)
    opackets = [o for o, _, _ in runs]
    tool_offered_med = median(opackets) / 30.0
    base = baseline_pps_offered.get(behavior, 0)
    overhead = (1.0 - tool_offered_med / base) * 100.0 if base > 0 else 0.0
    return {
        "visibility_pct": median(vis) if vis else 0.0,
        "overhead_pct":   overhead,
        "offered_pps_med": tool_offered_med,
    }

# --- Markdown table to stdout. ---
def fmt_vis(v):
    return "  —  " if v is None else f"{v:5.1f}%"
def fmt_over(o):
    return f"{o:+5.1f}%"

print("# Non-invasive observability matrix")
print()
hdr = "| Behavior | " + " | ".join(OBSERVER_LABELS[o] for o in OBSERVERS) + " |"
sep = "|" + "|".join(["---"] * (len(OBSERVERS) + 1)) + "|"
print(hdr)
print(sep)
print()
print("## Visibility %")
print(hdr)
print(sep)
for b in BEHAVIORS:
    cells = []
    for o in OBSERVERS:
        s = cell_stats(b, o)
        cells.append(fmt_vis(s["visibility_pct"]) if s else "  ?  ")
    print(f"| **{BEHAVIOR_LABELS[b]}** | " + " | ".join(cells) + " |")
print()
print("## Observer-induced overhead % (vs (baseline) tx_pps)")
print(hdr)
print(sep)
for b in BEHAVIORS:
    cells = []
    for o in OBSERVERS:
        s = cell_stats(b, o)
        cells.append(fmt_over(s["overhead_pct"]) if s else "  ?  ")
    print(f"| **{BEHAVIOR_LABELS[b]}** | " + " | ".join(cells) + " |")
print()

# --- Bar chart: visibility% grouped by behavior, one bar per observer. ---
plot_observers = ["tcpdump", "xdpdump", "ninja-entry", "ninja-exit"]
fig, ax = plt.subplots(figsize=(7.0, 3.0))
x = list(range(len(BEHAVIORS)))
w = 0.18
for i, obs in enumerate(plot_observers):
    medians, mins, maxs = [], [], []
    for b in BEHAVIORS:
        runs = samples.get((b, obs), [])
        vis = [(c / o) * 100.0 for o, c, _ in runs if o > 0]
        if vis:
            medians.append(median(vis))
            mins.append(min(vis))
            maxs.append(max(vis))
        else:
            medians.append(0)
            mins.append(0)
            maxs.append(0)
    err = [[m - mn for m, mn in zip(medians, mins)],
           [mx - m for mx, m in zip(maxs, medians)]]
    offset = (i - (len(plot_observers) - 1) / 2.0) * w
    ax.bar([xi + offset for xi in x], medians, width=w,
           label=OBSERVER_LABELS[obs], yerr=err, capsize=2)

ax.set_xticks(x)
ax.set_xticklabels([BEHAVIOR_LABELS[b] for b in BEHAVIORS])
ax.set_ylabel("Visibility (%)")
ax.set_xlabel("Production XDP behavior")
ax.set_ylim(0, 105)
ax.legend(frameon=False, loc="upper right", fontsize=8, ncol=2)
ax.grid(True, axis="y", alpha=0.3)
ax.set_axisbelow(True)

os.makedirs(os.path.dirname(OUT), exist_ok=True)
plt.tight_layout()
plt.savefig(OUT)
print(f"wrote {OUT}", file=sys.stderr)

# --- LaTeX-includable table for §6.6 (\input{}'d). ---
def latex_vis(v):
    if v is None:
        return "(baseline)"
    # Bold values < 1% to highlight structural blindness in tcpdump rows.
    if v < 1.0:
        return r"\textbf{" + f"{v:.1f}\\%" + "}"
    return f"{v:.1f}\\%"

def src_mod(observer):
    return {"tcpdump": "No", "xdpdump": "No", "ninja-entry": "No",
            "ninja-exit": "No"}.get(observer, "—")

tex_lines = []
tex_lines.append(r"\begin{tabular}{@{}l c c c c@{}}")
tex_lines.append(r"\toprule")
header = ["Production XDP"] + [OBSERVER_LABELS[o] for o in
                               ("tcpdump", "xdpdump", "ninja-entry", "ninja-exit")]
tex_lines.append(" & ".join(header) + r" \\")
tex_lines.append(r"\midrule")
for b in BEHAVIORS:
    cells = [BEHAVIOR_LABELS[b]]
    for o in ("tcpdump", "xdpdump", "ninja-entry", "ninja-exit"):
        s = cell_stats(b, o)
        cells.append(latex_vis(s["visibility_pct"]) if s else "—")
    tex_lines.append(" & ".join(cells) + r" \\")
tex_lines.append(r"\bottomrule")
tex_lines.append(r"\end{tabular}")

os.makedirs(os.path.dirname(TEX), exist_ok=True)
with open(TEX, "w") as f:
    f.write("\n".join(tex_lines) + "\n")
print(f"wrote {TEX}", file=sys.stderr)
