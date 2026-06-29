#!/usr/bin/env python3
# Bar chart of B4 datapath filter cost across reps (§5 figure).
#
# For each filter cell, cost% per rep = (accept_<stream> - cell) /
# accept_<stream> * 100 (throughput reduction vs the window-copy-only
# accept_all of its own stream). One bar per filter showing the mean
# over the reps, with an SD error bar and a value label; where both
# languages express the filter (F1-F4, F6) the kunai and pcap-filter
# (cbpfc) bars are paired and colored.
#
# Run from the repo root. Usage:
#   python3 benchmark/analysis/b4_boxplot.py \
#       benchmark/results/b4_xdp_drop_rep*.csv \
#       -o docs/paper/ebpf_workshop_2026/paper/figures/fig_datapath.pdf
import csv, argparse, statistics
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

# filter cell -> its own-stream accept_all baseline (mirror b4_stats.py)
ACCEPT = {
    "cbpfc_F1": "accept_tcp443",  "kunai_F1": "accept_tcp443",
    "cbpfc_F2": "accept_tcp80",   "kunai_F2": "accept_tcp80",
    "cbpfc_F3": "accept_ipv6tcp", "kunai_F3": "accept_ipv6tcp",
    "cbpfc_F4": "accept_vlan",    "kunai_F4": "accept_vlan",
    "cbpfc_F5": "accept_icmp",    "kunai_F5": "accept_icmp",
    "kunai_F6": "accept_qinq",
    "kunai_F7": "accept_gtpu",
    "kunai_F8": "accept_srv6",
    "kunai_F9": "accept_geneve",
    "kunai_F10": "accept_tcpmss",
}
# pcap-filter (cbpfc) counterpart for the filters both languages express
PCAP = {f"kunai_F{n}": f"cbpfc_F{n}" for n in (1, 2, 3, 4, 5)}
KUNAI_C, PCAP_C = "#4878a8", "#e8923a"


def load(path):
    with open(path) as f:
        return {r["cell"]: float(r["xdp_mpps"]) for r in csv.DictReader(f)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("reps", nargs="+")
    ap.add_argument("-o", "--out",
                    default="docs/paper/ebpf_workshop_2026/paper/figures/fig_datapath.pdf")
    args = ap.parse_args()

    reps = [load(p) for p in args.reps]
    n = len(reps)

    def ms(cell):
        ref = ACCEPT[cell]
        v = [(r[ref] - r[cell]) / r[ref] * 100.0
             for r in reps if cell in r and ref in r and r[ref]]
        return (statistics.mean(v), statistics.pstdev(v)) if v else (0.0, 0.0)

    def lab(m):
        return "0.0" if abs(m) < 0.05 else f"{m:.1f}"

    fig, ax = plt.subplots(figsize=(7.0, 3.0))
    w = 0.38
    for i in range(1, 11):
        kc = f"kunai_F{i}"
        pc = PCAP.get(kc)
        km, ks = ms(kc)
        if pc:
            pm, ps = ms(pc)
            ax.bar(i - 0.2, km, w, yerr=ks, color=KUNAI_C, capsize=2, error_kw={"lw": 0.8})
            ax.bar(i + 0.2, pm, w, yerr=ps, color=PCAP_C, capsize=2, error_kw={"lw": 0.8})
            ax.text(i - 0.2, km + ks + 0.12, lab(km), ha="center", va="bottom", fontsize=6)
            ax.text(i + 0.2, pm + ps + 0.12, lab(pm), ha="center", va="bottom", fontsize=6)
        else:
            ax.bar(i, km, w * 1.4, yerr=ks, color=KUNAI_C, capsize=2, error_kw={"lw": 0.8})
            ax.text(i, km + ks + 0.12, lab(km), ha="center", va="bottom", fontsize=6)

    ax.set_xticks(range(1, 11))
    ax.set_xticklabels([f"F{i}" for i in range(1, 11)])
    ax.set_xlim(0.4, 10.6)
    ax.set_ylim(top=8.4)
    ax.set_ylabel("throughput reduction\nvs accept-all (%)")
    ax.set_xlabel(f"filter (n={n} reps, error bars = SD)")
    ax.axhline(0, lw=0.6, color="black")
    ax.grid(axis="y", ls=":", alpha=0.5)
    ax.legend(handles=[Patch(facecolor=KUNAI_C, label="kunai"),
                       Patch(facecolor=PCAP_C, label="pcap-filter")],
              loc="upper left", fontsize=8, frameon=False)
    fig.tight_layout()
    fig.savefig(args.out)
    print(f"wrote {args.out}  ({n} reps)")


if __name__ == "__main__":
    main()
