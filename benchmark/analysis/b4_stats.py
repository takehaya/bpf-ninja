#!/usr/bin/env python3
# Aggregate B4 datapath reps into mean±sd (RR1 statistical reporting).
#
# Input : one or more b4_xdp_drop_rep{K}.csv (cell,path,stream,filter,
#         duration_s,xdp_total,xdp_matched,xdp_mpps,trex_tx_mpps,nic_rx_mpps)
# Output: per-cell mean±sd of xdp_mpps, plus derived metrics with mean±sd
#         across reps:
#           - filter cost % = (cell - accept_<stream>) / accept_<stream>
#           - kunai_F1 vs cbpfc_F1 gap (common-filter gap)
#           - window-copy fixed cost = (accept_udp64 - floor) / floor
#
# Usage: python3 benchmark/analysis/b4_stats.py results/b4_xdp_drop_rep*.csv
import sys, csv, statistics as st

# stream each filter cell is normalized against (its own accept_all)
ACCEPT = {
    "cbpfc_F1": "accept_tcp443",
    "kunai_F1": "accept_tcp443",
    "kunai_F2": "accept_tcp80",
    "kunai_F3": "accept_ipv6tcp",
    "kunai_F4": "accept_vlan",
    "kunai_F5": "accept_icmp",
    "kunai_F6": "accept_qinq",
    "kunai_F7": "accept_gtpu",
    "kunai_F8": "accept_srv6",
    "kunai_F9": "accept_geneve",
    "kunai_F10": "accept_tcpmss",
}


def load(path):
    rows = {}
    with open(path) as f:
        for r in csv.DictReader(f):
            rows[r["cell"]] = float(r["xdp_mpps"])
    return rows


def msd(xs):
    m = st.mean(xs)
    s = st.stdev(xs) if len(xs) > 1 else 0.0
    return m, s


def pct(cell, ref, reps):
    out = []
    for r in reps:
        if cell in r and ref in r and r[ref]:
            out.append((r[cell] / r[ref] - 1.0) * 100.0)
    return out


def main(argv):
    paths = argv[1:]
    if not paths:
        sys.exit("usage: b4_stats.py rep1.csv [rep2.csv ...]")
    reps = [load(p) for p in paths]
    n = len(reps)
    cells = sorted(set().union(*[set(r) for r in reps]))

    print(f"# n={n} reps from: {', '.join(paths)}")
    print("metric,n,mean,sd")
    for c in cells:
        xs = [r[c] for r in reps if c in r]
        m, s = msd(xs)
        print(f"mpps:{c},{len(xs)},{m:.2f},{s:.3f}")

    for cell, ref in ACCEPT.items():
        ps = pct(cell, ref, reps)
        if ps:
            m, s = msd(ps)
            print(f"cost%:{cell}_vs_{ref},{len(ps)},{m:.2f},{s:.3f}")

    gap = pct("kunai_F1", "cbpfc_F1", reps)
    if gap:
        m, s = msd(gap)
        print(f"gap%:kunai_F1_vs_cbpfc_F1,{len(gap)},{m:.2f},{s:.3f}")

    fixed = pct("accept_udp64", "floor", reps)
    if fixed:
        m, s = msd(fixed)
        print(f"fixed%:window_copy_udp64,{len(fixed)},{m:.2f},{s:.3f}")


if __name__ == "__main__":
    main(sys.argv)
