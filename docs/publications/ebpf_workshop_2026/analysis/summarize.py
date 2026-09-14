#!/usr/bin/env python3
"""Recompute the paper's summaries from the supplied measurement CSVs."""

import csv
from pathlib import Path
import statistics
import sys

DATA = Path(__file__).resolve().parents[1] / "data"


def rows(name):
    with (DATA / name).open(newline="") as source:
        return list(csv.DictReader(source))


def main():
    writer = csv.writer(sys.stdout, lineterminator="\n")
    print("# Datapath: positive values are throughput reductions; population SD")
    writer.writerow(["cell", "n", "mean_percent", "sd_percent"])
    reps = [{row["cell"]: row for row in rows(f"b4_xdp_drop_rep{i}.csv")}
            for i in range(1, 11)]
    for number in range(1, 11):
        variants = ["kunai", "cbpfc"] if number <= 5 else ["kunai"]
        for variant in variants:
            cell = f"{variant}_F{number}"
            values = []
            for rep in reps:
                row = rep[cell]
                baseline = float(rep["accept_" + row["stream"]]["xdp_mpps"])
                values.append(100 * (baseline - float(row["xdp_mpps"])) / baseline)
            writer.writerow([cell, len(values), f"{statistics.mean(values):.6f}",
                             f"{statistics.pstdev(values):.6f}"])
    fixed = [100 * (float(rep["floor"]["xdp_mpps"]) -
                    float(rep["accept_udp64"]["xdp_mpps"])) /
             float(rep["floor"]["xdp_mpps"]) for rep in reps]
    writer.writerow(["window_copy_udp64", len(fixed), f"{statistics.mean(fixed):.6f}",
                     f"{statistics.pstdev(fixed):.6f}"])

    print("\n# BPF_PROG_TEST_RUN: ns/pkt; sample SD")
    writer.writerow(["filter", "path", "n", "mean_ns", "sd_ns"])
    runtime = {}
    for i in range(1, 11):
        for row in rows(f"b2_runtime_rep{i}.csv"):
            runtime.setdefault((row["filter"], row["path"]), []).append(
                float(row["ns_per_pkt"]))
    for (filter_id, path), values in runtime.items():
        writer.writerow([filter_id, path, len(values), f"{statistics.mean(values):.1f}",
                         f"{statistics.stdev(values):.1f}"])

    print("\n# Verifier: maximum processed instructions across six kernels")
    writer.writerow(["filter", "variant", "max_verified_insns"])
    for row in rows("verifier_insns_matrix_v0.23.1.csv"):
        writer.writerow([row["filter"], row["variant"],
                         max(int(value) for key, value in row.items()
                             if key.startswith("k"))])


if __name__ == "__main__":
    main()
