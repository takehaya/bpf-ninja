# Measurement data

This directory contains the measurements supporting the camera-ready evaluation
in [`../paper/sections/05_evaluation.tex`](../paper/sections/05_evaluation.tex).
The measurement CSVs are preserved byte for byte. `make data` in the parent
directory recomputes their summaries.

| Files | Paper result | Units / interpretation |
|---|---|---|
| `b4_xdp_drop_rep1.csv` through `rep10.csv` | Datapath chart and window-copy overhead | Packet counts, seconds, and million packets/s |
| `b2_runtime_rep1.csv` through `rep10.csv` | `BPF_PROG_TEST_RUN` runtime paragraph | `ns_per_pkt`, including fixed per-call work |
| `b2_runtime_stats.csv` | Saved runtime summary | Mean and sample SD over ten repetitions |
| `verifier_insns_matrix_v0.23.1.csv` | Table 2, verifier column | Instructions processed by the verifier, including the host fentry probe |
| `b5_envelope.csv` | Instruction-growth paragraph | Instruction count versus chain cap or stacked SRv6 walks |

## Datapath measurements

The DUT used Linux 6.15, an Intel Xeon 8362, and an Intel E810 NIC on a
100 GbE link. A native XDP program returns `XDP_DROP`; each filter measurement
includes the packet-head copy into the per-CPU scratch window. Each CSV records
its traffic duration and the offered, NIC receive, and XDP processing rates.

The `floor` row has neither the window copy nor a filter. `accept_<stream>`
copies the packet head without applying a filter. Each `kunai_Fn` or `cbpfc_Fn`
row is compared with the accept-all row whose stream matches its `stream`
column:

```text
cost_percent(rep) = 100 * (accept_mpps(rep) - filter_mpps(rep)) / accept_mpps(rep)
bar = mean(cost_percent over the ten reps)
error_bar = population SD(cost_percent over the ten reps), denominator n
```

The chart's population-SD convention is retained from its original plotting
script. Small negative reductions, including F5, are retained in the data;
the figure displays near-zero labels as `0.0`.

These ten `b4_xdp_drop` repetitions reproduce the supplied chart: Kunai F1--F6
round to 0.0--1.8% and F7--F10 to 3.9--7.3%. The fixed-copy overhead uses
`floor` and `accept_udp64` and rounds to 7.7%.

## Runtime measurements

`filter` is the paper's F1--F10 ID; F0 is the filterless baseline. `path` is
`kunai` or `cbpfc`. The saved summary uses the arithmetic mean and **sample**
standard deviation (denominator `n - 1`), rounded to one decimal place.
Every summary row can be regenerated from the ten repetition CSVs.

## Verifier and compiler version

`verifier_insns_matrix_v0.23.1.csv` contains measurements on Linux 6.1, 6.6,
6.12, 6.15, 6.18, and 7.0. They were recorded on August 1 and August 5, 2026
using compiler paths matching the paper's `v0.23.1` tag. Table 2 takes the
maximum of each Kunai row across the six kernels. This is verifier work,
distinct from the raw size of the generated filter bytecode.

The pinned tests are:

- [Filter definitions and raw instruction counts](https://github.com/takehaya/bpf-ninja/blob/v0.23.1/internal/program/filterset_test.go)
- [Verifier instruction measurements](https://github.com/takehaya/bpf-ninja/blob/v0.23.1/internal/program/verifier_stats_test.go)
- [Verifier regression corpus](https://github.com/takehaya/bpf-ninja/blob/v0.23.1/internal/program/filterset_corpus_test.go)

**Filter numbering:** the paper and these CSVs use F5 for ICMP and F6 for
QinQ. The compiler's `v0.23.1` `FilterSet` uses F5 for QinQ and F6 for ICMP.
Swap those two IDs when comparing test output with the paper; use the filter
expression to identify a row. TC excludes VLAN and QinQ, which are paper
F4/F6 and compiler-test F4/F5.

The compiler's `TestFilterSetCounts` checks the raw instruction counts printed
in Table 2. It runs without root. `TestBpfVerifierStats` requires a compatible
kernel and BPF privileges; the repository's testing guide describes the setup.
The envelope CSV records the saved sweep (including 68 instructions per added
SRv6 walk); it is a separate measurement from the per-filter verifier matrix.
