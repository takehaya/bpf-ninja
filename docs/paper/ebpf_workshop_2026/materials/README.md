# Measurement materials for the eBPF'26 camera-ready

Data referenced by the paper that has no other tracked home. The
datapath measurements behind Figure 5 live in
`benchmark/results/b4_xdp_drop_rep*.csv`, with the plotting pipeline
documented in `paper/figures/README.md`.

File names carry the release tag whose compiler produced the numbers.
The measurements were taken on 2026-08-01 and 2026-08-05 on code whose
compiler paths are identical to the `v0.23.1` tag the paper's
footnotes pin (every commit between v0.23.0 and v0.23.1 touches only
tests and documentation).

## verifier_insns_matrix_v0.23.1.csv

Source data for the "verifier" column of Table 2. Each probe was
loaded on six kernels and `bpf_prog_info.verified_insns` (the number
of instructions the verifier processes before accepting the load,
kernel 5.16+) was read back. Values include the host fentry program
that embeds the filter. The `cbpfc` rows cover the filters that have
an equivalent pcap-filter expression. The paper reports the maximum
of the `kunai` row across the six kernels.

- Reproduce one kernel:
  `vimto -sudo -kernel :<ver> -- go test -v -count 1 ./internal/program/ -run TestBpfVerifierStats`
- Test: `internal/program/verifier_stats_test.go` (in v0.23.1 and
  logged by the CI kernel matrix on every run)
- Kernel images: ghcr.io/cilium/ci-kernels

## verifier_insns_bisect_v0.23.1.csv

Follow-up measurement narrowing the cost jump between 6.6 and 6.12 to
a single release. Not used in the paper; kept for the talk and future
work.

- Findings: the jump lands between 6.7 and 6.8 (about 50x for F10),
  the all-time peak is 292,820 on 6.11 (29% of the verifier limit),
  and 6.12 and 7.0 both improve on their predecessors, so the cost is
  not monotone in the kernel version.
- Working hypothesis, unverified: the 6.8 verifier tracks scalar
  bounds more precisely, which weakens state pruning for
  exploration-heavy walks.
- Same reproduction command with the kernel tag set to 6.7 through
  6.11.
