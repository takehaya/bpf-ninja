package program

import (
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
)

// TestM2Envelope pins the instruction-count scaling behind Figure 5
// (paper/figures/fig_envelope.tex) and benchmark/results/b5_envelope.csv:
// how the raw eBPF instruction count grows with (A) a chain quantifier's
// compile-time cap and (B) the number of stacked SRv6 segment walks. Like
// TestFilterSetCounts, this exists so a codegen change that alters the
// curve surfaces as a test failure rather than a quiet drift in the
// paper's §5.4 figure. Pure compile + count; no root, no kernel load.
func TestM2Envelope(t *testing.T) {
	count := func(expr string) int {
		out, err := compileFilter(expr, true /*useDSL*/, false /*isFexit*/, ebpf.XDP)
		if err != nil {
			t.Fatalf("compile %q: %v", expr, err)
		}
		return countRawInsns(out.Main, out.Callbacks)
	}

	// Axis A: chain-quantifier cap. mpls{1,N} unrolls statically for
	// N <= staticChainCap (=4); above it the chain lowers to a bpf_loop
	// callback whose size no longer grows with N (flat at 254).
	axisA := []struct {
		n         int
		wantInsns int
		regime    string
	}{
		{1, 216, "unroll"},
		{2, 233, "unroll"},
		{3, 249, "unroll"},
		{4, 265, "unroll"},
		{5, 254, "bpf_loop"},
		{6, 254, "bpf_loop"},
		{7, 254, "bpf_loop"},
		{8, 254, "bpf_loop"},
	}
	for _, tc := range axisA {
		expr := fmt.Sprintf("eth/mpls{1,%d}/ipv4/tcp", tc.n)
		if got := count(expr); got != tc.wantInsns {
			t.Errorf("axisA N=%d (%s): insns drifted: got %d, want %d\n  expr: %s\n  -> update fig_envelope.tex / b5_envelope.csv",
				tc.n, tc.regime, got, tc.wantInsns, expr)
		}
	}

	// Axis B: stacked aux-walks over the SRv6 segment list (cap 8 each).
	// Each added any() walk is one bpf_loop callback + its ctx setup
	// (+68 insns), flat in the segment capacity — not a Capacity-sized
	// unrolled block. (Before the bpf_loop aux-walk lowering this was
	// +202/walk; see git history.)
	axisB := []struct {
		k         int
		wantInsns int
	}{
		{1, 332},
		{2, 400},
		{3, 468},
		{4, 536},
		{5, 604},
		{6, 672},
		{7, 740},
		{8, 808},
	}
	for _, tc := range axisB {
		expr := "eth/ipv6/srv6 where "
		for i := 0; i < tc.k; i++ {
			if i > 0 {
				expr += " and "
			}
			expr += fmt.Sprintf("any(srv6.segments.addr == fc00::%d)", i+1)
		}
		if got := count(expr); got != tc.wantInsns {
			t.Errorf("axisB k=%d: insns drifted: got %d, want %d\n  expr: %s\n  -> update fig_envelope.tex / b5_envelope.csv",
				tc.k, got, tc.wantInsns, expr)
		}
	}
}
