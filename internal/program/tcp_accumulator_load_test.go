package program

// Kernel-load + compile-boundary coverage for the multi-option TCP
// accumulator lowering (see docs/ja/dsl-multi-option-accumulator.md). A
// `where` clause that queries several options of the same TLV list is
// compiled to one combined bpf_loop whose cursor and accumulator are
// forgotten each iteration; this test loads that bytecode on the real
// verifier so a regression shows up as a kernel rejection, not just a
// changed instruction count.
//
// TestBpf-prefixed and host-doubled (XDP + tc) so it rides the same vimto
// matrix as TestBpfFilterSet* in .github/workflows/bpf_load_test.yaml; a
// rejection on any of the six kernels fails the matching subtest.

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/takehaya/xdp-ninja/pkg/kunai/codegen"
)

// accumulatorExprs returns multi-option `where` clauses that exercise the
// accumulator at a range of atom counts: 2 and 3 (common), 4 (every
// distinct TCP option type), 8 (two fields per option), and 14 (every
// field of every option type, TCP's maximum constructible query). Geneve's
// counter-driven dispatch loads multiple options on its own path and is
// included as a cross-check.
func accumulatorExprs() []struct{ id, expr string } {
	return []struct{ id, expr string }{
		{"tcp_opts_2", "eth/ipv4/tcp where tcp.options.MSS.value == 1460 and tcp.options.WS.shift == 7"},
		{"tcp_opts_3", "eth/ipv4/tcp where tcp.options.MSS.value == 1460 and tcp.options.WS.shift == 7 and tcp.options.SACK_PERM.kind == 4"},
		{"tcp_opts_4", "eth/ipv4/tcp where tcp.options.MSS.value == 1460 and tcp.options.WS.shift == 7 and tcp.options.SACK_PERM.kind == 4 and tcp.options.TS.tsval == 1"},
		{"tcp_opts_8", "eth/ipv4/tcp where tcp.options.MSS.value == 1460 and tcp.options.MSS.length == 4 " +
			"and tcp.options.WS.shift == 7 and tcp.options.WS.length == 3 " +
			"and tcp.options.SACK_PERM.kind == 4 and tcp.options.SACK_PERM.length == 2 " +
			"and tcp.options.TS.tsval == 1 and tcp.options.TS.tsecr == 2"},
		{"tcp_opts_14", "eth/ipv4/tcp where tcp.options.MSS.kind == 2 and tcp.options.MSS.length == 4 and tcp.options.MSS.value == 1460 " +
			"and tcp.options.WS.kind == 3 and tcp.options.WS.length == 3 and tcp.options.WS.shift == 7 " +
			"and tcp.options.SACK_PERM.kind == 4 and tcp.options.SACK_PERM.length == 2 " +
			"and tcp.options.TS.kind == 8 and tcp.options.TS.length == 10 and tcp.options.TS.tsval == 1 and tcp.options.TS.tsecr == 2 " +
			"and tcp.options.SACK.kind == 5 and tcp.options.SACK.length == 10"},
		{"geneve_opts_2", "eth/ipv4/udp/geneve where geneve.options.OVN.egress_port == 42 and geneve.options.GWLB.flow_cookie == 0x12345678"},
		// Accumulator threaded through an alternation member: the acc slot is
		// zeroed before the alt so the non-matching (udp) branch loads too.
		{"tcp_opts_2_in_alt", "eth/ipv4/(tcp|udp) where tcp.options.MSS.value == 1460 and tcp.options.WS.shift == 7"},
	}
}

// TestTCPMultiOptionBoundary pins the compile-time boundary. A single
// option and a pure AND of `<option>.<field> == <const>` equalities over
// several options both lower (the accumulator folds them into one slot).
// Shapes the accumulator does not cover reject with ErrNotImplemented: a
// non-eq (`!=`) leaf, or mixing a non-option atom into the AND (which
// leaves a queried option uncovered). Compile-only, so it needs no root.
func TestTCPMultiOptionBoundary(t *testing.T) {
	cases := []struct {
		id     string
		expr   string
		reject bool
	}{
		{"tcp_1opt", "eth/ipv4/tcp where tcp.options.MSS.value == 1460", false},
		{"tcp_2opt", "eth/ipv4/tcp where tcp.options.MSS.value == 1460 and tcp.options.WS.shift == 7", false},
		{"tcp_4opt", "eth/ipv4/tcp where tcp.options.MSS.value == 1460 and tcp.options.WS.shift == 7 and tcp.options.SACK_PERM.kind == 4 and tcp.options.TS.tsval == 1", false},
		{"tcp_14opt_max", "eth/ipv4/tcp where tcp.options.MSS.kind == 2 and tcp.options.MSS.length == 4 and tcp.options.MSS.value == 1460 and tcp.options.WS.kind == 3 and tcp.options.WS.length == 3 and tcp.options.WS.shift == 7 and tcp.options.SACK_PERM.kind == 4 and tcp.options.SACK_PERM.length == 2 and tcp.options.TS.kind == 8 and tcp.options.TS.length == 10 and tcp.options.TS.tsval == 1 and tcp.options.TS.tsecr == 2 and tcp.options.SACK.kind == 5 and tcp.options.SACK.length == 10", false},
		{"tcp_2opt_ne_rejects", "eth/ipv4/tcp where tcp.options.MSS.value == 1460 and tcp.options.WS.shift != 7", true},
		{"tcp_mixed_atom_rejects", "eth/ipv4/tcp where tcp.dport == 443 and tcp.options.MSS.value == 1460 and tcp.options.WS.shift == 7", true},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			_, err := compileFilter(c.expr, true /*useDSL*/, false /*isFexit*/, ebpf.XDP)
			if c.reject {
				if !errors.Is(err, codegen.ErrNotImplemented) {
					t.Fatalf("expected ErrNotImplemented, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected success, got %v", err)
			}
		})
	}
}

func TestBpfTCPAccumulatorXDP(t *testing.T) {
	runAccumulatorMatrix(t, loadDummyXDP(t), xdpFuncName)
}

func TestBpfTCPAccumulatorTC(t *testing.T) {
	runAccumulatorMatrix(t, loadDummyTC(t), tcFuncName)
}

func runAccumulatorMatrix(t *testing.T, hostProg *ebpf.Program, funcName string) {
	t.Helper()
	for _, c := range accumulatorExprs() {
		t.Run(c.id, func(t *testing.T) {
			loadProbeOrFail(t, hostProg, funcName, c.expr, false /*exit*/, true /*useDSL*/)
		})
	}
}
