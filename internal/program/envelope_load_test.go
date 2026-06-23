package program

// Verifier-load coverage for the structural extremes of the generator's
// bpf_loop-bearing lowering paths. The regression corpus exercises each
// only at its minimal shape (the chain quantifier at the unroll cap, the
// aux-list walk at one walk, the parser-machine self-loop at one queried
// option); this test actually loads the deepest bytecode the generator
// emits, so the verifier — not just a static instruction counter — sees
// the extremes:
//
//   - Axis A: the bounded bpf_loop chain at high caps, up to the
//     bpfLoopChainCap (32) boundary.
//   - Axis B: 2..8 stacked SRv6 aux-walk callbacks (the eight-walk case).
//   - Axis C: a counter-driven TLV option walk querying multiple options
//     (Geneve OVN+GWLB), which fattens the per-iteration callback body.
//     (The lookahead-only TCP-options accumulator path is loaded by
//     tcp_accumulator_load_test.go, TestBpfTCPAccumulator.)
//
// TestBpf-prefixed and host-doubled (XDP + tc) so it rides the same
// vimto matrix as TestBpfFilterSet* in .github/workflows/bpf_load_test.yaml;
// a rejection on any of the matrix kernels fails the matching subtest.

import (
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
)

// envelopeExprs returns the structural-extreme expressions, labelled by the
// three lowering-path axes (A: chain quantifier, B: SRv6 aux-walk stack,
// C: counter-driven Geneve option walk) exercised below.
func envelopeExprs() []struct{ id, expr string } {
	out := []struct{ id, expr string }{
		// Axis A — chain quantifier past the static-unroll cap (4), in the
		// bpf_loop regime, up to the bpfLoopChainCap boundary (32). The
		// mechanism itself is already loaded via mpls+/mpls* (D02/D03,
		// default depth 8); these pin the bounded {1,m>4} shape at its
		// largest caps.
		{"A_mpls_1_5", "eth/mpls{1,5}/ipv4/tcp"},
		{"A_mpls_1_8", "eth/mpls{1,8}/ipv4/tcp"},
		{"A_mpls_1_32", "eth/mpls{1,32}/ipv4/tcp"},
	}
	// Axis B — k stacked SRv6 segment aux-walks, each a bpf_loop callback.
	// The loaded corpus has only k=1 (G00/G01); k=2..8 is the headline
	// "eight stacked walks" case and was previously count-only.
	for k := 2; k <= 8; k++ {
		expr := "eth/ipv6/srv6 where "
		for i := 0; i < k; i++ {
			if i > 0 {
				expr += " and "
			}
			expr += fmt.Sprintf("any(srv6.segments.addr == fc00::%d)", i+1)
		}
		out = append(out, struct{ id, expr string }{fmt.Sprintf("B_srv6_walks_%d", k), expr})
	}

	// Axis C — TLV option walk (parser-machine self-loop) querying multiple
	// options. Geneve's counter-driven 2-key dispatch carries several
	// queried options on its native path. (The lookahead-only TCP-options
	// accumulator path is loaded separately by tcp_accumulator_load_test.go,
	// TestBpfTCPAccumulator, so it is not duplicated here.)
	out = append(out,
		struct{ id, expr string }{
			"C_geneve_opts_2",
			"eth/ipv4/udp/geneve where geneve.options.OVN.egress_port == 42 and geneve.options.GWLB.flow_cookie == 0x12345678",
		},
	)
	return out
}

func TestBpfEnvelopeXDP(t *testing.T) {
	runEnvelopeMatrix(t, loadDummyXDP(t), xdpFuncName)
}

func TestBpfEnvelopeTC(t *testing.T) {
	runEnvelopeMatrix(t, loadDummyTC(t), tcFuncName)
}

func runEnvelopeMatrix(t *testing.T, hostProg *ebpf.Program, funcName string) {
	t.Helper()
	for _, c := range envelopeExprs() {
		t.Run(c.id, func(t *testing.T) {
			loadProbeOrFail(t, hostProg, funcName, c.expr, false /*exit*/, true /*useDSL*/)
		})
	}
}
