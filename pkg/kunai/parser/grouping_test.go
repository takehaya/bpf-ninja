package parser

import (
	"testing"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
)

func TestWhereGroupingPreservesIntegerComparison(t *testing.T) {
	for _, expr := range []string{
		"tcp.dport == 443", "(tcp.dport) == 443", "((tcp.dport)) == (443)",
		"(tcp.dport + 1) == 444", "(tcp.dport + 1) > (444)",
		"(tcp.flags & 0x12) == 0x12", "(tcp.dport) + 1 == 444",
	} {
		t.Run(expr, func(t *testing.T) {
			w := mustParse(t, "eth/ipv4/tcp where "+expr).Where
			if w.Kind != ast.WAtomArith {
				t.Fatalf("got %v; grouping must preserve integer comparison", w.Kind)
			}
		})
	}
}

func TestWhereExistsEqualitySymmetric(t *testing.T) {
	for _, expr := range []string{"gtp.opt.exists == true", "true == gtp.opt.exists", "(gtp.opt.exists) == true", "gtp.opt.exists != false"} {
		t.Run(expr, func(t *testing.T) {
			w := mustParse(t, "eth/ipv4/udp/gtp where "+expr).Where
			if w.Kind != ast.WAtomBoolEq {
				t.Fatalf("got %v, want Boolean equality", w.Kind)
			}
		})
	}
}
