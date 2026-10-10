package dsltest

import (
	"testing"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
)

// checkCaptureBound compares the length Go would capture with the ranges
// the spec expects. For `headers` / `headers+N` (D-039) and `absolute N`
// both sides are a bound known at compile time, clamped to the packet. Go
// keeps one MaxCapLen, the largest clause bound, so the check runs only
// when every clause of the vector is one of those kinds: the largest end
// the spec expects is then min(MaxCapLen, |P|). A `capture <layer>`
// clause (the spec drops it when the layer is absent and starts at the
// layer, D-020) or an `all` clause (Go leaves MaxCapLen at 0 for the
// host's default) keeps a vector verdict-only.
func checkCaptureBound(t *testing.T, v specVector, f *ast.Filter, out codegen.Output, pktLen int) {
	t.Helper()
	if f == nil || v.Expected.Kind != "accept" || len(v.Expected.Captures) == 0 || len(f.Captures) != len(v.Expected.Captures) {
		return
	}
	var end int64
	for i, c := range f.Captures {
		switch c.Kind {
		case ast.CapHeaders, ast.CapHeadersPlus, ast.CapAbsolute:
		default:
			return
		}
		if e := v.Expected.Captures[i][1]; e > end {
			end = e
		}
	}
	got := out.Capture.MaxCapLen
	if pktLen < got {
		got = pktLen
	}
	if int64(got) != end {
		t.Fatalf("%q: Go captures min(MaxCapLen %d, |P| %d) = %d bytes; Lean ends at %d. %s", v.Expr, out.Capture.MaxCapLen, pktLen, got, end, v.Note)
	}
}
