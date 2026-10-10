package dsltest

import (
	"testing"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
	"github.com/takehaya/bpf-ninja/pkg/kunai/parser"
)

// checkHeadersCaptureBound compares the length Go would capture with the
// range the spec expects for `capture headers` / `headers+N` (D-039): both
// are a bound computed from the chain's shape, clamped to the packet. Go
// keeps one MaxCapLen, the largest clause bound, so the check runs only
// when every clause of the vector is a headers clause: the largest Lean end
// is then min(MaxCapLen, |P|). Vectors with other clause kinds (`all`,
// `absolute`, `<layer>`) are compared on the verdict alone.
func checkHeadersCaptureBound(t *testing.T, v specVector, out codegen.Output, pktLen int) {
	t.Helper()
	if v.Expected.Kind != "accept" || len(v.Expected.Captures) == 0 {
		return
	}
	f, err := parser.Parse(v.Expr, "", nil)
	if err != nil || len(f.Captures) != len(v.Expected.Captures) {
		return
	}
	var end int64
	for i, c := range f.Captures {
		if c.Kind != ast.CapHeaders && c.Kind != ast.CapHeadersPlus {
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
