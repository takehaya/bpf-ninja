package ir

import (
	"testing"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
)

// TestLayerQuantifier pins the three views of a layer's quantifier the
// resolver and codegen share: the instance bounds (a negative max is
// open), whether a second header can match, and the DSL spelling the
// diagnostics print.
func TestLayerQuantifier(t *testing.T) {
	cases := []struct {
		l        LayerInstance
		min, max int
		repeat   bool
		text     string
	}{
		{LayerInstance{Quant: ast.QuantOne}, 1, 1, false, ""},
		{LayerInstance{Quant: ast.QuantOpt}, 0, 1, false, "?"},
		{LayerInstance{Quant: ast.QuantPlus}, 1, -1, true, "+"},
		{LayerInstance{Quant: ast.QuantStar}, 0, -1, true, "*"},
		{LayerInstance{Quant: ast.QuantRange, RangeMin: 0, RangeMax: 0}, 0, 0, false, "{0,0}"},
		{LayerInstance{Quant: ast.QuantRange, RangeMin: 0, RangeMax: 1}, 0, 1, false, "{0,1}"},
		{LayerInstance{Quant: ast.QuantRange, RangeMin: 1, RangeMax: 1}, 1, 1, false, "{1,1}"},
		{LayerInstance{Quant: ast.QuantRange, RangeMin: 1, RangeMax: 2}, 1, 2, true, "{1,2}"},
		{LayerInstance{Quant: ast.QuantRange, RangeMin: 2, RangeMax: -1}, 2, -1, true, "{2,}"},
	}
	for _, tc := range cases {
		min, max := tc.l.Bounds()
		if min != tc.min || max != tc.max {
			t.Errorf("%q: Bounds() = (%d, %d), want (%d, %d)", tc.text, min, max, tc.min, tc.max)
		}
		if got := tc.l.CanRepeat(); got != tc.repeat {
			t.Errorf("%q: CanRepeat() = %v, want %v", tc.text, got, tc.repeat)
		}
		if got := tc.l.QuantText(); got != tc.text {
			t.Errorf("QuantText() = %q, want %q", got, tc.text)
		}
	}
}
