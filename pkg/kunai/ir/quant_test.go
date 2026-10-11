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
		name     string
		l        LayerInstance
		min, max int
		repeat   bool
		text     string
	}{
		{"one", LayerInstance{Quant: ast.QuantOne}, 1, 1, false, ""},
		{"one ignores range", LayerInstance{Quant: ast.QuantOne, RangeMin: 2, RangeMax: 5}, 1, 1, false, ""},
		{"opt", LayerInstance{Quant: ast.QuantOpt}, 0, 1, false, "?"},
		{"plus", LayerInstance{Quant: ast.QuantPlus}, 1, -1, true, "+"},
		{"star", LayerInstance{Quant: ast.QuantStar}, 0, -1, true, "*"},
		{"0,0", LayerInstance{Quant: ast.QuantRange, RangeMin: 0, RangeMax: 0}, 0, 0, false, "{0,0}"},
		{"0,1", LayerInstance{Quant: ast.QuantRange, RangeMin: 0, RangeMax: 1}, 0, 1, false, "{0,1}"},
		{"1,1", LayerInstance{Quant: ast.QuantRange, RangeMin: 1, RangeMax: 1}, 1, 1, false, "{1,1}"},
		{"1,2", LayerInstance{Quant: ast.QuantRange, RangeMin: 1, RangeMax: 2}, 1, 2, true, "{1,2}"},
		{"0,40", LayerInstance{Quant: ast.QuantRange, RangeMin: 0, RangeMax: 40}, 0, 40, true, "{0,40}"},
		{"0,", LayerInstance{Quant: ast.QuantRange, RangeMin: 0, RangeMax: -1}, 0, -1, true, "{0,}"},
		{"2,", LayerInstance{Quant: ast.QuantRange, RangeMin: 2, RangeMax: -1}, 2, -1, true, "{2,}"},
	}
	for _, tc := range cases {
		min, max := tc.l.Bounds()
		if min != tc.min || max != tc.max {
			t.Errorf("%s: Bounds() = (%d, %d), want (%d, %d)", tc.name, min, max, tc.min, tc.max)
		}
		if got := tc.l.CanRepeat(); got != tc.repeat {
			t.Errorf("%s: CanRepeat() = %v, want %v", tc.name, got, tc.repeat)
		}
		if got := tc.l.QuantText(); got != tc.text {
			t.Errorf("%s: QuantText() = %q, want %q", tc.name, got, tc.text)
		}
	}
}
