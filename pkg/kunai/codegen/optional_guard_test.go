package codegen

import (
	"errors"
	"strings"
	"testing"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
	"github.com/takehaya/bpf-ninja/pkg/kunai/ir"
	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
)

// TestOptionalLayerGuardVariableShapes pins the variable-length rules of
// the guard on synthetic specs (no bundled protocol combines a chain-end
// rule with a variable-length header): one optional header is admitted,
// a repeated one and one with a chain-end rule are refused.
func TestOptionalLayerGuardVariableShapes(t *testing.T) {
	parent := &ir.LayerInstance{Spec: &vocab.ProtocolSpec{Name: "p"}}
	layer := func(rangeMax int, chainEnd bool) *ir.LayerInstance {
		spec := &vocab.ProtocolSpec{Name: "v", FlagTriggers: []vocab.FlagTrigger{{}}}
		if chainEnd {
			spec.ChainEnd = &vocab.ChainEndConst{FieldName: "s", Value: 1, Bits: 1}
		}
		return &ir.LayerInstance{Spec: spec, Dispatch: &ir.DispatchChoice{Type: vocab.DispatchField}, Quant: ast.QuantRange, RangeMax: rangeMax}
	}
	if err := optionalLayerGuard(layer(1, false), 1, []*ir.LayerInstance{parent, nil}); err != nil {
		t.Errorf("{0,1} on a variable-length layer: %v", err)
	}
	for name, l := range map[string]*ir.LayerInstance{"repeated": layer(2, false), "open": layer(-1, false), "chain-end": layer(1, true)} {
		err := optionalLayerGuard(l, 1, []*ir.LayerInstance{parent, l})
		if !errors.Is(err, ErrNotImplemented) || !strings.Contains(err.Error(), "variable-length") {
			t.Errorf("%s: err = %v; want the variable-length refusal", name, err)
		}
	}
}
