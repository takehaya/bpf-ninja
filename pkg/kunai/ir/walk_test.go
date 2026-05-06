package ir

import (
	"testing"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
)

// TestWalkConditionFieldRefsCoversBoolBranches pins the invariant
// that markRuntimeOffsetLayers depends on: every FieldRef-bearing
// field on Condition is visited. A regression here silently leaves
// layers unmarked past a het-alt, producing stale R0+static_prefix
// addressing at codegen.
func TestWalkConditionFieldRefsCoversBoolBranches(t *testing.T) {
	literalRef := &FieldRef{}
	arithRef := &FieldRef{}
	boolRef := &FieldRef{}
	boolLLiteralRef := &FieldRef{}
	boolRArithRef := &FieldRef{}

	cond := &Condition{
		LiteralField: literalRef,
		ArithL:       &ArithExpr{Kind: ast.ArithField, Field: arithRef},
		BoolField:    boolRef,
		BoolL:        &Condition{LiteralField: boolLLiteralRef},
		BoolR:        &Condition{ArithR: &ArithExpr{Kind: ast.ArithField, Field: boolRArithRef}},
	}

	want := map[*FieldRef]bool{
		literalRef:      false,
		arithRef:        false,
		boolRef:         false,
		boolLLiteralRef: false,
		boolRArithRef:   false,
	}
	WalkConditionFieldRefs(cond, func(f *FieldRef) {
		if _, expected := want[f]; expected {
			want[f] = true
		}
	})
	for ref, seen := range want {
		if !seen {
			t.Errorf("FieldRef %p not visited (one of LiteralField / ArithL.Field / BoolField / BoolL.LiteralField / BoolR.ArithR.Field)", ref)
		}
	}
}
