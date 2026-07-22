package ir

import "github.com/takehaya/bpf-ninja/pkg/kunai/ast"

// WalkConditionFieldRefs invokes fn on every FieldRef reachable
// from c — LiteralField, BoolField (WAtomBoolExists), fields inside
// ArithL/ArithR, and the equivalents inside Left/Right/Inner/BoolL/
// BoolR sub-conditions. The traversal is pre-order; fn must not
// mutate c.
//
// Caller invariant: any new FieldRef-bearing field on Condition MUST
// be threaded through here. resolve.markRuntimeOffsetLayers depends
// on full coverage to mark layers past a heterogeneous-size alt;
// missed branches silently leave layers unmarked, producing
// codegen with stale R0+static_prefix addressing.
func WalkConditionFieldRefs(c *Condition, fn func(*FieldRef)) {
	if c == nil {
		return
	}
	if c.LiteralField != nil {
		fn(c.LiteralField)
	}
	if c.BoolField != nil {
		fn(c.BoolField)
	}
	WalkArithFieldRefs(c.ArithL, fn)
	WalkArithFieldRefs(c.ArithR, fn)
	WalkConditionFieldRefs(c.Left, fn)
	WalkConditionFieldRefs(c.Right, fn)
	WalkConditionFieldRefs(c.Inner, fn)
	WalkConditionFieldRefs(c.BoolL, fn)
	WalkConditionFieldRefs(c.BoolR, fn)
}

// WalkArithFieldRefs invokes fn on every FieldRef reachable from a
// — fields directly held by ArithField nodes and the operands of
// binary operators.
func WalkArithFieldRefs(a *ArithExpr, fn func(*FieldRef)) {
	if a == nil {
		return
	}
	if a.Kind == ast.ArithField {
		fn(a.Field)
		return
	}
	WalkArithFieldRefs(a.Left, fn)
	WalkArithFieldRefs(a.Right, fn)
}
