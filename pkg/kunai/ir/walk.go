package ir

import "github.com/takehaya/xdp-ninja/pkg/kunai/ast"

// WalkConditionFieldRefs invokes fn on every FieldRef reachable
// from c — LiteralField, fields inside ArithL/ArithR, and the
// equivalents inside Left/Right/Inner sub-conditions. The traversal
// is pre-order; fn must not mutate c.
func WalkConditionFieldRefs(c *Condition, fn func(*FieldRef)) {
	if c == nil {
		return
	}
	if c.LiteralField != nil {
		fn(c.LiteralField)
	}
	WalkArithFieldRefs(c.ArithL, fn)
	WalkArithFieldRefs(c.ArithR, fn)
	WalkConditionFieldRefs(c.Left, fn)
	WalkConditionFieldRefs(c.Right, fn)
	WalkConditionFieldRefs(c.Inner, fn)
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
