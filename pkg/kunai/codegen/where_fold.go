package codegen

import (
	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
	"github.com/takehaya/bpf-ninja/pkg/kunai/ir"
)

// foldBooleanConstants removes constant control-flow arms before emitting BPF.
// The verifier rejects structurally unreachable branches even when the source
// expression is valid. Copy nodes so compiling never mutates the caller's IR.
func foldBooleanConstants(w *ir.Condition) *ir.Condition {
	if w == nil {
		return nil
	}
	c := *w
	c.Left, c.Right = foldBooleanConstants(w.Left), foldBooleanConstants(w.Right)
	// Quantifier walkers discover iterator bounds from the original inner
	// field references. Fold their instantiated predicates when gen is called,
	// after the walker has established its domain (including empty domains).
	if w.Kind != ast.WAny && w.Kind != ast.WAll {
		c.Inner = foldBooleanConstants(w.Inner)
	}
	c.BoolL, c.BoolR = foldBooleanConstants(w.BoolL), foldBooleanConstants(w.BoolR)
	literal := func(v bool) *ir.Condition { return &ir.Condition{Kind: ast.WAtomBoolLit, BoolLitValue: v, Pos: w.Pos} }
	isLiteral := func(x *ir.Condition) bool { return x != nil && x.Kind == ast.WAtomBoolLit }
	switch c.Kind {
	case ast.WAny, ast.WAll:
		inner := foldBooleanConstants(w.Inner)
		if isLiteral(inner) && !inner.BoolLitValue {
			// any(false) is false whatever the domain. all(false) is false
			// when the domain is statically non-empty. A true body is not
			// folded: the quantifier is still false on an absent layer
			// (D-003) and all() on a truncated stack (D-029), which the
			// generated guards decide.
			if c.Kind == ast.WAny {
				return literal(false)
			}
			if count, err := stackCountSource(w); err == nil && count == nil && w.QuantTarget.Capacity > 0 {
				return literal(false)
			}
		}

	case ast.WNot:
		if isLiteral(c.Inner) {
			return literal(!c.Inner.BoolLitValue)
		}
	case ast.WAnd, ast.WOr:
		for _, pair := range [][2]*ir.Condition{{c.Left, c.Right}, {c.Right, c.Left}} {
			if !isLiteral(pair[0]) {
				continue
			}
			v := pair[0].BoolLitValue
			if c.Kind == ast.WAnd {
				if !v {
					return literal(false)
				}
				return pair[1]
			}
			if v {
				return literal(true)
			}
			return pair[1]
		}
	case ast.WAtomBoolEq:
		if isLiteral(c.BoolL) && isLiteral(c.BoolR) {
			equal := c.BoolL.BoolLitValue == c.BoolR.BoolLitValue
			if c.BoolEqOp == ast.CmpNeq {
				equal = !equal
			}
			return literal(equal)
		}
	}
	return &c
}
