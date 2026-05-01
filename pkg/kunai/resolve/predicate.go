package resolve

import (
	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
)

// resolveBracketPredicate handles a predicate inside a layer's `[...]`
// list. The field is unqualified (single-name) for primary fields or
// two-part `<aux>.<field>` / `<aux>.exists` for auxiliary access,
// always scoped to the owning layer.
func (r *resolver) resolveBracketPredicate(ap *ast.Predicate, layer *ir.LayerInstance) (*ir.Predicate, error) {
	field, err := resolveUnqualifiedField(ap.Field, layer)
	if err != nil {
		return nil, err
	}
	if field.Aux != nil && field.Aux.Stack != nil && field.Aux.Stack.IsIterator {
		return nil, errorf(ap.Pos, "auxiliary header stack %q needs an index inside a bracket predicate (use `[N]` or wrap in `any(...)` / `all(...)`)", field.Aux.OutParam)
	}
	// Bracket-predicate fit check: integer literal must fit the
	// field's declared bit width (dsl-types.md §7.2). Delegated to
	// the typing helper so the same rule is in one place.
	if ap.Kind == ast.PredCmp {
		if err := checkBracketIntFit(field, ap.Value, layer.Spec.Name, ap.Pos); err != nil {
			return nil, err
		}
	}
	rp := &ir.Predicate{
		Kind:     ap.Kind,
		Field:    field,
		Op:       ap.Op,
		Value:    ap.Value,
		List:     ap.List,
		FlagName: ap.FlagName,
		Pos:      ap.Pos,
	}
	switch ap.Kind {
	case ast.PredIn:
		rp.Unsupported = "'in' predicate not yet implemented"
	case ast.PredHas:
		rp.Unsupported = "'has' predicate not yet implemented"
	}
	return rp, nil
}

// resolveUnqualifiedField looks up a field path scoped to one
// layer's headers. Single-segment paths bind to the primary header
// (the existing `tcp[dport == 443]` shape). Two-segment paths
// `<aux>.<field>` or `<aux>.exists` bind to one of the layer's
// auxiliary headers (e.g. `gtp[opt.next_ext == 0]`). Anything
// deeper belongs in a `where` clause and is rejected here.
func resolveUnqualifiedField(fp *ast.FieldPath, layer *ir.LayerInstance) (*ir.FieldRef, error) {
	if fp == nil || len(fp.Parts) == 0 {
		return nil, errorf(ast.Position{}, "empty field path")
	}
	switch len(fp.Parts) {
	case 1:
		name := fp.Parts[0]
		f, ok := layer.Spec.FindField(name)
		if !ok {
			return nil, errorf(fp.Pos, "protocol %q has no field %q", layer.Spec.Name, name)
		}
		return &ir.FieldRef{Layer: layer, Field: f}, nil
	case 2:
		return resolveAuxField(layer, fp.Parts[0], fp.Parts[1], fp)
	default:
		return nil, errorf(fp.Pos, "nested field access %q is not supported inside a predicate", fp.String())
	}
}
