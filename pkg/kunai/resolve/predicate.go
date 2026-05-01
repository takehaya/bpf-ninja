package resolve

import (
	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
)

// resolveBracketPredicate handles a predicate inside a layer's `[...]`
// list. The field is always unqualified and binds to the owning layer.
func (r *resolver) resolveBracketPredicate(ap *ast.Predicate, layer *ir.LayerInstance) (*ir.Predicate, error) {
	field, err := resolveUnqualifiedField(ap.Field, layer)
	if err != nil {
		return nil, err
	}
	// Catch values that cannot fit the field's declared width. This is
	// a semantic error ("tcp.dport is 16 bits, 99999 does not fit"),
	// not a codegen limitation, so it belongs here.
	if ap.Kind == ast.PredCmp && ap.Value != nil && ap.Value.Kind == ast.ValInt {
		bits := field.Field.Bits
		if bits < 64 && ap.Value.Int >= (uint64(1)<<bits) {
			return nil, errorf(ap.Pos, "value %d does not fit in %d-bit field %s.%s", ap.Value.Int, bits, layer.Spec.Name, field.Field.Name)
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

// resolveUnqualifiedField looks up a single-segment field path in a
// layer's header. Dotted paths (e.g. "outer.total_length") belong in
// where clauses and are rejected here.
func resolveUnqualifiedField(fp *ast.FieldPath, layer *ir.LayerInstance) (*ir.FieldRef, error) {
	if fp == nil || len(fp.Parts) == 0 {
		return nil, errorf(ast.Position{}, "empty field path")
	}
	if len(fp.Parts) != 1 {
		return nil, errorf(fp.Pos, "field path %q inside a predicate must be a single name; use 'where' for qualified paths", fp.String())
	}
	name := fp.Parts[0]
	f, ok := layer.Spec.FindField(name)
	if !ok {
		return nil, errorf(fp.Pos, "protocol %q has no field %q", layer.Spec.Name, name)
	}
	return &ir.FieldRef{Layer: layer, Field: f}, nil
}
