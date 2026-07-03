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
	// `in @set` extracts the field into a host key buffer that the host
	// looks up unconditionally after the filter. That is only correct if
	// the predicate is always evaluated on the accept path, so the owning
	// layer must be mandatory: a `?` / `*` / `+` / `{n,m}` layer that is
	// absent would leave the buffer unwritten and the lookup would match
	// the wrong (zeroed) key. (Alternation members are rejected in
	// resolveAlternation.)
	if ap.Kind == ast.PredInSet && layer.Quant != ast.QuantOne {
		return nil, errorf(ap.Pos, "`in @%s` is only supported on a mandatory layer; %q here is optional/repeated (quantifier %s)", ap.SetName, layer.Spec.Name, layer.Quant)
	}
	// Bracket-predicate fit check: integer literal must fit the
	// field's declared bit width (dsl-types.md §7.2). Delegated to
	// the typing helper so the same rule is in one place.
	if ap.Kind == ast.PredCmp {
		if err := rejectBareIdentValue(ap.Value); err != nil {
			return nil, err
		}
		if err := checkBracketIntFit(field, ap.Value, layer.Spec.Name, ap.Pos); err != nil {
			return nil, err
		}
	}
	if ap.Kind == ast.PredIn {
		if len(ap.List) == 0 {
			return nil, errorf(ap.Pos, "'in' predicate needs at least one alternative")
		}
		// Each alternative narrows independently against the same
		// field — apply the bracket fit-check per element so
		// out-of-range values surface here, not at codegen time.
		for _, v := range ap.List {
			if err := rejectBareIdentValue(v); err != nil {
				return nil, err
			}
			if err := checkBracketIntFit(field, v, layer.Spec.Name, ap.Pos); err != nil {
				return nil, err
			}
		}
	}
	rp := &ir.Predicate{
		Kind:     ap.Kind,
		Field:    field,
		Op:       ap.Op,
		Value:    ap.Value,
		List:     ap.List,
		FlagName: ap.FlagName,
		SetName:  ap.SetName,
		Pos:      ap.Pos,
	}
	if ap.Kind == ast.PredHas {
		rp.Unsupported = "'has' predicate not yet implemented"
	}
	// PredInSet is wired in codegen (emitInSetPredicate); it needs the
	// host's SetSlotResolver, which the resolver does not carry, so its
	// set-existence / field checks happen there, not here.
	return rp, nil
}

// rejectBareIdentValue surfaces a typing error when the RHS of a
// bracket predicate is a bare identifier (`tcp[dport == true]`,
// `tcp[dport == port]`). Predicate values must be typed literals;
// the previous failure mode here was a codegen-side
// ErrNotImplemented "predicate value type ident" that masked the
// actual type violation. Surface it here with position info so users
// see "1:14: predicate value cannot be a bare identifier..." instead
// of a kunai internals error.
func rejectBareIdentValue(v *ast.Value) error {
	if v == nil || v.Kind != ast.ValIdent {
		return nil
	}
	return errBareIdentValue(v.Pos, v.Ident)
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
	// Detach a trailing bit-slice so the existing dispatch can run on
	// the un-sliced path; reattach to the resolved FieldRef before
	// returning.
	fp, slice, err := detachTrailingSlice(fp)
	if err != nil {
		return nil, err
	}
	var ref *ir.FieldRef
	switch len(fp.Parts) {
	case 1:
		name := fp.Parts[0]
		f, ok := layer.Spec.FindField(name)
		if !ok {
			return nil, errorf(fp.Pos, "protocol %q has no field %q", layer.Spec.Name, name)
		}
		ref = &ir.FieldRef{Layer: layer, Field: f}
	case 2:
		ref, err = resolveAuxField(layer, fp.Parts[0], fp.Parts[1], fp)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errorf(fp.Pos, "nested field access %q is not supported inside a predicate", fp.String())
	}
	if slice != nil {
		if err := attachSlice(ref, slice); err != nil {
			return nil, err
		}
	}
	return ref, nil
}
