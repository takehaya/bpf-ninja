package resolve

import (
	"fmt"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
)

// resolveWhere converts an ast.WhereExpr tree to ir.Condition, binding
// field references inside arithmetic atoms to layers via FieldRef.
func (r *resolver) resolveWhere(w *ast.WhereExpr) (*ir.Condition, error) {
	if w == nil {
		return nil, nil
	}
	c := &ir.Condition{Kind: w.Kind, Pos: w.Pos}
	switch w.Kind {
	case ast.WOr, ast.WAnd:
		l, err := r.resolveWhere(w.Left)
		if err != nil {
			return nil, err
		}
		rt, err := r.resolveWhere(w.Right)
		if err != nil {
			return nil, err
		}
		c.Left, c.Right = l, rt
	case ast.WNot:
		inner, err := r.resolveWhere(w.Inner)
		if err != nil {
			return nil, err
		}
		c.Inner = inner
	case ast.WAtomArith:
		al, err := r.resolveArith(w.ArithL)
		if err != nil {
			return nil, err
		}
		ar, err := r.resolveArith(w.ArithR)
		if err != nil {
			return nil, err
		}
		c.ArithL, c.ArithR = al, ar
		c.Op = w.Op
	case ast.WAtomLiteralCmp:
		ref, err := r.resolveQualifiedField(w.LiteralField)
		if err != nil {
			return nil, err
		}
		if err := validateLiteralFieldType(ref, w.LiteralValue, w.Pos); err != nil {
			return nil, err
		}
		c.LiteralField = ref
		c.LiteralValue = w.LiteralValue
		c.LiteralOp = w.LiteralOp
	case ast.WAtomAction:
		if r.allowedActions == nil {
			return nil, errorf(w.Pos, "`action == %s` is not available on this host (no action atoms declared in caps)", w.ActionValue)
		}
		if _, ok := r.allowedActions[w.ActionValue]; !ok {
			return nil, errorf(w.Pos, "unknown action %q (host accepts %d symbols)", w.ActionValue, len(r.allowedActions))
		}
		c.ActionValue = w.ActionValue
	case ast.WAtomFlow:
		c.FlowKind = w.FlowKind
		c.Unsupported = fmt.Sprintf("flow.%s is not yet implemented in MVP codegen", w.FlowKind)
	default:
		return nil, errorf(w.Pos, "internal: unknown where kind %v", w.Kind)
	}
	return c, nil
}

// validateLiteralFieldType pins the network-literal RHS to a field
// whose width can hold it: IPv4/CIDR-v4 → bit<32>, IPv6/CIDR-v6 →
// bit<128>, MAC → bit<48>. Mismatches surface as resolver errors so
// the user gets a clear diagnostic before codegen.
func validateLiteralFieldType(ref *ir.FieldRef, v *ast.Value, pos ast.Position) error {
	want := 0
	desc := ""
	switch v.Kind {
	case ast.ValIPv4:
		want, desc = 32, "IPv4 address"
	case ast.ValIPv6:
		want, desc = 128, "IPv6 address"
	case ast.ValMAC:
		want, desc = 48, "MAC address"
	case ast.ValCIDR:
		if v.AF == 4 {
			want, desc = 32, "IPv4 CIDR"
		} else {
			want, desc = 128, "IPv6 CIDR"
		}
	default:
		return errorf(pos, "internal: %v is not a network literal", v.Kind)
	}
	if ref.Field.Bits != want {
		return errorf(pos, "%s literal needs a bit<%d> field; %s.%s is bit<%d>", desc, want, ref.Layer.Spec.Name, ref.Field.Name, ref.Field.Bits)
	}
	return nil
}

// resolveArith converts an ast.ArithExpr to ir.ArithExpr, binding every
// field reference to its owning layer.
func (r *resolver) resolveArith(a *ast.ArithExpr) (*ir.ArithExpr, error) {
	if a == nil {
		return nil, errorf(ast.Position{}, "internal: nil arithmetic expression")
	}
	out := &ir.ArithExpr{Kind: a.Kind, Pos: a.Pos}
	switch a.Kind {
	case ast.ArithConst:
		out.Const = a.Const
	case ast.ArithField:
		ref, err := r.resolveQualifiedField(a.Field)
		if err != nil {
			return nil, err
		}
		out.Field = ref
	case ast.ArithBinOp:
		l, err := r.resolveArith(a.Left)
		if err != nil {
			return nil, err
		}
		rt, err := r.resolveArith(a.Right)
		if err != nil {
			return nil, err
		}
		out.Left, out.Right = l, rt
		out.Op = a.Op
	default:
		return nil, errorf(a.Pos, "internal: unknown arith kind %v", a.Kind)
	}
	return out, nil
}

// resolveQualifiedField looks up a `<qualifier>.<field>` path. The
// qualifier is either a user-assigned "@label" or a bare protocol name
// (the latter only when the filter has exactly one instance of that
// protocol).
func (r *resolver) resolveQualifiedField(fp *ast.FieldPath) (*ir.FieldRef, error) {
	if fp == nil || len(fp.Parts) == 0 {
		return nil, errorf(ast.Position{}, "internal: empty field path")
	}
	if len(fp.Parts) < 2 {
		return nil, errorf(fp.Pos, "field path %q must be qualified (e.g. 'ipv4.src' or '<label>.<field>')", fp.String())
	}
	if len(fp.Parts) > 2 {
		return nil, errorf(fp.Pos, "nested field access %q is not supported", fp.String())
	}
	qualifier, fieldName := fp.Parts[0], fp.Parts[1]
	layer, err := r.lookupByQualifier(qualifier, fp.Pos)
	if err != nil {
		return nil, err
	}
	f, ok := layer.Spec.FindField(fieldName)
	if !ok {
		return nil, errorf(fp.Pos, "protocol %q has no field %q", layer.Spec.Name, fieldName)
	}
	return &ir.FieldRef{Layer: layer, Field: f}, nil
}

// lookupByQualifier resolves a name to a layer. User labels and
// auto-indexed keys live in r.labels; a bare protocol name resolves
// only when there is exactly one instance of that protocol.
func (r *resolver) lookupByQualifier(name string, pos ast.Position) (*ir.LayerInstance, error) {
	if li, ok := r.labels[name]; ok {
		return li, nil
	}
	var found *ir.LayerInstance
	count := 0
	for _, li := range r.flatLayers {
		if li.Spec != nil && li.Spec.Name == name {
			found = li
			count++
		}
	}
	switch count {
	case 0:
		return nil, errorf(pos, "unknown label or protocol %q", name)
	case 1:
		return found, nil
	}
	return nil, errorf(pos, "protocol %q is ambiguous (%d instances); qualify with an @label", name, count)
}
