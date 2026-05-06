package resolve

import (
	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
)

// resolveCapture binds a capture clause, including the optional
// per-capture where condition and the field list for CapFields.
func (r *resolver) resolveCapture(ac *ast.CaptureClause) (*ir.CaptureClause, error) {
	out := &ir.CaptureClause{
		Kind:  ac.Kind,
		Extra: ac.Extra,
		Pos:   ac.Pos,
	}
	// Only CapFields is parser-marked Unsupported in MVP. CapToLayer
	// and CapAbsolute are fully supported by codegen — quantifier-
	// chain incompatibility is detected later by prefixHeaderSize, not
	// signalled via Unsupported.
	if ac.Unsupported {
		out.Unsupported = "field-list capture is not yet implemented in MVP codegen"
	}
	if ac.Kind == ast.CapFields {
		refs := make([]*ir.FieldRef, 0, len(ac.Fields))
		for _, fp := range ac.Fields {
			ref, err := r.resolveQualifiedField(fp)
			if err != nil {
				return nil, err
			}
			refs = append(refs, ref)
		}
		out.Fields = refs
	}
	if ac.Kind == ast.CapToLayer {
		layer, err := r.lookupByQualifier(ac.LayerName, ac.Pos)
		if err != nil {
			return nil, err
		}
		out.TargetLayer = layer
	}
	if ac.Kind == ast.CapAbsolute && ac.Extra <= 0 {
		return nil, errorf(ac.Pos, "`capture absolute %d` must be > 0", ac.Extra)
	}
	if ac.Where != nil {
		w, err := r.resolveWhere(ac.Where)
		if err != nil {
			return nil, err
		}
		out.Where = w
	}
	return out, nil
}
