package resolve

import (
	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
	"github.com/takehaya/bpf-ninja/pkg/kunai/ir"
)

// dropEmptyLayers removes the layers quantified `{0,0}` from the
// program. Such a layer takes no header (spec iterate with fuel 0): it
// extracts nothing, evaluates no bracket and binds no label, so its
// follower dispatches off the layer before it. The static checks have
// already seen it (its edge, its brackets, the follower's runtime
// parents) and the label table keeps it, so a bare protocol name still
// counts it. What remains is lowered as the chain without it:
//   - the follower's dispatch is chosen against the kept predecessor;
//   - a where atom reading the layer is false (D-003, an absent layer),
//     and so is any()/all() over its stacks; codegen folds the rest;
//   - `capture <label>` of the layer captures through its predecessor.
//     The spec drops the clause (D-020); Go already captures the static
//     bound for an absent `?` layer, and the retarget keeps that policy.
//     A field capture (CapFields) never gets here: the parser marks it
//     unsupported.
//
// The first layer cannot be `{0,0}` (checkChainShape), so every dropped
// layer has a kept predecessor. An alternation group is never dropped.
func dropEmptyLayers(p *ir.Program) error {
	dropped := map[*ir.LayerInstance]*ir.LayerInstance{}
	kept := make([]*ir.LayerInstance, 0, len(p.Layers))
	for i, l := range p.Layers {
		if _, max := l.Bounds(); i > 0 && l.Alternation == nil && max == 0 {
			dropped[l] = kept[len(kept)-1]
			continue
		}
		if i > 0 && dropped[p.Layers[i-1]] != nil {
			if err := redispatch(l, kept[len(kept)-1]); err != nil {
				return err
			}
		}
		kept = append(kept, l)
	}
	if len(dropped) == 0 {
		return nil
	}
	p.Layers = kept
	p.Where = foldDroppedLayerAtoms(p.Where, dropped)
	for _, c := range p.Captures {
		c.Where = foldDroppedLayerAtoms(c.Where, dropped)
		if c.Kind != ast.CapToLayer {
			continue
		}
		if pred, ok := dropped[c.TargetLayer]; ok {
			if pred.Alternation != nil {
				c.Unsupported = "capture of a `{0,0}` layer that follows an alternation"
				continue
			}
			c.TargetLayer = pred
		}
	}
	return nil
}

// redispatch chooses l's dispatch, or each member's for a group, against
// parent, the layer l follows once the `{0,0}` layers between them are
// gone. checkRuntimeParents has already required that edge for a plain
// parent; after a group it has not, and a missing edge is the type error
// here. The rule for an absentable layer on a no-check dispatch
// (checkChainShape) runs again against the new parent.
func redispatch(l, parent *ir.LayerInstance) error {
	members := []*ir.LayerInstance{l}
	if l.Alternation != nil {
		members = l.Alternation
	}
	for _, m := range members {
		var (
			choice *ir.DispatchChoice
			err    error
		)
		if parent.Alternation != nil {
			choice, err = selectAltParentDispatch(m.Spec, parent.Alternation, m.Pos)
		} else {
			choice, err = selectDispatch(m.Spec, parent.Spec.Name, m.Pos)
		}
		if err != nil {
			return err
		}
		m.Dispatch = choice
	}
	if l.Alternation == nil {
		return checkNoCheckAbsence(l, parent)
	}
	return nil
}

// foldDroppedLayerAtoms returns w with every atom that reads a dropped
// layer replaced by `false`, and every any()/all() over a dropped
// layer's stack too. The atoms stay in place, so `not`, `or` and `==`
// between booleans see the false operand the spec gives them.
func foldDroppedLayerAtoms(w *ir.Condition, dropped map[*ir.LayerInstance]*ir.LayerInstance) *ir.Condition {
	if w == nil {
		return nil
	}
	falseAt := func() *ir.Condition {
		return &ir.Condition{Kind: ast.WAtomBoolLit, BoolLitValue: false, Pos: w.Pos}
	}
	switch w.Kind {
	case ast.WAnd, ast.WOr:
		c := *w
		c.Left = foldDroppedLayerAtoms(w.Left, dropped)
		c.Right = foldDroppedLayerAtoms(w.Right, dropped)
		return &c
	case ast.WNot:
		c := *w
		c.Inner = foldDroppedLayerAtoms(w.Inner, dropped)
		return &c
	case ast.WAtomBoolEq:
		c := *w
		c.BoolL = foldDroppedLayerAtoms(w.BoolL, dropped)
		c.BoolR = foldDroppedLayerAtoms(w.BoolR, dropped)
		return &c
	case ast.WAny, ast.WAll:
		if w.QuantTarget != nil {
			if _, ok := dropped[w.QuantTarget.Layer]; ok {
				return falseAt()
			}
		}
		c := *w
		c.Inner = foldDroppedLayerAtoms(w.Inner, dropped)
		return &c
	}
	readsDropped := false
	ir.WalkConditionFieldRefs(w, func(f *ir.FieldRef) {
		if _, ok := dropped[f.Layer]; ok {
			readsDropped = true
		}
	})
	if readsDropped {
		return falseAt()
	}
	return w
}
