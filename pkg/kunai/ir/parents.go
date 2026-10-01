package ir

import (
	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
)

// RuntimeParents lists the indices of the layers that can end right
// before layer `i` at run time, nearest first: the static predecessor
// and, while that layer may match zero headers, the one before it. The
// walk stops at an alternation group without listing it; altReached
// reports that case (the group's members keep the static rule, so a
// caller that needs every runtime parent has to refuse the shape).
func RuntimeParents(layers []*LayerInstance, i int) (parents []int, altReached bool) {
	for j := i - 1; j >= 0; j-- {
		prev := layers[j]
		if prev.Alternation != nil {
			return parents, true
		}
		parents = append(parents, j)
		if !prev.Absentable() {
			return parents, false
		}
	}
	return parents, false
}

// AbsentEdgeApplies reports whether the absent path of the absentable
// layer at `i` carries its own dispatch of the next layer against the
// grandparent (D-034). It needs a non-absentable, non-alternation
// grandparent and a plain (QuantOne, non-alternation) next layer; other
// shapes dispatch the next layer against its runtime parent instead
// (NeedsParentCascade).
func AbsentEdgeApplies(layers []*LayerInstance, i int) bool {
	if i < 1 || i+1 >= len(layers) || !layers[i].Absentable() {
		return false
	}
	gp, next := layers[i-1], layers[i+1]
	if gp.Absentable() || gp.Alternation != nil {
		return false
	}
	return next.Quant == ast.QuantOne && next.Alternation == nil && next.Dispatch != nil && !next.Dispatch.IsAltDiverged
}

// NeedsParentCascade reports whether layer `i` must pick its dispatch at
// run time among several possible parents: it follows absentable layers
// whose absent edge does not dispatch it (AbsentEdgeApplies), and those
// parents do not all dispatch it the same way (vocab.DispatchEquivalent).
// The returned parents are the candidates, nearest first; altReached is
// RuntimeParents' flag.
func NeedsParentCascade(layers []*LayerInstance, i int) (needed bool, parents []int, altReached bool, err error) {
	cur := layers[i]
	if i == 0 || cur.Alternation != nil || cur.Dispatch == nil || cur.Dispatch.IsAltDiverged {
		return false, nil, false, nil
	}
	parents, altReached = RuntimeParents(layers, i)
	if len(parents) == 0 || AbsentEdgeApplies(layers, i-1) {
		return false, parents, altReached, nil
	}
	alike, err := RuntimeParentsDispatchAlike(layers, i, cur.Spec)
	if err != nil {
		return false, nil, false, err
	}
	return !alike, parents, altReached, nil
}

// RuntimeParentsDispatchAlike reports whether every layer that can
// precede layer `i` at run time dispatches `child` the same way as the
// static predecessor does: the listed parents and, when the walk ran into
// an alternation, each of its members (vocab.DispatchEquivalentFor).
func RuntimeParentsDispatchAlike(layers []*LayerInstance, i int, child *vocab.ProtocolSpec) (bool, error) {
	parents, altReached := RuntimeParents(layers, i)
	if len(parents) == 0 {
		return true, nil
	}
	static := layers[parents[0]]
	others := make([]*vocab.ProtocolSpec, 0, len(parents))
	for _, j := range parents[1:] {
		others = append(others, layers[j].Spec)
	}
	if altReached {
		for _, alt := range layers[parents[len(parents)-1]-1].Alternation {
			others = append(others, alt.Spec)
		}
	}
	for _, other := range others {
		same, err := static.Spec.DispatchEquivalentFor(child, other)
		if err != nil {
			return false, err
		}
		if !same {
			return false, nil
		}
	}
	return true, nil
}
