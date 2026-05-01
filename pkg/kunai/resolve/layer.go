package resolve

import (
	"fmt"
	"strings"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
)

func (r *resolver) resolveLayer(al *ast.Layer, parent *ir.LayerInstance) (*ir.LayerInstance, error) {
	if al.Kind == ast.LayerAltGroup {
		return r.resolveAlternation(al, parent)
	}

	spec, ok := r.vocab[al.ProtoName]
	if !ok {
		return nil, errorf(al.Pos, "unknown protocol %q", al.ProtoName)
	}

	li := &ir.LayerInstance{
		Spec:     spec,
		Quant:    al.Quant,
		RangeMin: al.RangeMin,
		RangeMax: al.RangeMax,
		Pos:      al.Pos,
	}

	// Auto-index captures occurrence order even when no label is written.
	li.Index = r.protoAutoIndex[spec.Name]
	r.protoAutoIndex[spec.Name]++

	if al.Label != "" {
		if _, conflict := r.vocab[al.Label]; conflict {
			return nil, errorf(al.Pos, "label %q collides with protocol name", al.Label)
		}
		if _, dup := r.labels[al.Label]; dup {
			return nil, errorf(al.Pos, "duplicate label %q", al.Label)
		}
		li.Label = al.Label
		r.labels[al.Label] = li
		r.protoLabelCount[spec.Name]++
	}
	r.labels[autoKey(spec.Name, li.Index)] = li
	r.flatLayers = append(r.flatLayers, li)

	for _, ap := range al.Predicates {
		rp, err := r.resolveBracketPredicate(ap, li)
		if err != nil {
			return nil, err
		}
		li.Predicates = append(li.Predicates, rp)
	}

	if parent != nil {
		var (
			choice *ir.DispatchChoice
			err    error
		)
		if parent.Alternation != nil {
			choice, err = selectAltParentDispatch(spec, parent.Alternation, al.Pos)
		} else {
			choice, err = selectDispatch(spec, parent.Spec.Name, al.Pos)
		}
		if err != nil {
			return nil, err
		}
		li.Dispatch = choice
	}

	return li, nil
}

// resolveAlternation resolves each alternative so name and dispatch
// errors still surface. The group itself carries the per-alt
// LayerInstance slice; MVP-specific constraints (uniform header
// size, alt count cap, quantifier) are enforced by codegen.
func (r *resolver) resolveAlternation(al *ast.Layer, parent *ir.LayerInstance) (*ir.LayerInstance, error) {
	alts := make([]*ir.LayerInstance, 0, len(al.Alternatives))
	for _, a := range al.Alternatives {
		alt, err := r.resolveLayer(a, parent)
		if err != nil {
			return nil, err
		}
		alts = append(alts, alt)
	}
	return &ir.LayerInstance{
		Alternation: alts,
		Quant:       al.Quant,
		RangeMin:    al.RangeMin,
		RangeMax:    al.RangeMax,
		Pos:         al.Pos,
	}, nil
}

// selectDispatch finds the strongest matching DispatchConst on spec
// whose Parent equals parentName and wraps it in an ir.DispatchChoice.
// When no const matches but the child's parser block self-validates
// (e.g. ipv4 / ipv6 with `transition select(version) { ...; default:
// reject; }`), we synthesize a DispatchSelfValidating choice — the
// boundary emits nothing and the parser machine handles the check.
func selectDispatch(spec *vocab.ProtocolSpec, parentName string, pos ast.Position) (*ir.DispatchChoice, error) {
	c := spec.SelectDispatchConst(parentName)
	if c == nil {
		if spec.IsSelfValidating() {
			return &ir.DispatchChoice{Type: vocab.DispatchSelfValidating}, nil
		}
		return nil, errorf(pos, "no dispatch constant for %q under %q (declare %s_%s_<FIELD|NO_CHECK> in %s.p4, or have %s.p4 self-validate via a parser-block `transition select(...) { ...; default: reject; }`)", spec.Name, parentName, strings.ToUpper(spec.Name), strings.ToUpper(parentName), spec.Name, spec.Name)
	}
	return &ir.DispatchChoice{Type: c.Type, Const: c}, nil
}

// selectAltParentDispatch handles the case where this layer's parent
// is an alternation group. Codegen uses the first alt as the dispatch
// reference (alt groups are uniform per the MVP), so every alt must
// resolve to a dispatch const that agrees on type, field name, value,
// and bit width. Diverging alts get a targeted diagnostic so the
// vocab author can decide whether to add the missing const or rework
// the filter expression.
func selectAltParentDispatch(spec *vocab.ProtocolSpec, alts []*ir.LayerInstance, pos ast.Position) (*ir.DispatchChoice, error) {
	var representative *vocab.DispatchConst
	for _, alt := range alts {
		c := spec.SelectDispatchConst(alt.Spec.Name)
		if c == nil {
			return nil, errorf(pos, "no dispatch constant for %q under alternative %q (declare %s_%s_<FIELD|NO_CHECK> in %s.p4, or have %s.p4 self-validate via a parser-block `transition select(...) { ...; default: reject; }`)", spec.Name, alt.Spec.Name, strings.ToUpper(spec.Name), strings.ToUpper(alt.Spec.Name), spec.Name, spec.Name)
		}
		if representative == nil {
			representative = c
			continue
		}
		if !altDispatchAgrees(representative, c) {
			return nil, errorf(pos, "alternation alts disagree on dispatch for %q: %q vs %q (MVP requires matching field/value across alts)", spec.Name, representative.Name, c.Name)
		}
	}
	return &ir.DispatchChoice{Type: representative.Type, Const: representative}, nil
}

func altDispatchAgrees(a, b *vocab.DispatchConst) bool {
	return a.Type == b.Type && a.FieldName == b.FieldName && a.Value == b.Value && a.Bits == b.Bits
}

func autoKey(proto string, index int) string {
	return fmt.Sprintf("%s#%d", proto, index)
}
