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
// LayerInstance slice; MVP-specific constraints (alt count cap,
// quantifier on the group) are enforced by codegen.
//
// Nested alt groups (`((a|b)|(c|d))`, P3-13) are flattened here
// when the inner group has the default QuantOne — semantically
// equivalent to `(a|b|c|d)` because alt members are single layers
// with no chain / quantifier / predicate of their own. Inner alt
// groups that carry a quantifier (`(a|b)?`, `(a|b)+`, etc.) are
// left intact, so codegen's "QuantOne only on alt" check still
// fires with a clear error — supporting quantified nested alt
// would be different semantics and is not part of P3-13.
func (r *resolver) resolveAlternation(al *ast.Layer, parent *ir.LayerInstance) (*ir.LayerInstance, error) {
	flattened := flattenAltMembers(al.Alternatives)
	alts := make([]*ir.LayerInstance, 0, len(flattened))
	for _, a := range flattened {
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

// flattenAltMembers walks `((a|b)|c)` into `(a|b|c)`. Recursive on
// LayerAltGroup members with QuantOne; quantified alt groups stay
// as-is (codegen will reject them downstream). Order of leaf
// members is preserved (depth-first left-to-right) so error
// messages and alt-index stamping match the source order users
// see in the filter expression.
func flattenAltMembers(members []*ast.Layer) []*ast.Layer {
	out := make([]*ast.Layer, 0, len(members))
	for _, m := range members {
		if m.Kind == ast.LayerAltGroup && m.Quant == ast.QuantOne {
			out = append(out, flattenAltMembers(m.Alternatives)...)
			continue
		}
		out = append(out, m)
	}
	return out
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
// is an alternation group. We collect every alt's dispatch const and
// detect whether they agree on type / field name / value / bit width:
//
//   - all agree → fast path: IsAltDiverged=false, Const carries the
//     single representative; codegen emits one dispatch check exactly
//     like the non-alt case.
//   - any disagree → diverged path: IsAltDiverged=true, AltConsts
//     carries the per-alt vector; codegen routes through the
//     matched-alt-index flag set by the alt block (`(ipv4|ipv6)/tcp`
//     etc., where IPv4 reads `protocol` at byte 9 and IPv6 reads
//     `next_header` at byte 6).
//
// Per-alt missing dispatch (the alt has no `<self>_<altname>_<field>`
// const at all) is still a hard error — a divergence means each alt
// resolves to a *different* const, not "no const for some alt".
func selectAltParentDispatch(spec *vocab.ProtocolSpec, alts []*ir.LayerInstance, pos ast.Position) (*ir.DispatchChoice, error) {
	altConsts := make([]*vocab.DispatchConst, 0, len(alts))
	diverged := false
	var representative *vocab.DispatchConst
	for _, alt := range alts {
		c := spec.SelectDispatchConst(alt.Spec.Name)
		if c == nil {
			return nil, errorf(pos, "no dispatch constant for %q under alternative %q (declare %s_%s_<FIELD|NO_CHECK> in %s.p4, or have %s.p4 self-validate via a parser-block `transition select(...) { ...; default: reject; }`)", spec.Name, alt.Spec.Name, strings.ToUpper(spec.Name), strings.ToUpper(alt.Spec.Name), spec.Name, spec.Name)
		}
		altConsts = append(altConsts, c)
		if representative == nil {
			representative = c
			continue
		}
		if !altDispatchAgrees(representative, c) {
			diverged = true
		}
	}
	choice := &ir.DispatchChoice{
		Type:          representative.Type,
		Const:         representative,
		AltConsts:     altConsts,
		IsAltDiverged: diverged,
	}
	// Codegen for diverged dispatch only handles DispatchField (the
	// per-alt offset / value pair fits the single LDX + JNE shape).
	// NoCheck alts are already rejected by validateAlternatives, and
	// SelfValidating + diverged-shape would need parser-machine
	// integration that isn't planned.
	if diverged {
		for _, c := range altConsts {
			if c.Type != vocab.DispatchField {
				return nil, errorf(pos, "alternation alts disagree on dispatch for %q and at least one alt uses %s dispatch — codegen only handles diverged Field dispatch (per-alt JNE check)", spec.Name, c.Type)
			}
		}
	}
	return choice, nil
}

func altDispatchAgrees(a, b *vocab.DispatchConst) bool {
	return a.Type == b.Type && a.FieldName == b.FieldName && a.Value == b.Value && a.Bits == b.Bits
}

func autoKey(proto string, index int) string {
	return fmt.Sprintf("%s#%d", proto, index)
}
