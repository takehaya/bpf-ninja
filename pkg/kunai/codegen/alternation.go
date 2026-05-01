package codegen

import (
	"fmt"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
)

// altCountCap is the MVP upper bound on alternatives per group. The
// emitted stream grows roughly linearly per alternative (bounds is
// shared; dispatch + predicates + branching per alt), and beyond four
// the filter-expression readability collapses anyway.
const altCountCap = 4

// genAlternation emits `(a|b|c)`. Each alternative is tried in order:
// its dispatch check jumps to the next alternative on mismatch; on
// match the alternative's predicates run and control jumps to the
// shared group-end landing. When no alternative matches, the last
// alt's dispatch falls through to dslReject. offsetBase advances by
// the group's uniform header size exactly once at the end.
//
// MVP constraints:
//   - alt count ∈ [2, altCountCap]
//   - QuantOne only
//   - every alternative has the same headerSize (so the post-group
//     advance is a single Add.Imm regardless of which alt matched)
//   - every alternative carries a parent-side dispatch (no first-
//     layer alternation)
//   - no nested alternation
//
// Layers following an alternation group stay Unsupported at resolve
// time — the post-group dispatch selection is a separate feature.
func genAlternation(layer *ir.LayerInstance, index int, all []*ir.LayerInstance) (asm.Instructions, error) {
	if layer.Quant != ast.QuantOne {
		return nil, fmt.Errorf("%w: quantifier %s on alternation group", ErrNotImplemented, layer.Quant)
	}
	if index == 0 {
		return nil, fmt.Errorf("%w: alternation as the first layer has no parent to dispatch from", ErrNotImplemented)
	}
	alts := layer.Alternation
	if len(alts) < 2 {
		return nil, fmt.Errorf("%w: alternation needs at least two alternatives, got %d", ErrNotImplemented, len(alts))
	}
	if len(alts) > altCountCap {
		return nil, fmt.Errorf("%w: alternation with %d alts exceeds MVP cap %d", ErrNotImplemented, len(alts), altCountCap)
	}

	if err := validateAlternatives(alts); err != nil {
		return nil, err
	}
	hs, err := uniformAltHeaderSize(alts)
	if err != nil {
		return nil, err
	}

	parent := dispatchParent(all[index-1])
	parentHS, err := headerSize(parent.Spec)
	if err != nil {
		return nil, err
	}

	altEnd := fmt.Sprintf("dsl_alt_end_%d", index)

	// Bounds check fires once — every alt has the same hs so the
	// verifier's bounds decision is the same regardless of which
	// dispatch winds up matching.
	insns := emitBounds(hs, dslReject)

	for i, alt := range alts {
		failLabel := dslReject
		if i+1 < len(alts) {
			failLabel = fmt.Sprintf("dsl_alt_%d_%d", index, i+1)
		}

		dispatch, err := genDispatch(alt, parent, parentHS, failLabel)
		if err != nil {
			return nil, err
		}
		preds, err := emitPredicates(alt.Predicates)
		if err != nil {
			return nil, err
		}

		// Append directly to insns (no intermediate slice) and
		// remember the index of this alt's first instruction so we
		// can stamp the entry-point symbol. i==0 has no jumpers, so
		// it needs no symbol.
		start := len(insns)
		insns = append(insns, dispatch...)
		insns = append(insns, preds...)
		if i > 0 {
			sym := fmt.Sprintf("dsl_alt_%d_%d", index, i)
			if existing := insns[start].Symbol(); existing != "" {
				return nil, fmt.Errorf("codegen: alt %d entry already carries symbol %q", i, existing)
			}
			insns[start] = insns[start].WithSymbol(sym)
		}

		if i+1 < len(alts) {
			insns = append(insns, asm.Ja.Label(altEnd))
		}
		// The last alternative falls through naturally to the advance.
	}

	insns = append(insns, emitAdvance(hs).WithSymbol(altEnd))
	return insns, nil
}

// validateAlternatives walks the alt list once rejecting MVP-invalid
// shapes so the emission loop stays focused on codegen. NoCheck
// dispatch is rejected because two fall-through alternatives are
// semantic noise — the first one always "wins" and codegen would
// have to emit a no-op symbol holder.
func validateAlternatives(alts []*ir.LayerInstance) error {
	for _, alt := range alts {
		if alt.Alternation != nil {
			return fmt.Errorf("%w: nested alternation group", ErrNotImplemented)
		}
		if alt.Dispatch == nil {
			return fmt.Errorf("%w: alternative %q has no parent dispatch", ErrNotImplemented, alt.Spec.Name)
		}
		if alt.Dispatch.Type == vocab.DispatchNoCheck {
			return fmt.Errorf("%w: alternative %q uses NoCheck dispatch — alternation needs a distinguishing predicate", ErrNotImplemented, alt.Spec.Name)
		}
	}
	return nil
}

// uniformAltHeaderSize returns the header size every alternative
// shares, or an ErrNotImplemented when they diverge. Uniformity lets
// genAlternation use a single advance and a single bounds check at
// the group level.
func uniformAltHeaderSize(alts []*ir.LayerInstance) (int, error) {
	hs, err := headerSize(alts[0].Spec)
	if err != nil {
		return 0, err
	}
	for _, alt := range alts[1:] {
		other, err := headerSize(alt.Spec)
		if err != nil {
			return 0, err
		}
		if other != hs {
			return 0, fmt.Errorf("%w: alternation alt %q has header size %d, expected %d (MVP requires uniform size)", ErrNotImplemented, alt.Spec.Name, other, hs)
		}
	}
	return hs, nil
}
