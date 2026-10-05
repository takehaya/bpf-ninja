package codegen

import (
	"fmt"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
	"github.com/takehaya/bpf-ninja/pkg/kunai/ir"
	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
)

// altCountCap is the MVP upper bound on alternatives per group. The
// emitted stream grows linearly per alternative (per-alt guard +
// full layer body), and beyond four the filter-expression readability
// collapses anyway.
const altCountCap = 4

// matchedAltReg is the register genFieldDispatchAltDiverged loads the
// group's matched-member slot into to pick the matched member's dispatch
// field/value pair (P3-12). The index lives in the slot, not in the
// register, between the group and its readers: a member's body may call
// bpf_loop, and a second group's members each need it.
var matchedAltReg = asm.R5

// genAlternation emits `(a|b|c)`. Each non-last alt is fronted by a
// 2-insn guard (LDX parent.<field>; JNE alt.value, dsl_alt_<idx>_<i+1>)
// that routes a mismatch to the next alt's entry; the last alt has no
// guard since its body's own dispatch failure correctly lands at
// dslReject. After the guard each alt's full layer body runs via
// genLayerInner — that gives us bounds, dispatch (re-checked, redundant
// but cheap), predicates, slot store, advance, primary variable tail,
// flag triggers, and parser-machine self-loops, exactly the same way
// a non-alt layer would emit them. Per-alt size differences therefore
// fall out for free (each body advances R4 by its own size).
//
// When something reads which member matched — the next layer's
// IsAltDiverged dispatch, or a where / capture read of a member — each
// alt branch records its own index in the group's matched-member slot
// (queriedOptions.matchedSlot) before falling through to altEnd.
//
// MVP constraints (the resolver's checkChainShape rejects the typing
// violations first; the guards below stay as defence in depth):
//   - alt count ∈ [2, altCountCap]
//   - QuantOne only
//   - every alternative carries a parent-side dispatch (no first-
//     layer alternation)
//   - no nested alternation
//   - alt members must use Field dispatch (the guard is a Field check;
//     a NoCheck alternative would always "win")
func genAlternation(layer *ir.LayerInstance, index int, all []*ir.LayerInstance, qo queriedOptions, plan *accPlan, pc *predCtx) (asm.Instructions, asm.Instructions, error) {
	if layer.Quant != ast.QuantOne {
		return nil, nil, fmt.Errorf("%w: quantifier %s on alternation group", ErrNotImplemented, layer.Quant)
	}
	if index == 0 {
		return nil, nil, fmt.Errorf("%w: alternation as the first layer has no parent to dispatch from", ErrNotImplemented)
	}
	// The member guards read the static parent; after optional layers
	// (or an alternation behind them) that dispatch a member differently
	// the guard would be unsound.
	for _, alt := range layer.Alternation {
		alike, err := ir.RuntimeParentsDispatchAlike(all, index, alt.Spec)
		if err != nil {
			return nil, nil, err
		}
		if !alike {
			return nil, nil, fmt.Errorf("%w: alternation %s after optional layers whose runtime parents dispatch %q differently", ErrNotImplemented, layer.DisplayName(), alt.Spec.Name)
		}
	}
	alts := layer.Alternation
	if len(alts) < 2 {
		return nil, nil, fmt.Errorf("%w: alternation needs at least two alternatives, got %d", ErrNotImplemented, len(alts))
	}
	if len(alts) > altCountCap {
		return nil, nil, fmt.Errorf("%w: alternation with %d alts exceeds MVP cap %d", ErrNotImplemented, len(alts), altCountCap)
	}

	if err := validateAlternatives(alts); err != nil {
		return nil, nil, err
	}


	altEnd := fmt.Sprintf("dsl_alt_end_%d", index)

	var (
		insns     asm.Instructions
		callbacks asm.Instructions
	)
	// If the accumulator plan targets one of these alternation members,
	// zero its acc slot before the dispatch. A non-matching branch never
	// runs that member's parser machine (which is where the slot is
	// otherwise inited), so without this the post-layer (acc & mask) == mask
	// check would read an undefined slot on that branch.
	if plan != nil {
		for _, alt := range alts {
			if plan.layer != alt {
				continue
			}
			slot, err := plan.accSlot(qo)
			if err != nil {
				return nil, nil, err
			}
			// R3 is a scratch register here (the same one
			// emitDynamicAuxSentinelInit uses); R0/R1 hold the packet
			// window and must not be clobbered.
			insns = append(insns,
				asm.Mov.Imm(asm.R3, 0),
				asm.StoreMem(asm.R10, slot, asm.R3, asm.DWord),
			)
			break
		}
	}
	for i, alt := range alts {
		altStart := len(insns)

		// Guard for non-last alts: route a mismatch to the next alt's
		// entry. Last alt has no guard since its body's dispatch
		// already targets dslReject (correct on no-match).
		if i+1 < len(alts) {
			nextAltLabel := fmt.Sprintf("dsl_alt_%d_%d", index, i+1)
			// The guard is the member's own dispatch, failing to the next
			// alt instead of dslReject; after a group whose members
			// dispatch this one differently it is picked by the parent's
			// matched member.
			guard, err := genParentDispatch(alt, index, all, qo, precedingLayersLeaveR4Range(all, index), precedingLayersLeaveR4Range(all, index-1), nextAltLabel)
			if err != nil {
				return nil, nil, err
			}
			insns = append(insns, guard...)
		}

		// Full alt-member body via the same path a standalone layer
		// would take (bounds + dispatch + preds + advance + tail +
		// flags + parser machine). Dispatch in the body re-checks the
		// same field as the guard but with dslReject as failLabel —
		// since the guard already passed, the body's dispatch will
		// pass too, so the duplicate is dead code at runtime. The
		// alternative is threading a custom fail label through every
		// layer emit which is a much larger refactor for marginal gain.
		// Thread the accumulator plan only to the member it targets (e.g.
		// the tcp member of `(tcp|udp) where tcp.options.MSS.value == ..`);
		// other members and the non-accumulator case get nil and stay on
		// the per-option path. The acc slot was zeroed above so a non-
		// matching branch still leaves it defined for the post-layer mask
		// check.
		altPlan := (*accPlan)(nil)
		if plan != nil && plan.layer == alt {
			altPlan = plan
		}
		altBody, altCbs, err := genLayerInner(alt, index, all, qo, altPlan, pc)
		if err != nil {
			return nil, nil, err
		}
		insns = append(insns, altBody...)
		callbacks = append(callbacks, altCbs...)

		// Something reads which member matched (the slot is planned only
		// then): the next layer's diverged dispatch, or a where / capture
		// read of a member, which is false on another member (D-003)
		// instead of reading this member's bytes. R3 is scratch after the
		// member's body.
		if slot, ok := qo.matchedSlot(layer.LayerPos); ok {
			insns = append(insns,
				asm.Mov.Imm(asm.R3, int32(i)),
				asm.StoreMem(asm.R10, slot, asm.R3, asm.DWord),
			)
		}

		if i > 0 {
			sym := fmt.Sprintf("dsl_alt_%d_%d", index, i)
			if existing := insns[altStart].Symbol(); existing != "" {
				return nil, nil, fmt.Errorf("codegen: alt %d entry already carries symbol %q", i, existing)
			}
			insns[altStart] = insns[altStart].WithSymbol(sym)
		}

		if i+1 < len(alts) {
			insns = append(insns, asm.Ja.Label(altEnd))
		}
		// The last alt falls through naturally to the altEnd landing.
	}

	// Landing for the `Ja altEnd` jumps from earlier alts. We use a
	// `Mov R0, R0` rather than the canonical `Mov R3, R3` (landingNoop)
	// because the alt body may end in a parser machine bpf_loop —
	// after a bpf_loop call R3 is killed by the helper, while R0 is
	// reloaded from a stack save. Same idiom genParserMachine's done
	// landing uses for the same reason.
	insns = append(insns, asm.Mov.Reg(asm.R0, asm.R0).WithSymbol(altEnd))
	return insns, callbacks, nil
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
