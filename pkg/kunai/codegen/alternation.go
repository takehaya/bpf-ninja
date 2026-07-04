package codegen

import (
	"fmt"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
)

// altCountCap is the MVP upper bound on alternatives per group. The
// emitted stream grows linearly per alternative (per-alt guard +
// full layer body), and beyond four the filter-expression readability
// collapses anyway.
const altCountCap = 4

// matchedAltReg holds the matched alt index for the layer immediately
// following an alt group with diverged dispatch (P3-12). genAlternation
// stores the alt index here as it falls through to altEnd, and
// genFieldDispatchAltDiverged reads it back to pick the correct alt's
// dispatch field/value pair. R5 is otherwise unused between the alt
// emit and the next layer's dispatch (only the where-arith pipeline
// uses R5, and that runs after every chain layer).
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
// When the layer immediately following the alt group has IsAltDiverged
// dispatch, each alt branch additionally records its own index in
// matchedAltReg before falling through to altEnd, so the next layer
// can read it back and pick the right per-alt dispatch field.
//
// MVP constraints:
//   - alt count ∈ [2, altCountCap]
//   - QuantOne only
//   - every alternative carries a parent-side dispatch (no first-
//     layer alternation)
//   - no nested alternation
//   - DispatchNoCheck alternatives are rejected (a fall-through alt
//     would always "win" — semantic noise)
//   - alt members must use Field dispatch (the guard is a Field check)
func genAlternation(layer *ir.LayerInstance, index int, all []*ir.LayerInstance, qo queriedOptions, plan *accPlan, pc *predCtx) (asm.Instructions, asm.Instructions, error) {
	if layer.Quant != ast.QuantOne {
		return nil, nil, fmt.Errorf("%w: quantifier %s on alternation group", ErrNotImplemented, layer.Quant)
	}
	if index == 0 {
		return nil, nil, fmt.Errorf("%w: alternation as the first layer has no parent to dispatch from", ErrNotImplemented)
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

	parent := dispatchParent(all[index-1])
	parentHS, err := headerSize(parent.Spec)
	if err != nil {
		return nil, nil, err
	}

	altEnd := fmt.Sprintf("dsl_alt_end_%d", index)

	// Only emit `Mov R5, i` markers when a downstream layer actually
	// reads them — otherwise uniform-dispatch alts (vlan|qinq) would
	// carry dead writes to R5 that just bloat the stream.
	needMatchedFlag := false
	if index+1 < len(all) {
		next := all[index+1]
		if next.Dispatch != nil && next.Dispatch.IsAltDiverged {
			needMatchedFlag = true
		}
	}

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
			guard, err := emitAltGuard(alt, parent, parentHS, nextAltLabel)
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

		if needMatchedFlag {
			insns = append(insns, asm.Mov.Imm(matchedAltReg, int32(i)))
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

// emitAltGuard emits the per-alt lookahead: load parent's dispatch
// field and JNE to nextAltLabel on mismatch. Identical shape to the
// fixed-size dispatch check, but routed to the next alt's entry
// rather than dslReject so the body of the previous alt can be
// skipped without rejecting the packet outright.
func emitAltGuard(alt *ir.LayerInstance, parent *ir.LayerInstance, parentHS int, nextAltLabel string) (asm.Instructions, error) {
	if alt.Dispatch == nil || alt.Dispatch.Type != vocab.DispatchField {
		return nil, fmt.Errorf("%w: alternation guard requires Field dispatch on alt %q (got %v)", ErrNotImplemented, alt.Spec.Name, alt.Dispatch.Type)
	}
	if parent.Spec.HasVariableLayout() {
		return emitFieldDispatchCheck(
			parent.Spec,
			alt.Dispatch.Const,
			0,
			asm.R3,
			asm.Instructions{
				asm.LoadMem(asm.R3, asm.R10, bpfLoopCtxLayerEntrySlot, asm.DWord),
				asm.Add.Reg(asm.R3, asm.R0),
			},
			nextAltLabel,
		)
	}
	return emitFieldDispatchCheck(
		parent.Spec,
		alt.Dispatch.Const,
		parentHS,
		asm.R3,
		asm.Instructions{
			asm.Mov.Reg(asm.R3, asm.R0),
			asm.Add.Reg(asm.R3, offsetBase),
		},
		nextAltLabel,
	)
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
