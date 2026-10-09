package codegen

import (
	"fmt"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
	"github.com/takehaya/bpf-ninja/pkg/kunai/ir"
	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
)

// accAtom is one leaf of an accumulator plan: a single
// `<option.field> == <const>` equality on a dynamic-eligible TCP
// option. The TLV-walk callback reloads the option's kind byte at the
// live cursor, and when it matches DynamicKindByte, reads the field at
// cursor+fieldByteOff (width bytes, network byte order), compares it to
// cmpVal, and on equality ORs (1<<bit) into the single accumulator
// slot.
type accAtom struct {
	layout       *vocab.AuxLayout
	fieldByteOff int
	width        int // 1, 2, or 4 bytes
	cmpVal       uint64
	bit          int
	// never marks a leaf whose constant the field cannot hold (an
	// `int<128>(n)` at or above 2^width): the equality is false for every
	// packet (D-035 compares values, whatever the width). Such an atom
	// never gets a bit; the plan records it as `never` instead.
	never bool
}

// accPlan is the accumulator lowering for a multi-option TCP `where`
// clause that is a pure conjunction of `<option.field> == <const>`
// leaves. Instead of recording each queried option's byte position into
// a distinct stack slot (which blows the verifier's state budget for
// >=2 options, see emitStateBody), the per-iteration callback collects a
// RESULT BIT per leaf into ONE accumulator slot. The where clause then
// reduces to a single `(acc & mask) == mask` check.
//
// nil when the program is not eligible — callers fall back to the
// existing compile-time reject for >=2 length-byte options.
type accPlan struct {
	layer *ir.LayerInstance
	atoms []accAtom
	mask  uint64 // OR of (1<<bit) for every atom
	// valid is set when the conjunction also holds `<layer>.options.valid`
	// (spec D-029): the mask check then also requires the layer's
	// validity flag. The malformed landing zeroes the accumulator too, so
	// the flag check is defensive: it keeps the rule from depending on
	// that reset.
	valid bool
	// never is set when a leaf compares an option field against a constant
	// the field cannot hold: the conjunction is false for every packet, so
	// the mask check rejects unconditionally. The walk still runs (the slot
	// layout and the D-029 landing are unchanged); only the final check
	// collapses.
	never bool
	// residual holds the `<layer>.options.valid` leaves on layers other
	// than the plan's. Their flags come from those layers' own walks, so
	// the plan cannot fold them into the accumulator; the caller emits them
	// through genCondition after the mask check (with the usual absent-
	// layer guards) and ANDs the two.
	residual []*ir.Condition
}

// buildAccPlan inspects a merged where condition and the program's
// queried-option set, returning an accPlan when the whole clause is a
// pure conjunction of equality leaves over >=2 distinct dynamic-eligible
// options on a single layer, every leaf byte-aligned with width in
// {1,2,4}, optionally ANDed with `.options.valid` atoms (this layer's
// joins the mask check, another layer's goes to residual). A constant the
// field cannot hold marks the plan `never`. Returns nil for any other
// shape; the caller then falls through to the existing reject.
func buildAccPlan(where *ir.Condition, qo queriedOptions) *accPlan {
	if where == nil {
		return nil
	}
	leaves := flattenPureAnd(where)
	if leaves == nil {
		return nil
	}

	// atoms stays non-nil even when every leaf is `never`: atomsFor must
	// still report the plan to the walk (emitStateBody / the prelude).
	plan := &accPlan{atoms: []accAtom{}}
	seen := map[*vocab.AuxLayout]bool{}
	var validLeaves []*ir.Condition
	for _, leaf := range leaves {
		if leaf.Kind == ast.WAtomBoolValid {
			if leaf.BoolField == nil || leaf.BoolField.Layer == nil {
				return nil
			}
			validLeaves = append(validLeaves, leaf)
			continue
		}
		layer, atom, ok := eqLeafToAtom(leaf, qo)
		if !ok {
			return nil
		}
		// Every leaf must live on the same layer.
		if plan.layer == nil {
			plan.layer = layer
		} else if plan.layer != layer {
			return nil
		}
		// The option still counts as covered: its position slot is not
		// wanted, the leaf just can never hold.
		seen[atom.layout] = true
		if atom.never {
			plan.never = true
			continue
		}
		atom.bit = len(plan.atoms)
		plan.atoms = append(plan.atoms, atom)
		plan.mask |= uint64(1) << uint(atom.bit)
	}
	if plan.layer == nil {
		return nil
	}
	// `.options.valid` on the plan's own layer joins the mask check (that
	// layer's walk sets the flag). On another layer it stays a where atom
	// of its own, ANDed after the mask check (residual).
	for _, leaf := range validLeaves {
		if leaf.BoolField.Layer != plan.layer {
			plan.residual = append(plan.residual, leaf)
			continue
		}
		plan.valid = true
	}
	if plan.valid {
		if _, ok := qo.validSlot(plan.layer); !ok {
			return nil
		}
	}
	// Length-byte TLV walks retain the accumulator when a byte counter bounds
	// the region. Counter walks with another discriminator keep their path.
	if !layerOptionWalkHasLengthByte(plan.layer) {
		return nil
	}
	// Require >=2 DISTINCT queried options, and every option the layer
	// queries must be covered by an eq-leaf — otherwise an un-covered
	// queried option would still want its own recorded-position slot
	// (the explosion shape this lowering exists to avoid).
	if len(seen) < 2 {
		return nil
	}
	for _, layout := range qo.optionDemand(plan.layer) {
		if !seen[layout] {
			return nil
		}
	}
	// Cap the total number of option-field equality atoms. All atoms lower
	// into one combined bpf_loop callback; the per-iteration cursor and
	// accumulator forgets (emitMultiStateCallback / emitAccPrelude) make it
	// converge regardless of the atom count, so the cap is a policy ceiling
	// (see accMaxAtoms), not a hard verifier limit. Above it, returning nil
	// routes the program to the compile-time reject in emitStateBody — a
	// clean diagnostic instead of bytecode the verifier refuses.
	if len(plan.atoms) > accMaxAtoms {
		return nil
	}
	return plan
}

// layerOptionWalkHasLengthByte recognizes the TLV fallback shared by
// single-option and accumulator queries, including counter-bounded TCP.
func layerOptionWalkHasLengthByte(layer *ir.LayerInstance) bool {
	if layer == nil || layer.Spec == nil || layer.Spec.ParseStateMachine == nil {
		return false
	}
	states := layer.Spec.ParseStateMachine.States
	for i := range states {
		if !vocab.IsMultiStateLoopEntry(states, i) {
			continue
		}
		sel := states[i].Trans.Select
		if sel == nil {
			return false
		}
		return lengthByteOptionLoop(states, sel)
	}
	return false
}

// accMaxAtoms bounds how many option-field equality atoms the accumulator
// lowering folds into one combined bpf_loop callback. With the per-
// iteration cursor AND accumulator forgets the callback converges
// regardless of how many option bits it sets, so one loop carries every
// queried option in a single TLV re-scan — the full 14-atom TCP query
// (every field of every option type) loads across the 6.1--7.0 matrix.
// This is a policy ceiling, not a hard verifier limit: it sits above TCP's
// maximum constructible query (14) and below the emitAccMaskCheck
// int32-mask limit (31 bits). See buildAccPlan and the forgets in
// emitMultiStateCallback / emitAccPrelude.
const accMaxAtoms = 16

// accNeverBit is the mask bit emitAccMaskCheck requires for a `never`
// plan. Atom bits stop at accMaxAtoms, the slot starts at zero and the
// walk only ORs atom bits into it (the forget XORs a value twice), so
// this bit is never set and the check fails for every packet. It stays
// below bit 31 so the mask remains a non-negative int32 immediate.
const accNeverBit = uint64(1) << 30

// flattenPureAnd returns the flat leaf list of a where condition that is
// a pure conjunction (a tree of ast.WAnd whose leaves are all
// ast.WAtomArith or ast.WAtomBoolValid). Returns nil when the tree
// contains any non-AND connective (or/not/any/all/bool-eq/...) or any
// other leaf — signalling "not the supported pure-AND-equality shape".
func flattenPureAnd(c *ir.Condition) []*ir.Condition {
	if c == nil {
		return nil
	}
	switch c.Kind {
	case ast.WAnd:
		left := flattenPureAnd(c.Left)
		if left == nil {
			return nil
		}
		right := flattenPureAnd(c.Right)
		if right == nil {
			return nil
		}
		return append(left, right...)
	case ast.WAtomArith, ast.WAtomBoolValid:
		return []*ir.Condition{c}
	default:
		return nil
	}
}

// eqLeafToAtom validates one leaf as `<option.field> == <const>` over a
// dynamic-eligible aux on a layer the program queries, and returns the
// owning layer plus the populated atom (bit unset; caller assigns it).
// ok is false for any other shape.
func eqLeafToAtom(leaf *ir.Condition, qo queriedOptions) (*ir.LayerInstance, accAtom, bool) {
	if leaf == nil || leaf.Kind != ast.WAtomArith {
		return nil, accAtom{}, false
	}
	if leaf.Op != ast.CmpEq {
		return nil, accAtom{}, false
	}
	l, r := leaf.ArithL, leaf.ArithR
	if l == nil || r == nil {
		return nil, accAtom{}, false
	}
	// `==` is symmetric and the parser does not canonicalize operand order,
	// so accept the constant on either side (`<const> == <field>` too).
	if l.Kind == ast.ArithConst && r.Kind == ast.ArithField {
		l, r = r, l
	}
	if l.Kind != ast.ArithField || r.Kind != ast.ArithConst {
		return nil, accAtom{}, false
	}
	f := l.Field
	if f == nil || f.Aux == nil {
		return nil, accAtom{}, false
	}
	// The field must be a dynamic-eligible option on this layer (the same
	// predicate the demand walker uses), and that option must actually be
	// in the layer's queried set (so a slot was allocated / the kind byte
	// participates in the walk dispatch).
	layout := dynamicAuxLayoutOf(f)
	if layout == nil {
		return nil, accAtom{}, false
	}
	if _, ok := qo.dynamicAuxSlotForLayout(f.Layer, layout); !ok {
		return nil, accAtom{}, false
	}
	// Owner-bound stacks (TCP SACK blocks) resolve dynamicAuxLayoutOf to
	// the owner option, not the queried field's own option; reject so the
	// accumulator never tries to read a per-element array via this path.
	if f.Aux.OwnerOption != nil || f.Aux.Stack != nil {
		return nil, accAtom{}, false
	}
	// Byte-aligned field, width in {1,2,4}.
	if f.Aux.FieldBitOff%8 != 0 || f.Aux.FieldBitWidth%8 != 0 {
		return nil, accAtom{}, false
	}
	if f.Slice != nil {
		return nil, accAtom{}, false
	}
	width := f.Aux.FieldBitWidth / 8
	switch width {
	case 1, 2, 4:
	default:
		return nil, accAtom{}, false
	}
	// Narrow the constant to the field width, the same way the normal
	// arith path (genArithWithBits) does — so a negative literal on an
	// unsigned field is accepted (e.g. `WS.shift == -1` means shift ==
	// 0xff). An `int<128>(n)` is not narrowed: it compares at 128 bits
	// (D-038), so a value the field cannot hold makes the leaf false for
	// every packet. That leaf becomes a `never` atom and the plan rejects
	// outright (emitAccMaskCheck), instead of leaving the accumulator.
	if r.Wide && (r.ConstHi != 0 || r.Const>>uint(f.Aux.FieldBitWidth) != 0) {
		return f.Layer, accAtom{layout: layout, never: true}, true
	}
	cmpVal := r.Const & ((uint64(1) << uint(f.Aux.FieldBitWidth)) - 1)
	// A 4-byte value with the high bit set does not fit JNE.Imm (the
	// immediate sign-extends); emitAccPrelude compares it from a register.
	return f.Layer, accAtom{
		layout:       layout,
		fieldByteOff: f.Aux.FieldBitOff / 8,
		width:        width,
		cmpVal:       cmpVal,
		bit:          0,
	}, true
}

// accSlot returns the single stack slot the accumulator uses for the
// plan's layer (slot index 1 — the same allocator the per-option
// position slots would have used, but here it holds the result bitmask
// instead of an option position).
func (p *accPlan) accSlot(qo queriedOptions) (int16, error) {
	return qo.slotForLayer(p.layer, 1)
}

// emitAccMaskCheck loads the accumulator slot and rejects when not every
// bit in the plan's mask is set. The mask is the OR of all leaves' bits,
// so `(acc & mask) == mask` means every `<option.field> == <const>`
// matched; an absent option keeps its bit at 0 and fails the AND.
// Emitted in place of the normal genCondition call for the supported
// pure-AND pattern.
func emitAccMaskCheck(p *accPlan, qo queriedOptions, failLabel string) (asm.Instructions, error) {
	slot, err := p.accSlot(qo)
	if err != nil {
		return nil, err
	}
	// mask fits int32: buildAccPlan caps the atoms at accMaxAtoms (16),
	// so And.Imm / JNE.Imm suffice.
	mask := p.mask
	// A leaf the field can never satisfy makes the whole conjunction
	// false. Require a bit no atom sets: the check then fails for every
	// packet, while the accept path stays reachable in the control-flow
	// graph (an unconditional jump would leave it unreachable, which the
	// verifier refuses).
	if p.never {
		mask |= accNeverBit
	}
	insns := asm.Instructions{
		asm.LoadMem(asm.R3, asm.R10, slot, asm.DWord),
		asm.And.Imm(asm.R3, int32(mask)),
		asm.JNE.Imm(asm.R3, int32(mask), failLabel),
	}
	if p.valid {
		vslot, ok := qo.validSlot(p.layer)
		if !ok {
			return nil, fmt.Errorf("codegen: %s has no option-validity slot", p.layer.DisplayName())
		}
		insns = append(insns,
			asm.LoadMem(asm.R3, asm.R10, vslot, asm.DWord),
			asm.JEq.Imm(asm.R3, 0, failLabel),
		)
	}
	return insns, nil
}

// atomsFor returns the accumulator atoms that belong to the given layer,
// or nil when the plan is nil or targets a different layer. Used by the
// per-iteration prelude to decide whether to emit the bit-collect path.
func (p *accPlan) atomsFor(layer *ir.LayerInstance) []accAtom {
	if p == nil || p.layer != layer {
		return nil
	}
	return p.atoms
}

// lengthByteOptionLoop recognizes option walks whose fallback consumes a
// byte-sized TLV length. Counter-bounded TCP retains the accumulator lowering.
func lengthByteOptionLoop(states []*vocab.ParseState, sel *vocab.SelectOp) bool {
	if sel == nil {
		return false
	}
	idx := sel.Default
	for _, cs := range sel.Cases {
		if len(cs.Values) == 2 && cs.Values[1].IsWildcard && !cs.Values[0].IsWildcard && cs.Values[0].IsBool && !cs.Values[0].Bool {
			idx = cs.Target
		}
	}
	if idx < 0 || idx >= len(states) {
		return false
	}
	st := states[idx]
	return len(st.Extracts) == 0 && len(st.Advances) == 1 && st.Advances[0].Kind == vocab.AdvanceOpLookahead
}
