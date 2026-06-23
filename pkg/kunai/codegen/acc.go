package codegen

import (
	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
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
// existing compile-time reject for >=2 lookahead-only options.
type accPlan struct {
	layer *ir.LayerInstance
	atoms []accAtom
	mask  uint64 // OR of (1<<bit) for every atom
}

// buildAccPlan inspects a merged where condition and the program's
// queried-option set, returning an accPlan when the whole clause is a
// pure conjunction of equality leaves over >=2 distinct dynamic-eligible
// options on a single layer, every leaf byte-aligned with width in
// {1,2,4} and a const that fits int32. Returns nil for any other shape;
// the caller then falls through to the existing reject.
func buildAccPlan(where *ir.Condition, qo queriedOptions) *accPlan {
	if where == nil {
		return nil
	}
	leaves := flattenPureAnd(where)
	if leaves == nil {
		return nil
	}

	plan := &accPlan{}
	seen := map[*vocab.AuxLayout]bool{}
	for _, leaf := range leaves {
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
		atom.bit = len(plan.atoms)
		plan.atoms = append(plan.atoms, atom)
		plan.mask |= uint64(1) << uint(atom.bit)
		seen[atom.layout] = true
	}
	if plan.layer == nil {
		return nil
	}
	// Require >=2 DISTINCT queried options, and every option the layer
	// queries must be covered by an eq-leaf — otherwise an un-covered
	// queried option would still want its own recorded-position slot
	// (the explosion shape this lowering exists to avoid).
	if len(seen) < 2 {
		return nil
	}
	for _, layout := range qo[plan.layer] {
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

// flattenPureAnd returns the flat leaf list of a where condition that is
// a pure conjunction (a tree of ast.WAnd whose leaves are all
// ast.WAtomArith). Returns nil when the tree contains any non-AND
// connective (or/not/any/all/bool-eq/...) or any non-arith leaf —
// signalling "not the supported pure-AND-equality shape".
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
	case ast.WAtomArith:
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
	// Narrow the constant to the field width before the int32 check, the
	// same way the normal arith path (genArithWithBits) does — so a negative
	// literal on an unsigned field is accepted (e.g. `WS.shift == -1` means
	// shift == 0xff). A constant whose high bit is set on a 4-byte field
	// still rejects: JNE.Imm sign-extends a 32-bit immediate, so the
	// accumulator cannot compare it correctly and must fall back.
	cmpVal := r.Const & ((uint64(1) << uint(f.Aux.FieldBitWidth)) - 1)
	if cmpVal > 0x7FFFFFFF {
		return nil, accAtom{}, false
	}
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
	// mask fits int32 in every realistic case (<=29 slots => <=29 bits),
	// so And.Imm / JNE.Imm suffice. The slot-region cap keeps len(atoms)
	// well under 31.
	return asm.Instructions{
		asm.LoadMem(asm.R3, asm.R10, slot, asm.DWord),
		asm.And.Imm(asm.R3, int32(p.mask)),
		asm.JNE.Imm(asm.R3, int32(p.mask), failLabel),
	}, nil
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
