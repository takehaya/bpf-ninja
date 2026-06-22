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
	// Cap the number of per-iteration field-read atoms. Each atom adds a
	// bounded packet read plus kind/value compares to the bpf_loop
	// callback; even though the loop carries a single accumulator slot,
	// the per-iteration branch + pointer-state count still grows with the
	// atom count and crosses the verifier's instruction-processing budget
	// past this bound (measured on 6.15: 2 atoms load, 3+ blow the 1M
	// limit). Above the cap, returning nil routes the program to the
	// compile-time reject in emitStateBody — a clean diagnostic instead of
	// bytecode the verifier refuses. Raising it needs the per-atom callback
	// cost cut further (see the multi-option follow-up).
	if len(plan.atoms) > accMaxAtoms {
		return nil
	}
	return plan
}

// accMaxAtoms bounds how many option-field equality atoms the accumulator
// lowering folds in one TLV walk — the largest count verified to load
// across the kernel matrix (see buildAccPlan).
const accMaxAtoms = 2

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
	// Const must fit int32 (JNE.Imm immediate range), like the normal
	// arith-compare path narrows it.
	if r.Const > 0x7FFFFFFF {
		return nil, accAtom{}, false
	}
	return f.Layer, accAtom{
		layout:       layout,
		fieldByteOff: f.Aux.FieldBitOff / 8,
		width:        width,
		cmpVal:       r.Const,
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
