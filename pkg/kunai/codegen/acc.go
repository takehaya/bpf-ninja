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
	// folded holds the bracket predicates lowered into atoms; the layer
	// does not emit them (splitPredicates).
	folded map[*ir.Predicate]bool
	// rest is the part of the where clause the plan did not fold: the
	// conjuncts that are not equalities on the plan's options, ANDed. The
	// caller emits it through genCondition after the mask check (with the
	// usual absent-layer guards). nil when the whole clause folded.
	rest *ir.Condition
}

// buildAccPlan picks the layer whose option walk would have to record
// the positions of two or more length-byte TLV options (TCP), and lowers
// every read of those options into accumulator atoms: the layer's bracket
// predicates and the where clause's top-level conjuncts of the form
// `<option.field> == <const>` (byte aligned, width 1, 2 or 4), plus
// `<layer>.options.valid`. The other conjuncts become plan.rest. A
// constant the field cannot hold marks the plan `never`.
//
// The plan is refused, with the reason returned for the error message,
// when something else still reads one of the layer's options (a bracket
// predicate other than `== <integer>`, or a rest conjunct, capture field
// or capture condition naming the option), or when the layer may be
// absent and no folded where conjunct is on it: a bracket on an absent
// layer is skipped while the mask check would reject. It is also refused
// when two or more layers each query two or more options, or when the
// equalities exceed accMaxAtoms. Without a candidate layer it returns nil
// and no reason.
func buildAccPlan(p *ir.Program, where *ir.Condition, qo queriedOptions) (*accPlan, string) {
	cands := accCandidates(p, qo)
	switch {
	case len(cands) == 0:
		return nil, ""
	case len(cands) > 1 && accSameAlternation(cands):
		return nil, ir.AlternationShadowText(accSameSpecMembers(p, cands[0])) + "; keep one of them"
	case len(cands) > 1:
		return nil, fmt.Sprintf("%s each query two or more options, and the walk folds the options of one layer only; query a single option on all but one of them", ir.LayersAt(cands))
	}
	layer := cands[0]
	// atoms stays non-nil even when every leaf is `never`: atomsFor must
	// still report the plan to the walk (emitStateBody / the prelude).
	plan := &accPlan{layer: layer, atoms: []accAtom{}, folded: map[*ir.Predicate]bool{}}
	seen := map[*vocab.AuxLayout]bool{}
	add := func(atom accAtom) {
		// The option still counts as covered: its position slot is not
		// wanted, the leaf just can never hold.
		seen[atom.layout] = true
		if atom.never {
			plan.never = true
			return
		}
		atom.bit = len(plan.atoms)
		plan.atoms = append(plan.atoms, atom)
		plan.mask |= uint64(1) << uint(atom.bit)
	}
	for _, pred := range layer.Predicates {
		if dynamicAuxLayoutOf(pred.Field) == nil {
			continue
		}
		atom, ok := predToAtom(pred, qo)
		if !ok {
			return nil, fmt.Sprintf("the bracket predicate on %s is not `== <integer>` on the whole field, the only form the walk folds", optionFieldName(pred.Field))
		}
		plan.folded[pred] = true
		add(atom)
	}
	whereOnLayer := false
	for _, leaf := range flattenAnd(where) {
		if leaf.Kind == ast.WAtomBoolValid && leaf.BoolField != nil && leaf.BoolField.Layer == layer {
			plan.valid, whereOnLayer = true, true
			continue
		}
		if l, atom, ok := eqLeafToAtom(leaf, qo); ok && l == layer {
			add(atom)
			whereOnLayer = true
			continue
		}
		// An atom on the layer is false when the layer is absent (D-003),
		// like a folded equality, so it also keeps the verdict when the
		// layer's brackets are folded.
		if accAtomOnLayer(leaf, layer) {
			whereOnLayer = true
		}
		plan.rest = andCondition(plan.rest, leaf, leaf.Pos)
	}
	if plan.valid {
		if _, ok := qo.validSlot(layer); !ok {
			return nil, ""
		}
	}
	// The capture conditions are already part of where (computeCapture);
	// the capture fields are not.
	var fields []*ir.FieldRef
	for _, c := range p.Captures {
		fields = append(fields, c.Fields...)
	}
	ir.WalkConditionFieldRefs(plan.rest, func(f *ir.FieldRef) { fields = append(fields, f) })
	for _, f := range fields {
		if f != nil && f.Layer == layer && dynamicAuxLayoutOf(f) != nil {
			return nil, fmt.Sprintf("%s is read by a where or capture term the walk cannot fold: only `<option>.<field> == <integer>` on a whole field, ANDed at the top level of the where clause, folds", optionFieldName(f))
		}
	}
	// Every option the layer queries must be covered by an atom; an
	// uncovered one would still want its own position slot (the explosion
	// shape this lowering exists to avoid).
	for _, layout := range qo.optionDemand(layer) {
		if !seen[layout] {
			return nil, ""
		}
	}
	if len(seen) < 2 {
		return nil, ""
	}
	if len(plan.folded) > 0 && !whereOnLayer && !accLayerAlwaysPresent(layer, qo) {
		return nil, fmt.Sprintf("%s may be absent, which skips its bracket but fails the folded check; add a where term on it, such as `%s.options.valid`", layer.DisplayName(), layer.DisplayName())
	}
	// Cap the total number of option-field equality atoms. All atoms lower
	// into one combined bpf_loop callback; the per-iteration cursor and
	// accumulator forgets (emitMultiStateCallback / emitAccPrelude) make it
	// converge regardless of the atom count, so the cap is a policy ceiling
	// (see accMaxAtoms), not a hard verifier limit. Above it, the program
	// goes to the compile-time reject in emitStateBody — a clean diagnostic
	// instead of bytecode the verifier refuses. Equalities are not
	// deduplicated, so only repeating them can get here.
	if len(plan.atoms) > accMaxAtoms {
		return nil, fmt.Sprintf("the filter has %d equalities on %s options; the walk folds at most %d", len(plan.atoms), layer.DisplayName(), accMaxAtoms)
	}
	return plan, ""
}

// accCandidates lists, in chain order, the layers (alternation members
// included) whose length-byte option walk queries two or more options.
// The plan holds a single layer, so it applies only when there is one.
func accCandidates(p *ir.Program, qo queriedOptions) []*ir.LayerInstance {
	var found []*ir.LayerInstance
	for _, l := range p.Layers {
		for _, inst := range append([]*ir.LayerInstance{l}, l.Alternation...) {
			if inst == nil || inst.Spec == nil || len(qo.optionDemand(inst)) < 2 || !layerOptionWalkHasLengthByte(inst) {
				continue
			}
			found = append(found, inst)
		}
	}
	return found
}

// accSameAlternation reports whether the layers are members of one
// alternation naming one protocol. Members are tried in order and the
// first whose protocol matches is taken, so only the first can match.
func accSameAlternation(layers []*ir.LayerInstance) bool {
	for _, l := range layers[1:] {
		if l.LayerPos != layers[0].LayerPos || l.Spec != layers[0].Spec {
			return false
		}
	}
	return true
}

// accSameSpecMembers lists every member of cand's alternation with
// cand's protocol, the first of them included even when it queries one
// option and so is no candidate: the first is the one that matches.
func accSameSpecMembers(p *ir.Program, cand *ir.LayerInstance) []*ir.LayerInstance {
	var ms []*ir.LayerInstance
	for _, m := range p.Layers[cand.LayerPos].Alternation {
		if m.Spec == cand.Spec {
			ms = append(ms, m)
		}
	}
	return ms
}

// accLayerAlwaysPresent reports whether every accepted packet has the
// layer: one mandatory header outside an alternation. Its brackets then
// run on every accepted packet, so folding them into the mask check keeps
// the verdict.
func accLayerAlwaysPresent(layer *ir.LayerInstance, qo queriedOptions) bool {
	if _, member := qo.members[layer]; member {
		return false
	}
	lo, _ := layer.Bounds()
	return lo >= 1 && !layer.CanRepeat()
}

// accAtomOnLayer reports whether a where conjunct is an atom reading the
// layer: such an atom is false when the layer is absent (D-003). A
// negation, a bool equality or a quantifier is not an atom here, since
// each can hold on an absent layer.
func accAtomOnLayer(c *ir.Condition, layer *ir.LayerInstance) bool {
	switch c.Kind {
	case ast.WAtomArith, ast.WAtomLiteralCmp, ast.WAtomBoolExists, ast.WAtomBoolValid:
	default:
		return false
	}
	on := false
	ir.WalkConditionFieldRefs(c, func(f *ir.FieldRef) { on = on || (f != nil && f.Layer == layer) })
	return on
}

// optionFieldName spells an option field for an error message.
func optionFieldName(f *ir.FieldRef) string {
	name := f.Layer.DisplayName()
	if layout := dynamicAuxLayoutOf(f); layout != nil {
		name += "." + layout.OutParam
	}
	// An entry of a stack inside the option (SACK blocks).
	if f.Aux != nil && f.Aux.OwnerOption != nil && f.Aux.Stack != nil {
		idx := "[i]"
		if f.Aux.Stack.IsStatic {
			idx = fmt.Sprintf("[%d]", f.Aux.Stack.Static)
		}
		name += "." + f.Aux.OutParam + idx
	}
	if f.Field != nil {
		name += "." + f.Field.Name
	}
	return name
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

// flattenAnd returns the top-level conjuncts of a where condition: the
// operands of a tree of ast.WAnd, any other node being one conjunct. nil
// for a nil condition.
func flattenAnd(c *ir.Condition) []*ir.Condition {
	if c == nil {
		return nil
	}
	if c.Kind == ast.WAnd {
		return append(flattenAnd(c.Left), flattenAnd(c.Right)...)
	}
	return []*ir.Condition{c}
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
	if f == nil {
		return nil, accAtom{}, false
	}
	atom, ok := fieldToAtom(f, qo)
	if !ok {
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
		return f.Layer, accAtom{layout: atom.layout, never: true}, true
	}
	// A 4-byte value with the high bit set does not fit JNE.Imm (the
	// immediate sign-extends); emitAccPrelude compares it from a register.
	atom.cmpVal = r.Const & ((uint64(1) << uint(f.Aux.FieldBitWidth)) - 1)
	return f.Layer, atom, true
}

// predToAtom lowers a bracket predicate `<option.field> == <integer>` to
// an atom. The resolver has checked that the literal fits the field, and
// the constant is narrowed like emitIntPredicate does, so `shift == -1`
// still means 0xff.
func predToAtom(pred *ir.Predicate, qo queriedOptions) (accAtom, bool) {
	if pred.Kind != ast.PredCmp || pred.Op != ast.CmpEq || pred.Value.Kind != ast.ValInt || pred.Field == nil {
		return accAtom{}, false
	}
	atom, ok := fieldToAtom(pred.Field, qo)
	if !ok {
		return accAtom{}, false
	}
	// A negative literal arrives sign-extended (`-1` is 0xff..ff).
	atom.cmpVal = pred.Value.Int & ((uint64(1) << uint(pred.Field.Aux.FieldBitWidth)) - 1)
	return atom, true
}

// fieldToAtom checks that f is a field the walk can compare in place: a
// dynamic-eligible option the layer queries, byte aligned, 1, 2 or 4
// bytes wide, not sliced and not inside an owner-bound stack. The atom
// comes back without its constant and bit.
func fieldToAtom(f *ir.FieldRef, qo queriedOptions) (accAtom, bool) {
	if f.Aux == nil {
		return accAtom{}, false
	}
	// The field must be a dynamic-eligible option on this layer (the same
	// predicate the demand walker uses), and that option must actually be
	// in the layer's queried set (so a slot was allocated / the kind byte
	// participates in the walk dispatch).
	layout := dynamicAuxLayoutOf(f)
	if layout == nil {
		return accAtom{}, false
	}
	if _, ok := qo.dynamicAuxSlotForLayout(f.Layer, layout); !ok {
		return accAtom{}, false
	}
	// Owner-bound stacks (TCP SACK blocks) resolve dynamicAuxLayoutOf to
	// the owner option, not the queried field's own option; reject so the
	// accumulator never tries to read a per-element array via this path.
	if f.Aux.OwnerOption != nil || f.Aux.Stack != nil {
		return accAtom{}, false
	}
	// Byte-aligned field, width in {1,2,4}.
	if f.Aux.FieldBitOff%8 != 0 || f.Aux.FieldBitWidth%8 != 0 || f.Slice != nil {
		return accAtom{}, false
	}
	width := f.Aux.FieldBitWidth / 8
	switch width {
	case 1, 2, 4:
	default:
		return accAtom{}, false
	}
	return accAtom{layout: layout, fieldByteOff: f.Aux.FieldBitOff / 8, width: width}, true
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
