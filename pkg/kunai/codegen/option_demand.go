package codegen

import (
	"fmt"
	"slices"
	"sort"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ir"
	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
)

// queriedOptions is the demand walker's result: the dynamic-eligible aux
// references per layer, and the stack plan that places their slots and
// the layers' runtime entry slots. The zero value has no demand and no
// slots.
type queriedOptions struct {
	// demand maps each LayerInstance to the dynamic-eligible AuxLayouts
	// that the program's where clauses (top-level + per-layer brackets +
	// per-capture) actually reference, sorted by DynamicKindByte for
	// deterministic codegen. The TLV-walk callback writes one stack slot
	// per (layer, queried option) pair, not per spec-eligible aux, so the
	// per-iteration verifier state cost follows what the program needs
	// (TCP declares four eligible options; a program that only reads
	// tcp.options.MSS pays for one slot, not four).
	demand map[*ir.LayerInstance][]*vocab.AuxLayout
	plan   *stackPlan
	// members maps each alternation member to its index in its group
	// (the group's chain position is the member's own LayerPos).
	members map[*ir.LayerInstance]int
	// whereOnlyGroups are the groups whose matched-member slot exists for
	// where / capture reads alone (no diverged dispatch follows them).
	whereOnlyGroups map[int]bool
}

// of returns the layer's demand list (nil when nothing is queried).
func (qo queriedOptions) of(layer *ir.LayerInstance) []*vocab.AuxLayout { return qo.demand[layer] }

// entrySlot is the stack slot holding the layer's runtime entry offset
// (planStack); only layers the resolver marked NeedsRuntimeOffset have one.
func (qo queriedOptions) entrySlot(layer *ir.LayerInstance) (int16, error) {
	if qo.plan == nil {
		return 0, fmt.Errorf("codegen: runtime entry slot of %s requested without a stack plan", layer.DisplayName())
	}
	if slot, ok := qo.plan.entry[layer.LayerPos]; ok {
		return slot, nil
	}
	return 0, fmt.Errorf("codegen: %s has no runtime entry slot (the resolver did not mark it)", layer.DisplayName())
}

// matchedSlot is the stack slot in which the alternation group at chain
// position `pos` records the index of its matched member; ok is false
// when nothing reads it: no where / capture clause reads a member of the
// group and the next layer dispatches the same way under every member.
func (qo queriedOptions) matchedSlot(pos int) (slot int16, ok bool) {
	if qo.plan == nil {
		return 0, false
	}
	slot, ok = qo.plan.matched[pos]
	return slot, ok
}

// dropWhereReads forgets the matched-member slots that only where /
// capture reads asked for, when the where clause is lowered elsewhere
// (the accumulator plan) and no guard will read them. Those slots are the
// last ones planned, so nothing else moves.
func (qo queriedOptions) dropWhereReads() {
	if qo.plan == nil {
		return
	}
	for pos := range qo.whereOnlyGroups {
		delete(qo.plan.matched, pos)
	}
}

// readsAltMember reports whether any matched-member slot is planned,
// i.e. whether a where atom can need a member guard.
func (qo queriedOptions) readsAltMember() bool {
	return qo.plan != nil && len(qo.plan.matched) > 0
}

// collectQueriedOptions walks the resolved program and gathers every
// dynamic-eligible aux reference, then plans the stack slots. Preserves
// sort-by-kind-byte ordering so slot indices stay stable across compiles
// regardless of source order.
func collectQueriedOptions(p *ir.Program) (queriedOptions, error) {
	qo := queriedOptions{demand: map[*ir.LayerInstance][]*vocab.AuxLayout{}}
	if p == nil {
		return qo, nil
	}
	visit := func(f *ir.FieldRef) { qo.record(f) }
	for _, layer := range p.Layers {
		visitLayerPredicates(layer, visit)
	}
	// A where / capture read of an alternation member needs to know
	// whether that member is the one that matched. A member's own bracket
	// predicate runs inside its branch and does not.
	qo.members = map[*ir.LayerInstance]int{}
	readGroups := map[int]bool{}
	dispatchGroups := map[int]bool{}
	divergedUnder := func(l *ir.LayerInstance) bool {
		return l != nil && l.Dispatch != nil && l.Dispatch.IsAltDiverged
	}
	for i, layer := range p.Layers {
		if layer == nil {
			continue
		}
		for j, alt := range layer.Alternation {
			qo.members[alt] = j
		}
		// The layer after a group whose members dispatch it differently
		// (`(ipv4|ipv6)/tcp`, or a second group `(ipv4|ipv6)/(tcp|udp)`)
		// picks its dispatch by the matched member.
		if i > 0 && p.Layers[i-1] != nil && len(p.Layers[i-1].Alternation) > 0 &&
			(divergedUnder(layer) || slices.ContainsFunc(layer.Alternation, divergedUnder)) {
			readGroups[p.Layers[i-1].LayerPos] = true
			dispatchGroups[p.Layers[i-1].LayerPos] = true
		}
	}
	visitRead := func(f *ir.FieldRef) {
		visit(f)
		if f != nil {
			if _, ok := qo.members[f.Layer]; ok {
				readGroups[f.Layer.LayerPos] = true
			}
		}
	}
	ir.WalkConditionFieldRefs(p.Where, visitRead)
	for _, cap := range p.Captures {
		if cap == nil {
			continue
		}
		ir.WalkConditionFieldRefs(cap.Where, visitRead)
		for _, f := range cap.Fields {
			visitRead(f)
		}
	}
	for layer, layouts := range qo.demand {
		sort.Slice(layouts, func(i, j int) bool {
			if layouts[i].DynamicKindByte != layouts[j].DynamicKindByte {
				return layouts[i].DynamicKindByte < layouts[j].DynamicKindByte
			}
			return layouts[i].OutParam < layouts[j].OutParam
		})
		qo.demand[layer] = layouts
	}
	qo.whereOnlyGroups = map[int]bool{}
	for pos := range readGroups {
		if !dispatchGroups[pos] {
			qo.whereOnlyGroups[pos] = true
		}
	}
	plan, err := planStack(p.Layers, qo.demand, readGroups)
	if err != nil {
		return queriedOptions{}, err
	}
	// Every demand key is a layer of the program (or an alternation
	// member), so the plan placed its slots; anything else is a walker or
	// resolver bug, caught here rather than as a silent "not recorded".
	for layer := range qo.demand {
		if _, ok := plan.aux[layer]; !ok {
			return queriedOptions{}, fmt.Errorf("codegen: %s has queried options but is not a layer of the program", layer.DisplayName())
		}
	}
	qo.plan = plan
	return qo, nil
}

// visitLayerPredicates fans visit() over a layer's bracket
// predicates plus every Alternation member. Bracket predicates
// carry FieldRef on Predicate.Field directly; ir.WalkConditionFieldRefs
// only covers where-clause / capture conditions, not these.
func visitLayerPredicates(l *ir.LayerInstance, visit func(*ir.FieldRef)) {
	if l == nil {
		return
	}
	for _, pred := range l.Predicates {
		if pred == nil {
			continue
		}
		visit(pred.Field)
	}
	for _, alt := range l.Alternation {
		visitLayerPredicates(alt, visit)
	}
}

// dynamicAuxLayoutOf returns the AuxLayout entry a FieldRef refers
// to when (and only when) the aux is dynamic-eligible — i.e. would
// be served by a parser-machine slot rather than the static-offset
// path. The eligibility predicate is shared between the demand
// walker (recording references) and the where codegen (looking up
// allocated slots) so they agree on which refs the slot allocator
// owns.
func dynamicAuxLayoutOf(f *ir.FieldRef) *vocab.AuxLayout {
	if f == nil || f.Aux == nil || f.Layer == nil || f.Layer.Spec == nil {
		return nil
	}
	// Owner-bound stacks ride past their option's per-packet base.
	// The slot the demand walker records is the owner's, not the
	// stack's — the stack header itself has no AuxLayout entry.
	if f.Aux.OwnerOption != nil {
		return f.Aux.OwnerOption
	}
	machine := f.Layer.Spec.ParseStateMachine
	if machine == nil {
		return nil
	}
	layout, ok := machine.AuxLayouts[f.Aux.OutParam]
	if !ok || layout == nil || !layout.IsDynamicEligible {
		return nil
	}
	return layout
}

// record adds a dynamic-eligible aux reference to the layer's
// demand list, deduping. Static auxes and primary-header refs are
// silently dropped — they ride the static-offset path. A reference
// into a push-counted stack records that stack's count slot instead.
func (qo queriedOptions) record(f *ir.FieldRef) {
	layout := dynamicAuxLayoutOf(f)
	if layout == nil {
		layout = qo.stackCountLayout(f)
	}
	if layout == nil {
		return
	}
	if slices.Contains(qo.demand[f.Layer], layout) {
		return
	}
	qo.demand[f.Layer] = append(qo.demand[f.Layer], layout)
}

// needsPushCount reports whether a stack reference can only learn how
// many entries the packet carries from the parser machine itself: a
// top-level out-stack (`extract(exts.next)` in ipv6 / gtp) with no
// @kunai_stack_count field and no owner option. Such a stack gets a
// demand slot that the machine increments on every push (spec D-031:
// an entry past the pushed count is absent).
func needsPushCount(f *ir.FieldRef) bool {
	if f == nil || f.Aux == nil || f.Aux.Stack == nil || f.Aux.OwnerOption != nil || f.Layer == nil || f.Layer.Spec == nil {
		return false
	}
	machine := f.Layer.Spec.ParseStateMachine
	return machine != nil && isPushedStack(machine, f.Aux.OutParam) && f.Layer.Spec.StackCounts[f.Aux.OutParam] == nil
}

// isPushedStack reports whether `name` is an out-stack the machine pushes
// onto. The loader lists out-stacks in StackRefs and never in AuxLayouts
// (pinned by vocab's loader tests), so the two name spaces are disjoint;
// the AuxLayouts check keeps that assumption explicit.
func isPushedStack(machine *vocab.ParseStateMachine, name string) bool {
	return machine.StackRefs[name] != nil && machine.AuxLayouts[name] == nil
}

// stackCountLayout returns the layer's demand entry for the push count
// of the stack `f` indexes, synthesizing it on first use. The loader
// never lists an out-stack in AuxLayouts (stacks live in StackRefs), so
// a demand entry whose OutParam names a stack is a count slot — see
// isStackCountLayout.
func (qo queriedOptions) stackCountLayout(f *ir.FieldRef) *vocab.AuxLayout {
	if !needsPushCount(f) {
		return nil
	}
	for _, l := range qo.demand[f.Layer] {
		if l.OutParam == f.Aux.OutParam {
			return l
		}
	}
	st := f.Layer.Spec.ParseStateMachine.StackRefs[f.Aux.OutParam]
	return &vocab.AuxLayout{OutParam: f.Aux.OutParam, HeaderName: st.HeaderName, HeaderRef: st.HeaderRef, HeaderSize: st.ElemSize}
}

// isStackCountLayout reports whether a demand entry is a stack's push
// count rather than an option's position: its slot starts at 0 and the
// machine adds one per push, instead of starting at the absent sentinel
// and recording the cursor when the option's kind byte matches.
func isStackCountLayout(layer *ir.LayerInstance, layout *vocab.AuxLayout) bool {
	machine := layer.Spec.ParseStateMachine
	return machine != nil && isPushedStack(machine, layout.OutParam)
}

// optionDemand is the layer's demand list without its stack count
// entries: the options whose positions the TLV walk records.
func (qo queriedOptions) optionDemand(layer *ir.LayerInstance) []*vocab.AuxLayout {
	var out []*vocab.AuxLayout
	for _, l := range qo.demand[layer] {
		if !isStackCountLayout(layer, l) {
			out = append(out, l)
		}
	}
	return out
}

// stackCountSlot returns the slot holding the push count of `stack` in
// `layer`, when a where / capture clause or a bracket predicate demanded it.
func (qo queriedOptions) stackCountSlot(layer *ir.LayerInstance, stack string) (int16, bool) {
	for _, l := range qo.demand[layer] {
		if l.OutParam == stack && isStackCountLayout(layer, l) {
			return qo.dynamicAuxSlotForLayout(layer, l)
		}
	}
	return 0, false
}

// dynamicAuxSlotForLayout returns the stack slot reserved for a
// given (layer, queried-aux) pair. The per-layer demand list is
// kind-byte-sorted; the layout's index in that list times 8 plus
// the cumulative offset of prior layers' demands is the slot.
//
// Returns (0, false) when the layout is not in the layer's demand
// set — indicates the caller is reaching for a slot that wasn't
// allocated, which means the where / capture walker missed a
// reference. Caller should fall back or fail loudly.
func (qo queriedOptions) dynamicAuxSlotForLayout(layer *ir.LayerInstance, layout *vocab.AuxLayout) (int16, bool) {
	if layer == nil || layout == nil {
		return 0, false
	}
	demand, ok := qo.demand[layer]
	if !ok {
		return 0, false
	}
	for idx, l := range demand {
		if l != layout {
			continue
		}
		slot, err := qo.slotForLayer(layer, idx+1)
		if err != nil {
			return 0, false
		}
		return slot, true
	}
	return 0, false
}

// slotForLayer returns the stack slot at index `slotIdx` (1-based) in
// `layer`'s demand list: the layer's first demand slot in the stack plan
// (planStack packs the lists in chain order, so a layer that queries no
// option takes no space) minus 8 bytes per earlier entry.
func (qo queriedOptions) slotForLayer(layer *ir.LayerInstance, slotIdx int) (int16, error) {
	demand := qo.demand[layer]
	if slotIdx <= 0 || slotIdx > len(demand) {
		return 0, fmt.Errorf("codegen: dynamic aux slot %d of %s out of range [1, %d]", slotIdx, layer.DisplayName(), len(demand))
	}
	if qo.plan == nil {
		return 0, fmt.Errorf("codegen: dynamic aux slot of %s requested without a stack plan", layer.DisplayName())
	}
	base, ok := qo.plan.aux[layer]
	if !ok {
		return 0, fmt.Errorf("codegen: %s has demand but no planned aux slots (not a layer of the program)", layer.DisplayName())
	}
	return base - int16(slotIdx-1)*8, nil
}

// dynamicAuxSentinel is the value stored in a dynamic aux offset
// slot before any extract has overwritten it. Where-time access
// compares the slot value against this constant — equality means
// the option was not present in this packet. -1 (= 0xFFFF...) is
// outside every valid offset (offsets are non-negative and bounded
// by ScratchBufSize).
const dynamicAuxSentinel = int32(-1)
