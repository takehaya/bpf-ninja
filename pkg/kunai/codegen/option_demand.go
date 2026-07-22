package codegen

import (
	"fmt"
	"slices"
	"sort"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ir"
	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
)

// queriedOptions maps each LayerInstance to the dynamic-eligible aux
// AuxLayouts that the program's where clauses (top-level + per-
// layer brackets + per-capture) actually reference. Slices are
// sorted by DynamicKindByte for deterministic codegen.
//
// The codegen's TLV-walk callback writes one stack slot per (layer,
// queried option) pair — *not* per spec-eligible aux. This keeps
// the per-iteration verifier state cost proportional to what the
// program actually needs rather than to the vocab's option vocabulary
// (TCP declares four eligible options today; a program that only
// reads tcp.options.MSS pays for one slot, not four).
type queriedOptions map[*ir.LayerInstance][]*vocab.AuxLayout

// collectQueriedOptions walks the resolved program and gathers every
// dynamic-eligible aux reference. Preserves sort-by-kind-byte
// ordering so slot indices stay stable across compiles regardless
// of source order.
func collectQueriedOptions(p *ir.Program) queriedOptions {
	qo := queriedOptions{}
	if p == nil {
		return qo
	}
	visit := func(f *ir.FieldRef) { qo.record(f) }
	for _, layer := range p.Layers {
		visitLayerPredicates(layer, visit)
	}
	ir.WalkConditionFieldRefs(p.Where, visit)
	for _, cap := range p.Captures {
		if cap == nil {
			continue
		}
		ir.WalkConditionFieldRefs(cap.Where, visit)
		for _, f := range cap.Fields {
			visit(f)
		}
	}
	for layer, layouts := range qo {
		sort.Slice(layouts, func(i, j int) bool {
			return layouts[i].DynamicKindByte < layouts[j].DynamicKindByte
		})
		qo[layer] = layouts
	}
	return qo
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
// silently dropped — they ride the static-offset path.
func (qo queriedOptions) record(f *ir.FieldRef) {
	layout := dynamicAuxLayoutOf(f)
	if layout == nil {
		return
	}
	if slices.Contains(qo[f.Layer], layout) {
		return
	}
	qo[f.Layer] = append(qo[f.Layer], layout)
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
	if qo == nil || layer == nil || layout == nil {
		return 0, false
	}
	demand, ok := qo[layer]
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

// slotForLayer returns the stack slot at index `slotIdx` (1-based)
// for `layer`'s demand list. Per-layer-demand-sized stride: the
// cumulative offset is the sum of prior layers' actual demand
// lengths (× 8 bytes), so layers that query 0 options consume 0
// slots and layers that query N consume exactly N. This packs
// better than the prior fixed `dynamicAuxMaxSlotsPerLayer = 5`
// stride which reserved 40 bytes per layer regardless of demand,
// freeing slot region headroom for deeper / wider vocabs.
//
// The base descends from -280 in 8-byte steps; bpfStackBottom (-512)
// caps total demand at 29 slots (= 232 bytes). Worst-case packing
// is `whereLayerEntrySlotCap (7) × dynamicAuxMaxSlotsPerLayer (5) =
// 35 slots = 280 bytes` if every layer queried every option, which
// would still exceed bpfStackBottom — but no realistic vocab gets
// near that density. The error message names the layer and the
// chain shape so the user can shrink either dimension.
const dynamicAuxOffsetSlotBase = int16(-280)
const dynamicAuxMaxSlotsPerLayer = 5
const bpfStackBottom = int16(-512)

func (qo queriedOptions) slotForLayer(layer *ir.LayerInstance, slotIdx int) (int16, error) {
	if slotIdx <= 0 || slotIdx > dynamicAuxMaxSlotsPerLayer {
		return 0, fmt.Errorf("%w: dynamic aux slot %d out of range [1, %d]", ErrNotImplemented, slotIdx, dynamicAuxMaxSlotsPerLayer)
	}
	if layer.LayerPos < 0 || layer.LayerPos >= whereLayerEntrySlotCap {
		return 0, fmt.Errorf("%w: dynamic aux slot for layer position %d exceeds cap %d", ErrNotImplemented, layer.LayerPos, whereLayerEntrySlotCap)
	}
	cumulative := 0
	for other, demand := range qo {
		if other == layer {
			continue
		}
		if other.LayerPos < layer.LayerPos {
			cumulative += len(demand)
		}
	}
	slot := dynamicAuxOffsetSlotBase - int16(cumulative+(slotIdx-1))*8
	if slot < bpfStackBottom {
		return 0, fmt.Errorf("%w: dynamic aux slot for layer position %d slot %d (= %d) sits below the 512-byte BPF stack — total demand × 8 bytes exceeds the 232-byte slot region", ErrNotImplemented, layer.LayerPos, slotIdx, slot)
	}
	return slot, nil
}

// dynamicAuxSentinel is the value stored in a dynamic aux offset
// slot before any extract has overwritten it. Where-time access
// compares the slot value against this constant — equality means
// the option was not present in this packet. -1 (= 0xFFFF...) is
// outside every valid offset (offsets are non-negative and bounded
// by ScratchBufSize).
const dynamicAuxSentinel = int32(-1)
