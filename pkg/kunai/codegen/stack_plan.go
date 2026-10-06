package codegen

import (
	"fmt"
	"slices"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ir"
	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
)

// stackPlanTop is the first slot of the demand-driven part of kunai's
// stack, right below the fixed regions (arith, bpf_loop ctx, parser
// counters; see the KunaiStackTop docblock for the map).
const stackPlanTop = int16(-232)

// bpfStackBottom is the lowest slot the BPF stack offers.
const bpfStackBottom = int16(-512)

// stackPlan places the slots whose number depends on the filter: one
// runtime entry slot per layer group the resolver marked
// NeedsRuntimeOffset (alternation members share their group's slot), then
// every layer's dynamic-aux demand (option positions, push counts), packed
// in chain order from stackPlanTop downward, then one matched-member slot
// per alternation group whose matched member something reads (a where /
// capture clause on a member, or the next layer's per-member dispatch).
// Positions that need no slot take no space, so the only bound is the BPF
// stack itself.
//
// Entry slots are keyed by chain position: the group's members share the
// position, and the `?` lowering in genLayerInner emits a copy of the
// layer, so the pointer is not an identity there. Aux slots are keyed by
// the layer the demand walker recorded (members have their own demand),
// which is also the pointer every aux lookup uses today.
type stackPlan struct {
	entry map[int]int16
	aux   map[*ir.LayerInstance]int16 // the layer's first demand slot
	// matched holds, per alternation group (by chain position), the slot
	// the group records the index of its matched member in.
	matched map[int]int16
	// valid holds, per layer a `.options.valid` atom reads, the slot its
	// parser walk sets to 1 when the option region parsed and 0 when it
	// was malformed.
	valid map[*ir.LayerInstance]int16
}

// planStack lays out `layers`, their demand and the alternation groups
// in `readGroups` (chain positions of the groups whose matched member is
// read); it fails when the plan would run past the BPF stack.
func planStack(layers []*ir.LayerInstance, demand map[*ir.LayerInstance][]*vocab.AuxLayout, readGroups map[int]bool, validRead map[*ir.LayerInstance]bool) (*stackPlan, error) {
	plan := &stackPlan{entry: map[int]int16{}, aux: map[*ir.LayerInstance]int16{}, matched: map[int]int16{}, valid: map[*ir.LayerInstance]int16{}}
	cursor := int(stackPlanTop)
	// take hands out `slots` consecutive slots for `l`, naming it when the
	// plan runs past the BPF stack.
	take := func(l *ir.LayerInstance, slots int, what string) (int16, error) {
		first := cursor
		cursor -= 8 * slots
		if cursor+8 < int(bpfStackBottom) {
			return 0, fmt.Errorf("%w: %s of %s (chain position %d, %d bytes) end %d bytes past the 512-byte BPF stack: the runtime entry slots, dynamic aux slots and matched-member slots of this filter do not fit (reference fewer options, or a shallower chain)", ErrNotImplemented, what, l.DisplayName(), l.LayerPos+1, 8*slots, int(bpfStackBottom)-(cursor+8))
		}
		return int16(first), nil
	}
	marked := func(l *ir.LayerInstance) bool { return l != nil && l.NeedsRuntimeOffset }
	for _, l := range layers {
		if l == nil || (!marked(l) && !slices.ContainsFunc(l.Alternation, marked)) {
			continue
		}
		if _, dup := plan.entry[l.LayerPos]; dup {
			return nil, fmt.Errorf("codegen: two marked layers share chain position %d (%s); the resolver assigns LayerPos", l.LayerPos, l.DisplayName())
		}
		slot, err := take(l, 1, "the runtime entry slot")
		if err != nil {
			return nil, err
		}
		plan.entry[l.LayerPos] = slot
	}
	for _, l := range layers {
		if l == nil {
			continue
		}
		for _, m := range append([]*ir.LayerInstance{l}, l.Alternation...) {
			if n := len(demand[m]); m != nil && n > 0 {
				slot, err := take(m, n, "the dynamic aux slots")
				if err != nil {
					return nil, err
				}
				plan.aux[m] = slot
			}
		}
	}
	for _, l := range layers {
		if l == nil || len(l.Alternation) == 0 || !readGroups[l.LayerPos] {
			continue
		}
		slot, err := take(l, 1, "the matched-member slot")
		if err != nil {
			return nil, err
		}
		plan.matched[l.LayerPos] = slot
	}
	for _, l := range layers {
		if l == nil {
			continue
		}
		// Alternation members run their own walk, so each read member
		// gets its own flag; the where guard checks which one matched.
		for _, m := range append([]*ir.LayerInstance{l}, l.Alternation...) {
			if m == nil || !validRead[m] {
				continue
			}
			slot, err := take(m, 1, "the option-validity slot")
			if err != nil {
				return nil, err
			}
			plan.valid[m] = slot
		}
	}
	return plan, nil
}
