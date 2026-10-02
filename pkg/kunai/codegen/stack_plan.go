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
// in chain order from stackPlanTop downward. Positions that need no slot
// take no space, so the only bound is the BPF stack itself.
//
// Entry slots are keyed by chain position: the group's members share the
// position, and the `?` desugar emits a copy of the layer, so the pointer
// is not an identity. Aux slots are keyed by the layer the demand walker
// recorded.
type stackPlan struct {
	entry map[int]int16
	aux   map[*ir.LayerInstance]int16 // the layer's first demand slot
}

// planStack lays out `layers` and their demand; it fails when the plan
// would run past the BPF stack.
func planStack(layers []*ir.LayerInstance, demand map[*ir.LayerInstance][]*vocab.AuxLayout) (*stackPlan, error) {
	plan := &stackPlan{entry: map[int]int16{}, aux: map[*ir.LayerInstance]int16{}}
	cursor := stackPlanTop
	marked := func(l *ir.LayerInstance) bool { return l != nil && l.NeedsRuntimeOffset }
	for _, l := range layers {
		if l == nil || (!marked(l) && !slices.ContainsFunc(l.Alternation, marked)) {
			continue
		}
		plan.entry[l.LayerPos] = cursor
		cursor -= 8
	}
	for _, l := range layers {
		if l == nil {
			continue
		}
		for _, m := range append([]*ir.LayerInstance{l}, l.Alternation...) {
			if n := len(demand[m]); m != nil && n > 0 {
				plan.aux[m] = cursor
				cursor -= 8 * int16(n)
			}
		}
	}
	if lowest := cursor + 8; lowest < bpfStackBottom {
		return nil, fmt.Errorf("%w: runtime entry slots and dynamic aux slots need %d bytes below %d, past the 512-byte BPF stack (reference fewer options, or a shallower chain)", ErrNotImplemented, int(stackPlanTop-cursor), stackPlanTop)
	}
	return plan, nil
}

// queriedOf is the demand set a predicate context carries to the chain
// emitters; a nil context (unit tests of single emitters) has none.
func queriedOf(pc *predCtx) queriedOptions {
	if pc == nil {
		return queriedOptions{}
	}
	return pc.queried
}
