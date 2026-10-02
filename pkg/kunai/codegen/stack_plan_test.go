package codegen

import (
	"errors"
	"testing"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ir"
	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
)

// TestPlanStackPacksByNeed pins the plan: marked layer groups take one
// entry slot each in chain order (members share), unmarked layers take
// none, and dynamic aux demand follows below.
func TestPlanStackPacksByNeed(t *testing.T) {
	a := &ir.LayerInstance{LayerPos: 0}
	m1, m2 := &ir.LayerInstance{LayerPos: 1, NeedsRuntimeOffset: true}, &ir.LayerInstance{LayerPos: 1, NeedsRuntimeOffset: true}
	group := &ir.LayerInstance{LayerPos: 1, Alternation: []*ir.LayerInstance{m1, m2}}
	b := &ir.LayerInstance{LayerPos: 2}
	c := &ir.LayerInstance{LayerPos: 3, NeedsRuntimeOffset: true}
	demand := map[*ir.LayerInstance][]*vocab.AuxLayout{
		m2: {{OutParam: "x"}},
		c:  {{OutParam: "y"}, {OutParam: "z"}},
	}
	plan, err := planStack([]*ir.LayerInstance{a, group, b, c}, demand)
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.entry[1]; got != stackPlanTop {
		t.Errorf("group entry slot = %d, want %d", got, stackPlanTop)
	}
	if got := plan.entry[3]; got != stackPlanTop-8 {
		t.Errorf("c entry slot = %d, want %d (b takes none)", got, stackPlanTop-8)
	}
	if _, ok := plan.entry[2]; ok {
		t.Error("unmarked layer b has an entry slot")
	}
	if got := plan.aux[m2]; got != stackPlanTop-16 {
		t.Errorf("m2 aux base = %d, want %d", got, stackPlanTop-16)
	}
	if got := plan.aux[c]; got != stackPlanTop-24 {
		t.Errorf("c aux base = %d, want %d", got, stackPlanTop-24)
	}
	qo := queriedOptions{demand: demand, plan: plan}
	if slot, err := qo.slotForLayer(c, 2); err != nil || slot != stackPlanTop-32 {
		t.Errorf("c slot 2 = %d, %v; want %d", slot, err, stackPlanTop-32)
	}
	if slot, err := qo.entrySlot(m1); err != nil || slot != stackPlanTop {
		t.Errorf("member entry slot = %d, %v; want the group's %d", slot, err, stackPlanTop)
	}
	if _, err := qo.entrySlot(b); err == nil {
		t.Error("entrySlot(unmarked) = nil error")
	}
}

// TestPlanStackOverflow pins the only limit left: a plan past the BPF
// stack bottom is refused as ErrNotImplemented.
func TestPlanStackOverflow(t *testing.T) {
	var layers []*ir.LayerInstance
	for i := range 37 {
		layers = append(layers, &ir.LayerInstance{LayerPos: i, NeedsRuntimeOffset: true})
	}
	if _, err := planStack(layers[:36], nil); err != nil {
		t.Errorf("36 slots: %v", err)
	}
	_, err := planStack(layers, nil)
	if !errors.Is(err, ErrNotImplemented) {
		t.Errorf("37 slots: err = %v; want ErrNotImplemented", err)
	}
}
