package codegen

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ir"
	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
)

// TestVariableTrailWriteBackStoresToSlot pins where the write-back byte
// goes: into the layer's stack slot, through R10 on the inline path and
// through the bpf_loop ctx pointer (R2) on the callback path, never into
// the packet. A trail whose write-back has no slot bound is refused.
func TestVariableTrailWriteBackStoresToSlot(t *testing.T) {
	vt := func(slot int16) variableTailSkip {
		return variableTailSkip{
			LenFieldByteOff: 1, Scale: 8, Base: 8, LenMask: 0xff,
			WriteBack: &writeBackOp{SourceByteOff: 0, ParentByteOff: 6, Slot: slot},
		}
	}
	stores := func(insns asm.Instructions) []asm.Instruction {
		var out []asm.Instruction
		for _, ins := range insns {
			if ins.OpCode.Class() == asm.StXClass {
				out = append(out, ins)
			}
		}
		return out
	}

	inline, err := emitVariableTrailInline(8, vt(-240), "fail")
	if err != nil {
		t.Fatal(err)
	}
	got := stores(inline)
	if len(got) != 1 || got[0].Dst != asm.R10 || got[0].Offset != -240 || got[0].Src != asm.R3 || got[0].OpCode != asm.StoreMemOp(asm.DWord) {
		t.Fatalf("inline stores = %v; want one DWord store of R3 to R10-240", got)
	}

	cb, err := emitVariableTrailCallback(8, vt(-240), "break")
	if err != nil {
		t.Fatal(err)
	}
	got = stores(cb)
	// The callback also stores the running offset back into the ctx.
	var slotStore *asm.Instruction
	for i := range got {
		if got[i].Dst == asm.R2 && got[i].Offset == mainStackOffsetFromCb(-240) {
			slotStore = &got[i]
		}
		if got[i].Dst != asm.R2 {
			t.Errorf("callback store %v is not through the ctx pointer", got[i])
		}
	}
	if slotStore == nil || slotStore.Src != asm.R0 || slotStore.OpCode != asm.StoreMemOp(asm.DWord) {
		t.Fatalf("callback stores = %v; want a DWord store of R0 to R2%+d", got, mainStackOffsetFromCb(-240))
	}

	if _, err := emitVariableTrailInline(8, vt(0), "fail"); err == nil || !strings.Contains(err.Error(), "no stack slot bound") {
		t.Fatalf("unbound write-back slot: err = %v", err)
	}
}

// TestPlanStackWriteBackSlot pins that every layer (and alternation
// member) whose protocol declares a write-back gets one slot, and that
// a protocol without one takes none.
func TestPlanStackWriteBackSlot(t *testing.T) {
	wb := &vocab.ProtocolSpec{Name: "wb", HeaderAnnotations: map[string]*vocab.HeaderAnnotations{
		"ext": {WriteBack: &vocab.WriteBackSpec{ParentByteOff: 6, Resolved: true}},
	}}
	plain := &vocab.ProtocolSpec{Name: "plain"}
	a := &ir.LayerInstance{LayerPos: 0, Spec: plain}
	m1 := &ir.LayerInstance{LayerPos: 1, Spec: plain}
	m2 := &ir.LayerInstance{LayerPos: 1, Spec: wb}
	group := &ir.LayerInstance{LayerPos: 1, Spec: plain, Alternation: []*ir.LayerInstance{m1, m2}}
	b := &ir.LayerInstance{LayerPos: 2, Spec: wb}
	plan, err := planStack([]*ir.LayerInstance{a, group, b}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	qo := queriedOptions{plan: plan}
	if slot, ok := qo.writeBackSlot(m2); !ok || slot != stackPlanTop {
		t.Errorf("member write-back slot = %d, %v; want %d", slot, ok, stackPlanTop)
	}
	if slot, ok := qo.writeBackSlot(b); !ok || slot != stackPlanTop-8 {
		t.Errorf("b write-back slot = %d, %v; want %d", slot, ok, stackPlanTop-8)
	}
	for _, l := range []*ir.LayerInstance{a, m1, group} {
		if _, ok := qo.writeBackSlot(l); ok {
			t.Errorf("%s has a write-back slot without a write-back", l.DisplayName())
		}
	}
	if writeBackOf(plain) != nil || writeBackOf(nil) != nil || writeBackOf(wb) == nil {
		t.Error("writeBackOf")
	}
}
