package codegen

import (
	"testing"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
	"github.com/takehaya/bpf-ninja/pkg/kunai/ir"
	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
)

// Per-layer entry slot lifecycle for quantified layers (D-003 / D-018): a
// marked layer stores every present instance's start (the last one wins),
// an absentable one is pre-marked absent, and unmarked layers emit nothing.

func countSlotStores(insns asm.Instructions, slot int16, src asm.Register) int {
	n := 0
	for _, ins := range insns {
		if ins.OpCode == asm.StoreMem(asm.R10, 0, asm.R4, asm.DWord).OpCode && ins.Dst == asm.R10 && ins.Offset == slot && ins.Src == src {
			n++
		}
	}
	return n
}

func TestStaticChainWritesEntrySlotPerIteration(t *testing.T) {
	slot, err := whereLayerEntrySlot(1)
	if err != nil {
		t.Fatal(err)
	}
	for _, marked := range []bool{false, true} {
		p := vlanChainProgram(1, 3)
		p.Layers[1].LayerPos, p.Layers[1].NeedsRuntimeOffset = 1, marked
		out, err := Gen(p, Capabilities{})
		if err != nil {
			t.Fatalf("Gen(marked=%v): %v", marked, err)
		}
		want := 0
		if marked {
			want = 3 // one store per unrolled iteration
		}
		if got := countSlotStores(out.Main, slot, asm.R4); got != want {
			t.Errorf("marked=%v: %d entry-slot stores, want %d", marked, got, want)
		}
		if got := countSlotStores(out.Main, slot, asm.R3); got != 0 {
			t.Errorf("marked=%v: %d sentinel stores on a mandatory chain, want 0", marked, got)
		}
	}
}

func TestOptionalChainSentinelThenStore(t *testing.T) {
	slot, err := whereLayerEntrySlot(1)
	if err != nil {
		t.Fatal(err)
	}
	p := vlanChainProgram(0, 1)
	p.Layers[1].LayerPos, p.Layers[1].NeedsRuntimeOffset = 1, true
	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	// The sentinel (Mov R3,-1; store) precedes the peek's JNE; the R4 store
	// follows it (present path), before the advance.
	sentinelAt, peekAt, storeAt := -1, -1, -1
	for i, ins := range out.Main {
		switch {
		case ins.OpCode == asm.Mov.Imm(asm.R3, 0).OpCode && ins.Dst == asm.R3 && ins.Constant == int64(layerEntryAbsent) && sentinelAt < 0:
			sentinelAt = i
		case ins.OpCode == asm.JNE.Imm(asm.R3, 0, "").OpCode && peekAt < 0 && sentinelAt >= 0:
			peekAt = i
		case ins.OpCode == asm.StoreMem(asm.R10, 0, asm.R4, asm.DWord).OpCode && ins.Offset == slot && ins.Src == asm.R4:
			storeAt = i
		}
	}
	if sentinelAt < 0 || peekAt < 0 || storeAt < 0 {
		t.Fatalf("sentinel=%d peek=%d store=%d: all three must be emitted", sentinelAt, peekAt, storeAt)
	}
	if sentinelAt >= peekAt || peekAt >= storeAt {
		t.Errorf("order sentinel(%d) < peek(%d) < store(%d) violated", sentinelAt, peekAt, storeAt)
	}
}

func TestBpfLoopCallbackWritesMainSlot(t *testing.T) {
	slot, err := whereLayerEntrySlot(1)
	if err != nil {
		t.Fatal(err)
	}
	eth := &ir.LayerInstance{Spec: ethSpec}
	mpls := &ir.LayerInstance{
		Spec:     mplsSpecForChain,
		Dispatch: &ir.DispatchChoice{Type: vocab.DispatchField, Const: mplsFromEthConst},
		Quant:    ast.QuantPlus, RangeMin: 1, RangeMax: -1,
		LayerPos: 1, NeedsRuntimeOffset: true,
	}
	out, err := Gen(&ir.Program{Layers: []*ir.LayerInstance{eth, mpls}}, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	if got := countSlotStores(out.Main, slot, asm.R4); got != 1 {
		t.Errorf("iteration 0 stores: %d, want 1", got)
	}
	cb := 0
	for _, ins := range out.Callbacks {
		if ins.OpCode == asm.StoreMem(asm.R2, 0, asm.R3, asm.DWord).OpCode && ins.Dst == asm.R2 && ins.Offset == mainStackOffsetFromCb(slot) && ins.Src == asm.R3 {
			cb++
		}
	}
	if cb != 1 {
		t.Errorf("callback stores through ctx: %d, want 1", cb)
	}
}
