package codegen

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
)

// Hand-built vocab for chain tests; matches bundled vlan.p4 / mpls.p4
// closely enough to exercise the self-dispatch + offset advancement
// paths without the full loader.
var (
	vlanFromEthConst = &vocab.DispatchConst{
		Type: vocab.DispatchField, Name: "VLAN_ETH_ETHERTYPE",
		Parent: "eth", FieldName: "ethertype", Bits: 16, Value: 0x8100,
	}
	vlanFromVlanConst = &vocab.DispatchConst{
		Type: vocab.DispatchField, Name: "VLAN_VLAN_ETHERTYPE",
		Parent: "vlan", FieldName: "ethertype", Bits: 16, Value: 0x8100,
	}
	vlanSpecForChain = newSpecWithConsts(
		"vlan", "vlan_h",
		[]vocab.Field{
			{Name: "tci", Bits: 16},
			{Name: "ethertype", Bits: 16},
		},
		*vlanFromEthConst,
		*vlanFromVlanConst,
	)

	mplsFromEthConst = &vocab.DispatchConst{
		Type: vocab.DispatchField, Name: "MPLS_ETH_ETHERTYPE",
		Parent: "eth", FieldName: "ethertype", Bits: 16, Value: 0x8847,
	}
	mplsSelfNoCheck = &vocab.DispatchConst{
		Type: vocab.DispatchNoCheck, Name: "MPLS_MPLS_NO_CHECK",
		Parent: "mpls", Bool: true,
	}
	mplsSpecForChain = func() *vocab.ProtocolSpec {
		s := newSpecWithConsts(
			"mpls", "mpls_h",
			[]vocab.Field{
				{Name: "label", Bits: 20},
				{Name: "tc", Bits: 3},
				{Name: "s", Bits: 1},
				{Name: "ttl", Bits: 8},
			},
			*mplsFromEthConst,
			*mplsSelfNoCheck,
		)
		s.ChainEnd = &vocab.ChainEndConst{
			Name:      "MPLS_CHAIN_END_S",
			FieldName: "s",
			Value:     1,
			Bits:      1,
		}
		return s
	}()
)

func vlanChainProgram(min, max int) *ir.Program {
	eth := &ir.LayerInstance{Spec: ethSpec}
	vlan := &ir.LayerInstance{
		Spec:     vlanSpecForChain,
		Dispatch: &ir.DispatchChoice{Type: vocab.DispatchField, Const: vlanFromEthConst},
		Quant:    ast.QuantRange,
		RangeMin: min, RangeMax: max,
	}
	return &ir.Program{Layers: []*ir.LayerInstance{eth, vlan}}
}

func TestGenStaticChainVlanOptionalRange(t *testing.T) {
	// vlan{1,3}: 1 mandatory iteration + 2 optional. Optional failure
	// should land on a single chain_done symbol.
	p := vlanChainProgram(1, 3)
	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	var sawChainDone bool
	for _, ins := range out.Main {
		if strings.HasPrefix(ins.Symbol(), "dsl_chain_done_") {
			sawChainDone = true
		}
	}
	if !sawChainDone {
		t.Error("chain with optional iterations must emit a chain_done symbol")
	}

	// Each iteration advances offsetBase (R4) by vlan_hs (4 bytes).
	// Count Add.Imm instructions targeting R4 specifically — bounds
	// checks also use Add.Imm but on R3, so filter by Dst.
	if got := countOffsetAdvances(out.Main, 4); got != 3 {
		t.Errorf("expected 3 offsetBase advances (one per vlan iter), got %d", got)
	}
}

func TestGenStaticChainVlanFixedCount(t *testing.T) {
	// vlan{3,3}: all mandatory. No chain_done symbol needed because
	// every mismatch jumps to dslReject.
	p := vlanChainProgram(3, 3)
	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	for _, ins := range out.Main {
		if strings.HasPrefix(ins.Symbol(), "dsl_chain_done_") {
			t.Errorf("{3,3} should not emit chain_done: %v", ins)
		}
	}
}

func TestGenStaticChainMplsUsesNoCheckSelfDispatch(t *testing.T) {
	eth := &ir.LayerInstance{Spec: ethSpec}
	mpls := &ir.LayerInstance{
		Spec:     mplsSpecForChain,
		Dispatch: &ir.DispatchChoice{Type: vocab.DispatchField, Const: mplsFromEthConst},
		Quant:    ast.QuantRange,
		RangeMin: 2, RangeMax: 4,
	}
	p := &ir.Program{Layers: []*ir.LayerInstance{eth, mpls}}
	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	// Iterations 2..4 on MPLS dispatch via NO_CHECK (zero instructions
	// from genNoCheckDispatch), but bounds + advance still appear.
	// Four iterations → 4 offsetBase advances.
	if got := countOffsetAdvances(out.Main, 4); got != 4 {
		t.Errorf("expected 4 offsetBase advances, got %d", got)
	}
}

// countOffsetAdvances counts Add.Imm R4, <hs> entries (i.e.
// emitAdvance output), filtering out bounds-check Add.Imm ops that
// target R3.
func countOffsetAdvances(insns asm.Instructions, hs int64) int {
	n := 0
	for _, ins := range insns {
		if ins.OpCode != asm.Add.Imm(offsetBase, 0).OpCode {
			continue
		}
		if ins.Dst == offsetBase && ins.Constant == hs {
			n++
		}
	}
	return n
}

func TestGenStaticChainOverCapUsesBpfLoop(t *testing.T) {
	// {1,5} exceeds the static-unroll cap, so codegen must switch to
	// the bpf_loop path. A successful Gen here proves the routing;
	// the verifier behaviour is covered by the load tests.
	p := vlanChainProgram(1, staticChainCap+1)
	if _, err := Gen(p, Capabilities{}); err != nil {
		t.Fatalf("Gen: %v", err)
	}
}

func TestGenOpenEndedChainUsesBpfLoop(t *testing.T) {
	p := vlanChainProgram(1, -1) // `{1,}` shape; same path as `+`
	if _, err := Gen(p, Capabilities{}); err != nil {
		t.Fatalf("Gen: %v", err)
	}
}

func TestGenStaticChainRejectsZeroMin(t *testing.T) {
	// `{0,3}` would need bpf_loop semantics (the whole chain can be
	// skipped); outside the static-unroll scope.
	p := vlanChainProgram(0, 3)
	_, err := Gen(p, Capabilities{})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v; want ErrNotImplemented for {0,3}", err)
	}
}

func TestGenStaticChainRejectsMissingSelfDispatch(t *testing.T) {
	// Strip the VLAN_VLAN self-dispatch so only VLAN_ETH remains.
	lonely := newSpecWithConsts(
		"vlan", "vlan_h",
		[]vocab.Field{
			{Name: "tci", Bits: 16},
			{Name: "ethertype", Bits: 16},
		},
		*vlanFromEthConst,
	)
	eth := &ir.LayerInstance{Spec: ethSpec}
	vlan := &ir.LayerInstance{
		Spec:     lonely,
		Dispatch: &ir.DispatchChoice{Type: vocab.DispatchField, Const: vlanFromEthConst},
		Quant:    ast.QuantRange,
		RangeMin: 2, RangeMax: 3,
	}
	p := &ir.Program{Layers: []*ir.LayerInstance{eth, vlan}}
	_, err := Gen(p, Capabilities{})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v; want ErrNotImplemented for missing self-dispatch", err)
	}
	if !strings.Contains(err.Error(), "self-dispatch") {
		t.Errorf("error should mention self-dispatch: %v", err)
	}
}

func TestGenBpfLoopMplsEmitsChainEndCheck(t *testing.T) {
	eth := &ir.LayerInstance{Spec: ethSpec}
	mpls := &ir.LayerInstance{
		Spec:     mplsSpecForChain,
		Dispatch: &ir.DispatchChoice{Type: vocab.DispatchField, Const: mplsFromEthConst},
		Quant:    ast.QuantPlus,
	}
	p := &ir.Program{Layers: []*ir.LayerInstance{eth, mpls}}
	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	// s-bit mask = `And.Imm R0, 1`. Verifies the MPLS special-case
	// kicked in on the callback stream.
	sawMask := false
	for _, ins := range out.Callbacks {
		if ins.OpCode == asm.And.Imm(asm.R0, 0).OpCode && ins.Constant == 1 {
			sawMask = true
			break
		}
	}
	if !sawMask {
		t.Error("expected `And.Imm R0, 1` (s-bit mask) in MPLS chain callback")
	}
}

func TestGenBpfLoopStarQuantifierEmitsSkipLabel(t *testing.T) {
	eth := &ir.LayerInstance{Spec: ethSpec}
	vlan := &ir.LayerInstance{
		Spec:     vlanSpecForChain,
		Dispatch: &ir.DispatchChoice{Type: vocab.DispatchField, Const: vlanFromEthConst},
		Quant:    ast.QuantStar,
	}
	p := &ir.Program{Layers: []*ir.LayerInstance{eth, vlan}}
	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	sawSkip := false
	for _, ins := range out.Main {
		if strings.HasPrefix(ins.Symbol(), "dsl_chain_done_") {
			sawSkip = true
			break
		}
	}
	if !sawSkip {
		t.Error("`*` quantifier must emit a chain_done landing in main")
	}
}

func TestGenBpfLoopStarRejectsFirstLayer(t *testing.T) {
	// `vlan*` as the only (first) layer has no parent to peek; codegen
	// must refuse rather than emit dispatch against uninitialised
	// state.
	vlan := &ir.LayerInstance{
		Spec:  vlanSpecForChain,
		Quant: ast.QuantStar,
	}
	p := &ir.Program{Layers: []*ir.LayerInstance{vlan}}
	_, err := Gen(p, Capabilities{})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v; want ErrNotImplemented for `*` on first layer", err)
	}
}

func TestGenBpfLoopVlanSkipsChainEndCheck(t *testing.T) {
	// Non-MPLS protocols shouldn't get the s-bit instructions even if
	// their chain uses NO_CHECK semantics elsewhere.
	eth := &ir.LayerInstance{Spec: ethSpec}
	vlan := &ir.LayerInstance{
		Spec:     vlanSpecForChain,
		Dispatch: &ir.DispatchChoice{Type: vocab.DispatchField, Const: vlanFromEthConst},
		Quant:    ast.QuantPlus,
	}
	p := &ir.Program{Layers: []*ir.LayerInstance{eth, vlan}}
	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	for _, ins := range out.Callbacks {
		if ins.OpCode == asm.And.Imm(asm.R0, 0).OpCode && ins.Constant == 1 {
			t.Errorf("VLAN chain should not emit s-bit mask, got %v", ins)
		}
	}
}

func TestGenPlusQuantifierCompiles(t *testing.T) {
	// `+` rides the bpf_loop path; we only check that Gen succeeds and
	// surfaces the callback instructions. End-to-end verifier coverage
	// lives in the program package load tests.
	eth := &ir.LayerInstance{Spec: ethSpec}
	vlan := &ir.LayerInstance{
		Spec:     vlanSpecForChain,
		Dispatch: &ir.DispatchChoice{Type: vocab.DispatchField, Const: vlanFromEthConst},
		Quant:    ast.QuantPlus,
	}
	p := &ir.Program{Layers: []*ir.LayerInstance{eth, vlan}}
	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	// Main carries a PseudoFunc load referencing the callback; the
	// callback stream itself lives on out.Callbacks and must start
	// with the matching Symbol so cilium/ebpf's linker can fix up
	// the offset.
	sawRef := false
	for _, ins := range out.Main {
		if ins.IsLoadOfFunctionPointer() && strings.HasPrefix(ins.Reference(), "dsl_chain_cb_") {
			sawRef = true
		}
	}
	if !sawRef {
		t.Error("expected main to emit a PseudoFunc load referencing dsl_chain_cb_*")
	}
	if len(out.Callbacks) == 0 || !strings.HasPrefix(out.Callbacks[0].Symbol(), "dsl_chain_cb_") {
		t.Errorf("expected callback stream starting with dsl_chain_cb_* symbol, got %+v", out.Callbacks)
	}
}
