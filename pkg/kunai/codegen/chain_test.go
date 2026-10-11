package codegen

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
	"github.com/takehaya/bpf-ninja/pkg/kunai/dslvocab"
	"github.com/takehaya/bpf-ninja/pkg/kunai/ir"
	"github.com/takehaya/bpf-ninja/pkg/kunai/parser"
	"github.com/takehaya/bpf-ninja/pkg/kunai/resolve"
	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
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
		Type: vocab.DispatchNoCheck, Name: "KUNAI_MPLS_MPLS_NO_CHECK",
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

func TestGenStaticChainZeroMinUsesPeek(t *testing.T) {
	// `{0,m}` (m ≤ staticChainCap) is the `?` peek-and-skip block followed
	// by the unroll; the whole chain skips on a parent dispatch miss.
	for _, max := range []int{1, 3} {
		p := vlanChainProgram(0, max)
		out, err := Gen(p, Capabilities{})
		if err != nil {
			t.Fatalf("{0,%d}: Gen: %v", max, err)
		}
		found := false
		for _, ins := range out.Main {
			if strings.HasPrefix(ins.Symbol(), "dsl_chain_done_") {
				found = true
			}
		}
		if !found {
			t.Fatalf("{0,%d}: missing chain-done landing", max)
		}
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

// TestGenMachineChainOpenQuantifiers pins the routing of `+`, `*` and
// `{n,}` on a parser-machine layer: no bpf_loop chain callback, MAX_DEPTH
// unrolled instances (ipv4 8), and the optional iteration 0 of `*`.
func TestGenMachineChainOpenQuantifiers(t *testing.T) {
	symbols := func(out Output) map[string]bool {
		seen := map[string]bool{}
		for _, ins := range append(append(asm.Instructions{}, out.Main...), out.Callbacks...) {
			if s := ins.Symbol(); s != "" {
				seen[s] = true
			}
		}
		return seen
	}
	plus := symbols(compileBundled(t, "eth/ipv4+/tcp"))
	for s := range plus {
		if strings.HasPrefix(s, "dsl_chain_cb_") {
			t.Fatalf("ipv4+ emitted a bpf_loop chain callback %q", s)
		}
	}
	if !plus["dsl_pm_ipv4_1_0_i7_done"] {
		t.Errorf("ipv4+ lacks the eighth instance (symbol dsl_pm_ipv4_1_0_i7_done); symbols: %v", plus)
	}
	if plus["dsl_pm_ipv4_1_0_i8_done"] {
		t.Error("ipv4+ emitted a ninth instance")
	}
	star := symbols(compileBundled(t, "eth/ipv4/ipv4*/tcp"))
	if !star["dsl_chain_done_2"] {
		t.Error("ipv4* lacks the chain-done landing")
	}
	open := symbols(compileBundled(t, "eth/ipv6{1,}/tcp"))
	if !open["dsl_pm_ipv6_1_0_i3_done"] || open["dsl_pm_ipv6_1_0_i4_done"] {
		t.Errorf("ipv6{1,} should unroll to IPV6_MAX_DEPTH = 4 instances; symbols: %v", open)
	}
}

func TestLayerEntryIsRangeOpenQuantifiers(t *testing.T) {
	for _, expr := range []string{"eth/ipv4+/tcp", "eth/ipv4/ipv4*/tcp", "eth/ipv4{2,}/tcp", "eth/ipv4{1,2}/tcp"} {
		p := parseResolveBundled(t, expr)
		idx := len(p.Layers) - 2
		if !layerEntryIsRange(p.Layers, idx) {
			t.Errorf("%s: layer %d (%s) should leave a range-valued entry", expr, idx, p.Layers[idx].Spec.Name)
		}
	}
	p := parseResolveBundled(t, "eth/ipv4/tcp")
	if layerEntryIsRange(p.Layers, 1) {
		t.Error("eth/ipv4/tcp: a single ipv4 has a constant entry")
	}
}

// parseResolveBundled parses and resolves expr against the bundled
// vocabulary without generating code.
func parseResolveBundled(t *testing.T, expr string) *ir.Program {
	t.Helper()
	v, err := dslvocab.Bundled()
	if err != nil {
		t.Fatalf("dslvocab.Bundled: %v", err)
	}
	f, err := parser.Parse(expr, "", nil)
	if err != nil {
		t.Fatalf("parser.Parse(%q): %v", expr, err)
	}
	prog, err := resolve.ResolveWithOptions(f, v, nil, resolve.Options{})
	if err != nil {
		t.Fatalf("resolve(%q): %v", expr, err)
	}
	return prog
}
