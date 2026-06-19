package codegen

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
)

func newSpec(name, header string, fields ...vocab.Field) *vocab.ProtocolSpec {
	return &vocab.ProtocolSpec{Name: name, HeaderName: header, Fields: fields}
}

// newSpecWithConsts is newSpec + a pre-populated dispatch-const
// slice, so tests that need to exercise DispatchConst lookups can
// build a fully-formed spec inline instead of patching a package
// variable.
func newSpecWithConsts(name, header string, fields []vocab.Field, consts ...vocab.DispatchConst) *vocab.ProtocolSpec {
	s := &vocab.ProtocolSpec{Name: name, HeaderName: header, Fields: fields}
	s.Consts = append(s.Consts, consts...)
	return s
}

// ethIPv4TCPSpecs matches the bundled vocabulary closely enough to
// exercise byte offsets and dispatch constants without the full load
// machinery. Using purpose-built specs keeps these tests unit-scoped.
var (
	ethSpec = newSpec("eth", "eth_h",
		vocab.Field{Name: "dst", Bits: 48},
		vocab.Field{Name: "src", Bits: 48},
		vocab.Field{Name: "ethertype", Bits: 16},
	)
	ipv4Spec = newSpec("ipv4", "ipv4_h",
		vocab.Field{Name: "version", Bits: 4},
		vocab.Field{Name: "ihl", Bits: 4},
		vocab.Field{Name: "diffserv", Bits: 8},
		vocab.Field{Name: "total_length", Bits: 16},
		vocab.Field{Name: "identification", Bits: 16},
		vocab.Field{Name: "flags", Bits: 3},
		vocab.Field{Name: "frag_offset", Bits: 13},
		vocab.Field{Name: "ttl", Bits: 8},
		vocab.Field{Name: "protocol", Bits: 8},
		vocab.Field{Name: "checksum", Bits: 16},
		vocab.Field{Name: "src", Bits: 32},
		vocab.Field{Name: "dst", Bits: 32},
	)
	ipv6Spec = newSpec("ipv6", "ipv6_h",
		vocab.Field{Name: "version", Bits: 4},
		vocab.Field{Name: "traffic_class", Bits: 8},
		vocab.Field{Name: "flow_label", Bits: 20},
		vocab.Field{Name: "payload_length", Bits: 16},
		vocab.Field{Name: "next_header", Bits: 8},
		vocab.Field{Name: "hop_limit", Bits: 8},
		vocab.Field{Name: "src", Bits: 128},
		vocab.Field{Name: "dst", Bits: 128},
	)
	tcpSpec = newSpec("tcp", "tcp_h",
		vocab.Field{Name: "sport", Bits: 16},
		vocab.Field{Name: "dport", Bits: 16},
		vocab.Field{Name: "seq", Bits: 32},
		vocab.Field{Name: "ack", Bits: 32},
		vocab.Field{Name: "data_offset", Bits: 4},
		vocab.Field{Name: "reserved", Bits: 3},
		vocab.Field{Name: "flags", Bits: 9},
		vocab.Field{Name: "window", Bits: 16},
		vocab.Field{Name: "checksum", Bits: 16},
		vocab.Field{Name: "urgent_ptr", Bits: 16},
	)
	ipv4EthertypeConst = &vocab.DispatchConst{
		Type: vocab.DispatchField, Name: "IPV4_ETH_ETHERTYPE",
		Parent: "eth", FieldName: "ethertype", Bits: 16, Value: 0x0800,
	}
	tcpProtocolConst = &vocab.DispatchConst{
		Type: vocab.DispatchField, Name: "TCP_IPV4_PROTOCOL",
		Parent: "ipv4", FieldName: "protocol", Bits: 8, Value: 6,
	}
)

func ethIPv4TCPProgram() *ir.Program {
	eth := &ir.LayerInstance{Spec: ethSpec}
	ipv4 := &ir.LayerInstance{Spec: ipv4Spec, Dispatch: &ir.DispatchChoice{Type: vocab.DispatchField, Const: ipv4EthertypeConst}}
	tcp := &ir.LayerInstance{Spec: tcpSpec, Dispatch: &ir.DispatchChoice{Type: vocab.DispatchField, Const: tcpProtocolConst}}
	return &ir.Program{Layers: []*ir.LayerInstance{eth, ipv4, tcp}}
}

// ethIPv6TCPProgram is the IPv6 sibling of ethIPv4TCPProgram. The
// dispatch consts are inline (rather than package-level like the v4
// ones) because IPv6 tests are still rare; promote them when the
// next caller appears.
func ethIPv6TCPProgram() *ir.Program {
	eth := &ir.LayerInstance{Spec: ethSpec}
	ipv6 := &ir.LayerInstance{
		Spec: ipv6Spec,
		Dispatch: &ir.DispatchChoice{
			Type: vocab.DispatchField,
			Const: &vocab.DispatchConst{
				Type: vocab.DispatchField, Name: "IPV6_ETH_ETHERTYPE",
				Parent: "eth", FieldName: "ethertype", Bits: 16, Value: 0x86DD,
			},
		},
	}
	tcp := &ir.LayerInstance{
		Spec: tcpSpec,
		Dispatch: &ir.DispatchChoice{
			Type: vocab.DispatchField,
			Const: &vocab.DispatchConst{
				Type: vocab.DispatchField, Name: "TCP_IPV6_NEXT_HEADER",
				Parent: "ipv6", FieldName: "next_header", Bits: 8, Value: 6,
			},
		},
	}
	return &ir.Program{Layers: []*ir.LayerInstance{eth, ipv6, tcp}}
}

func TestGenEthIPv4TCP(t *testing.T) {
	out, err := Gen(ethIPv4TCPProgram(), Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	if len(out.Main) == 0 {
		t.Fatal("expected non-empty instruction stream")
	}
	// The accept path ends with Mov.Imm(R2,1); Ja filter_result;
	// the reject landing is Mov.Imm(R2,0) with the dsl_reject symbol.
	wantSymbols := map[string]bool{dslReject: false}
	for _, ins := range out.Main {
		if sym := ins.Symbol(); sym != "" {
			if _, ok := wantSymbols[sym]; ok {
				wantSymbols[sym] = true
			}
		}
	}
	if !wantSymbols[dslReject] {
		t.Errorf("emitted stream missing %q label", dslReject)
	}

	// Count bounds checks: each of the 3 layers should produce one JGT R3,R1.
	jgtCount := 0
	for _, ins := range out.Main {
		if ins.OpCode == asm.JGT.Reg(asm.R3, asm.R1, "").OpCode {
			jgtCount++
		}
	}
	if jgtCount != 3 {
		t.Errorf("expected 3 bounds-check JGTs, got %d", jgtCount)
	}

	// Each non-root layer should emit one JNE against its dispatch constant.
	jneCount := 0
	for _, ins := range out.Main {
		if ins.OpCode == asm.JNE.Imm(asm.R3, 0, "").OpCode {
			jneCount++
		}
	}
	if jneCount != 2 {
		t.Errorf("expected 2 dispatch JNEs, got %d", jneCount)
	}
}

func TestGenActionAtomFExitSucceeds(t *testing.T) {
	p := ethIPv4TCPProgram()
	p.Where = &ir.Condition{Kind: ast.WAtomAction, ActionValue: "XDP_DROP"}
	out, err := Gen(p, xdpFexitCapsForTest())
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	// The action check reads args ptr from stack[-48] and reads args[1]
	// from there; verify the two LoadMem pattern appears.
	loadFromStack := 0
	for _, ins := range out.Main {
		if ins.OpCode == asm.LoadMem(asm.R3, asm.R10, -48, asm.DWord).OpCode {
			loadFromStack++
		}
	}
	if loadFromStack == 0 {
		t.Error("action atom should emit LoadMem from stack[-48]")
	}
}

func TestGenActionAtomFEntryRejected(t *testing.T) {
	p := ethIPv4TCPProgram()
	p.Where = &ir.Condition{Kind: ast.WAtomAction, ActionValue: "XDP_PASS"}
	_, err := Gen(p, Capabilities{})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v; want ErrNotImplemented", err)
	}
}

func TestGenActionAtomUnknownName(t *testing.T) {
	p := ethIPv4TCPProgram()
	p.Where = &ir.Condition{Kind: ast.WAtomAction, ActionValue: "XDP_BOGUS"}
	_, err := Gen(p, xdpFexitCapsForTest())
	if err == nil {
		t.Fatal("expected error for unknown XDP action")
	}
}

func TestGenArithFieldEqualsConst(t *testing.T) {
	p := ethIPv4TCPProgram()
	// ipv4.total_length (at eth_hs=14 + 2 = 16, 2 bytes)
	totalLenField := &ipv4Spec.Fields[3] // total_length
	p.Where = &ir.Condition{
		Kind: ast.WAtomArith,
		Op:   ast.CmpEq,
		ArithL: &ir.ArithExpr{
			Kind:  ast.ArithField,
			Field: &ir.FieldRef{Layer: p.Layers[1], Field: totalLenField},
		},
		ArithR: &ir.ArithExpr{Kind: ast.ArithConst, Const: 100},
	}
	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	// Must see a HostTo(BE) on the 2-byte field load (BPF_END opcode,
	// 5.x-safe alternative to BSwap), a StoreMem/LoadMem pair for the
	// left-operand stack save, and a JNE.Reg for the reject compare.
	var bswap, storeMem, loadR5, jneReg bool
	for _, ins := range out.Main {
		switch ins.OpCode {
		case asm.HostTo(asm.BE, asm.R3, asm.Half).OpCode:
			bswap = true
		case asm.StoreMem(asm.R10, arithStackSlot(0), asm.R3, asm.DWord).OpCode:
			storeMem = true
		case asm.LoadMem(asm.R5, asm.R10, arithStackSlot(0), asm.DWord).OpCode:
			loadR5 = true
		case asm.JNE.Reg(asm.R5, asm.R3, "").OpCode:
			jneReg = true
		}
	}
	if !bswap || !storeMem || !loadR5 || !jneReg {
		t.Errorf("arith codegen missing a pattern: bswap=%v store=%v load=%v jne=%v", bswap, storeMem, loadR5, jneReg)
	}
}

func TestGenArithBinaryOpEvaluatesBothSides(t *testing.T) {
	p := ethIPv4TCPProgram()
	// ipv4.total_length == ipv4.total_length + 0 (structurally a binary
	// op) is enough to exercise the nested arith stack slot logic.
	totalLenField := &ipv4Spec.Fields[3]
	field := &ir.ArithExpr{
		Kind:  ast.ArithField,
		Field: &ir.FieldRef{Layer: p.Layers[1], Field: totalLenField},
	}
	p.Where = &ir.Condition{
		Kind:   ast.WAtomArith,
		Op:     ast.CmpEq,
		ArithL: field,
		ArithR: &ir.ArithExpr{
			Kind:  ast.ArithBinOp,
			Op:    ast.ArithAdd,
			Left:  field,
			Right: &ir.ArithExpr{Kind: ast.ArithConst, Const: 0},
		},
	}
	if _, err := Gen(p, Capabilities{}); err != nil {
		t.Fatalf("Gen: %v", err)
	}
}

func TestGenArithRejectsQuantifiedUpstream(t *testing.T) {
	// eth / vlan? / ipv4 / tcp with `where ipv4.total_length == 100`:
	// the optional vlan makes ipv4's absolute offset runtime-variable,
	// so the where codegen must refuse.
	vlanSpec := newSpec("vlan", "vlan_h",
		vocab.Field{Name: "tci", Bits: 16},
		vocab.Field{Name: "ethertype", Bits: 16},
	)
	vlanFromEth := &vocab.DispatchConst{
		Type: vocab.DispatchField, Name: "VLAN_ETH_ETHERTYPE",
		Parent: "eth", FieldName: "ethertype", Bits: 16, Value: 0x8100,
	}
	eth := &ir.LayerInstance{Spec: ethSpec}
	vlan := &ir.LayerInstance{
		Spec:     vlanSpec,
		Dispatch: &ir.DispatchChoice{Type: vocab.DispatchField, Const: vlanFromEth},
		Quant:    ast.QuantOpt,
	}
	ipv4 := &ir.LayerInstance{
		Spec:     ipv4Spec,
		Dispatch: &ir.DispatchChoice{Type: vocab.DispatchField, Const: ipv4EthertypeConst},
	}
	p := &ir.Program{
		Layers: []*ir.LayerInstance{eth, vlan, ipv4},
		Where: &ir.Condition{
			Kind: ast.WAtomArith,
			Op:   ast.CmpEq,
			ArithL: &ir.ArithExpr{
				Kind:  ast.ArithField,
				Field: &ir.FieldRef{Layer: ipv4, Field: &ipv4Spec.Fields[3]},
			},
			ArithR: &ir.ArithExpr{Kind: ast.ArithConst, Const: 100},
		},
	}
	_, err := Gen(p, Capabilities{})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v; want ErrNotImplemented", err)
	}
}

func TestGenArithDepthLimit(t *testing.T) {
	// Build an arith tree nested deeper than maxArithDepth to confirm
	// the guard.
	var deep = &ir.ArithExpr{Kind: ast.ArithConst, Const: 1}
	for range maxArithDepth + 1 {
		deep = &ir.ArithExpr{
			Kind:  ast.ArithBinOp,
			Op:    ast.ArithAdd,
			Left:  deep,
			Right: &ir.ArithExpr{Kind: ast.ArithConst, Const: 1},
		}
	}
	p := ethIPv4TCPProgram()
	p.Where = &ir.Condition{
		Kind:   ast.WAtomArith,
		Op:     ast.CmpEq,
		ArithL: deep,
		ArithR: &ir.ArithExpr{Kind: ast.ArithConst, Const: 0},
	}
	_, err := Gen(p, Capabilities{})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v; want ErrNotImplemented for deep arith", err)
	}
}

func TestGenArithNestedHappyPath(t *testing.T) {
	// Pin every nesting count from 1 up to the largest tree the depth
	// guard accepts so a future bump (or stack-layout change) cannot
	// silently drop a level. The tree is left-leaning:
	// ((((1+1)+1)+1)... — `binops` = N produces N nested binops on the
	// left spine. The depth guard rejects at call-depth >= maxArithDepth,
	// which is reached by the leaf children of the deepest binop, so the
	// largest accepted tree has maxArithDepth-1 binops (deepest binop at
	// call-depth maxArithDepth-2, its leaves at maxArithDepth-1).
	totalLenField := &ipv4Spec.Fields[3]
	for binops := 1; binops < maxArithDepth; binops++ {
		t.Run(fmt.Sprintf("binops_%d", binops), func(t *testing.T) {
			var expr = &ir.ArithExpr{Kind: ast.ArithConst, Const: 1}
			for range binops {
				expr = &ir.ArithExpr{
					Kind:  ast.ArithBinOp,
					Op:    ast.ArithAdd,
					Left:  expr,
					Right: &ir.ArithExpr{Kind: ast.ArithConst, Const: 1},
				}
			}
			p := ethIPv4TCPProgram()
			p.Where = &ir.Condition{
				Kind: ast.WAtomArith,
				Op:   ast.CmpEq,
				ArithL: &ir.ArithExpr{
					Kind:  ast.ArithField,
					Field: &ir.FieldRef{Layer: p.Layers[1], Field: totalLenField},
				},
				ArithR: expr,
			}
			if _, err := Gen(p, Capabilities{}); err != nil {
				t.Fatalf("binops %d: Gen: %v", binops, err)
			}
		})
	}
}

// deepLeftArithCompare returns `ipv4.total_length == (1+1+...+1)` whose
// RHS is `binops` left-leaning additions, so its leaves land at arith
// call-depth `binops`. layer is the ipv4 LayerInstance the field reads.
func deepLeftArithCompare(layer *ir.LayerInstance, binops int) *ir.Condition {
	var expr = &ir.ArithExpr{Kind: ast.ArithConst, Const: 1}
	for range binops {
		expr = &ir.ArithExpr{
			Kind:  ast.ArithBinOp,
			Op:    ast.ArithAdd,
			Left:  expr,
			Right: &ir.ArithExpr{Kind: ast.ArithConst, Const: 1},
		}
	}
	return &ir.Condition{
		Kind:   ast.WAtomArith,
		Op:     ast.CmpEq,
		ArithL: &ir.ArithExpr{Kind: ast.ArithField, Field: &ir.FieldRef{Layer: layer, Field: &ipv4Spec.Fields[3]}},
		ArithR: expr,
	}
}

// TestGenBoolEqOperandArithDepthBudget pins the bool-eq / operand-arith
// slot accounting. genBoolEq parks each operand's LHS truth value at the
// top of the arith region, so genArithWithBits lowers the usable arith
// depth by the bool-eq nesting level: a `+`/`-` chain that compiles at the
// top depth standalone must be rejected once it sits inside a bool-eq
// operand, where climbing that deep would clobber the parked LHS and
// silently mis-compare.
func TestGenBoolEqOperandArithDepthBudget(t *testing.T) {
	// binops = maxArithDepth-1 puts the leaves at the deepest call-depth
	// the full (boolEqDepth == 0) guard still accepts.
	const binops = maxArithDepth - 1

	standalone := ethIPv4TCPProgram()
	standalone.Where = deepLeftArithCompare(standalone.Layers[1], binops)
	if _, err := Gen(standalone, Capabilities{}); err != nil {
		t.Fatalf("standalone deep arith should compile at the top depth: %v", err)
	}

	// Same chain as a bool-eq operand: the budget drops by one level, so
	// the deepest leaf now exceeds the ceiling and is rejected.
	nested := ethIPv4TCPProgram()
	nested.Where = &ir.Condition{
		Kind:     ast.WAtomBoolEq,
		BoolEqOp: ast.CmpEq,
		BoolL:    deepLeftArithCompare(nested.Layers[1], binops),
		BoolR:    deepLeftArithCompare(nested.Layers[1], 0), // shallow, valid operand
	}
	if _, err := Gen(nested, Capabilities{}); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("deep arith inside bool-eq operand: err = %v; want ErrNotImplemented", err)
	}
}

// --- Logical ops ---

func actionAtom(v string) *ir.Condition {
	return &ir.Condition{Kind: ast.WAtomAction, ActionValue: v}
}

func TestGenAndCombinesActionAtoms(t *testing.T) {
	p := ethIPv4TCPProgram()
	p.Where = &ir.Condition{
		Kind:  ast.WAnd,
		Left:  actionAtom("XDP_DROP"),
		Right: actionAtom("XDP_PASS"),
	}
	_, err := Gen(p, xdpFexitCapsForTest())
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
}

func TestGenOrEmitsShortCircuit(t *testing.T) {
	p := ethIPv4TCPProgram()
	p.Where = &ir.Condition{
		Kind:  ast.WOr,
		Left:  actionAtom("XDP_DROP"),
		Right: actionAtom("XDP_PASS"),
	}
	out, err := Gen(p, xdpFexitCapsForTest())
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	// OR emits one Ja <or_done> to short-circuit when left succeeds, and
	// two symbol landings: or_right_N (on the first right instr) and
	// or_done_N (after right).
	var sawOrRight, sawOrDone, sawJa bool
	for _, ins := range out.Main {
		switch ins.Symbol() {
		case "dsl_or_right_1":
			sawOrRight = true
		case "dsl_or_done_2":
			sawOrDone = true
		}
		if ins.OpCode == asm.Ja.Label("").OpCode {
			sawJa = true
		}
	}
	if !sawOrRight || !sawOrDone || !sawJa {
		t.Errorf("or codegen missing pieces: orRight=%v orDone=%v ja=%v", sawOrRight, sawOrDone, sawJa)
	}
}

func TestGenNotInverts(t *testing.T) {
	p := ethIPv4TCPProgram()
	p.Where = &ir.Condition{
		Kind:  ast.WNot,
		Inner: actionAtom("XDP_DROP"),
	}
	out, err := Gen(p, xdpFexitCapsForTest())
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	// not emits inner's check, a Ja failLabel on inner-success, and a
	// not_succ landing on inner-failure.
	var sawNotSucc bool
	for _, ins := range out.Main {
		if ins.Symbol() == "dsl_not_succ_1" {
			sawNotSucc = true
		}
	}
	if !sawNotSucc {
		t.Error("not codegen must emit a not_succ landing symbol")
	}
}

func TestGenNestedLogicalOps(t *testing.T) {
	// "not (action == XDP_DROP and action == XDP_PASS)"
	p := ethIPv4TCPProgram()
	p.Where = &ir.Condition{
		Kind: ast.WNot,
		Inner: &ir.Condition{
			Kind:  ast.WAnd,
			Left:  actionAtom("XDP_DROP"),
			Right: actionAtom("XDP_PASS"),
		},
	}
	if _, err := Gen(p, xdpFexitCapsForTest()); err != nil {
		t.Fatalf("Gen: %v", err)
	}
}

func TestGenUnsupportedInsideAndBubbles(t *testing.T) {
	// Unsupported atoms buried in a logical op must still bubble up.
	// Use a synthetic Unsupported marker rather than a real WhereKind
	// so the test stays isolated from the live atom catalogue.
	p := ethIPv4TCPProgram()
	p.Where = &ir.Condition{
		Kind: ast.WAnd,
		Left: actionAtom("XDP_DROP"),
		Right: &ir.Condition{
			Kind:        ast.WAtomArith,
			Unsupported: "synthetic unsupported atom for test",
		},
	}
	_, err := Gen(p, xdpFexitCapsForTest())
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v; want ErrNotImplemented", err)
	}
}

func TestGenCaptureAllKeepsDefault(t *testing.T) {
	p := ethIPv4TCPProgram()
	p.Captures = []*ir.CaptureClause{{Kind: ast.CapAll}}
	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	if out.Capture.MaxCapLen != 0 {
		t.Errorf("capture all should leave MaxCapLen=0, got %d", out.Capture.MaxCapLen)
	}
}

func TestGenCaptureHeadersSumsHeaderSizes(t *testing.T) {
	p := ethIPv4TCPProgram()
	p.Captures = []*ir.CaptureClause{{Kind: ast.CapHeaders}}
	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	// eth(14) + ipv4(20) + tcp(20) = 54
	if out.Capture.MaxCapLen != 54 {
		t.Errorf("capture headers: MaxCapLen = %d, want 54", out.Capture.MaxCapLen)
	}
}

func TestGenCaptureHeadersPlusAddsExtra(t *testing.T) {
	p := ethIPv4TCPProgram()
	p.Captures = []*ir.CaptureClause{{Kind: ast.CapHeadersPlus, Extra: 64}}
	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	if out.Capture.MaxCapLen != 54+64 {
		t.Errorf("capture headers+64: MaxCapLen = %d, want %d", out.Capture.MaxCapLen, 54+64)
	}
}

func TestGenCaptureToLayerSumsThroughTarget(t *testing.T) {
	// eth(14) + ipv4(20) + tcp(20). `capture ipv4` covers eth+ipv4 = 34;
	// `capture tcp` covers all three = 54.
	p := ethIPv4TCPProgram()
	p.Captures = []*ir.CaptureClause{{Kind: ast.CapToLayer, TargetLayer: p.Layers[1]}} // ipv4
	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	if out.Capture.MaxCapLen != 14+20 {
		t.Errorf("capture ipv4: MaxCapLen = %d, want 34", out.Capture.MaxCapLen)
	}

	p.Captures = []*ir.CaptureClause{{Kind: ast.CapToLayer, TargetLayer: p.Layers[2], Extra: 8}} // tcp+8
	out, err = Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen tcp+8: %v", err)
	}
	if out.Capture.MaxCapLen != 14+20+20+8 {
		t.Errorf("capture tcp+8: MaxCapLen = %d, want 62", out.Capture.MaxCapLen)
	}
}

func TestGenFilterMinPrefixForChain(t *testing.T) {
	// FilterMinPrefix is the chain prefix sum even when no `where`
	// clause is present. eth+ipv4+tcp = 14+20+20 = 54.
	p := ethIPv4TCPProgram()
	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	if out.Capture.FilterMinPrefix != 54 {
		t.Errorf("eth/ipv4/tcp: FilterMinPrefix = %d, want 54", out.Capture.FilterMinPrefix)
	}
}

// No `capture` clause is sugar for `capture all`: MaxCapLen=0 so the
// host falls back to DefaultCapLen (= 1500 B). Locks in the
// principle-of-least-surprise behaviour after the Option A redesign
// — `tcp where dport == 443` should capture full packets the same
// way tcpdump does, not silently truncate to 54 B.
func TestGenNoCaptureClauseLeavesMaxCapLenZero(t *testing.T) {
	p := ethIPv4TCPProgram()
	// tcp where tcp.dport == 443
	p.Where = &ir.Condition{
		Kind: ast.WAtomArith,
		Op:   ast.CmpEq,
		ArithL: &ir.ArithExpr{
			Kind:  ast.ArithField,
			Field: &ir.FieldRef{Layer: p.Layers[2], Field: &tcpSpec.Fields[1]}, // dport
		},
		ArithR: &ir.ArithExpr{Kind: ast.ArithConst, Const: 443},
	}
	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	if out.Capture.MaxCapLen != 0 {
		t.Errorf("no capture clause: MaxCapLen = %d, want 0 (= host fallback to DefaultCapLen)", out.Capture.MaxCapLen)
	}
	// FilterMinPrefix is the scratch-read sizing, independent of the
	// payload truncation; it must still be computed when the where
	// clause reaches into tcp.dport.
	if out.Capture.FilterMinPrefix < 54 {
		t.Errorf("no capture clause: FilterMinPrefix = %d, want >= 54 (eth+ipv4+tcp.dport offset)", out.Capture.FilterMinPrefix)
	}
}

func TestGenCaptureAbsoluteIndependentOfChain(t *testing.T) {
	p := ethIPv4TCPProgram()
	p.Captures = []*ir.CaptureClause{{Kind: ast.CapAbsolute, Extra: 96}}
	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	if out.Capture.MaxCapLen != 96 {
		t.Errorf("capture absolute 96: MaxCapLen = %d, want 96", out.Capture.MaxCapLen)
	}
}

func TestGenCaptureRejectsFieldList(t *testing.T) {
	p := ethIPv4TCPProgram()
	p.Captures = []*ir.CaptureClause{{Kind: ast.CapFields, Unsupported: "field-list capture"}}
	_, err := Gen(p, Capabilities{})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v; want ErrNotImplemented", err)
	}
}

func TestGenCaptureRejectsQuantifiedChain(t *testing.T) {
	vlanSpec := newSpec("vlan", "vlan_h",
		vocab.Field{Name: "tci", Bits: 16},
		vocab.Field{Name: "ethertype", Bits: 16},
	)
	vlanFromEth := &vocab.DispatchConst{
		Type: vocab.DispatchField, Name: "VLAN_ETH_ETHERTYPE",
		Parent: "eth", FieldName: "ethertype", Bits: 16, Value: 0x8100,
	}
	eth := &ir.LayerInstance{Spec: ethSpec}
	vlan := &ir.LayerInstance{
		Spec:     vlanSpec,
		Dispatch: &ir.DispatchChoice{Type: vocab.DispatchField, Const: vlanFromEth},
		Quant:    ast.QuantOpt,
	}
	p := &ir.Program{
		Layers:   []*ir.LayerInstance{eth, vlan},
		Captures: []*ir.CaptureClause{{Kind: ast.CapHeadersPlus, Extra: 16}},
	}
	_, err := Gen(p, Capabilities{})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v; want ErrNotImplemented", err)
	}
}

func TestGenCaptureWhereAndsWithTopLevel(t *testing.T) {
	p := ethIPv4TCPProgram()
	p.Where = &ir.Condition{Kind: ast.WAtomAction, ActionValue: "XDP_DROP"}
	p.Captures = []*ir.CaptureClause{{
		Kind:  ast.CapHeaders,
		Where: &ir.Condition{Kind: ast.WAtomAction, ActionValue: "XDP_PASS"},
	}}
	out, err := Gen(p, xdpFexitCapsForTest())
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	// Each action atom loads the saved args pointer from stack[-48];
	// an AND fold emits both atoms sequentially, so the load pattern
	// appears twice.
	loads := 0
	for _, ins := range out.Main {
		if ins.OpCode == asm.LoadMem(asm.R3, asm.R10, -48, asm.DWord).OpCode {
			loads++
		}
	}
	if loads != 2 {
		t.Errorf("AND-ed action atoms should emit 2 args loads, got %d", loads)
	}
}

func TestGenCaptureMultipleClausesTakeMaxAndAndWheres(t *testing.T) {
	p := ethIPv4TCPProgram()
	p.Captures = []*ir.CaptureClause{
		{Kind: ast.CapHeaders},                   // 54
		{Kind: ast.CapHeadersPlus, Extra: 128},   // 54 + 128 = 182
		{Kind: ast.CapHeadersPlus, Extra: 32},    // 86
	}
	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	if out.Capture.MaxCapLen != 54+128 {
		t.Errorf("MaxCapLen = %d, want %d (max across clauses)", out.Capture.MaxCapLen, 54+128)
	}
}

func TestGenRejectsUnsupportedLayer(t *testing.T) {
	p := ethIPv4TCPProgram()
	p.Layers[1].Unsupported = "test"
	_, err := Gen(p, Capabilities{})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v; want ErrNotImplemented", err)
	}
}

func TestGenRejectsUnsupportedPredicate(t *testing.T) {
	p := ethIPv4TCPProgram()
	p.Layers[2].Predicates = []*ir.Predicate{
		{Kind: ast.PredIn, Unsupported: "in predicate"},
	}
	_, err := Gen(p, Capabilities{})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v; want ErrNotImplemented", err)
	}
}

func TestGenRejectsUnsupportedQuantifier(t *testing.T) {
	// QuantPlus, QuantStar, QuantRange arrive in PR 5b. QuantOpt is
	// supported by this commit and exercised below.
	p := ethIPv4TCPProgram()
	p.Layers[1].Quant = ast.QuantPlus
	_, err := Gen(p, Capabilities{})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v; want ErrNotImplemented", err)
	}
}

func TestGenOptionalLayerEmitsSkipMarker(t *testing.T) {
	// eth / vlan? / ipv4 with a hand-built vlan dispatch const.
	vlanSpec := newSpec("vlan", "vlan_h",
		vocab.Field{Name: "tci", Bits: 16},
		vocab.Field{Name: "ethertype", Bits: 16},
	)
	vlanFromEth := &vocab.DispatchConst{
		Type: vocab.DispatchField, Name: "VLAN_ETH_ETHERTYPE",
		Parent: "eth", FieldName: "ethertype", Bits: 16, Value: 0x8100,
	}
	ipv4FromVlan := &vocab.DispatchConst{
		Type: vocab.DispatchField, Name: "IPV4_VLAN_ETHERTYPE",
		Parent: "vlan", FieldName: "ethertype", Bits: 16, Value: 0x0800,
	}
	eth := &ir.LayerInstance{Spec: ethSpec}
	vlan := &ir.LayerInstance{
		Spec:     vlanSpec,
		Dispatch: &ir.DispatchChoice{Type: vocab.DispatchField, Const: vlanFromEth},
		Quant:    ast.QuantOpt,
	}
	ipv4 := &ir.LayerInstance{
		Spec:     ipv4Spec,
		Dispatch: &ir.DispatchChoice{Type: vocab.DispatchField, Const: ipv4FromVlan},
	}
	p := &ir.Program{Layers: []*ir.LayerInstance{eth, vlan, ipv4}}

	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	var skipSeen bool
	for _, ins := range out.Main {
		if sym := ins.Symbol(); sym == "dsl_skip_1" {
			skipSeen = true
		}
	}
	if !skipSeen {
		t.Error("optional layer must emit a skip marker symbol")
	}
}

func TestGenOptionalLayerRejectsNoDispatch(t *testing.T) {
	eth := &ir.LayerInstance{Spec: ethSpec}
	bogus := &ir.LayerInstance{Spec: ipv4Spec, Quant: ast.QuantOpt}
	p := &ir.Program{Layers: []*ir.LayerInstance{eth, bogus}}
	_, err := Gen(p, Capabilities{})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v; want ErrNotImplemented", err)
	}
}

func TestGenOptionalLayerRejectsNoCheckDispatch(t *testing.T) {
	noCheck := &vocab.DispatchConst{
		Type: vocab.DispatchNoCheck, Name: "FOO_BAR_NO_CHECK", Parent: "bar", Bool: true,
	}
	eth := &ir.LayerInstance{Spec: ethSpec}
	opt := &ir.LayerInstance{
		Spec:     ipv4Spec,
		Dispatch: &ir.DispatchChoice{Type: vocab.DispatchNoCheck, Const: noCheck},
		Quant:    ast.QuantOpt,
	}
	p := &ir.Program{Layers: []*ir.LayerInstance{eth, opt}}
	_, err := Gen(p, Capabilities{})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v; want ErrNotImplemented", err)
	}
}

func TestGenOptionalLayerRejectsFirstLayer(t *testing.T) {
	opt := &ir.LayerInstance{Spec: ethSpec, Quant: ast.QuantOpt}
	p := &ir.Program{Layers: []*ir.LayerInstance{opt}}
	_, err := Gen(p, Capabilities{})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v; want ErrNotImplemented", err)
	}
}

// --- Predicate codegen ---

func TestGenIntegerPredicateEq(t *testing.T) {
	p := ethIPv4TCPProgram()
	p.Layers[2].Predicates = []*ir.Predicate{
		{
			Kind:  ast.PredCmp,
			Field: &ir.FieldRef{Layer: p.Layers[2], Field: &tcpSpec.Fields[1]}, // dport
			Op:    ast.CmpEq,
			Value: &ast.Value{Kind: ast.ValInt, Int: 443},
		},
	}
	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	// After the 3 bounds JGTs and 2 dispatch JNEs, the dport predicate
	// adds one more JNE (since CmpEq emits JNE → reject-if-not-equal).
	jneCount := 0
	for _, ins := range out.Main {
		if ins.OpCode == asm.JNE.Imm(asm.R3, 0, "").OpCode {
			jneCount++
		}
	}
	if jneCount != 3 {
		t.Errorf("expected 3 JNEs (2 dispatch + 1 predicate), got %d", jneCount)
	}
}

func TestGenIntegerPredicateOrderedUsesHostToBE(t *testing.T) {
	p := ethIPv4TCPProgram()
	p.Layers[2].Predicates = []*ir.Predicate{
		{
			Kind:  ast.PredCmp,
			Field: &ir.FieldRef{Layer: p.Layers[2], Field: &tcpSpec.Fields[1]}, // dport (16 bit)
			Op:    ast.CmpGt,
			Value: &ast.Value{Kind: ast.ValInt, Int: 1024},
		},
	}
	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	// Multi-byte ordered comparisons need a runtime byte-swap so the
	// register holds the natural-order value for the jump. We use
	// HostTo(BE) (BPF_END family) rather than BSwap (BPF_BSWAP, 6.6+)
	// so the program loads back to Linux 5.x.
	swapSeen := false
	for _, ins := range out.Main {
		if ins.OpCode == asm.HostTo(asm.BE, asm.R3, asm.Half).OpCode {
			swapSeen = true
			break
		}
	}
	if !swapSeen {
		t.Error("ordered comparison on 2-byte field must emit HostTo(BE)")
	}
	// And BSwap (the 6.6+ opcode) must NOT appear.
	for _, ins := range out.Main {
		if ins.OpCode == asm.BSwap(asm.R3, asm.Half).OpCode {
			t.Error("BSwap opcode must not appear (kernel 6.1 lacks 0xd7)")
		}
	}
}

// withIPv4Predicate returns the program with a single IPv4-typed
// predicate on ipv4.src. Tests that vary only op / value share the
// rest of the boilerplate.
func withIPv4Predicate(op ast.CmpOp, val *ast.Value) *ir.Program {
	p := ethIPv4TCPProgram()
	p.Layers[1].Predicates = []*ir.Predicate{
		{
			Kind:  ast.PredCmp,
			Field: &ir.FieldRef{Layer: p.Layers[1], Field: &ipv4Spec.Fields[10]},
			Op:    op,
			Value: val,
		},
	}
	return p
}

func TestGenPredicateAcceptsIPv4Host(t *testing.T) {
	p := withIPv4Predicate(ast.CmpEq, &ast.Value{Kind: ast.ValIPv4, V4: [4]byte{10, 0, 0, 1}})
	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	// Expected = byte-swap of 10.0.0.1 (BE 0x0a000001) → 0x0100000a.
	// IP host compares load the constant via `LoadImm R5` (DWord,
	// zero-extended) and JNE.Reg against R3, so values whose top
	// byte has bit 7 set don't sign-extend on int32 imm and miss.
	wantImm := int64(uint64(uint32(0x0100000a)))
	sawLoad := false
	for _, ins := range out.Main {
		if ins.OpCode == asm.LoadImm(asm.R5, 0, asm.DWord).OpCode && ins.Dst == asm.R5 && ins.Constant == wantImm {
			sawLoad = true
			break
		}
	}
	if !sawLoad {
		t.Errorf("expected LoadImm R5, 0x%x for 10.0.0.1, not found", uint32(wantImm))
	}
}

func TestGenPredicateAcceptsIPv4CIDR(t *testing.T) {
	p := withIPv4Predicate(ast.CmpEq, &ast.Value{Kind: ast.ValCIDR, AF: 4, V4: [4]byte{10, 0, 0, 0}, Prefix: 8})
	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	// /8 mask BE = 0xff000000 → LE = 0x000000ff
	wantMaskImm := int32(0x000000ff)
	sawAnd := false
	for _, ins := range out.Main {
		if ins.OpCode == asm.And.Imm(asm.R3, 0).OpCode && ins.Constant == int64(wantMaskImm) {
			sawAnd = true
		}
	}
	if !sawAnd {
		t.Errorf("expected And.Imm R3, 0x%x for /8 mask, not found", uint32(wantMaskImm))
	}
}

func TestGenPredicateIPv4OrderedRejected(t *testing.T) {
	p := withIPv4Predicate(ast.CmpGt, &ast.Value{Kind: ast.ValIPv4, V4: [4]byte{10, 0, 0, 0}})
	_, err := Gen(p, Capabilities{})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v; want ErrNotImplemented for ordered IPv4", err)
	}
}

func TestGenPredicateRejectsIPv6OnIPv4Field(t *testing.T) {
	// AF=6 CIDR against ipv4.src (a 4-byte field) must be rejected
	// because the field width does not match. IPv6 == on the proper
	// 128-bit ipv6.src field is exercised in compile_test.go.
	p := withIPv4Predicate(ast.CmpEq, &ast.Value{Kind: ast.ValCIDR, AF: 6, V6: [16]byte{}, Prefix: 64})
	_, err := Gen(p, Capabilities{})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v; want ErrNotImplemented for AF=6 CIDR on 4-byte field", err)
	}
}

func TestGenPredicateIPv4CIDRSlash32CollapsesToHost(t *testing.T) {
	// /32 has the same semantics as a host match; codegen should
	// short-circuit through emitIPv4Predicate so no redundant
	// And.Imm 0xffffffff sneaks into the stream.
	p := withIPv4Predicate(ast.CmpEq, &ast.Value{Kind: ast.ValCIDR, AF: 4, V4: [4]byte{10, 0, 0, 1}, Prefix: 32})
	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	for _, ins := range out.Main {
		if ins.OpCode == asm.And.Imm(asm.R3, 0).OpCode && uint32(ins.Constant) == 0xffffffff {
			t.Errorf("/32 CIDR should not emit a noop And.Imm 0xffffffff: %v", ins)
		}
	}
}

// withMACPredicate is the eth.dst sibling of withIPv4Predicate.
func withMACPredicate(op ast.CmpOp, val *ast.Value) *ir.Program {
	p := ethIPv4TCPProgram()
	p.Layers[0].Predicates = []*ir.Predicate{
		{
			Kind:  ast.PredCmp,
			Field: &ir.FieldRef{Layer: p.Layers[0], Field: &ethSpec.Fields[0]}, // eth.dst
			Op:    op,
			Value: val,
		},
	}
	return p
}

// withIPv6Predicate mirrors withIPv4Predicate but on an ipv6/tcp chain
// so 128-bit predicate codegen has a place to land.
func withIPv6Predicate(op ast.CmpOp, val *ast.Value) *ir.Program {
	p := ethIPv6TCPProgram()
	p.Layers[1].Predicates = []*ir.Predicate{
		{
			Kind:  ast.PredCmp,
			Field: &ir.FieldRef{Layer: p.Layers[1], Field: &ipv6Spec.Fields[6]}, // src
			Op:    op,
			Value: val,
		},
	}
	return p
}

// hasMatchLandingSymbol reports whether out carries a `!=` match
// landing — a dsl_pred_match_<n> symbol on any instruction.
func hasMatchLandingSymbol(out Output) bool {
	for _, ins := range out.Main {
		if strings.HasPrefix(ins.Symbol(), predMatchLabelPrefix) {
			return true
		}
	}
	return false
}

func TestGenPredicateMACNotEqualEmitsMatchLanding(t *testing.T) {
	// MAC != lands a per-predicate match symbol so any per-word JNE
	// reaches a no-op landing (not dslReject) and the fall-through
	// drops into Ja dslReject for the "all words equal" case.
	p := withMACPredicate(ast.CmpNeq, &ast.Value{Kind: ast.ValMAC, MAC: [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}})
	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	if !hasMatchLandingSymbol(out) {
		t.Error("MAC != should emit a dsl_pred_match_<n> landing symbol")
	}
}

func TestGenPredicateIPv6NotEqualEmitsMatchLanding(t *testing.T) {
	// Same invariant as MAC !=, but exercising the 8-byte LDX-DWord
	// path through ipv6HalfCheck.
	p := withIPv6Predicate(ast.CmpNeq, &ast.Value{Kind: ast.ValIPv6, V6: [16]byte{
		0xfe, 0x80, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0x01,
	}})
	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	if !hasMatchLandingSymbol(out) {
		t.Error("IPv6 != should emit a dsl_pred_match_<n> landing symbol")
	}
}

func TestGenSelfValidatingNoBoundaryEmit(t *testing.T) {
	// After the SANITY removal, an mpls → ipv4 chain resolves the inner
	// ipv4 via DispatchSelfValidating (ipv4's parser block validates
	// version=4 itself). The boundary must emit zero dispatch
	// instructions — no RSh.Imm, no JNE.Imm beyond the standard layer
	// bounds check / accept-reject epilogue.
	mplsSpec := newSpec("mpls", "mpls_h",
		vocab.Field{Name: "label", Bits: 20},
		vocab.Field{Name: "tc", Bits: 3},
		vocab.Field{Name: "s", Bits: 1},
		vocab.Field{Name: "ttl", Bits: 8},
	)
	mpls := &ir.LayerInstance{Spec: mplsSpec}
	ipv4 := &ir.LayerInstance{Spec: ipv4Spec, Dispatch: &ir.DispatchChoice{Type: vocab.DispatchSelfValidating}}
	p := &ir.Program{Layers: []*ir.LayerInstance{mpls, ipv4}}

	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	for _, ins := range out.Main {
		if ins.OpCode == asm.RSh.Op(asm.ImmSource) {
			t.Error("DispatchSelfValidating must not emit RSh.Imm at the boundary")
			break
		}
	}
}

func TestGenNoCheckDispatchEmitsNothing(t *testing.T) {
	// Hand-build a layer pair where the child declares NoCheck. The
	// child's genDispatch should contribute zero instructions — only
	// the bounds check remains on the child's block.
	mplsSpec := newSpec("mpls", "mpls_h", vocab.Field{Name: "stack", Bits: 32})
	innerEthSpec := newSpec("eth", "eth_h",
		vocab.Field{Name: "dst", Bits: 48},
		vocab.Field{Name: "src", Bits: 48},
		vocab.Field{Name: "ethertype", Bits: 16},
	)
	noCheck := &vocab.DispatchConst{
		Type: vocab.DispatchNoCheck, Name: "ETH_MPLS_NO_CHECK", Parent: "mpls", Bool: true,
	}
	mpls := &ir.LayerInstance{Spec: mplsSpec}
	innerEth := &ir.LayerInstance{Spec: innerEthSpec, Dispatch: &ir.DispatchChoice{Type: vocab.DispatchNoCheck, Const: noCheck}}
	p := &ir.Program{Layers: []*ir.LayerInstance{mpls, innerEth}}

	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	// Neither a dispatch JNE nor a BSwap should appear on the child's
	// dispatch. Verify by checking JNE count: only accept/reject paths
	// and layer bounds checks (no dispatch) should remain.
	jneCount := 0
	for _, ins := range out.Main {
		if ins.OpCode == asm.JNE.Imm(asm.R3, 0, "").OpCode {
			jneCount++
		}
	}
	if jneCount != 0 {
		t.Errorf("NoCheck dispatch should emit zero JNEs, got %d", jneCount)
	}
}

func TestGenNoCheckRejectsFalseConst(t *testing.T) {
	noCheck := &vocab.DispatchConst{
		Type: vocab.DispatchNoCheck, Name: "ETH_MPLS_NO_CHECK", Parent: "mpls", Bool: false,
	}
	p := ethIPv4TCPProgram()
	p.Layers[1].Dispatch = &ir.DispatchChoice{Type: vocab.DispatchNoCheck, Const: noCheck}
	_, err := Gen(p, Capabilities{})
	if err == nil {
		t.Fatal("expected error for NO_CHECK=false const reaching codegen")
	}
}


func TestGenPredicateRejectsInt32Overflow(t *testing.T) {
	// The resolver catches "does not fit in the field" (99999 in 16-bit
	// dport), so codegen only polices its own int32 immediate limit.
	// Exercise that path with a 4-byte field (tcp.seq) and a value
	// above 2^31.
	p := ethIPv4TCPProgram()
	p.Layers[2].Predicates = []*ir.Predicate{
		{
			Kind:  ast.PredCmp,
			Field: &ir.FieldRef{Layer: p.Layers[2], Field: &tcpSpec.Fields[2]}, // seq (32 bits)
			Op:    ast.CmpEq,
			Value: &ast.Value{Kind: ast.ValInt, Int: 0x80000000},
		},
	}
	_, err := Gen(p, Capabilities{})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v; want ErrNotImplemented", err)
	}
}

func TestByteSwap(t *testing.T) {
	cases := []struct {
		value uint64
		bytes int
		want  uint64
	}{
		{0x06, 1, 0x06},
		{0x0800, 2, 0x0008},
		{0x86DD, 2, 0xDD86},
		{0x0A000000, 4, 0x0000000A}, // 10.0.0.0
		{0x12345678, 4, 0x78563412},
	}
	for _, tc := range cases {
		got := byteSwap(tc.value, tc.bytes)
		if got != tc.want {
			t.Errorf("byteSwap(%#x, %d) = %#x, want %#x", tc.value, tc.bytes, got, tc.want)
		}
	}
}

func TestHeaderSize(t *testing.T) {
	cases := []struct {
		spec *vocab.ProtocolSpec
		want int
	}{
		{ethSpec, 14},
		{ipv4Spec, 20},
		{tcpSpec, 20},
	}
	for _, tc := range cases {
		got, err := headerSize(tc.spec)
		if err != nil {
			t.Fatalf("headerSize(%q): %v", tc.spec.Name, err)
		}
		if got != tc.want {
			t.Errorf("headerSize(%q) = %d, want %d", tc.spec.Name, got, tc.want)
		}
	}
}

func TestFindFieldByteOffset(t *testing.T) {
	cases := []struct {
		spec      *vocab.ProtocolSpec
		field     string
		wantOff   int
		wantBytes int
	}{
		{ethSpec, "ethertype", 12, 2},
		// ipv4.protocol sits at byte 9: version+ihl (1B), diffserv (1B),
		// total_length (2B), identification (2B), flags+frag_offset (2B),
		// ttl (1B) = 9 bytes before it.
		{ipv4Spec, "protocol", 9, 1},
		{tcpSpec, "dport", 2, 2},
	}
	for _, tc := range cases {
		off, size, err := findFieldByteOffset(tc.spec, tc.field)
		if err != nil {
			t.Fatalf("findFieldByteOffset(%q.%q): %v", tc.spec.Name, tc.field, err)
		}
		if off != tc.wantOff || size != tc.wantBytes {
			t.Errorf("findFieldByteOffset(%q.%q) = (%d, %d), want (%d, %d)", tc.spec.Name, tc.field, off, size, tc.wantOff, tc.wantBytes)
		}
	}
}

func TestFindFieldRejectsNonByteAligned(t *testing.T) {
	_, _, err := findFieldByteOffset(ipv4Spec, "version")
	if err == nil {
		t.Fatal("expected error for non-byte-sized field")
	}
}
