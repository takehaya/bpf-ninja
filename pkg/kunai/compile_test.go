package kunai

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
	cgskbhost "github.com/takehaya/bpf-ninja/pkg/kunai/host/cgroupskb"
	xdphost "github.com/takehaya/bpf-ninja/pkg/kunai/host/xdp"
)

// compileForTest wraps Compile with the zero Capabilities so most
// tests stay terse and target-agnostic. Tests that need action atoms
// pass xdphost.FexitCapabilities() explicitly. Callers that need the
// CaptureInfo or the callback subprograms should invoke Compile
// directly.
func compileForTest(expr string) (asm.Instructions, error) {
	out, err := Compile(expr, codegen.Capabilities{})
	return out.Instructions(), err
}

// runCompileExprCases asserts that each expression compiles cleanly
// at fentry and produces a non-empty main instruction stream. Most
// "<feature> succeeds" tests want exactly this shape.
func runCompileExprCases(t *testing.T, cases []string) {
	t.Helper()
	for _, expr := range cases {
		t.Run(expr, func(t *testing.T) {
			out, err := Compile(expr, codegen.Capabilities{})
			if err != nil {
				t.Fatalf("Compile(%q): %v", expr, err)
			}
			if len(out.Main) == 0 {
				t.Fatalf("Compile(%q) produced empty instructions", expr)
			}
		})
	}
}

func TestCompileEthIPv4TCPSucceeds(t *testing.T) {
	insns, err := compileForTest("eth/ipv4/tcp")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(insns) == 0 {
		t.Fatal("expected non-empty instructions")
	}
}

func TestCompileWithIntegerPredicateSucceeds(t *testing.T) {
	insns, err := compileForTest("eth/ipv4/tcp[dport==443]")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(insns) == 0 {
		t.Fatal("expected non-empty instructions")
	}
}

func TestCompileReachesCodegenForUnsupportedValue(t *testing.T) {
	// `[field has FLAG]` is one of the predicate kinds the resolver
	// still flags Unsupported. Use it as a stable probe that codegen
	// surfaces ErrNotImplemented for a not-yet-emitted predicate shape.
	_, err := compileForTest("eth/ipv4/tcp[flags has SYN]")
	if !errors.Is(err, codegen.ErrNotImplemented) {
		t.Fatalf("expected codegen.ErrNotImplemented, got %v", err)
	}
}

func TestCompileIPv4Predicates(t *testing.T) {
	runCompileExprCases(t, []string{
		"eth/ipv4[src==10.0.0.1]/tcp",
		"eth/ipv4[dst==192.168.1.42]/tcp",
		"eth/ipv4[dst==10.0.0.0/8]/tcp",
		"eth/ipv4[src==192.168.0.0/16]/tcp[dport==443]",
		"eth/ipv4[src==0.0.0.0/0]/tcp", // /0 ==-match collapses to a no-op (host-bits must be 0)
	})
}

func TestCompileIPv6Predicates(t *testing.T) {
	runCompileExprCases(t, []string{
		"eth/ipv6[src==fe80::1]/tcp",
		"eth/ipv6[dst==::1]/tcp",
		"eth/ipv6[src==2001:db8::1]/tcp",
		"eth/ipv6[src==fe80::/10]/tcp",       // /10 — only high half masked
		"eth/ipv6[dst==2001:db8::/32]/tcp",   // /32 — high half partial
		"eth/ipv6[src==2001:db8::1/128]/tcp", // /128 — host match
		"eth/ipv6[src==::/0]/tcp",            // /0 ==-match collapses to no-op
	})
}

func TestCompileIPv6NotEqualSucceeds(t *testing.T) {
	runCompileExprCases(t, []string{
		"eth/ipv6[src!=fe80::1]/tcp",
		"eth/ipv6[dst!=2001:db8::/32]/tcp",
		"eth/ipv6[src!=2001:db8::1/128]/tcp", // /128 collapses to host !=
		"eth/ipv6[src!=::/0]/tcp",            // /0 != is `Ja dsl_reject`
	})
}

func TestCompileMACPredicates(t *testing.T) {
	runCompileExprCases(t, []string{
		"eth[dst==de:ad:be:ef:00:01]/ipv4/tcp",
		"eth[src==00:11:22:33:44:55]/ipv4/tcp",
	})
}

func TestCompileMACNotEqualSucceeds(t *testing.T) {
	runCompileExprCases(t, []string{
		"eth[dst!=de:ad:be:ef:00:01]/ipv4/tcp",
		"eth[src!=00:11:22:33:44:55]/ipv4/tcp",
	})
}

func TestCompileIPv4OrderedRejected(t *testing.T) {
	// IPv4 host literals support only == / !=. Ordered comparisons
	// are not meaningful on IP addresses; codegen must reject.
	_, err := Compile("eth/ipv4[src>10.0.0.0]/tcp", codegen.Capabilities{})
	if !errors.Is(err, codegen.ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented for ordered IPv4, got %v", err)
	}
}

func TestCompileInSetNeedsHostSupport(t *testing.T) {
	// Without a SetSlotResolver the host does not support set matching,
	// so `in @set` is rejected (zero Capabilities).
	_, err := Compile("eth/ipv4/udp/gtp[teid in @teids]", codegen.Capabilities{})
	if !errors.Is(err, codegen.ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented for `in @set` without host support, got %v", err)
	}
}

// fakeSetSlots is a test SetSlotResolver: set "teids" has a 4-byte "teid"
// key field at host slot R10-40.
type fakeSetSlots struct{}

func (fakeSetSlots) HasSet(name string) bool { return name == "teids" }
func (fakeSetSlots) SlotFor(set, field string) (int16, int, bool) {
	if set == "teids" && field == "teid" {
		return -40, 4, true
	}
	return 0, 0, false
}

// TestCompileInSetKeyWrittenTwice pins that one key slot of a set takes
// one extraction: the host looks the set up once, so a second predicate
// on the same key field would silently overwrite the first. (A composite
// set's distinct key fields are distinct slots and may each be written.)
func TestCompileInSetKeyWrittenTwice(t *testing.T) {
	caps := codegen.Capabilities{Lang: codegen.LangCaps{SetSlots: fakeSetSlots{}}}
	_, err := Compile("eth/ipv4/udp/gtp[teid in @teids, teid in @teids]", caps)
	if err == nil || errors.Is(err, codegen.ErrNotImplemented) || !strings.Contains(err.Error(), "written twice") {
		t.Fatalf("Compile: err = %v; want the key-written-twice error", err)
	}
}

// TestCompileDeepChainRuntimeOffsets pins that the number of layers with a
// runtime entry slot is bounded only by the stack plan, not by a fixed
// cap: both chains put their where field past the seventh position.
func TestCompileDeepChainRuntimeOffsets(t *testing.T) {
	for _, expr := range []string{
		"eth/ipv4/udp/gtp/ipv4/udp/vxlan/eth/ipv4/tcp where tcp.dport == 80",
		"eth/vlan?/vlan?/vlan?/vlan?/vlan?/vlan?/vlan?/ipv4/tcp where tcp.dport == 80",
	} {
		if _, err := compileForTest(expr); err != nil {
			t.Errorf("Compile(%q): %v", expr, err)
		}
	}
}

func TestCompileInSetExtractsToSlotStayingMapAgnostic(t *testing.T) {
	caps := codegen.Capabilities{Lang: codegen.LangCaps{SetSlots: fakeSetSlots{}}}
	out, err := Compile("eth/ipv4/udp/gtp[teid in @teids]", caps)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	// The host is told which field went to which slot.
	if len(out.Extractions) != 1 {
		t.Fatalf("extractions = %+v, want 1", out.Extractions)
	}
	if ex := out.Extractions[0]; ex.SetName != "teids" || ex.FieldName != "teid" || ex.StackOff != -40 || ex.StoreSize != 4 {
		t.Errorf("extraction = %+v", ex)
	}

	insns := out.Instructions()
	// Invariant: kunai never emits a map lookup — the host does that.
	for _, ins := range insns {
		if ins.OpCode.JumpOp() == asm.Call && ins.Src != asm.PseudoCall && ins.Constant == int64(asm.FnMapLookupElem) {
			t.Fatal("codegen emitted FnMapLookupElem; kunai must stay map-agnostic")
		}
	}
	// The extracted field is stored into the host slot (R10-40).
	var stored bool
	for _, ins := range insns {
		if ins.Dst == asm.R10 && ins.OpCode.Class().IsStore() && int16(ins.Offset) == -40 {
			stored = true
		}
	}
	if !stored {
		t.Error("no store of the extracted field to host slot R10-40")
	}
	// Byte-order contract: a multi-byte field is byte-swapped to host
	// order (BPF_END, not BSwap) so the stored key matches `set add`.
	swapOp := asm.HostTo(asm.BE, asm.R3, asm.Word).OpCode
	var swapped bool
	for _, ins := range insns {
		if ins.OpCode == swapOp {
			swapped = true
		}
	}
	if !swapped {
		t.Error("no HostTo(BE) byte-swap before the slot store (byte-order would mismatch the map key)")
	}
}

// wideSlot returns an 8-byte slot for teid, wider than gtp.teid (4 bytes),
// to exercise the exact-width-match rejection.
type wideSlot struct{}

func (wideSlot) HasSet(name string) bool                            { return name == "teids" }
func (wideSlot) SlotFor(_, _ string) (off int16, size int, ok bool) { return -40, 8, true }

func TestCompileInSetRejectsWidthMismatch(t *testing.T) {
	caps := codegen.Capabilities{Lang: codegen.LangCaps{SetSlots: wideSlot{}}}
	_, err := Compile("eth/ipv4/udp/gtp[teid in @teids]", caps)
	if err == nil || !strings.Contains(err.Error(), "widths must match") {
		t.Fatalf("expected width-mismatch rejection, got %v", err)
	}
}

func TestCompileInSetRejectsSlotInsideKunaiRegion(t *testing.T) {
	// A host that hands back a slot in kunai's own stack range must be
	// rejected — the extraction would be clobbered mid-filter.
	caps := codegen.Capabilities{Lang: codegen.LangCaps{SetSlots: badSlot{}}}
	_, err := Compile("eth/ipv4/udp/gtp[teid in @teids]", caps)
	if err == nil || !strings.Contains(err.Error(), "kunai's stack region") {
		t.Fatalf("expected kunai-region rejection, got %v", err)
	}
}

// badSlot returns an offset inside kunai's stack region (<= KunaiStackTop).
type badSlot struct{}

func (badSlot) HasSet(name string) bool                            { return name == "teids" }
func (badSlot) SlotFor(_, _ string) (off int16, size int, ok bool) { return -200, 4, true }

// sidSlot is a scalar 16-byte ipv6 set at -40 (a SID set). Like a real
// scalar set, its lone key field is name-agnostic, so it matches any DSL
// field (ipv6.dst, srv6.segments[N].addr) referencing @sids.
type sidSlot struct{}

func (sidSlot) HasSet(name string) bool { return name == "sids" }
func (sidSlot) SlotFor(set, _ string) (off int16, size int, ok bool) {
	if set == "sids" {
		return -40, 16, true
	}
	return 0, 0, false
}

func TestCompileInSetIPv6DstRawByteStore(t *testing.T) {
	caps := codegen.Capabilities{Lang: codegen.LangCaps{SetSlots: sidSlot{}}}
	out, err := Compile("eth/ipv6[dst in @sids]", caps)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(out.Extractions) != 1 {
		t.Fatalf("extractions = %+v, want 1", out.Extractions)
	}
	if ex := out.Extractions[0]; ex.SetName != "sids" || ex.FieldName != "dst" || ex.StackOff != -40 || ex.StoreSize != 16 {
		t.Errorf("extraction = %+v", ex)
	}

	insns := out.Instructions()
	// Both 8-byte halves are stored to the host slot: R10-40 and R10-32.
	var loAt40, hiAt32 bool
	for _, ins := range insns {
		if ins.Dst == asm.R10 && ins.OpCode.Class().IsStore() && ins.OpCode.Size() == asm.DWord {
			switch int16(ins.Offset) {
			case -40:
				loAt40 = true
			case -32:
				hiAt32 = true
			}
		}
	}
	if !loAt40 || !hiAt32 {
		t.Errorf("want DWord stores at -40 and -32, got lo=%v hi=%v", loAt40, hiAt32)
	}
	// Byte-order: a 16-byte address is a raw wire-byte copy — NO HostTo.
	for _, sz := range []asm.Size{asm.Word, asm.DWord, asm.Half} {
		swapOp := asm.HostTo(asm.BE, asm.R3, sz).OpCode
		for _, ins := range insns {
			if ins.OpCode == swapOp {
				t.Fatal("16-byte extraction emitted HostTo(BE); it must copy raw network-order bytes")
			}
		}
	}
	// Map-agnostic invariant still holds.
	for _, ins := range insns {
		if ins.OpCode.JumpOp() == asm.Call && ins.Src != asm.PseudoCall && ins.Constant == int64(asm.FnMapLookupElem) {
			t.Fatal("codegen emitted FnMapLookupElem; kunai must stay map-agnostic")
		}
	}
}

func TestCompileInSetSRv6SegmentRawByteStore(t *testing.T) {
	// A static aux-stack element (a specific SID in the SRH list) extracts
	// as raw wire bytes too — same 16-byte path as ipv6.dst, only the
	// offset resolves through the aux fold instead of the primary header.
	caps := codegen.Capabilities{Lang: codegen.LangCaps{SetSlots: sidSlot{}}}
	out, err := Compile("eth/ipv6/srv6[segments[0].addr in @sids]", caps)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(out.Extractions) != 1 {
		t.Fatalf("extractions = %+v, want 1", out.Extractions)
	}
	if ex := out.Extractions[0]; ex.SetName != "sids" || ex.StackOff != -40 || ex.StoreSize != 16 {
		t.Errorf("extraction = %+v", ex)
	}

	insns := out.Instructions()
	var loAt40, hiAt32 bool
	for _, ins := range insns {
		if ins.Dst == asm.R10 && ins.OpCode.Class().IsStore() && ins.OpCode.Size() == asm.DWord {
			switch int16(ins.Offset) {
			case -40:
				loAt40 = true
			case -32:
				hiAt32 = true
			}
		}
	}
	if !loAt40 || !hiAt32 {
		t.Errorf("want DWord stores at -40 and -32, got lo=%v hi=%v", loAt40, hiAt32)
	}
	// Raw wire-byte copy: no HostTo on the extracted SID.
	for _, sz := range []asm.Size{asm.Word, asm.DWord, asm.Half} {
		swapOp := asm.HostTo(asm.BE, asm.R3, sz).OpCode
		for _, ins := range insns {
			if ins.OpCode == swapOp {
				t.Fatal("segment SID extraction emitted HostTo(BE); it must copy raw network-order bytes")
			}
		}
	}
	// Map-agnostic: still no lookup in kunai.
	for _, ins := range insns {
		if ins.OpCode.JumpOp() == asm.Call && ins.Src != asm.PseudoCall && ins.Constant == int64(asm.FnMapLookupElem) {
			t.Fatal("codegen emitted FnMapLookupElem; kunai must stay map-agnostic")
		}
	}
}

func TestCompileInSetRejectsDynamicSegmentIndex(t *testing.T) {
	// A dynamic stack index cannot be extracted (no runtime address
	// compute in the raw-copy path); resolve rejects it inside a bracket.
	caps := codegen.Capabilities{Lang: codegen.LangCaps{SetSlots: sidSlot{}}}
	_, err := Compile("eth/ipv6/srv6[segments[srv6.last_entry].addr in @sids]", caps)
	if err == nil || !strings.Contains(err.Error(), "constant index") {
		t.Fatalf("expected dynamic-index rejection, got %v", err)
	}
}

func TestCompileVlanOptionalSucceeds(t *testing.T) {
	// `?` quantifier + real vlan vocab — verifies end-to-end path.
	insns, err := compileForTest("eth/vlan?/ipv4/tcp")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(insns) == 0 {
		t.Fatal("expected non-empty instructions")
	}
}

func TestCompileVlanOptionalWithPredicateSucceeds(t *testing.T) {
	insns, err := compileForTest("eth/vlan?/ipv4/tcp[dport==443]")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(insns) == 0 {
		t.Fatal("expected non-empty instructions")
	}
}

func TestCompileWhereActionAtFExit(t *testing.T) {
	out, err := Compile("eth/ipv4/tcp where action == XDP_DROP", xdphost.FexitCapabilities())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(out.Main) == 0 {
		t.Fatal("expected non-empty instructions")
	}
}

func TestCompileWhereActionAtFEntryFails(t *testing.T) {
	// `action == XDP_DROP` requires the host to declare a non-nil
	// Capabilities.Action map. With the zero Capabilities the
	// resolver rejects the atom early with a host-mismatch message.
	_, err := Compile("eth/ipv4/tcp where action == XDP_DROP", codegen.Capabilities{})
	if err == nil {
		t.Fatal("expected error compiling action atom against zero Capabilities")
	}
	if !strings.Contains(err.Error(), "not available on this host") {
		t.Fatalf("error = %v; want host-mismatch message", err)
	}
}

func TestCompileWhereArithCompare(t *testing.T) {
	// eth/ipv4/tcp where ipv4.total_length == 100
	insns, err := compileForTest("eth/ipv4/tcp where ipv4.total_length == 100")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(insns) == 0 {
		t.Fatal("expected non-empty instructions")
	}
}

func TestCompileWhereDeepNestedArith(t *testing.T) {
	// Left-leaning chain of 15 `+` binops — the largest tree the
	// post-10b maxArithDepth=16 guard accepts (deepest binop at
	// call-depth 14, its leaf children at call-depth 15 < 16).
	// Pre-10b maxArithDepth=8 rejected anything past 7 binops; this
	// expression is the headline gain for the 8 → 16 bump and
	// confirms the stack re-layout (arith spill 0..15 at -56..-176)
	// doesn't trip the verifier or other slot allocators.
	//
	// Using tcp.sport (a 16-bit field) keeps codegen on the 64-bit
	// arith path that owns slot 0..15.
	expr := "eth/ipv4/tcp where tcp.sport+1+2+3+4+5+6+7+8+9+10+11+12+13+14 == 100"
	insns, err := compileForTest(expr)
	if err != nil {
		t.Fatalf("Compile %q: %v", expr, err)
	}
	if len(insns) == 0 {
		t.Fatal("expected non-empty instructions")
	}
}

func TestCompileWhereBoolLitTrue(t *testing.T) {
	// `where true` is the identity condition; compile must succeed.
	insns, err := compileForTest("eth/ipv4/tcp where true")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(insns) == 0 {
		t.Fatal("expected non-empty instructions")
	}
}

func TestCompileWhereBoolLitFalse(t *testing.T) {
	// `where false` always rejects; compile must succeed.
	insns, err := compileForTest("eth/ipv4/tcp where false")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(insns) == 0 {
		t.Fatal("expected non-empty instructions")
	}
}

func TestCompileWhereBareBoolFieldDecay(t *testing.T) {
	// `where tcp.dport` triggers Int<16> -> Bool decay -> `tcp.dport != 0`.
	// (tcp.dport is byte-aligned; the sub-byte field-load path that gates
	// flag bits is exercised by TestCompileSubByteField.)
	insns, err := compileForTest("eth/ipv4/tcp where tcp.dport")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(insns) == 0 {
		t.Fatal("expected non-empty instructions")
	}
}

func TestCompileWhereBoolEqIff(t *testing.T) {
	insns, err := compileForTest("eth/ipv4/tcp where (tcp.dport == 443) == (tcp.sport == 443)")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(insns) == 0 {
		t.Fatal("expected non-empty instructions")
	}
}

func TestCompileWhereNetworkLiteralOnLHS(t *testing.T) {
	// Network literal on the LHS resolves to the same WAtomLiteralCmp
	// IR as the field-LHS form, so codegen reuses the existing
	// emitIPv4/IPv6/MAC/CIDR predicate paths.
	for _, expr := range []string{
		"eth/ipv4/tcp where 10.0.0.1 == ipv4.dst",
		"eth/ipv4/tcp where 10.0.0.0/8 != ipv4.dst",
		"eth/ipv4/tcp where aa:bb:cc:dd:ee:ff == eth.dst",
	} {
		t.Run(expr, func(t *testing.T) {
			insns, err := compileForTest(expr)
			if err != nil {
				t.Fatalf("Compile(%q): %v", expr, err)
			}
			if len(insns) == 0 {
				t.Fatal("expected non-empty instructions")
			}
		})
	}
}

func TestCompileBracketInAccepted(t *testing.T) {
	// F7: bracket-predicate `in [...]` for integer alternatives.
	for _, expr := range []string{
		"eth/ipv4/tcp[dport in [80, 443]]",
		"eth/ipv4/tcp[dport in [80, 443, 8080, 8443]]",
	} {
		t.Run(expr, func(t *testing.T) {
			insns, err := compileForTest(expr)
			if err != nil {
				t.Fatalf("Compile(%q): %v", expr, err)
			}
			if len(insns) == 0 {
				t.Fatal("expected non-empty instructions")
			}
		})
	}
}

func TestCompileBracketInOutOfRangeRejected(t *testing.T) {
	// Each alternative is fit-checked against the field width.
	_, err := compileForTest("eth/ipv4/tcp[dport in [99999]]")
	if err == nil || !strings.Contains(err.Error(), "does not fit") {
		t.Fatalf("err = %v; want fit-check rejection", err)
	}
}

func TestCompileWhereBitwiseOps(t *testing.T) {
	// F6: full bitwise op set. `&`, `<<`, `>>` at mul/div precedence;
	// `|`, `^` at add/sub precedence.
	for _, expr := range []string{
		"eth/ipv4/tcp where tcp.dport & 0xff == 80",
		"eth/ipv4/tcp where ipv4.ttl & 0x0f != 0",
		"eth/ipv4/tcp where tcp.dport | 0x80 == 80",
		"eth/ipv4/tcp where tcp.dport ^ 0x01 == 80",
		"eth/ipv4/tcp where tcp.dport >> 4 == 0",
		"eth/ipv4/tcp where tcp.dport << 1 == 160",
	} {
		t.Run(expr, func(t *testing.T) {
			insns, err := compileForTest(expr)
			if err != nil {
				t.Fatalf("Compile(%q): %v", expr, err)
			}
			if len(insns) == 0 {
				t.Fatal("expected non-empty instructions")
			}
		})
	}
}

func TestCompileBitSlice(t *testing.T) {
	// `field[lo:hi]` MVP: byte-aligned slices on Int<128> fields,
	// usable in both bracket predicates and where-arith.
	for _, expr := range []string{
		"eth/ipv6/tcp where ipv6.src[0:32] == 0x20010db8",
		"eth/ipv6/tcp where ipv6.src[96:128] == ipv6.dst[96:128]",
		"eth/ipv6/tcp where ipv6.src[64:128] == ipv6.dst[64:128]",
		"eth/ipv6/tcp where ipv6.src[0:64] != ipv6.dst[0:64]",
		"eth/ipv6[src[0:32]==0x20010db8]/tcp",
	} {
		t.Run(expr, func(t *testing.T) {
			insns, err := compileForTest(expr)
			if err != nil {
				t.Fatalf("Compile(%q): %v", expr, err)
			}
			if len(insns) == 0 {
				t.Fatal("expected non-empty instructions")
			}
		})
	}
}

func TestCompileBitSliceRejected(t *testing.T) {
	// Slice-related resolver rejections that survive the F13
	// non-aligned support: out-of-field-width, empty range,
	// and >64bit non-aligned slice (the F12 desugar requires
	// byte-aligned endpoints when crossing the 64-bit boundary).
	for _, c := range []struct {
		expr string
		want string
	}{
		{"eth/ipv6/tcp where ipv6.src[0:200] == 0", "exceeds field width"},
		{"eth/ipv6/tcp where ipv6.src[64:64] == 0", "lo < hi"},
		{"eth/ipv6/tcp where ipv6.src[1:80] == ipv6.dst[1:80]", "not byte-aligned"},
	} {
		t.Run(c.expr, func(t *testing.T) {
			_, err := compileForTest(c.expr)
			if err == nil {
				t.Fatalf("Compile(%q): expected error containing %q", c.expr, c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v; want substring %q", err, c.want)
			}
		})
	}
}

func TestCompileBitSliceNonAligned(t *testing.T) {
	// F13: slice endpoints no longer need to be byte-aligned. The
	// codegen rounds the load up to the next pow-of-2 byte size and
	// emits shift+mask after the bswap so the register holds the
	// slice bits in host order.
	for _, expr := range []string{
		"eth/ipv6/tcp where ipv6.src[3:9] == 1",     // sub-byte within first byte
		"eth/ipv6/tcp where ipv6.src[4:12] == 0xff", // crosses byte boundary
		"eth/ipv6/tcp where ipv6.src[0:24] == 0xa0", // byte-aligned but odd byte count
		"eth/ipv6[src[3:9]==1]/tcp",                 // bracket form
	} {
		t.Run(expr, func(t *testing.T) {
			insns, err := compileForTest(expr)
			if err != nil {
				t.Fatalf("Compile(%q): %v", expr, err)
			}
			if len(insns) == 0 {
				t.Fatal("expected non-empty instructions")
			}
		})
	}
}

func TestCompileSubByteField(t *testing.T) {
	// Non-byte-aligned / sub-byte-sized primary fields read via a
	// covering window + post-load shift+mask, in both where clauses
	// and bracket predicates. These were ErrNotImplemented before the
	// field-load generalization; the bit-extraction math is pinned in
	// codegen.slice_test.go and the packet-level correctness in
	// dsltest. Here we only assert they compile to non-empty bytecode.
	runCompileExprCases(t, []string{
		"eth/ipv4/tcp where tcp.flags & 0x02 != 0", // SYN, bit<9>@103
		"eth/ipv4/tcp where tcp.data_offset == 5",  // bit<4>@96
		"eth/ipv4 where ipv4.version == 4",         // bit<4>@0, shift 4
		"eth/ipv4 where ipv4.ihl >= 5",             // bit<4>@4, ordered
		"eth/ipv4 where ipv4.flags & 0x2 != 0",     // DF, bit<3>@48
		"eth/ipv4 where ipv4.frag_offset == 0",     // bit<13>@51, 2-byte window
		"eth/ipv6 where ipv6.traffic_class == 0",   // bit<8>@4
		"eth/ipv4[ihl==5]/tcp",                     // bracket predicate, eq
		"eth/ipv4[version==4]/tcp",                 // bracket predicate, shift
		"eth/ipv4[ihl in [5, 6]]/tcp",              // bracket 'in' predicate
	})
}

func TestCompileSubByteRawOffsetStillRejected(t *testing.T) {
	// kunai has no raw byte-offset escape hatch: every field is named
	// via the P4 vocab. pcap-filter's `tcp[13]` style stays rejected by
	// design (the §6 reverse gap), even though tcp.flags is now readable.
	_, err := compileForTest("eth/ipv4/tcp where tcp[13] & 0x02 != 0")
	if err == nil {
		t.Fatal("expected raw byte-offset access to be rejected")
	}
	if !strings.Contains(err.Error(), "must be qualified") {
		t.Errorf("err = %v; want 'must be qualified'", err)
	}
}

func TestCompileBitSlice128IsSugar(t *testing.T) {
	// `field[0:128]` is sugar for the full Int<128> field — the
	// resolver lifted the 64-bit cap so the dual-LDX cmp pipeline
	// fires the same way as `ipv6.src == ipv6.dst`.
	insns, err := compileForTest("eth/ipv6/tcp where ipv6.src[0:128] == ipv6.dst[0:128]")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(insns) == 0 {
		t.Fatal("expected non-empty instructions")
	}
}

func TestCompileBitSliceMidWidthSplit(t *testing.T) {
	// F12: slice widths in (64, 128) are now desugared in the
	// resolver into a chain of LDX-aligned sub-cmps, so the
	// previously-staged shapes compile cleanly. Each sub-cmp rides
	// the existing single-LDX path.
	for _, expr := range []string{
		"eth/ipv6/tcp where ipv6.src[0:96] == ipv6.dst[0:96]",     // 8+4
		"eth/ipv6/tcp where ipv6.src[0:80] == ipv6.dst[0:80]",     // 8+2
		"eth/ipv6/tcp where ipv6.src[0:72] == ipv6.dst[0:72]",     // 8+1
		"eth/ipv6/tcp where ipv6.src[0:88] == ipv6.dst[0:88]",     // 8+2+1
		"eth/ipv6/tcp where ipv6.src[0:120] == ipv6.dst[0:120]",   // 8+4+2+1
		"eth/ipv6/tcp where ipv6.src[0:96] != ipv6.dst[0:96]",     // != → OR-chain
		"eth/ipv6/tcp where ipv6.src[32:128] == ipv6.dst[32:128]", // non-zero start
	} {
		t.Run(expr, func(t *testing.T) {
			insns, err := compileForTest(expr)
			if err != nil {
				t.Fatalf("Compile(%q): %v", expr, err)
			}
			if len(insns) == 0 {
				t.Fatal("expected non-empty instructions")
			}
		})
	}
}

func TestCompileWhereIPv6Arith128(t *testing.T) {
	// F4: 128-bit equality comparisons in the where-arith path.
	// Plain field == field, plus field + const / field - const for
	// adjacent-address checks. Multiplication and field+field stay
	// staged (F5).
	for _, expr := range []string{
		"eth/ipv6/tcp where ipv6.src == ipv6.dst",
		"eth/ipv6/tcp where ipv6.src + 1 == ipv6.dst",
		"eth/ipv6/tcp where ipv6.src - 1 == ipv6.dst",
		"eth/ipv6/tcp where ipv6.src != ipv6.dst",
	} {
		t.Run(expr, func(t *testing.T) {
			insns, err := compileForTest(expr)
			if err != nil {
				t.Fatalf("Compile(%q): %v", expr, err)
			}
			if len(insns) == 0 {
				t.Fatal("expected non-empty instructions")
			}
		})
	}
}

func TestCompileWhereIPv6MulIllTyped(t *testing.T) {
	// Above 64 bits only + and - are defined (dsl-types.md §13.9): `*`
	// was dropped in favour of bit slices (F5/F11), and bitwise / div /
	// mod / shifts have no 128-bit codegen. The resolver rejects them as
	// a typing error, not as an implementation limit.
	for _, expr := range []string{
		"eth/ipv6/tcp where ipv6.src * 2 == ipv6.dst",
		"eth/ipv6/tcp where ipv6.src & 1 == 1",
		"eth/ipv6/tcp where ipv6.src >> 64 == 0",
	} {
		_, err := compileForTest(expr)
		if err == nil || !strings.Contains(err.Error(), "only + and - are defined") {
			t.Errorf("Compile(%q) = %v; want the §13.9 operator error", expr, err)
		}
	}
	// A 64-bit slice of the same field keeps every operator.
	if _, err := compileForTest("eth/ipv6/tcp where ipv6.src[64:128] * 2 == ipv6.dst[64:128]"); err != nil {
		t.Errorf("slice arithmetic: %v", err)
	}
	// A slice, a narrower field, or a sub-64-bit expression next to a full
	// Int<128> operand computes in 64 bits and joins zero-extended.
	for _, expr := range []string{
		"eth/ipv6/tcp where ipv6.src[64:128] + ipv6.dst == 1",
		"eth/ipv6/tcp where ipv6.src + tcp.dport == 1",
		"eth/ipv6/tcp where ipv6.src == tcp.dport * 2",
		"eth/ipv6/tcp where ipv6.src + tcp.dport * 2 == ipv6.dst",
		"eth/ipv6/tcp where ipv6.src == tcp.dport + -1", // -1 is 0xffff next to dport
		"eth/ipv6/tcp where ipv6.src == 2 * 3",          // literals only: 64 bits
	} {
		if _, err := compileForTest(expr); err != nil {
			t.Errorf("Compile(%q): %v", expr, err)
		}
	}
	// A 128-bit expression on the right of ± is computed first.
	for _, expr := range []string{
		"eth/ipv6/tcp where ipv6.src + (ipv6.dst + 1) == ipv6.dst",
		"eth/ipv6/tcp where ipv6.src - (ipv6.dst - (ipv6.src + ipv6.dst)) == 1",
		"eth/ipv6/tcp where (ipv6.src + ipv6.dst) - ipv6.src == (ipv6.dst - 1) + (ipv6.src + ipv6.dst)",
		"eth/ipv6/tcp where (ipv6.src == ipv6.dst - (ipv6.src + ipv6.dst)) == (tcp.dport == 80)",
	} {
		if _, err := compileForTest(expr); err != nil {
			t.Errorf("Compile(%q): %v", expr, err)
		}
	}
	// Both sides parking: the left result is held above the reserved
	// slots while the right side runs.
	for _, expr := range []string{
		"eth/ipv6/tcp where (ipv6.src + ipv6.dst) - (ipv6.dst + ipv6.src) == 0",
		"eth/ipv6/tcp where (ipv6.src + ipv6.dst + 1) + (ipv6.dst + ipv6.src) == 0",
		"eth/ipv6/tcp where (ipv6.src == (ipv6.src + ipv6.dst) - (ipv6.dst + ipv6.src)) == (tcp.dport == 80)",
	} {
		if _, err := compileForTest(expr); err != nil {
			t.Errorf("Compile(%q): %v", expr, err)
		}
	}
	// Still refused: a slice wider than 64 bits.
	for _, expr := range []string{
		"eth/ipv6/tcp where ipv6.src[0:96] + ipv6.dst == 1",
	} {
		if _, err := compileForTest(expr); !errors.Is(err, codegen.ErrNotImplemented) {
			t.Errorf("Compile(%q) = %v; want ErrNotImplemented", expr, err)
		}
	}
	// A literal fits the width of the operand next to it, at any nesting.
	for _, expr := range []string{
		"eth/ipv6/tcp where ipv6.src == tcp.dport * 70000",
		"eth/ipv6/tcp where ipv6.src == tcp.dport * 70000 + tcp.seq",
		"eth/ipv4/tcp where ipv4.ttl + 300 == tcp.dport",
	} {
		if _, err := compileForTest(expr); err == nil || errors.Is(err, codegen.ErrNotImplemented) {
			t.Errorf("Compile(%q) = %v; want a resolver error", expr, err)
		}
	}
	// Constants above int32 are a 64-bit load, at every width.
	for _, expr := range []string{
		"eth/ipv4/tcp where tcp.seq == 2147483648",
		"eth/ipv6/tcp where ipv6.src[64:128] == 4294967296",
	} {
		if _, err := compileForTest(expr); err != nil {
			t.Errorf("Compile(%q): %v", expr, err)
		}
	}
}

// TestArith128NestingInsideBoolEq pins the bool-eq term of the 128-bit
// nesting guards. A bool-eq parks its operands' truth values at the top
// of the arith region, so the slots a 128-bit expression may take shrink
// with each enclosing `==`. Without that term the hold slots of a
// both-sides node overwrite a parked truth value and the filter compiles
// to a wrong verdict.
func TestArith128NestingInsideBoolEq(t *testing.T) {
	// bothPark(k) nests k both-sides nodes on the right: S - (S - (… S)).
	const s = "(ipv6.src + ipv6.dst)"
	bothPark := func(k int) string {
		e := s
		for range k {
			e = s + " - (" + e + ")"
		}
		return e
	}
	// narrow(k) is a sub-64-bit expression nested k levels.
	narrow := func(k int) string {
		e := "tcp.dport"
		for range k {
			e = "tcp.dport + (" + e + ")"
		}
		return e
	}
	// boolEq wraps an atom in d nested `==`. On the right the atom runs
	// while the left operands' truth values are parked; on the left it runs
	// before any is. The limits are the same for both.
	boolEq := func(atom string, d int, right bool) string {
		for range d {
			if right {
				atom = "(tcp.dport == 80) == (" + atom + ")"
			} else {
				atom = "(" + atom + ") == (tcp.dport == 80)"
			}
		}
		return atom
	}
	// refusal is the guard's message; the per-node ceiling of the 64-bit
	// pipeline backs up the narrow guard, so its message is what tells the
	// two apart.
	for _, tc := range []struct {
		atom    string
		d       int
		refusal string
	}{
		{bothPark(5) + " == 0", 0, ""},
		{bothPark(5) + " == 0", 1, ""},
		{bothPark(5) + " == 0", 2, "both sides"},
		{bothPark(4) + " == 0", 2, ""},
		{bothPark(4) + " == 0", 3, ""},
		{"ipv6.src == " + narrow(11), 0, ""},
		{"ipv6.src == " + narrow(11), 1, "sub-64-bit expression"},
		{"ipv6.src == " + narrow(10), 1, ""},
	} {
		for _, right := range []bool{false, true} {
			expr := "eth/ipv6/tcp where " + boolEq(tc.atom, tc.d, right)
			_, err := compileForTest(expr)
			switch {
			case tc.refusal == "" && err != nil:
				t.Errorf("Compile(%q): %v", expr, err)
			case tc.refusal != "" && (!errors.Is(err, codegen.ErrNotImplemented) || !strings.Contains(err.Error(), tc.refusal)):
				t.Errorf("Compile(%q) = %v; want ErrNotImplemented from the %q guard", expr, err, tc.refusal)
			}
		}
	}
}

func TestCompileWhereIPv6FieldFieldArith(t *testing.T) {
	// F4 (full): `field + field` and `field - field` on Int<128>
	// compile via the dual-LDX pipeline and stack-bridged carry/borrow
	// propagation (no host-callee-saved registers touched).
	for _, expr := range []string{
		"eth/ipv6/tcp where ipv6.src + ipv6.dst == ipv6.src",
		"eth/ipv6/tcp where ipv6.src - ipv6.dst == ipv6.src",
		// Const path also works alongside (existing F4 partial,
		// regression guard).
		"eth/ipv6/tcp where ipv6.src + 1 == ipv6.dst",
		"eth/ipv6/tcp where ipv6.dst - 1 == ipv6.src",
	} {
		t.Run(expr, func(t *testing.T) {
			insns, err := compileForTest(expr)
			if err != nil {
				t.Fatalf("Compile(%q): %v", expr, err)
			}
			if len(insns) == 0 {
				t.Fatal("expected non-empty instructions")
			}
		})
	}
}

func TestCompileWhereIPv6OrderedCmp(t *testing.T) {
	// F3 where-arith: lexicographic compare for `<`, `≤`, `>`, `≥` on
	// Int<128> reaches the where path now (genArithCompare128 ordered
	// branch), mirroring the bracket-side support.
	for _, expr := range []string{
		"eth/ipv6/tcp where ipv6.src < ipv6.dst",
		"eth/ipv6/tcp where ipv6.src <= ipv6.dst",
		"eth/ipv6/tcp where ipv6.src > ipv6.dst",
		"eth/ipv6/tcp where ipv6.src >= ipv6.dst",
	} {
		t.Run(expr, func(t *testing.T) {
			insns, err := compileForTest(expr)
			if err != nil {
				t.Fatalf("Compile(%q): %v", expr, err)
			}
			if len(insns) == 0 {
				t.Fatal("expected non-empty instructions")
			}
		})
	}
}

func TestCompileBracketIPv6OrderedCmp(t *testing.T) {
	// F3: lexicographic compare for `<`, `≤`, `>`, `≥` on IPv6.
	for _, expr := range []string{
		"eth/ipv6[dst < fe80::ffff]/tcp",
		"eth/ipv6[dst <= fe80::ffff]/tcp",
		"eth/ipv6[dst > 2001:db8::1]/tcp",
		"eth/ipv6[dst >= ::1]/tcp",
	} {
		t.Run(expr, func(t *testing.T) {
			insns, err := compileForTest(expr)
			if err != nil {
				t.Fatalf("Compile(%q): %v", expr, err)
			}
			if len(insns) == 0 {
				t.Fatal("expected non-empty instructions")
			}
		})
	}
}

func TestCompileBracketInIPv4AlternativesNotYetWired(t *testing.T) {
	// MVP scope: integer alternatives only. IPv4/IPv6/MAC alternatives
	// would each need their own multi-word emit path, so they surface
	// as ErrNotImplemented for now.
	_, err := compileForTest("eth/ipv4[src in [10.0.0.1, 10.0.0.2]]/tcp")
	if err == nil {
		t.Fatal("expected ErrNotImplemented for IPv4 alternatives")
	}
	if !errors.Is(err, codegen.ErrNotImplemented) {
		t.Fatalf("err = %v; want ErrNotImplemented", err)
	}
}

func TestCompileWhereBareBoolExistsAux(t *testing.T) {
	// `where gtp.opt.exists` reuses the aux-gating emit path: the
	// parser machine has already extracted opt only on the E|S|PN tuple.
	insns, err := compileForTest("eth/ipv4/udp/gtp/ipv4/tcp where gtp.opt.exists")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(insns) == 0 {
		t.Fatal("expected non-empty instructions")
	}
}

func TestCompileWhereLogicalCombination(t *testing.T) {
	// "tcp.dport == 443 or tcp.dport == 80" exercises OR over two arith atoms.
	insns, err := compileForTest("eth/ipv4/tcp where tcp.dport == 443 or tcp.dport == 80")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(insns) == 0 {
		t.Fatal("expected non-empty instructions")
	}
}

func TestCompileSurfacesParseError(t *testing.T) {
	_, err := compileForTest("eth/ipv4/")
	if err == nil {
		t.Fatal("expected parse error")
	}
	if errors.Is(err, codegen.ErrNotImplemented) {
		t.Errorf("parse error masked by ErrNotImplemented: %v", err)
	}
}

func TestCompileSurfacesResolveError(t *testing.T) {
	_, err := compileForTest("eth/bogus/tcp")
	if err == nil {
		t.Fatal("expected resolve error")
	}
	if errors.Is(err, codegen.ErrNotImplemented) {
		t.Errorf("resolve error masked by ErrNotImplemented: %v", err)
	}
	if !strings.Contains(err.Error(), "unknown protocol") {
		t.Errorf("error = %v; want 'unknown protocol'", err)
	}
}

func TestCompileAlternationLastLayerSucceeds(t *testing.T) {
	// `eth/(vlan|qinq)` — both alts have the same 4-byte header size
	// and sit at the tail of the filter. Post-group dispatch is not
	// yet supported, so this is the MVP shape.
	out, err := Compile("eth/(vlan|qinq)", codegen.Capabilities{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(out.Main) == 0 {
		t.Fatal("expected non-empty instructions")
	}
}

func TestResolverAcceptsAlternationAgreementOK(t *testing.T) {
	// Internal-machinery regression test: when an alt group is
	// followed by another layer, the resolver requires every alt
	// member to agree on the dispatch const for that next layer.
	// `(vlan|qinq)` is the only bundled-vocab pair where the rule
	// is satisfiable (both 4-byte headers, both dispatch ipv4 via
	// ethertype==0x0800), so it doubles as the positive smoke
	// covering selectAltParentDispatch in resolve/layer.go.
	//
	// Pair test: TestResolverRejectsAlternationDivergence
	// (negative case for ipv4|ipv6 — different sizes, different
	// dispatch fields). User-facing alternation utility is
	// effectively gated on dsl-followups.md P3-12.
	out, err := Compile("eth/(vlan|qinq)/ipv4/tcp", codegen.Capabilities{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(out.Main) == 0 {
		t.Fatal("expected non-empty instructions")
	}
}

func TestCompileQinqVlanChainCoversAllTagShapes(t *testing.T) {
	// Practical pattern: `eth/qinq?/vlan?/ipv4/tcp` is the recommended
	// way to write a single filter that matches every realistic
	// tagging shape on Ethernet — untagged, single VLAN, QinQ-only
	// S-tag, and the typical QinQ-stacked S+C tags. It works because
	// `?` peeks the parent's last-2-byte ethertype field, which has
	// the same semantic ("next protocol") in eth, qinq, and vlan.
	//
	// Alternation cannot do this in MVP (`(vlan|qinq)` matches
	// single-tag only; stacked frames need a different chain
	// shape). Until alt is generalised in P3-12, optional-chain
	// is the user-facing answer for tag-flexibility filters.
	insns, err := compileForTest("eth/qinq?/vlan?/ipv4/tcp")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(insns) == 0 {
		t.Fatal("expected non-empty instructions")
	}
}

// TestCompileWhereOnQuantifiedLayers pins D-003 / D-013 / D-018 end to
// end: fields of an optional layer and of the layers after it compile
// (the absent layer makes the atom false at run time), a labelled
// repeated layer binds its last instance on both chain lowerings, and an
// unlabelled repeated layer is a type error, not an implementation limit.
func TestCompileWhereOnQuantifiedLayers(t *testing.T) {
	for _, expr := range []string{
		"eth/vlan?/ipv4/tcp where vlan.tci == 100",
		"eth/vlan?/ipv4/tcp where not (vlan.tci == 1)",
		"eth/vlan?/ipv4/tcp where vlan.tci != 1",
		"eth/vlan?/ipv4/tcp where ipv4.ttl == 64",
		"eth/qinq?/vlan?/ipv4/tcp where vlan.tci == 100 and ipv4.ttl == 64",
		"eth/mpls@m{1,3}/ipv4/tcp where m.label == 7", // static unroll
		"eth/mpls@m{1,8}/ipv4/tcp where m.label == 7", // bpf_loop
		"eth/mpls@m*/ipv4/tcp where not (m.label == 7)",
		"eth/mpls{1,8}/ipv4/tcp where ipv4.total_length > 100", // the README example
	} {
		if _, err := compileForTest(expr); err != nil {
			t.Errorf("%s: %v", expr, err)
		}
	}
	_, err := compileForTest("eth/mpls{1,3}/ipv4/tcp where mpls.label == 7")
	if err == nil || errors.Is(err, codegen.ErrNotImplemented) || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("unlabelled repeated layer: expected a resolver ambiguity error, got %v", err)
	}
	// A member of a heterogeneous alternation shares its group's slot;
	// the read is guarded by the group's matched-member slot.
	if _, err = compileForTest("eth/vlan?/(ipv4|ipv6)/tcp where ipv4.ttl == 64"); err != nil {
		t.Fatalf("het-alt member after an optional layer: %v", err)
	}
	// Capturing an alternation member behind an optional layer sizes the
	// bound from the member itself.
	out, err := Compile("eth/vlan?/(ipv4|ipv6)/tcp capture ipv4+8", codegen.Capabilities{})
	if err != nil {
		t.Fatalf("capture alt member: %v", err)
	}
	if out.Capture.MaxCapLen != 14+4+20+8 {
		t.Fatalf("capture alt member: MaxCapLen = %d, want %d", out.Capture.MaxCapLen, 14+4+20+8)
	}
}

// TestCompileCaptureUpperBoundOverQuantifiers pins that capture lengths
// over quantified layers are the compile-time upper bound (every instance
// the quantifier allows), which the host clamps with the packet length.
func TestCompileCaptureUpperBoundOverQuantifiers(t *testing.T) {
	for _, tc := range []struct {
		expr string
		want int
	}{
		{"eth/vlan?/ipv4/tcp capture headers", 14 + 4 + 20 + 20},
		{"eth/vlan?/ipv4/tcp capture vlan", 14 + 4},
		{"eth/mpls{1,3}/ipv4/tcp capture headers", 14 + 3*4 + 20 + 20},
		{"eth/mpls+/ipv4/tcp capture headers", 14 + 8*4 + 20 + 20}, // MPLS_MAX_DEPTH = 8
		{"eth/mpls@m+/ipv4/tcp capture m+8", 14 + 8*4 + 8},
	} {
		out, err := Compile(tc.expr, codegen.Capabilities{})
		if err != nil {
			t.Fatalf("%s: %v", tc.expr, err)
		}
		if out.Capture.MaxCapLen != tc.want {
			t.Errorf("%s: MaxCapLen = %d, want %d", tc.expr, out.Capture.MaxCapLen, tc.want)
		}
	}
}

// TestCompileInRangeBoundsFit pins that both bounds of a range alternative
// must fit the field and that a range is only an `in` alternative: the
// resolver rejects before codegen could mask a bound into a different
// range. (`90..80` is caught earlier, by the lexer; the resolver keeps
// the same rule for programmatically built ASTs.)
func TestCompileInRangeBoundsFit(t *testing.T) {
	for _, expr := range []string{"eth/ipv4/tcp[dport in [0..70000]]", "eth/ipv4/tcp[dport in [65535..70000]]", "eth/ipv4/tcp[dport in [90..80]]", "eth/ipv4/tcp[dport == 79..81]"} {
		_, err := compileForTest(expr)
		if err == nil || errors.Is(err, codegen.ErrNotImplemented) {
			t.Errorf("%s: expected a resolver error, got %v", expr, err)
		}
	}
}

// TestCompileOptionalSelfEdgeWithChainEnd pins that an optional
// continuation of a chain-end protocol (`mpls/mpls?`, `mpls/mpls*`) is
// accepted: the previous label's s bit stands in for the dispatch peek.
func TestCompileOptionalSelfEdgeWithChainEnd(t *testing.T) {
	for _, expr := range []string{"eth/mpls/mpls?/ipv4/tcp", "eth/mpls/mpls*/ipv4/tcp", "eth/mpls/mpls{0,3}/ipv4/tcp", "eth/mpls/mpls?/mpls?/ipv4/tcp"} {
		if _, err := compileForTest(expr); err != nil {
			t.Errorf("%s: %v", expr, err)
		}
	}
}

// TestCompileConsecutiveOptionals pins that a layer after consecutive
// optional layers dispatches against whichever of them matched (D-034):
// `eth/vlan?/mpls?/ipv4` needs a cascade (ipv4 self-validates under
// mpls but needs ethertype 0x0800 under vlan or eth), while
// `eth/qinq?/vlan?/ipv4` keeps one static read (ethertype sits in the
// last two bytes of eth, qinq and vlan alike).
func TestCompileConsecutiveOptionals(t *testing.T) {
	for _, expr := range []string{
		"eth/vlan?/mpls?/ipv4/tcp",
		"eth/qinq?/vlan?/mpls?/ipv4/tcp",
		"eth/vlan?/mpls{1,3}/ipv4/tcp",
		"eth/mpls?/mpls+/ipv4/tcp", // quantified after optional: cascade on the self edge
		// a uniform run needs no slot, so a deep chain stays under the slot cap
		"eth/ipv4/udp/vxlan/eth/ipv4/udp/vxlan/eth/qinq?/vlan?/ipv4/tcp",
	} {
		if _, err := compileForTest(expr); err != nil {
			t.Errorf("%s: %v", expr, err)
		}
	}
	// An alternation among the runtime parents keeps the static rule, so
	// a non-uniform dispatch behind it is refused rather than misread.
	for _, expr := range []string{"eth/(vlan|qinq)/mpls?/ipv4/tcp", "eth/(vlan|qinq)/mpls?/mpls?/ipv4/tcp"} {
		if _, err := compileForTest(expr); !errors.Is(err, codegen.ErrNotImplemented) {
			t.Errorf("%s: expected ErrNotImplemented, got %v", expr, err)
		}
	}
	// An alternation after optionals needs a field dispatch for every
	// member under every runtime parent: a type error from the resolver.
	if _, err := compileForTest("eth/vlan?/mpls?/(ipv4|ipv6)/tcp"); err == nil || errors.Is(err, codegen.ErrNotImplemented) || !strings.Contains(err.Error(), "needs a field dispatch") {
		t.Errorf("alternation after optionals: expected a resolver error, got %v", err)
	}
}

// TestCompileOptionalVariableLayers pins `?` / `{0,1}` on a variable-length
// layer: the parser machine (or the flag-trigger emit) runs with a failed
// dispatch routed to the absent path, the dispatch being the parent's
// constant or, with none, the self-validation probe. Repeating such a
// layer stays refused.
func TestCompileOptionalVariableLayers(t *testing.T) {
	for _, expr := range []string{
		"eth/ipv4?",
		"eth/ipv6/srv6?/tcp",
		"eth/ipv6/srv6{0,1}/tcp where tcp.options.mss.value == 1460",
		"eth/ipv6/srv6?/tcp where all(srv6.segments.addr != fc00::1)",
		"eth/ipv4/gre?/ipv4/tcp",
		"eth/ipv4/ipv4?/ipv4?/tcp",
		"eth/vlan?/ipv4?",
		"eth/mpls/ipv4?",        // no parent constant: self-validation probe
		"eth/vlan?/mpls?/ipv4?", // probe under mpls, ethertype under vlan / eth
	} {
		if _, err := compileForTest(expr); err != nil {
			t.Errorf("Compile(%q): %v", expr, err)
		}
	}
	// Repeating a layer needs a dispatch constant under itself: without one
	// it is a typing error (srv6, gre); with one, a variable-length layer
	// is still an implementation limit (ipv4 in ipv4).
	for _, expr := range []string{"eth/ipv6/srv6{0,2}/tcp", "eth/ipv6/srv6*/tcp", "eth/ipv4/gre{0,2}/ipv4/tcp", "eth/ipv4/gre*/ipv4/tcp"} {
		if _, err := compileForTest(expr); err == nil || errors.Is(err, codegen.ErrNotImplemented) || !strings.Contains(err.Error(), "under itself") {
			t.Errorf("Compile(%q) = %v; want the self-dispatch typing error", expr, err)
		}
	}
	for _, expr := range []string{"eth/ipv4/ipv4{0,2}/tcp", "eth/ipv4/ipv4*/tcp"} {
		if _, err := compileForTest(expr); !errors.Is(err, codegen.ErrNotImplemented) {
			t.Errorf("Compile(%q) = %v; want ErrNotImplemented", expr, err)
		}
	}
}

// TestCompileBracketOnPushCountedStack pins that a bracket predicate
// indexing a stack the parser machine pushes onto compiles: it is
// evaluated after the walk, when the push count that guards the index is
// final (D-031), for a protocol without write-back (gtp) as for one with
// (ipv6), like the where form.
func TestCompileBracketOnPushCountedStack(t *testing.T) {
	for _, expr := range []string{
		"eth/ipv4/udp/gtp[exts[0].next_ext == 1]/ipv4/tcp",
		"eth/ipv4/udp/gtp[teid == 1, exts[1].ext_type == 0]/ipv4/tcp",
		"eth/ipv4/udp/gtp/ipv4/tcp where gtp.exts[0].next_ext == 1",
		"eth/ipv6[exts[1].next_header == 6]/tcp",
	} {
		if _, err := compileForTest(expr); err != nil {
			t.Fatalf("%s must compile: %v", expr, err)
		}
	}
	// A quantified layer replays its predicates per iteration, where no
	// final count exists: still refused rather than read unguarded.
	for _, expr := range []string{"eth/ipv6[exts[0].next_header == 6]{1,2}/tcp"} {
		if _, err := compileForTest(expr); !errors.Is(err, codegen.ErrNotImplemented) || !strings.Contains(err.Error(), "where clause") {
			t.Fatalf("%s: expected ErrNotImplemented pointing at a where clause, got %v", expr, err)
		}
	}
	// gtp has no gtp-under-gtp constant, so repeating it is a typing error
	// before any predicate is looked at (D-037).
	if _, err := compileForTest("eth/ipv4/udp/gtp[exts[0].ext_type == 1]{1,2}/ipv4/tcp"); err == nil || errors.Is(err, codegen.ErrNotImplemented) || !strings.Contains(err.Error(), "under itself") {
		t.Fatalf("repeated gtp: expected the self-dispatch typing error, got %v", err)
	}
	// `in [...]` brackets carry the same push-count guard.
	if _, err := compileForTest("eth/ipv6[exts[1].next_header in [6, 60]]/tcp"); err != nil {
		t.Fatalf("in-list bracket on a push-counted stack must compile: %v", err)
	}
	// Bit slices narrow the loaded window on walked entries too.
	for _, expr := range []string{"eth/ipv6/tcp where ipv6.exts[1].next_header[4:8] == 6", "eth/ipv6[exts[1].next_header[4:8] == 6]/tcp", "eth/ipv6/tcp where ipv6.exts[0].next_header[0:4] == 0"} {
		if _, err := compileForTest(expr); err != nil {
			t.Fatalf("%s must compile: %v", expr, err)
		}
	}
	// Variable-length entries (ipv6 and, since ext_length is honoured, gtp)
	// are addressed from a runtime index by walking up to the push bound.
	for _, expr := range []string{"eth/ipv6/tcp where ipv6.exts[ipv6.hop_limit].next_header == 6", "eth/ipv4/udp/gtp/ipv4/tcp where gtp.exts[gtp.msg_type].next_ext == 6"} {
		if _, err := compileForTest(expr); err != nil {
			t.Fatalf("%s: %v", expr, err)
		}
	}
	// Entry 0 keeps its constant offset, so `in @set` style constant-offset
	// readers still accept it (the resolver needs a set here; the where
	// form stands in for the constant-offset path).
	if _, err := compileForTest("eth/ipv4/udp/gtp/ipv4/tcp where gtp.exts[0].ext_type == 1"); err != nil {
		t.Fatalf("gtp.exts[0] must compile: %v", err)
	}
}

func TestCompileAlternationDivergentSize(t *testing.T) {
	// P3-12: `eth/(ipv4|ipv6)/tcp` is the canonical user-facing alt
	// case. ipv4 and ipv6 differ in header size (20 vs 40 bytes) AND
	// in the dispatch field for tcp (ipv4.protocol at byte 9 vs
	// ipv6.next_header at byte 6). Both alts have variable layout
	// (ipv4 IHL options, ipv6 ext-header walk) so this also exercises
	// the layer-entry-slot path of the diverged dispatch emit.
	for _, expr := range []string{
		"eth/(ipv4|ipv6)/tcp",
		"eth/(ipv4|ipv6)/udp",
		// Bracket predicate inside the post-alt layer: uses R4-relative
		// addressing so the runtime offset works whichever alt matched.
		"eth/(ipv4|ipv6)/tcp[dport==443]",
		"eth/(ipv4|ipv6)/udp[dport==53]",
	} {
		t.Run(expr, func(t *testing.T) {
			insns, err := Compile(expr, codegen.Capabilities{})
			if err != nil {
				t.Fatalf("Compile(%q): %v", expr, err)
			}
			if len(insns.Main) == 0 {
				t.Fatal("expected non-empty instructions")
			}
		})
	}
}

func TestCompileAlternationHetSizeWhere(t *testing.T) {
	// PR-A/PR-B: where / capture across a heterogeneous-size alt now
	// works via per-layer entry slots. The resolver marks the post-
	// alt layer NeedsRuntimeOffset; codegen stores R4 to a slot at
	// layer entry; downstream where field loads address through the
	// slot instead of R0+static_prefix.
	for _, expr := range []string{
		"eth/(ipv4|ipv6)/tcp where tcp.dport == 443",
		"eth/(ipv4|ipv6)/tcp where tcp.dport > 1024",
		// Capture: max-alt rounding picks ipv6 (40) for the prefix.
		"eth/(ipv4|ipv6)/tcp capture headers+64",
		// Option lookup past het-alt — exercises slot anchor through
		// the option-walk loop.
		"eth/(ipv4|ipv6)/tcp where tcp.options.MSS.value == 1460",
	} {
		t.Run(expr, func(t *testing.T) {
			out, err := Compile(expr, codegen.Capabilities{})
			if err != nil {
				t.Fatalf("Compile(%q): %v", expr, err)
			}
			if len(out.Main) == 0 {
				t.Fatal("expected non-empty instructions")
			}
		})
	}
}

// TestAccPlanDropsMatchedMemberStore: under the multi-option accumulator
// plan no where guard runs, so the alternation does not record which
// member matched (the slot was asked for by the where clause alone).
func TestAccPlanDropsMatchedMemberStore(t *testing.T) {
	stores := func(expr string) int {
		out, err := Compile(expr, codegen.Capabilities{})
		if err != nil {
			t.Fatalf("Compile(%q): %v", expr, err)
		}
		// The member index store sits right before the alt's exit: a
		// `Ja dsl_alt_end_*`, or the end landing itself for the last alt.
		n := 0
		for i := 1; i+1 < len(out.Main); i++ {
			ins, next := out.Main[i], out.Main[i+1]
			atExit := strings.HasPrefix(next.Reference(), "dsl_alt_end_") || strings.HasPrefix(next.Symbol(), "dsl_alt_end_")
			if atExit && ins.OpCode.Class().IsStore() && ins.Dst == asm.R10 && ins.Src == asm.R3 &&
				out.Main[i-1].Dst == asm.R3 && out.Main[i-1].OpCode.Source() == asm.ImmSource {
				n++
			}
		}
		return n
	}
	if n := stores("eth/ipv4/(tcp|udp) where tcp.options.MSS.value == 1460"); n != 2 {
		t.Errorf("guarded where: %d matched-member stores, want 2", n)
	}
	if n := stores("eth/ipv4/(tcp|udp) where tcp.options.MSS.value == 1460 and tcp.options.WS.shift == 7"); n != 0 {
		t.Errorf("accumulator plan: %d matched-member stores, want 0", n)
	}
}

// TestAlternationDispatchOnce: a non-last member's guard is its parent
// dispatch, so its body does not compare the parent field again. Each
// member's protocol value appears in exactly one compare.
func TestAlternationDispatchOnce(t *testing.T) {
	out, err := Compile("eth/ipv4/(tcp|udp|icmp)", codegen.Capabilities{})
	if err != nil {
		t.Fatal(err)
	}
	for _, proto := range []int64{6, 17, 1} {
		n := 0
		for _, ins := range out.Main {
			if ins.OpCode.Class().IsJump() && ins.OpCode.Source() == asm.ImmSource && ins.Constant == proto &&
				(ins.OpCode.JumpOp() == asm.JNE || ins.OpCode.JumpOp() == asm.JEq) && ins.Dst == asm.R3 {
				n++
			}
		}
		if n != 1 {
			t.Errorf("ipv4.protocol == %d compared %d times, want 1", proto, n)
		}
	}
}

func TestCompileAlternationMemberWhere(t *testing.T) {
	// `where ipv6.src == ...` references an alt member directly, by
	// protocol name or by label. The atom is false when another member
	// matched: the group records the matched member's index and the read
	// tests it first.
	for _, expr := range []string{
		"eth/(ipv4|ipv6)/tcp where ipv6.src == fe80::1",
		"eth/(ipv4|ipv6)/tcp where ipv4.src == 10.0.0.1",
		"eth/(ipv4@a|ipv6@b)/tcp where a.ttl == 64 or b.hop_limit == 64",
		"eth/ipv4/(tcp@x|udp) where x.dport == 80",
		"eth/(vlan@v|qinq)/ipv4/tcp where v.tci == 100",
	} {
		t.Run(expr, func(t *testing.T) {
			out, err := Compile(expr, codegen.Capabilities{})
			if err != nil {
				t.Fatalf("Compile(%q): %v", expr, err)
			}
			if len(out.Main) == 0 {
				t.Fatal("expected non-empty instructions")
			}
		})
	}
}

func TestCompileNestedAlternationFlattens(t *testing.T) {
	// P3-13: nested alt groups are flattened in the resolver. The
	// flat result rides the existing P3-12 codegen — heterogeneous
	// sizes / dispatches across all flat leaves work the same.
	for _, expr := range []string{
		"eth/((vlan|qinq)|ipv4)",
		"eth/((vlan|qinq)|(ipv4|ipv6))",
		"eth/(((vlan|qinq)|ipv4)|ipv6)",
	} {
		t.Run(expr, func(t *testing.T) {
			out, err := Compile(expr, codegen.Capabilities{})
			if err != nil {
				t.Fatalf("Compile(%q): %v", expr, err)
			}
			if len(out.Main) == 0 {
				t.Fatal("expected non-empty instructions")
			}
		})
	}
}

func TestCompileNestedAlternationCapOverflow(t *testing.T) {
	// Flattening can blow past altCountCap (= 4). Codegen surfaces
	// the cap error verbatim; this test pins down the user-visible
	// behaviour so we don't accidentally start over-flattening.
	_, err := Compile("eth/((vlan|qinq)|(vlan|qinq|vlan))", codegen.Capabilities{})
	if err == nil {
		t.Fatal("expected ErrNotImplemented for flatten cap overflow")
	}
	if !errors.Is(err, codegen.ErrNotImplemented) {
		t.Fatalf("err = %v; want ErrNotImplemented", err)
	}
	if !strings.Contains(err.Error(), "exceeds MVP cap") {
		t.Errorf("error should mention MVP cap: %v", err)
	}
}

func TestCompileNestedAlternationQuantifiedRejected(t *testing.T) {
	// `(a|b)?` inside an outer alt is NOT flattened — the optional
	// semantics differ from a flat alt — and the resolver rejects it as a
	// type error (alternatives carry no quantifier, §12).
	_, err := Compile("eth/((vlan|qinq)?|ipv4)", codegen.Capabilities{})
	if err == nil || errors.Is(err, codegen.ErrNotImplemented) || !strings.Contains(err.Error(), "alternatives cannot carry quantifiers") {
		t.Fatalf("err = %v; want a resolver error on the quantified inner alt group", err)
	}
}

func TestCompileStaticChainSucceeds(t *testing.T) {
	// `{n,m}` with m <= 4 rides the static-unroll path; these cover
	// both field self-dispatch (VLAN) and NO_CHECK self-dispatch (MPLS).
	cases := []string{
		"eth/vlan{1,3}/ipv4/tcp",
		"eth/vlan{3,3}/ipv4/tcp",
		"eth/mpls{1,4}/ipv4/tcp",
		"eth/mpls{2,2}/ipv4/tcp",
	}
	for _, expr := range cases {
		t.Run(expr, func(t *testing.T) {
			out, err := Compile(expr, codegen.Capabilities{})
			if err != nil {
				t.Fatalf("Compile(%q): %v", expr, err)
			}
			if len(out.Main) == 0 {
				t.Fatalf("Compile(%q) produced empty instructions", expr)
			}
		})
	}
}

func TestCompileBpfLoopChainCompiles(t *testing.T) {
	// Chains beyond the static-unroll cap and open-ended `+` ride the
	// bpf_loop path. Verifier coverage lives in
	// internal/program.TestBpfEntryWithDSLFilter.
	cases := []string{
		"eth/vlan{1,5}/ipv4/tcp",
		"eth/vlan+/ipv4/tcp",
		"eth/mpls+/ipv4/tcp",
	}
	for _, expr := range cases {
		t.Run(expr, func(t *testing.T) {
			out, err := Compile(expr, codegen.Capabilities{})
			if err != nil {
				t.Fatalf("Compile(%q): %v", expr, err)
			}
			if len(out.Main) == 0 {
				t.Fatalf("Compile(%q) produced empty instructions", expr)
			}
		})
	}
}

func TestCompileStarQuantifierCompiles(t *testing.T) {
	// `*` rides the bpf_loop path with a pre-chain peek that can skip
	// the whole iteration group when the parent dispatch mismatches.
	out, err := Compile("eth/mpls*/ipv4/tcp", codegen.Capabilities{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(out.Main) == 0 || len(out.Callbacks) == 0 {
		t.Fatalf("expected main + callbacks for `*`, got %d/%d", len(out.Main), len(out.Callbacks))
	}
}

func TestCompileStarOnFirstLayerRejected(t *testing.T) {
	// No outer parent to peek before the chain: a type error from the
	// resolver, not an implementation limit.
	_, err := Compile("vlan*/ipv4/tcp", codegen.Capabilities{})
	if err == nil || errors.Is(err, codegen.ErrNotImplemented) || !strings.Contains(err.Error(), "first layer cannot be optional") {
		t.Fatalf("err = %v; want a resolver error for `*` on the first layer", err)
	}
}

func TestCompileIcmpAndIcmp6Succeed(t *testing.T) {
	cases := []string{
		"eth/ipv4/icmp",
		"eth/ipv6/icmp6",
		"eth/ipv4/icmp[type==8]",
		"eth/ipv6/icmp6[type==128] capture headers+16",
	}
	for _, expr := range cases {
		t.Run(expr, func(t *testing.T) {
			out, err := Compile(expr, codegen.Capabilities{})
			if err != nil {
				t.Fatalf("Compile(%q): %v", expr, err)
			}
			if len(out.Main) == 0 {
				t.Fatalf("Compile(%q) produced empty instructions", expr)
			}
		})
	}
}

func TestCompileCaptureHeadersPlusReportsLength(t *testing.T) {
	out, err := Compile("eth/ipv4/tcp capture headers+64", codegen.Capabilities{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(out.Main) == 0 {
		t.Fatal("expected non-empty instructions")
	}
	// eth(14) + ipv4(20) + tcp(20) + 64 = 118
	if out.Capture.MaxCapLen != 14+20+20+64 {
		t.Errorf("MaxCapLen = %d, want %d", out.Capture.MaxCapLen, 14+20+20+64)
	}
}

func TestCompilePerCaptureWhereReachesCodegen(t *testing.T) {
	// Smoke-test: a per-capture where must flow through resolve →
	// codegen instead of being silently dropped. The action atom
	// against a zero Capabilities is the cheapest atom that fails
	// loudly the moment resolve sees it.
	_, err := Compile(
		"eth/ipv4/tcp capture headers+32 where action == XDP_DROP",
		codegen.Capabilities{},
	)
	if err == nil {
		t.Fatal("expected per-capture action atom to fail against zero Capabilities")
	}
	if !strings.Contains(err.Error(), "not available on this host") {
		t.Fatalf("error = %v; want host-mismatch message", err)
	}
}

// TestZeroCapsIsHostAgnostic locks in the kunai-vs-host boundary:
// when the caller passes the zero Capabilities, the emitted main
// instruction stream must not read or write any register / stack
// slot the host owns (R6-R8 callee-saved, R9 read-only, stack[-48]
// host scratch). If a future change leaks XDP-specific assumptions
// back into the core codegen this test should turn red.
func TestZeroCapsIsHostAgnostic(t *testing.T) {
	cases := []string{
		"eth/ipv4/tcp",
		"eth/ipv4/tcp[dport==443]",
		"eth/ipv4[src==10.0.0.0/8]/tcp",
		"eth/(vlan|qinq)/ipv4/tcp",
		"eth/mpls+/ipv4/tcp",
		"eth/ipv4/tcp where ipv4.total_length > 100 capture headers+64",
		// Int<128> compare paths exercise the dual-half compare in
		// genArithCompare128. R9 is host pkt_len that
		// captureWithXdpOutput reads after filter eval, so a kunai
		// write would silently truncate MaxCapLen — pin both R6-R8
		// and R9 here so the regression is caught at unit time.
		"eth/ipv6/tcp where ipv6.src == ipv6.dst",
		"eth/ipv6/tcp where ipv6.src != ipv6.dst",
		"eth/ipv6/tcp where ipv6.src < ipv6.dst",
		"eth/ipv6/tcp where ipv6.src + 1 == ipv6.dst",
		"eth/ipv6/tcp where ipv6.src + ipv6.dst == ipv6.src",
		"eth/ipv6/tcp where ipv6.src == ipv6.dst capture headers+64",
	}
	for _, expr := range cases {
		t.Run(expr, func(t *testing.T) {
			out, err := Compile(expr, codegen.Capabilities{})
			if err != nil {
				t.Fatalf("Compile(%q): %v", expr, err)
			}
			all := append(asm.Instructions{}, out.Main...)
			all = append(all, out.Callbacks...)
			for _, ins := range all {
				if isHostOwned(ins) {
					t.Errorf("instruction touches host-owned register or stack slot: %+v", ins)
				}
			}
		})
	}
}

// isHostOwned reports whether ins touches a host-only resource per
// the ABI contract documented in codegen/codegen.go: R6-R8 must not
// be referenced (callee-saved from kunai's view), R9 is the host's
// pkt_len that captureWithXdpOutput re-reads after filter eval (so
// any kunai write would silently truncate MaxCapLen), and any R10
// slot shallower than codegen.KunaiStackTop is the host's scratch
// range.
func isHostOwned(ins asm.Instruction) bool {
	for _, r := range []asm.Register{asm.R6, asm.R7, asm.R8, asm.R9} {
		if ins.Dst == r || ins.Src == r {
			return true
		}
	}
	if (ins.Dst == asm.R10 || ins.Src == asm.R10) && ins.Offset > codegen.KunaiStackTop && ins.Offset < 0 {
		return true
	}
	return false
}

// TestVlanInMetadataRejectsVlanLayers asserts the VlanInMetadata host
// policy (e.g. tc, where the kernel strips the outer VLAN tag into skb
// metadata before the program runs). A mandatory outer vlan/qinq layer
// could never match a tagged frame there and is a type error. An
// optional outer tag compiles, with or without a predicate or a where /
// capture read: the filter sees the bytes the kernel holds, so the tag
// is absent on a single-tagged frame and the C-tag is read on a QinQ
// frame (spec D-003 / D-008). Every expression must still compile under
// the zero (in-band) Capabilities used by XDP and the test harness.
func TestVlanInMetadataRejectsVlanLayers(t *testing.T) {
	// A mandatory vlan or qinq layer is a type error at such a host.
	illTyped := []string{
		"eth/vlan/ipv4/tcp",
		"eth/vlan[tci==100]/ipv4/tcp where tcp.dport == 80", // mandatory + field
		"eth/vlan+/ipv4/tcp",
		"eth/(vlan|qinq)/ipv4/tcp", // alternation members are mandatory
		"eth/(qinq|vlan)/ipv4/tcp",
		"eth/((vlan|qinq)|ipv4)",
		"eth/qinq/vlan/ipv4/tcp where tcp.dport == 80",
		"eth/qinq/vlan?/ipv4/tcp where tcp.dport == 80", // an 802.1ad outer tag is moved too
		"eth/((qinq|mpls)|ipv4)",
	}
	// Optional tags are matchable at a VlanInMetadata host: at most one
	// tag survives in the bytes, and the skip path covers untagged /
	// single-tag / QinQ traffic. A predicate or a read on the optional
	// tag sees the C-tag of a QinQ frame and nothing on a single-tagged
	// one (the layer is absent: the predicate is not evaluated, the where
	// atom is false).
	accepted := []string{
		"eth/vlan?/ipv4/tcp",
		"eth/qinq?/vlan?/ipv4/tcp",
		"eth/vlan*/ipv4/tcp",
		"eth/vlan?/ipv4/tcp where ipv4.ttl == 64",  // past the tag: runtime offset, no tag read
		"eth/vlan[tci==100]?/ipv4/tcp",             // optional and reads tci
		"eth/vlan?/ipv4/tcp where vlan.tci == 100", // where reads the tag
		"eth/vlan?/ipv4/tcp capture vlan",          // capture targets the tag
	}
	tcCaps := codegen.Capabilities{Host: codegen.HostLayout{VlanInMetadata: true}}
	// Only the outer tag is in metadata: a tag inside a tunnel is in the
	// packet bytes, so it may be mandatory and read (spec D-008).
	for _, expr := range []string{
		"eth/ipv4/udp/vxlan/eth/vlan/ipv4/tcp",
		"eth/ipv4/udp/vxlan/eth/vlan[tci==100]/ipv4/tcp where vlan.tci == 100",
		"eth/ipv4/udp/vxlan/eth/qinq/vlan/ipv4/tcp capture vlan",
		"eth/vlan?/ipv4/udp/vxlan/eth/vlan@i[tci==100]/ipv4/tcp where i.tci == 100",
	} {
		t.Run("inner/"+expr, func(t *testing.T) {
			if _, err := Compile(expr, tcCaps); err != nil {
				t.Errorf("inner tag with VlanInMetadata: %v", err)
			}
		})
	}
	// The outer tag read by label compiles too; its atom is false when the
	// optional tag is absent (vector host-tc-outer-labelled-where).
	if _, err := Compile("eth/vlan@o?/ipv4/udp/vxlan/eth/vlan@i/ipv4/tcp where not (o.tci == 100)", tcCaps); err != nil {
		t.Errorf("outer tag read by label: %v", err)
	}
	for _, expr := range illTyped {
		t.Run("illTyped/"+expr, func(t *testing.T) {
			_, err := Compile(expr, tcCaps)
			if !errors.Is(err, codegen.ErrVlanInMetadata) || errors.Is(err, codegen.ErrNotImplemented) {
				t.Fatalf("Compile(%q) with VlanInMetadata = %v; want ErrVlanInMetadata", expr, err)
			}
		})
	}
	// The advice is one the user can follow: a tag inside an alternation
	// cannot take `?`, so the alternation is rewritten, and the rewrite
	// compiles.
	for _, tc := range []struct{ expr, advice, rewrite string }{
		{"eth/vlan/ipv4/tcp", "(vlan?)", "eth/vlan?/ipv4/tcp"},
		{"eth/(vlan|qinq)/ipv4/tcp", "write qinq?/vlan? instead", "eth/qinq?/vlan?/ipv4/tcp"},
		{"eth/((qinq|mpls)|ipv4)", "write qinq?/(mpls|ipv4) instead", "eth/qinq?/(mpls|ipv4)"},
		{"eth/(vlan|qinq|ipv4)", "write qinq?/vlan?/ipv4 instead", "eth/qinq?/vlan?/ipv4"},
	} {
		if _, err := Compile(tc.expr, tcCaps); err == nil || !strings.Contains(err.Error(), tc.advice) {
			t.Errorf("Compile(%q) = %v; want the advice %q", tc.expr, err, tc.advice)
		}
		if _, err := Compile(tc.rewrite, tcCaps); err != nil {
			t.Errorf("the advised rewrite %q does not compile: %v", tc.rewrite, err)
		}
	}
	for _, expr := range accepted {
		t.Run("accept/"+expr, func(t *testing.T) {
			if _, err := Compile(expr, tcCaps); err != nil {
				t.Fatalf("Compile(%q) with VlanInMetadata: expected success, got %v", expr, err)
			}
		})
	}
	for _, expr := range append(append([]string{}, illTyped...), accepted...) {
		t.Run("inband/"+expr, func(t *testing.T) {
			if _, err := Compile(expr, codegen.Capabilities{}); err != nil {
				t.Fatalf("Compile(%q) with zero caps: expected success, got %v", expr, err)
			}
		})
	}
}

// Cache correctness for dslvocab.Bundled is covered in its own
// package; Compile merely threads the call through.

// TestCompileCgroupSKBHost pins the cgroup-skb host adapter surface:
// SK_* action atoms resolve at fexit, and the L3-start layout flips
// the chain-root advice (warn on eth roots, stay silent on ipv4/ipv6).
func TestCompileCgroupSKBHost(t *testing.T) {
	t.Run("action atoms", func(t *testing.T) {
		out, err := Compile("ipv4/tcp where action == SK_DROP", cgskbhost.FexitCapabilities())
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if len(out.Main) == 0 {
			t.Fatal("empty instructions")
		}
	})
	t.Run("action atoms rejected at entry", func(t *testing.T) {
		_, err := Compile("ipv4/tcp where action == SK_DROP", cgskbhost.EntryCapabilities())
		if err == nil {
			t.Fatal("expected entry-caps compile to reject the action atom")
		}
	})
	t.Run("ipv4 root has no warning", func(t *testing.T) {
		out, err := Compile("ipv4/tcp", cgskbhost.EntryCapabilities())
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if len(out.Warnings) != 0 {
			t.Fatalf("unexpected warnings: %v", out.Warnings)
		}
	})
	t.Run("eth root warns", func(t *testing.T) {
		out, err := Compile("eth/ipv4/tcp", cgskbhost.EntryCapabilities())
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if len(out.Warnings) != 1 || !strings.Contains(out.Warnings[0], "no Ethernet header") {
			t.Fatalf("expected the L3-start eth-root warning, got %v", out.Warnings)
		}
	})
	t.Run("vlan layer rejected", func(t *testing.T) {
		_, err := Compile("eth/vlan/ipv4/tcp", cgskbhost.EntryCapabilities())
		if !errors.Is(err, codegen.ErrVlanInMetadata) {
			t.Fatalf("expected ErrVlanInMetadata for vlan on cgroup-skb, got %v", err)
		}
	})
}

// TestCompileL2HostRootWarningUnchanged pins the default polarity: with
// the zero Capabilities a non-eth root still draws the L2 advice.
func TestCompileL2HostRootWarningUnchanged(t *testing.T) {
	out, err := Compile("ipv4/tcp", codegen.Capabilities{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(out.Warnings) != 1 || !strings.Contains(out.Warnings[0], "is not 'eth'") {
		t.Fatalf("expected the L2 non-eth-root warning, got %v", out.Warnings)
	}
}

// TestOptionRegionPolicyCompiles: `.valid` exists only where a region's
// faults are skipped, and only those layers get the malformed landing
// (spec D-029, @kunai_option_region). srv6 says on_fault=fail.
func TestOptionRegionPolicyCompiles(t *testing.T) {
	_, err := Compile("eth/ipv6/srv6/tcp where srv6.segments.valid", codegen.Capabilities{})
	if err == nil || errors.Is(err, codegen.ErrNotImplemented) || !strings.Contains(err.Error(), "on_fault=skip") {
		t.Fatalf("srv6.segments.valid: got %v, want the type error naming on_fault=skip", err)
	}
	landing := func(expr string) bool {
		out, err := Compile(expr, codegen.Capabilities{})
		if err != nil {
			t.Fatalf("Compile(%q): %v", expr, err)
		}
		for _, ins := range out.Main {
			if strings.Contains(ins.Symbol(), "_malformed_") {
				return true
			}
		}
		return false
	}
	if !landing("eth/ipv4/tcp where tcp.options.MSS.value == 1460") {
		t.Errorf("tcp: no malformed landing for a skipped region")
	}
	if landing("eth/ipv6/srv6/tcp where any(srv6.segments.addr == fc00::1)") {
		t.Errorf("srv6: a malformed landing although on_fault=fail")
	}
}
