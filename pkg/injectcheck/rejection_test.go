package injectcheck

// Negative fixtures exercise path-sensitive effects and region ownership.

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf/asm"
)

func assertKind(t *testing.T, err error, want Kind) {
	t.Helper()
	if want == OriginalOrder || want == HookRange || want == HookOverlap || want == InputOriginalCFG {
		assertInputKind(t, err, want)
		return
	}
	var rejection *Rejection
	if !errors.As(err, &rejection) || rejection.Kind != want {
		t.Fatalf("got %v, want rejection kind %s", err, want)
	}
}
func expectPairKind(t *testing.T, name string, in, out asm.Instructions, c fixtureCertificate, want Kind) {
	t.Helper()
	_, err := checkFixture(in, out, c)
	assertKind(t, err, want)
	t.Logf("%s: %v", name, err)
}

func clone(is asm.Instructions) asm.Instructions { return append(asm.Instructions(nil), is...) }

// lookup fixture layout (callingConventionFixture(false)):
// out 0 entry spill; 6 prelude; 7 helper; 8..14 postlude; 19..20 hook.
func TestRejectPostlude(t *testing.T) {
	in, out, c := callingConventionFixture(false)
	if _, err := checkFixture(in, out, c); err != nil {
		t.Fatal(err)
	}
	// Postlude is out[8:15]: stx -32 r0; jeq r0 0 +4; ldx r1 -16; ldx r2 -24; mov r3 0; call hook; ldx r0 -32.
	t.Run("read-undefined-R4", func(t *testing.T) {
		bad := clone(out)
		bad[12] = asm.Mov.Reg(asm.R3, asm.R4)
		expectPairKind(t, "read-undefined-R4", in, bad, c, RegisterUndefined)
	})
	t.Run("store-into-original-frame", func(t *testing.T) {
		bad := clone(out)
		bad[12] = asm.StoreMem(asm.RFP, -8, asm.R1, asm.DWord)
		expectPairKind(t, "store-into-original-frame", in, bad, c, StoreBounds)
	})
	t.Run("store-reserved-not-copy", func(t *testing.T) {
		bad := clone(out)
		bad[12] = asm.StoreMem(asm.RFP, -48, asm.R1, asm.DWord)
		expectPairKind(t, "store-reserved-not-copy", in, bad, c, StoreShape)
	})
	t.Run("load-clobbers-R6", func(t *testing.T) {
		bad := clone(out)
		bad[11] = asm.LoadMem(asm.R6, asm.RFP, -24, asm.DWord)
		expectPairKind(t, "load-clobbers-R6", in, bad, c, LoadClobber)
	})
	t.Run("branch-escapes-postlude", func(t *testing.T) {
		bad := clone(out)
		bad[9].Offset = 6 // lands on original 6+ instead of inside the postlude
		expectPairKind(t, "branch-escapes-postlude", in, bad, c, BranchEscape)
	})
	t.Run("entry-spill-wrong-slot", func(t *testing.T) {
		bad := clone(out)
		bad[0] = asm.StoreMem(asm.RFP, -8, asm.R1, asm.DWord)
		expectPairKind(t, "entry-spill-wrong-slot", in, bad, c, EntrySpill)
	})

	t.Run("hook-symbol-collides-with-original-label", func(t *testing.T) {
		bad := clone(out)
		bad[19] = bad[19].WithSymbol("done")
		expectPairKind(t, "hook-symbol-collides-with-original-label", in, bad, c, SymbolAmbiguous)
	})
}

// Two-call P2 shapes: [stx r0][jeq][call][ja][call][ldx r0].
func twoCallLookup(jeqOff, jaOff int16) (asm.Instructions, asm.Instructions, fixtureCertificate) {
	in, out, c := callingConventionFixture(false)
	j := asm.JEq.Imm(asm.R0, 0, "")
	j.Offset = jeqOff
	ja := asm.Ja.Label("")
	ja.Offset = jaOff
	post := asm.Instructions{asm.StoreMem(asm.RFP, -32, asm.R0, asm.DWord), j, asm.Call.Label("hook"), ja, asm.Call.Label("hook"), asm.LoadMem(asm.R0, asm.RFP, -32, asm.DWord)}
	n := append(clone(out[:8]), post...)
	delta := len(post) - 7
	n = append(n, out[15:]...)
	for i := range c.Original {
		if c.Original[i] >= 15 {
			c.Original[i] += delta
		}
	}
	c.Hooks = []Span{{c.Hooks[0].Start + delta, c.Hooks[0].End + delta}}
	return in, n, c
}

func TestRejectTwoCallPaths(t *testing.T) {
	// Baseline: jeq to the second call, ja over the second call to the restore.
	in, out, c := twoCallLookup(2, 1)
	if _, err := checkFixture(in, out, c); err != nil {
		t.Fatalf("baseline two-call postlude rejected: %v", err)
	}
	// ja +2 skips the final R0 restore on the first-hook path: the original
	// then observes the hook's R0 instead of the lookup result.
	in, out, c = twoCallLookup(2, 2)
	expectPairKind(t, "ja-skips-R0-restore", in, out, c, ResultPath)
	// ja +0 runs both hooks on one path.
	in, out, c = twoCallLookup(3, 0)
	expectPairKind(t, "two-hooks-one-path", in, out, c, MultipleCalls)
}

func TestRejectTailReadsR0(t *testing.T) {
	in, out, c := callingConventionFixture(true)
	if _, err := checkFixture(in, out, c); err != nil {
		t.Fatal(err)
	}
	// Tail postlude: out 8 ldx r1; 9 ldx r2; 10 mov r3 0; 11 call hook.
	bad := clone(out)
	bad[10] = asm.Mov.Reg(asm.R3, asm.R0)
	expectPairKind(t, "tail-postlude-reads-R0", in, bad, c, RegisterUndefined)
}

func TestRejectGapsAndHooks(t *testing.T) {
	in := asm.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()}
	// Arbitrary code inserted after a non-helper, non-P6 instruction.
	out := asm.Instructions{in[0], asm.Mov.Imm(asm.R1, 0), in[1]}
	expectPairKind(t, "gap-after-plain-instruction", in, out, fixtureCertificate{Original: []int{0, 2}}, U32Placement)
	// Hook placed where the preceding original instruction falls through.
	out = asm.Instructions{in[0], asm.Mov.Imm(asm.R0, 0).WithSymbol("hook"), asm.Return(), in[1]}
	expectPairKind(t, "fall-through-into-hook", in, out, fixtureCertificate{Original: []int{0, 3}, Hooks: []Span{{1, 3}}}, HookFallthrough)
}

func TestRejectP6WrongHook(t *testing.T) {
	in := asm.Instructions{asm.Mov.Reg(asm.R0, asm.R1), asm.Mov.Imm(asm.R3, 7), asm.LoadMem(asm.R2, asm.R0, 0, asm.Word), asm.Mov.Imm(asm.R1, 0), asm.Mov.Reg(asm.R0, asm.R2), asm.Return()}
	out := clone(in[:3])
	out = append(out, asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord), asm.StoreMem(asm.RFP, -16, asm.R2, asm.DWord), asm.Mov.Imm32(asm.R1, 2), asm.Call.Label("hook"), asm.LoadMem(asm.R0, asm.RFP, -8, asm.DWord), asm.LoadMem(asm.R2, asm.RFP, -16, asm.DWord))
	out = append(out, in[3:]...)
	h := len(out)
	out = append(out, asm.Mov.Imm(asm.R0, 0).WithSymbol("hook"), asm.Return())
	expectPairKind(t, "p6-calls-non-u32-hook", in, out, fixtureCertificate{Original: []int{0, 1, 2, 9, 10, 11}, Hooks: []Span{{h, h + 2}}}, U32Hook)
}

// Numeric gotol (JA32 uses Constant) relocated across a P6 region.
func TestRejectJump32Ja(t *testing.T) {
	ja32 := asm.LongJump("")
	ja32 = ja32.WithReference("")
	ja32.Constant = 2
	in := asm.Instructions{ja32, asm.Mov.Imm(asm.R3, 7), asm.LoadMem(asm.R2, asm.R0, 0, asm.Word), asm.Mov.Imm(asm.R1, 0), asm.Mov.Reg(asm.R0, asm.R2), asm.Return()}
	out := clone(in[:3])
	out = append(out, asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord), asm.StoreMem(asm.RFP, -16, asm.R2, asm.DWord), asm.Mov.Imm32(asm.R1, 2), asm.Call.Label("hook"), asm.LoadMem(asm.R0, asm.RFP, -8, asm.DWord), asm.LoadMem(asm.R2, asm.RFP, -16, asm.DWord))
	out = append(out, in[3:]...)
	h := len(out)
	out = append(out, asm.Mov.Reg32(asm.R0, asm.R1).WithSymbol("hook"), asm.Xor.Reg32(asm.R0, asm.R2), asm.Return())
	c := fixtureCertificate{Original: []int{0, 1, 2, 9, 10, 11}, Hooks: []Span{{h, h + 3}}}
	expectPairKind(t, "gotol-unrelocated", in, out, c, EdgeTarget)
	out[0].Constant = 8
	if _, err := checkFixture(in, out, c); err != nil {
		t.Errorf("gotol-relocated: rejected: %v", err)
	} else {
		t.Logf("gotol-relocated: accepted")
	}
	out[0].Constant = 7
	expectPairKind(t, "gotol-off-by-one", in, out, c, EdgeTarget)
	out[0].Constant = 8
	out[0].Offset = 3
	expectPairKind(t, "gotol-offset-field-changed", in, out, c, OriginalChanged)
}

// P6 liveness through a bpf-to-bpf callee and through helper arities.
func p6Pair(tail asm.Instructions) (asm.Instructions, asm.Instructions, fixtureCertificate) {
	in := append(asm.Instructions{asm.Mov.Imm(asm.R3, 7), asm.LoadMem(asm.R2, asm.R0, 0, asm.Word)}, tail...)
	out := clone(in[:2])
	out = append(out, asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord), asm.StoreMem(asm.RFP, -16, asm.R2, asm.DWord), asm.Mov.Imm32(asm.R1, 2), asm.Call.Label("hook"), asm.LoadMem(asm.R0, asm.RFP, -8, asm.DWord), asm.LoadMem(asm.R2, asm.RFP, -16, asm.DWord))
	out = append(out, in[2:]...)
	c := fixtureCertificate{Original: []int{0, 1}}
	for i := 2; i < len(in); i++ {
		c.Original = append(c.Original, i+6)
	}
	h := len(out)
	out = append(out, asm.Mov.Reg32(asm.R0, asm.R1).WithSymbol("hook"), asm.Xor.Reg32(asm.R0, asm.R2), asm.Return())
	c.Hooks = []Span{{h, h + 3}}
	return in, out, c
}

func TestRejectP6Liveness(t *testing.T) {
	call := asm.Call.Label("")
	call.Constant = 1
	call = call.WithReference("")
	in, out, c := p6Pair(asm.Instructions{call, asm.Return(), asm.Mov.Reg(asm.R0, asm.R3), asm.Return()})
	expectPairKind(t, "p6-live-R3-in-callee", in, out, c, U32Live)
	in, out, c = p6Pair(asm.Instructions{asm.FnProbeRead.Call(), asm.Return()})
	expectPairKind(t, "p6-live-before-3-arg-helper", in, out, c, U32Live)
	in, out, c = p6Pair(asm.Instructions{asm.FnKtimeGetNs.Call(), asm.Return()})
	if _, err := checkFixture(in, out, c); err != nil {
		t.Errorf("p6-before-0-arg-helper: rejected: %v", err)
	} else {
		t.Logf("p6-before-0-arg-helper: accepted")
	}
}

// replacePostlude adjusts only layout hints; Check still derives the region.
func replacePostlude(post asm.Instructions) (asm.Instructions, asm.Instructions, fixtureCertificate) {
	in, out, c := callingConventionFixture(false)
	n := append(clone(out[:8]), post...)
	n = append(n, out[15:]...)
	delta := len(post) - 7
	for i, j := range c.Original {
		if j >= 15 {
			c.Original[i] += delta
		}
	}
	c.Hooks = []Span{{c.Hooks[0].Start + delta, c.Hooks[0].End + delta}}
	return in, n, c
}

func TestPostludeRejectionKinds(t *testing.T) {
	_, base, _ := callingConventionFixture(false)
	for _, tc := range []struct {
		name   string
		kind   Kind
		mutate func(asm.Instructions) asm.Instructions
	}{
		{"missing-result", ResultSaveRestore, func(p asm.Instructions) asm.Instructions { p[0] = asm.Mov.Imm(asm.R1, 0); return p }},
		{"lookup-structure", LookupStructure, func(p asm.Instructions) asm.Instructions { p[1] = asm.Mov.Imm(asm.R3, 0); return p }},
		{"invalid-register", RegisterInvalid, func(p asm.Instructions) asm.Instructions { p[4].Dst = 12; return p }},
		{"read-callee-saved", RegisterRead, func(p asm.Instructions) asm.Instructions { p[4] = asm.Mov.Reg(asm.R3, asm.R6); return p }},
		{"result-load-not-final", ResultLoad, func(p asm.Instructions) asm.Instructions {
			p[3] = asm.LoadMem(asm.R0, asm.RFP, -32, asm.DWord)
			return p
		}},
		{"spill-width", SpillUninitialized, func(p asm.Instructions) asm.Instructions {
			p[3] = asm.LoadMem(asm.R2, asm.RFP, -24, asm.Word)
			return p
		}},
		{"copy-offset", CopyShape, func(p asm.Instructions) asm.Instructions { p[3] = asm.LoadMem(asm.R1, asm.R0, -1, asm.Byte); return p }},
		{"copy-without-store", CopyShape, func(p asm.Instructions) asm.Instructions { p[3] = asm.LoadMem(asm.R1, asm.R0, 0, asm.Byte); return p }},
		{"alu-result", ALUClobber, func(p asm.Instructions) asm.Instructions { p[4] = asm.Mov.Imm(asm.R0, 0); return p }},
		{"alu-offset", ALUEncoding, func(p asm.Instructions) asm.Instructions { p[4].Offset = 1; return p }},
		{"alu-undefined-dst", RegisterUndefined, func(p asm.Instructions) asm.Instructions { p[4] = asm.And.Imm(asm.R3, 1); return p }},
		{"pointer-not-frame", PointerCalculation, func(p asm.Instructions) asm.Instructions { p[4] = asm.Add.Imm(asm.R1, -64); return p }},
		{"pointer-twice", PointerBounds, func(p asm.Instructions) asm.Instructions {
			p[2] = asm.Mov.Reg(asm.R1, asm.RFP)
			p[3] = asm.Add.Imm(asm.R1, -400)
			p[4] = asm.Add.Imm(asm.R1, -400)
			return p
		}},
		{"alu-operation", ALUOperation, func(p asm.Instructions) asm.Instructions { p[4] = asm.Sub.Imm(asm.R1, 1); return p }},
		{"branch-backward", BranchForward, func(p asm.Instructions) asm.Instructions { p[1].Offset = -1; return p }},
		{"guard-register", BranchGuard, func(p asm.Instructions) asm.Instructions { p[1].Dst = asm.R1; return p }},
		{"guard-width", BranchGuard, func(p asm.Instructions) asm.Instructions {
			p[1] = asm.JEq.Imm32(asm.R0, 0, "")
			p[1].Offset = 4
			return p
		}},
		{"unsupported-instruction", PostludeInstruction, func(p asm.Instructions) asm.Instructions { p[4] = asm.LoadImm(asm.R3, 0, asm.DWord); return p }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, out, c := replacePostlude(tc.mutate(clone(base[8:15])))
			expectPairKind(t, tc.name, in, out, c, tc.kind)
		})
	}
	for _, tc := range []struct {
		name   string
		change func(*asm.Instruction)
	}{
		{"ja-constant", func(i *asm.Instruction) { i.Constant = 1 }},
		{"ja-register", func(i *asm.Instruction) { i.Dst = asm.R1 }},
		{"ja-width", func(i *asm.Instruction) { i.OpCode = asm.LongJump("").OpCode }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, out, c := twoCallLookup(2, 1)
			tc.change(&out[11])
			expectPairKind(t, tc.name, in, out, c, BranchEncoding)
		})
	}
	in, out, c := callingConventionFixture(true)
	out[10] = asm.JEq.Imm(asm.R0, 0, "")
	expectPairKind(t, "tail-branch", in, out, c, HelperStructure)
}

func TestRegionRejectionKinds(t *testing.T) {
	in := asm.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()}
	for _, tc := range []struct {
		name string
		out  asm.Instructions
		c    fixtureCertificate
		kind Kind
	}{
		{"order", in, fixtureCertificate{Original: []int{1, 0}}, OriginalOrder},
		{"missing-index", in, fixtureCertificate{Original: []int{0, 2}}, OriginalOrder},
		{"range", in, fixtureCertificate{Original: []int{0, 1}, Hooks: []Span{{-1, 0}}}, HookRange},
		{"overlap", in, fixtureCertificate{Original: []int{0, 1}, Hooks: []Span{{0, 2}}}, HookOverlap},
		{"entry-restore", append(asm.Instructions{asm.StoreMem(asm.RFP, -8, asm.R1, asm.DWord), asm.Mov.Imm(asm.R1, 0)}, in...), fixtureCertificate{Original: []int{2, 3}}, EntryRestore},
		{"split", asm.Instructions{in[0], asm.Ja.Label(""), asm.Mov.Imm(asm.R0, 0), asm.Return(), asm.Mov.Imm(asm.R1, 0), in[1]}, fixtureCertificate{Original: []int{0, 5}, Hooks: []Span{{2, 4}}}, RegionSplit},
	} {
		t.Run(tc.name, func(t *testing.T) { expectPairKind(t, tc.name, in, tc.out, tc.c, tc.kind) })
	}
	// A dispatch-shaped entry reaches its argument check before its call check.
	entry := asm.Instructions{asm.StoreMem(asm.RFP, -8, asm.R1, asm.DWord), asm.Mov.Imm32(asm.R2, 0), asm.Mov.Imm(asm.R3, 0), asm.Mov.Imm(asm.R4, 0), asm.Mov.Imm(asm.R5, 0), asm.Call.Label("hook"), asm.LoadMem(asm.R1, asm.RFP, -8, asm.DWord)}
	expectPairKind(t, "dispatch-arguments", in, append(entry, in...), fixtureCertificate{Original: []int{7, 8}}, EntryArguments)
	for _, tc := range []struct {
		name string
		ins  asm.Instruction
		kind Kind
	}{
		{"helper", asm.FnKtimeGetNs.Call(), CallKind},
		{"non-hook", asm.Call.Label("original"), CallTarget},
		{"unresolved", asm.Call.Label("missing"), SymbolUnresolved},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := asm.Instructions{entry[0], tc.ins, entry[6], in[0].WithSymbol("original"), in[1]}
			expectPairKind(t, tc.name, in, out, fixtureCertificate{Original: []int{3, 4}}, tc.kind)
		})
	}
	// The hook header is valid, so a forbidden interior store/helper reaches HookBody.
	for _, ins := range []asm.Instruction{asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord), asm.FnKtimeGetNs.Call()} {
		assertKind(t, checkHook(asm.Instructions{asm.LoadMem(asm.R0, asm.R1, 0, asm.Word), ins, asm.Mov.Imm(asm.R0, 0), asm.Return()}), HookBody)
	}
}

func TestEdgeRejectionKinds(t *testing.T) {
	for _, tc := range []struct {
		name string
		is   asm.Instructions
		kind Kind
	}{
		{"resolved", asm.Instructions{asm.Ja.Label("end").WithReference("end"), asm.Return().WithSymbol("end")}, InputOriginalCFG},
		{"unresolved", asm.Instructions{asm.Ja.Label("missing"), asm.Return()}, InputOriginalCFG},
		{"slot", asm.Instructions{asm.Ja.Label(""), asm.Return()}, InputOriginalCFG},
		{"function-entry", asm.Instructions{asm.Call.Label("entry").WithSymbol("entry"), asm.Return()}, InputOriginalCFG},
	} {
		t.Run(tc.name, func(t *testing.T) {
			is := clone(tc.is)
			if tc.name == "resolved" {
				is[0].Offset = 0
			}
			if tc.name == "slot" {
				is[0].Offset = 99
			}
			expectPairKind(t, tc.name, is, is, fixtureCertificate{Original: []int{0, 1}}, tc.kind)
		})
	}
}

func TestInputErrorKinds(t *testing.T) {
	in := asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}
	for _, tc := range []struct {
		name string
		in   asm.Instructions
		c    fixtureCertificate
		kind Kind
	}{
		{"original-empty", nil, fixtureCertificate{}, InputOriginalEmpty},
		{"mapping-empty", in, fixtureCertificate{}, InputCertificateEmpty},
		{"mapping-length", in, fixtureCertificate{Original: []int{0}}, InputCertificateLength},
		{"floor-positive", in, fixtureCertificate{Original: []int{0, 1}, LowestOffset: 8}, InputStackFloor},
		{"floor-too-low", in, fixtureCertificate{Original: []int{0, 1}, LowestOffset: -513}, InputStackFloor},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := checkFixture(tc.in, tc.in, tc.c)
			var input *InputError
			if !errors.As(err, &input) || input.Kind != tc.kind {
				t.Fatalf("got %v, want input kind %s", err, tc.kind)
			}
		})
	}
}

func TestRemainingRejectionKinds(t *testing.T) {
	t.Run("duplicate-label", func(t *testing.T) {
		in := asm.Instructions{asm.Mov.Imm(asm.R0, 0)}
		Label(in)
		_, err := FromLabels(append(in, in[0]), 1, nil)
		assertKind(t, err, LabelInvalid)
	})
	t.Run("callback-unresolved", func(t *testing.T) {
		i := asm.LoadImm(asm.R2, -1, asm.DWord).WithReference("missing")
		i.Src = asm.PseudoFunc
		in := asm.Instructions{i, asm.Return()}
		expectPairKind(t, "callback", in, in, fixtureCertificate{Original: []int{0, 1}}, InputOriginalCFG)
	})
	t.Run("call-unresolved", func(t *testing.T) {
		in := asm.Instructions{asm.Call.Label("missing"), asm.Return()}
		expectPairKind(t, "call", in, in, fixtureCertificate{Original: []int{0, 1}}, InputOriginalCFG)
	})
	t.Run("prelude-bounds", func(t *testing.T) {
		in, out, c := callingConventionFixture(false)
		c.LowestOffset = -512
		out[6] = asm.StoreMem(asm.RFP, -528, asm.R2, asm.DWord)
		expectPairKind(t, "prelude-bounds", in, out, c, SpillBounds)
	})
	t.Run("missing-postlude", func(t *testing.T) {
		in := asm.Instructions{asm.Return(), asm.FnMapLookupElem.Call()}
		out := asm.Instructions{in[0], asm.StoreMem(asm.RFP, -16, asm.R2, asm.DWord), in[1]}
		expectPairKind(t, "missing-postlude", in, out, fixtureCertificate{Original: []int{0, 2}}, PostludeMissing)
	})
	t.Run("path-budget", func(t *testing.T) {
		_, base, _ := callingConventionFixture(false)
		post := clone(base[8:10])
		for range 4100 {
			post = append(post, asm.Mov.Imm(asm.R3, 0))
		}
		post = append(post, base[10:15]...)
		post[1].Offset = int16(len(post) - 3)
		in, out, c := replacePostlude(post)
		expectPairKind(t, "path-budget", in, out, c, PathBudget)
	})
	t.Run("store-undefined", func(t *testing.T) {
		in, out, c := callingConventionFixture(true)
		out[10] = asm.StoreMem(asm.RFP, -48, asm.R0, asm.DWord)
		expectPairKind(t, "store-undefined", in, out, c, RegisterUndefined)
	})
	t.Run("postlude-call-unresolved", func(t *testing.T) {
		in, out, c := callingConventionFixture(false)
		out[13] = asm.Call.Label("missing")
		expectPairKind(t, "postlude-call-unresolved", in, out, c, SymbolUnresolved)
	})
	t.Run("u32-length", func(t *testing.T) {
		in, out, c := p6Pair(asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()})
		out = append(out[:7:7], out[8:]...)
		for i, j := range c.Original {
			if j > 7 {
				c.Original[i]--
			}
		}
		c.Hooks[0].Start--
		c.Hooks[0].End--
		expectPairKind(t, "u32-length", in, out, c, U32Length)
	})
}

// fixtureCertificate holds both fixture data sources. The public API receives
// the trusted audit separately from the proposed correspondence.
type fixtureCertificate struct {
	Original     []int
	Hooks        []Span
	LowestOffset int16
}

func checkFixture(in, out asm.Instructions, c fixtureCertificate) (Counts, error) {
	return Check(in, out, Certificate{Original: c.Original, Hooks: c.Hooks}, Premises{LowestOffset: c.LowestOffset})
}

func assertInputKind(t *testing.T, err error, want Kind) {
	t.Helper()
	var input *InputError
	if !errors.As(err, &input) || input.Kind != want {
		t.Fatalf("got %v, want input kind %s", err, want)
	}
}
