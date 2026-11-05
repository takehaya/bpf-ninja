package injectcheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
)

func TestPremisesJSONRoundTrip(t *testing.T) {
	p := Pair{
		Format:      FormatVersion,
		Original:    Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
		Transformed: Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
		Certificate: Certificate{Original: []int{0, 1}},
		Premises:    Premises{LowestOffset: -8},
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var got Pair
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("nil Targets did not survive round trip: %v", err)
	}
	if got.Premises.Targets == nil || len(got.Premises.Targets) != 0 {
		t.Fatalf("targets = %#v, want non-nil empty slice", got.Premises.Targets)
	}
}

func TestPerFrameFloorsApplyToOwningFunction(t *testing.T) {
	in := asm.Instructions{
		asm.StoreImm(asm.RFP, -8, 0, asm.Word), asm.Return(),
		asm.StoreImm(asm.RFP, -32, 0, asm.Word), asm.Return(),
	}
	cert := Certificate{Original: []int{0, 1, 2, 3}}
	premises := Premises{LowestOffset: -8, Frames: []FrameFloor{{Start: 0, LowestOffset: -8}, {Start: 2, LowestOffset: -32}}, Targets: []SiteTarget{}}
	if _, err := Check(in, in, cert, premises); err != nil {
		t.Fatal(err)
	}
	premises.Frames[1].Start = 3
	if _, err := Check(in, in, cert, premises); err == nil {
		t.Fatal("accepted a subprogram access under the entry frame floor")
	}
}

func TestPairV1ReportsVersionFirst(t *testing.T) {
	b := []byte(`{"format":1,"original":[],"transformed":[],"certificate":{"original":[]},"premises":{"lowest_offset":-8}}`)
	var p Pair
	err := json.Unmarshal(b, &p)
	var input *InputError
	if !errors.As(err, &input) || input.Kind != InputVersion {
		t.Fatalf("got %v, want %s", err, InputVersion)
	}
}

func TestPairV2Compatibility(t *testing.T) {
	p := Pair{
		Format:      2,
		Original:    Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
		Transformed: Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
		Certificate: Certificate{Original: []int{0, 1}},
		Premises:    Premises{LowestOffset: -8, Targets: []SiteTarget{}},
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Pair
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if verdict, err := decoded.Validate(); err != nil || !verdict.Accepted {
		t.Fatalf("format 2 identity rejected: %+v %v", verdict, err)
	}
	p.Premises.Targets = []SiteTarget{{Site: 0, When: TargetAny, Hook: 0, Ctx: &CtxSource{Reg: 6}}}
	if _, err := p.Validate(); err == nil {
		t.Fatal("format 2 accepted a format 3 context premise")
	}
	b, err = json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &decoded); err == nil {
		t.Fatal("format 2 JSON accepted a format 3 context premise")
	}
}

func TestIdentityAndCertificate(t *testing.T) {
	in := asm.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()}
	c := fixtureCertificate{Original: []int{0, 1}}
	if _, err := checkFixture(in, in, c); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		c    fixtureCertificate
		kind Kind
	}{
		{fixtureCertificate{Original: []int{1, 0}}, OriginalOrder},
		{fixtureCertificate{Original: []int{0, 2}}, OriginalOrder},
		{fixtureCertificate{Original: []int{0, 1}, Hooks: []Span{{0, 2}}}, HookOverlap},
	} {
		_, err := checkFixture(in, in, tc.c)
		assertKind(t, err, tc.kind)
	}
}

func TestRelocatedRawSlotEdges(t *testing.T) {
	// The callback LDIMM64 occupies two raw slots; a callback and a call both
	// refer across an entry prologue and an inserted hook function.
	for _, symbolic := range []bool{false, true} {
		t.Run(map[bool]string{false: "numeric", true: "symbolic"}[symbolic], func(t *testing.T) {
			cb := asm.LoadImm(asm.R2, 4, asm.DWord)
			cb.Src = asm.PseudoFunc // PC 1 -> PC 6
			call := asm.Call.Label("")
			call.Constant = 2 // PC 3 -> PC 6
			if symbolic {
				cb.Constant = -1
				cb = cb.WithReference("sub")
				call = asm.Call.Label("sub")
			}
			in := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), cb, call, asm.Mov.Imm(asm.R0, 2), asm.Return(), asm.Mov.Imm(asm.R0, 0).WithSymbol("sub"), asm.Return()}
			out := asm.Instructions{asm.StoreMem(asm.RFP, -8, asm.R1, asm.DWord)}
			out = append(out, in[:5]...)
			h := len(out)
			out = append(out, asm.Mov.Imm(asm.R0, 0).WithSymbol("hook"), asm.Return())
			out = append(out, in[5:]...)
			if !symbolic {
				out[2].Constant += 2
				out[3].Constant += 2
			}
			c := fixtureCertificate{Original: []int{1, 2, 3, 4, 5, 8, 9}, Hooks: []Span{{h, h + 2}}}
			if _, err := checkFixture(in, out, c); err != nil {
				t.Fatal(err)
			}
			bad := append(asm.Instructions(nil), out...)
			if symbolic {
				bad[2] = bad[2].WithReference("hook")
			} else {
				bad[2].Constant--
			}
			_, err := checkFixture(in, bad, c)
			assertKind(t, err, EdgeTarget)
			bad = append(asm.Instructions(nil), out...)
			if symbolic {
				bad[3] = bad[3].WithReference("hook")
			} else {
				bad[3].Constant--
			}
			_, err = checkFixture(in, bad, c)
			assertKind(t, err, EdgeTarget)
		})
	}
}

func TestU32LivenessAndRestore(t *testing.T) {
	in := asm.Instructions{asm.Mov.Reg(asm.R0, asm.R1), asm.Mov.Imm(asm.R3, 7), asm.LoadMem(asm.R2, asm.R0, 0, asm.Word), asm.Mov.Imm(asm.R1, 0), asm.Mov.Reg(asm.R0, asm.R2), asm.Return()}
	out := append(asm.Instructions(nil), in[:3]...)
	out = append(out, asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord), asm.StoreMem(asm.RFP, -16, asm.R2, asm.DWord), asm.Mov.Imm32(asm.R1, 2), asm.Call.Label("hook"), asm.LoadMem(asm.R0, asm.RFP, -8, asm.DWord), asm.LoadMem(asm.R2, asm.RFP, -16, asm.DWord))
	out = append(out, in[3:]...)
	h := len(out)
	out = append(out, asm.Mov.Reg32(asm.R0, asm.R1).WithSymbol("hook"), asm.Xor.Reg32(asm.R0, asm.R2), asm.Return())
	c := fixtureCertificate{Original: []int{0, 1, 2, 9, 10, 11}, Hooks: []Span{{h, h + 3}}}
	if _, err := checkFixture(in, out, c); err != nil {
		t.Fatal(err)
	}
	// A load leaves caller-saved registers readable in P (unlike P2-P5).
	// Mutate both streams so instruction comparison passes and liveness must
	// reject each register the P6 call fails to preserve.
	for _, r := range []asm.Register{asm.R1, asm.R3, asm.R4, asm.R5} {
		in[1] = asm.Mov.Imm(r, 7)
		out[1] = in[1]
		in[3] = asm.Mov.Reg(asm.R0, r)
		out[9] = in[3]
		_, err := checkFixture(in, out, c)
		assertKind(t, err, U32Live)
		want := fmt.Sprintf("u32 clobbers live registers mask %#x", 1<<r)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("live R%d: got %v, want %q", r, err, want)
		}
		t.Logf("live R%d rejected: %v", r, err)
	}
}

func TestHookAndStackSafety(t *testing.T) {
	for _, hook := range []asm.Instructions{
		{asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord), asm.Return()},
		{asm.FnGetPrandomU32.Call(), asm.Return()},
		{asm.StoreMem(asm.R1, 0, asm.R0, asm.DWord), asm.Return()},
	} {
		assertKind(t, checkHook(hook), HookShape)
	}
	for _, ins := range []asm.Instruction{asm.StoreMem(asm.RFP, -9, asm.R0, asm.Byte), asm.LoadMem(asm.R0, asm.RFP, -16, asm.DWord)} {
		in := asm.Instructions{ins, asm.Return()}
		_, err := checkFixture(in, in, fixtureCertificate{Original: []int{0, 1}, LowestOffset: -8})
		assertKind(t, err, StackAudit)
	}
}

func TestHelperABI(t *testing.T) {
	if helperReads(int64(asm.FnTracePrintk)) != 0x3e {
		t.Fatal("variadic helper must read all arguments")
	}
	if helperReads(int64(asm.FnMapLookupElem)) != 0x6 {
		t.Fatal("lookup ABI")
	}
	if helperReads(1<<32+int64(asm.FnKtimeGetNs)) != argRegs || helperReads(-1) != argRegs {
		t.Fatal("out-of-range helper must be conservative")
	}
	if helperReads(999999) != 0x3e {
		t.Fatal("unknown helper must be conservative")
	}
}

func TestTargetInputs(t *testing.T) {
	in, out, fixture := callingConventionFixture(false)
	cert := Certificate{Original: fixture.Original, Hooks: fixture.Hooks}
	hook := fixture.Hooks[0].Start
	valid := SiteTarget{Site: 5, When: TargetHit, Hook: hook}
	check := func(targets ...SiteTarget) error {
		_, err := Check(in, out, cert, Premises{LowestOffset: fixture.LowestOffset, Targets: targets})
		return err
	}
	if err := check(valid); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		targets []SiteTarget
		kind    Kind
	}{
		{"missing", nil, InputTargetMissing},
		{"site-range", []SiteTarget{{Site: len(in), When: TargetHit, Hook: hook}}, InputTarget},
		{"condition", []SiteTarget{{Site: 5, When: "success", Hook: hook}}, InputTarget},
		{"hook-start", []SiteTarget{{Site: 5, When: TargetHit, Hook: hook + 1}}, InputTarget},
		{"duplicate", []SiteTarget{valid, valid}, InputTarget},
		{"ctx-register", []SiteTarget{{Site: 5, When: TargetHit, Hook: hook, Ctx: &CtxSource{Reg: 5}}}, InputTarget},
		{"ctx-slot", []SiteTarget{{Site: 5, When: TargetHit, Hook: hook, Ctx: &CtxSource{Slot: -7}}}, InputTarget},
		{"ctx-entry", []SiteTarget{{Site: -1, When: TargetAny, Hook: hook, Ctx: &CtxSource{Reg: 6}}}, InputTarget},
		{"ctx-inconsistent", []SiteTarget{valid, {Site: 5, When: TargetMiss, Hook: hook, Ctx: &CtxSource{Reg: 6}}}, InputTarget},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertInputKind(t, check(tc.targets...), tc.kind)
		})
	}
	t.Run("unused-non-call-site", func(t *testing.T) {
		assertKind(t, check(valid, SiteTarget{Site: 4, When: TargetAny, Hook: hook}), CallTarget)
	})
	t.Run("unplanned-site", func(t *testing.T) {
		assertKind(t, check(SiteTarget{Site: 4, When: TargetAny, Hook: hook}), CallTarget)
	})

	bad := clone(out)
	bad[9].OpCode = asm.JNE.Imm(asm.R0, 0, "").OpCode
	_, err := Check(in, bad, cert, Premises{LowestOffset: fixture.LowestOffset, Targets: []SiteTarget{valid}})
	assertKind(t, err, CallTarget)
}
