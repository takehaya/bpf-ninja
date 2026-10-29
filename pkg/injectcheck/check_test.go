package injectcheck

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
)

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
