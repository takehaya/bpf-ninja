package injectcheck

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
)

func TestIdentityAndCertificate(t *testing.T) {
	in := asm.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()}
	c := Certificate{Original: []int{0, 1}}
	if _, err := Check(in, in, c); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Certificate{{Original: []int{1, 0}}, {Original: []int{0, 2}}, {Original: []int{0, 1}, Hooks: []Span{{0, 2}}}} {
		if _, err := Check(in, in, bad); err == nil {
			t.Fatal("accepted forged certificate")
		}
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
			c := Certificate{Original: []int{1, 2, 3, 4, 5, 8, 9}, Hooks: []Span{{h, h + 2}}}
			if _, err := Check(in, out, c); err != nil {
				t.Fatal(err)
			}
			bad := append(asm.Instructions(nil), out...)
			if symbolic {
				bad[2] = bad[2].WithReference("hook")
			} else {
				bad[2].Constant--
			}
			if _, err := Check(in, bad, c); err == nil {
				t.Fatal("accepted wrong callback target")
			}
			bad = append(asm.Instructions(nil), out...)
			if symbolic {
				bad[3] = bad[3].WithReference("hook")
			} else {
				bad[3].Constant--
			}
			if _, err := Check(in, bad, c); err == nil {
				t.Fatal("accepted wrong call target")
			}
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
	c := Certificate{Original: []int{0, 1, 2, 9, 10, 11}, Hooks: []Span{{h, h + 3}}}
	if _, err := Check(in, out, c); err != nil {
		t.Fatal(err)
	}
	// Here R3 really is live across the inserted call, despite a valid R1
	// redefinition. A transform's claimed audit cannot override this check.
	in[4] = asm.Mov.Reg(asm.R0, asm.R3)
	out[10] = in[4]
	if _, err := Check(in, out, c); err == nil || !strings.Contains(err.Error(), "live") {
		t.Fatalf("live R3: %v", err)
	}
}

func TestHookAndStackSafety(t *testing.T) {
	for _, hook := range []asm.Instructions{
		{asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord), asm.Return()},
		{asm.FnGetPrandomU32.Call(), asm.Return()},
		{asm.StoreMem(asm.R1, 0, asm.R0, asm.DWord), asm.Return()},
	} {
		if err := checkHook(hook); err == nil {
			t.Fatal("accepted impure hook")
		}
	}
	for _, ins := range []asm.Instruction{asm.StoreMem(asm.RFP, -9, asm.R0, asm.Byte), asm.LoadMem(asm.R0, asm.RFP, -16, asm.DWord)} {
		in := asm.Instructions{ins, asm.Return()}
		if _, err := Check(in, in, Certificate{Original: []int{0, 1}, LowestOffset: -8}); err == nil {
			t.Fatal("accepted below-floor original access")
		}
	}
}

func TestHelperABI(t *testing.T) {
	if helperReads(int64(asm.FnTracePrintk)) != 0x3e {
		t.Fatal("variadic helper must read all arguments")
	}
	if helperReads(int64(asm.FnMapLookupElem)) != 0x6 {
		t.Fatal("lookup ABI")
	}
	if helperReads(999999) != 0x3e {
		t.Fatal("unknown helper must be conservative")
	}
}
