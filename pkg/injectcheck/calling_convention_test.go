package injectcheck

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
)

// The verifier prunes the R6 != 0 path. Syntactic liveness still includes its
// undefined read after the helper, as in value-dependent corpus branches.
func callingConventionFixture(tail bool) (asm.Instructions, asm.Instructions, fixtureCertificate) {
	in := asm.Instructions{
		asm.Mov.Imm(asm.R6, 0),
		asm.StoreMem(asm.RFP, -8, asm.R6, asm.DWord),
		asm.LoadMapPtr(asm.R1, 0).WithReference("m"),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R6, 0, "done"), asm.Mov.Reg(asm.R0, asm.R3),
		asm.Mov.Imm(asm.R0, 2).WithSymbol("done"), asm.Return(),
	}
	if tail {
		in[2] = asm.LoadMapPtr(asm.R2, 0).WithReference("m")
		in[3] = asm.Mov.Imm(asm.R3, 0)
		in[4] = asm.Mov.Reg(asm.R1, asm.R1)
		in[5] = asm.FnTailCall.Call()
		in[7] = asm.Mov.Reg(asm.R0, asm.R0)
	}
	out := asm.Instructions{asm.StoreMem(asm.RFP, -16, asm.R1, asm.DWord)}
	c := fixtureCertificate{LowestOffset: -8}
	for i, ins := range in {
		if i == 5 {
			r := asm.R2
			if tail {
				r = asm.R3
			}
			out = append(out, asm.StoreMem(asm.RFP, -24, r, asm.DWord))
		}
		c.Original = append(c.Original, len(out))
		out = append(out, ins)
		if i == 5 {
			if !tail {
				j := asm.JEq.Imm(asm.R0, 0, "")
				j.Offset = 4
				out = append(out, asm.StoreMem(asm.RFP, -32, asm.R0, asm.DWord), j)
			}
			out = append(out, asm.LoadMem(asm.R1, asm.RFP, -16, asm.DWord),
				asm.LoadMem(asm.R2, asm.RFP, -24, asm.DWord), asm.Mov.Imm(asm.R3, 0), asm.Call.Label("hook"))
			if !tail {
				out = append(out, asm.LoadMem(asm.R0, asm.RFP, -32, asm.DWord))
			}
		}
	}
	h := len(out)
	out = append(out, asm.Mov.Imm(asm.R0, 0).WithSymbol("hook"), asm.Return())
	c.Hooks = []Span{{h, len(out)}}
	return in, out, c
}

func TestHelperCallingConvention(t *testing.T) {
	for _, tail := range []bool{false, true} {
		name := "lookup"
		mask := uint16(1 << asm.R3)
		if tail {
			name, mask = "tail", 1
		}
		t.Run(name, func(t *testing.T) {
			in, out, c := callingConventionFixture(tail)
			pcs, idx := slots(in)
			live, err := liveness(in, pcs, idx)
			if err != nil || live[6]&mask == 0 {
				t.Fatalf("fixture must be syntactically live: live=%v err=%v", live, err)
			}
			if _, err := checkFixture(in, out, c); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMissingContextSpillWithU32HookFirst(t *testing.T) {
	in, out, c := callingConventionFixture(false)
	// Remove the entry spill, then put an unrelated u32 hook first in Hooks.
	out = out[1:]
	for i := range c.Original {
		c.Original[i]--
	}
	c.Hooks[0].Start--
	c.Hooks[0].End--
	h := len(out)
	out = append(out, asm.Mov.Reg32(asm.R0, asm.R1), asm.Xor.Reg32(asm.R0, asm.R2), asm.Return())
	c.Hooks = append([]Span{{h, len(out)}}, c.Hooks...)
	_, err := checkFixture(in, out, c)
	assertKind(t, err, SpillUninitialized)
	if err == nil || !strings.Contains(err.Error(), "load from uninitialized/nonmatching spill -16") {
		t.Fatalf("missing ctx spill: %v", err)
	}
	t.Logf("rejected: %v", err)
}
