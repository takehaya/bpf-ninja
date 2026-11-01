package program

import (
	"fmt"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/hook"
)

func TestStaticCtxReachesCalls(t *testing.T) {
	fn := func(name string, body ...asm.Instruction) asm.Instructions {
		body[0] = btf.WithFuncMetadata(body[0].WithSymbol(name), &btf.Func{Name: name, Linkage: btf.StaticFunc})
		return body
	}
	cat := func(parts ...asm.Instructions) asm.Instructions {
		var out asm.Instructions
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	key := asm.Instructions{asm.StoreImm(asm.RFP, -4, 0, asm.Word), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4)}
	lookup := asm.Instructions{asm.LoadImm(asm.R1, 0, asm.DWord), asm.FnMapLookupElem.Call()}
	spill := asm.Instructions{asm.StoreMem(asm.RFP, -64, asm.R1, asm.DWord)}
	reload := asm.Instructions{asm.LoadMem(asm.R1, asm.RFP, -64, asm.DWord)}
	call := asm.Instructions{asm.Call.Label("hook")}
	for _, tc := range []struct {
		name  string
		entry asm.Instructions
		ok    bool
	}{
		{"r1 untouched", cat(key, call), true},
		{"callee-saved copy", cat(asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}, key, lookup, asm.Instructions{asm.Mov.Reg(asm.R1, asm.R6)}, call), true},
		{"spill reloaded after helper", cat(spill, key, lookup, reload, asm.Instructions{asm.Mov.Reg(asm.R4, asm.R0)}, call), true},
		{"second site after a hook call", cat(spill, reload, key, asm.Instructions{asm.Mov.Reg(asm.R3, asm.R2)}, call, reload, call), true},
		{"dead context", cat(asm.Instructions{asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -4)}, call), false},
		{"spill clobbered by a writing callee", cat(spill, asm.Instructions{asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -64), asm.Call.Label("writer")}, reload, call), false},
		{"spill clobbered through a variable pointer", cat(spill, asm.Instructions{asm.LoadMem(asm.R2, asm.R1, 0, asm.Word), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Reg(asm.R3, asm.R2), asm.StoreImm(asm.R3, 0, 0, asm.Word)}, reload, call), false},
		{"one path without context", cat(asm.Instructions{asm.LoadMem(asm.R2, asm.R1, 0, asm.Word), asm.JEq.Imm(asm.R2, 0, "site"), asm.Mov.Imm(asm.R1, 0), asm.Call.Label("hook").WithSymbol("site")}), false},
		{"called from another function", asm.Instructions{asm.Call.Label("mid")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			insns := cat(fn("entry", append(tc.entry, asm.Mov.Imm(asm.R0, 0), asm.Return())...),
				fn("writer", asm.StoreImm(asm.R1, 0, 0, asm.Word), asm.Mov.Imm(asm.R0, 0), asm.Return()),
				fn("hook", asm.Mov.Imm(asm.R0, 0), asm.Return()))
			if tc.entry[0].Reference() == "mid" {
				insns = append(insns, fn("mid", asm.Call.Label("hook"), asm.Mov.Imm(asm.R0, 0), asm.Return())...)
			}
			if got := ctxReachesCalls(insns, "hook"); got != tc.ok {
				t.Fatalf("ctxReachesCalls=%v, want %v\n%v", got, tc.ok, insns)
			}
		})
	}
}

// The static tc prologue reads sk_buff only through bpf_probe_read_kernel,
// into stack -160..-145, and ends like the direct prologue.
func TestStaticTCPrologueShape(t *testing.T) {
	data, length, dataLen, err := hook.SkBuffPacketOffsets()
	if err != nil {
		t.Skipf("kernel BTF not available: %v", err)
	}
	tc, _ := hook.ByName(hook.KindTC)
	insns, err := staticTCHook(tc, "f").PacketPrologue()
	if err != nil {
		t.Fatal(err)
	}
	direct, err := tc.PacketPrologue()
	if err != nil {
		t.Fatal(err)
	}
	var reads []string
	for i, in := range insns {
		if in.OpCode.Class() == asm.LdXClass && in.Src == asm.R6 {
			t.Fatalf("direct sk_buff load: %v", in)
		}
		if in.IsBuiltinCall() {
			slot, size := insns[i-2].Constant, insns[i-1].Constant
			if slot < -160 || slot+size > -144 || insns[i+1].OpCode.JumpOp() != asm.JNE || insns[i+1].Reference() != "exit" {
				t.Fatalf("read %d: slot %d size %d, then %v", len(reads), slot, size, insns[i+1])
			}
			reads = append(reads, fmt.Sprintf("%d/%d", insns[i-4].Constant, size))
		}
	}
	if want := fmt.Sprintf("[%d/8 %d/4 %d/4]", data, length, dataLen); fmt.Sprint(reads) != want {
		t.Fatalf("reads %v, want %s", reads, want)
	}
	if got, want := fmt.Sprint(insns[len(insns)-3:]), fmt.Sprint(direct[len(direct)-3:]); got != want {
		t.Fatalf("tail %s, want %s", got, want)
	}
}
