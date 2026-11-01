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
	I := func(x ...asm.Instruction) asm.Instructions { return x }
	st64 := func(dst asm.Register, off int16) asm.Instruction { // asm.StoreImm refuses DWord
		return asm.Instruction{OpCode: asm.StoreImmOp(asm.DWord), Dst: dst, Offset: off}
	}
	atomic := func(mode asm.Mode, dst, src asm.Register, off int16, op int64) asm.Instruction {
		return asm.Instruction{OpCode: asm.OpCode(asm.StXClass).SetMode(mode).SetSize(asm.DWord), Dst: dst, Src: src, Offset: off, Constant: op}
	}
	const probeAtomic, xchg, cmpxchg = asm.Mode(0xe0), 0xe1, 0xf1
	key := I(asm.StoreImm(asm.RFP, -4, 0, asm.Word), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4))
	lookup := I(asm.LoadImm(asm.R1, 0, asm.DWord), asm.FnMapLookupElem.Call())
	spill := I(asm.StoreMem(asm.RFP, -64, asm.R1, asm.DWord))
	reload := I(asm.LoadMem(asm.R1, asm.RFP, -64, asm.DWord))
	call := I(asm.Call.Label("hook"))
	above := I(asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -56))
	fnptr := func(ref string) asm.Instruction {
		return asm.Instruction{OpCode: asm.LoadImmOp(asm.DWord), Dst: asm.R2, Src: asm.PseudoFunc}.WithReference(ref)
	}
	for _, tc := range []struct {
		name  string
		entry asm.Instructions
		ok    bool
	}{
		{"r1 untouched", cat(key, call), true},
		{"callee-saved copy", cat(I(asm.Mov.Reg(asm.R6, asm.R1)), key, lookup, I(asm.Mov.Reg(asm.R1, asm.R6)), call), true},
		{"spill reloaded after helper", cat(spill, key, lookup, reload, I(asm.Mov.Reg(asm.R4, asm.R0)), call), true},
		{"second site after a hook call", cat(spill, reload, key, I(asm.Mov.Reg(asm.R3, asm.R2)), call, reload, call), true},
		{"two counters through one map value", cat(spill, key, lookup, I(asm.JEq.Imm(asm.R0, 0, "out"), asm.Mov.Imm(asm.R2, 1),
			atomic(asm.AtomicMode, asm.R0, asm.R2, 0, int64(asm.Add)), atomic(asm.AtomicMode, asm.R0, asm.R2, 8, int64(asm.Add)),
			asm.LoadMem(asm.R1, asm.RFP, -64, asm.DWord).WithSymbol("out")), call), true},
		{"dead context", cat(I(asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -4)), call), false},
		{"helper clobbers r1", cat(I(asm.FnKtimeGetNs.Call()), call), false},
		{"ld_imm64 into r1", cat(I(asm.LoadImm(asm.R1, 0, asm.DWord)), call), false},
		{"mov32 of the context", cat(I(asm.Mov.Reg32(asm.R1, asm.R1)), call), false},
		{"partial overwrite of the spill", cat(spill, I(asm.StoreImm(asm.RFP, -60, 0, asm.Word)), reload, call), false},
		{"spill clobbered by a writing callee", cat(spill, I(asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -64), asm.Call.Label("writer")), reload, call), false},
		{"static callee stores below its pointer", cat(spill, above, I(asm.Call.Label("below")), reload, call), false},
		{"static callee's helper writes below its pointer", cat(spill, above, I(asm.Call.Label("helperbelow")), reload, call), false},
		{"store through a writing callee's r0 after a respill", cat(I(asm.Mov.Reg(asm.R6, asm.R1)), above, I(asm.Call.Label("below"), asm.StoreMem(asm.RFP, -64, asm.R6, asm.DWord), st64(asm.R0, 0)), reload, call), false},
		{"spill clobbered through a variable pointer", cat(spill, I(asm.LoadMem(asm.R2, asm.R1, 0, asm.Word), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Reg(asm.R3, asm.R2), asm.StoreImm(asm.R3, 0, 0, asm.Word)), reload, call), false},
		{"scalar plus frame pointer", cat(spill, I(asm.LoadMem(asm.R2, asm.R1, 0, asm.Word), asm.Mov.Reg(asm.R3, asm.R2), asm.Add.Reg(asm.R3, asm.RFP), st64(asm.R3, 0)), reload, call), false},
		{"variable frame pointer passed to a helper", cat(spill, I(asm.LoadMem(asm.R2, asm.R1, 0, asm.Word), asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Reg(asm.R1, asm.R2),
			asm.Mov.Imm(asm.R2, 8), asm.Mov.Imm(asm.R3, 0), asm.FnProbeReadKernel.Call()), reload, call), false},
		{"frame pointer loaded through a joined base", cat(spill, I(
			asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -72), asm.StoreMem(asm.RFP, -8, asm.R2, asm.DWord),
			asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -64), asm.StoreMem(asm.RFP, -16, asm.R2, asm.DWord),
			asm.LoadMem(asm.R4, asm.R1, 0, asm.Word),
			asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -8), asm.JEq.Imm(asm.R4, 0, "joined"),
			asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -16),
			asm.LoadMem(asm.R5, asm.R3, 0, asm.DWord).WithSymbol("joined"), st64(asm.R5, 0)), reload, call), false},
		{"callback writes below its ctx", cat(spill, I(asm.Mov.Imm(asm.R1, 4), fnptr("cb"), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -32), asm.Mov.Imm(asm.R4, 0), asm.FnLoop.Call()), reload, call), false},
		{"dynptr slice store", cat(I(asm.Mov.Reg(asm.R6, asm.R1), asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -64), asm.Mov.Imm(asm.R2, 8), asm.Mov.Imm(asm.R3, 0),
			asm.Mov.Reg(asm.R4, asm.RFP), asm.Add.Imm(asm.R4, -16), asm.FnDynptrFromMem.Call(), asm.StoreMem(asm.RFP, -64, asm.R6, asm.DWord),
			asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -16), asm.Mov.Imm(asm.R2, 0), asm.Mov.Imm(asm.R3, 8), asm.FnDynptrData.Call(),
			asm.JEq.Imm(asm.R0, 0, "out"), st64(asm.R0, 0), asm.LoadMem(asm.R1, asm.RFP, -64, asm.DWord).WithSymbol("out")), call), false},
		{"xchg returns the old value", cat(I(asm.Mov.Reg(asm.R2, asm.R1), atomic(asm.AtomicMode, asm.RFP, asm.R2, -64, int64(asm.Xchg)), asm.Mov.Reg(asm.R1, asm.R2)), call), false},
		{"probe-atomic xchg overwrites r1", cat(I(asm.LoadImm(asm.R2, 0, asm.DWord), atomic(probeAtomic, asm.R2, asm.R1, 0, xchg)), call), false},
		{"probe-atomic cmpxchg overwrites r0", cat(I(asm.Mov.Reg(asm.R0, asm.R1), asm.LoadImm(asm.R2, 0, asm.DWord), asm.Mov.Imm(asm.R3, 0),
			atomic(probeAtomic, asm.R2, asm.R3, 0, cmpxchg), asm.Mov.Reg(asm.R1, asm.R0)), call), false},
		{"gotox hides a call", I(asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -8), asm.LoadImm(asm.R2, 0, asm.DWord),
			asm.Instruction{OpCode: asm.Ja.Op(asm.RegSource), Dst: asm.R2}, asm.Mov.Imm(asm.R0, 0), asm.Return(), asm.Call.Label("hook")), false},
		{"target as a function pointer", I(fnptr("hook"), asm.Call.Label("hook")), false},
		{"one path without context", I(asm.LoadMem(asm.R2, asm.R1, 0, asm.Word), asm.JEq.Imm(asm.R2, 0, "site"), asm.Mov.Imm(asm.R1, 0), asm.Call.Label("hook").WithSymbol("site")), false},
		{"called from another function", I(asm.Call.Label("mid")), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			insns := cat(fn("entry", append(tc.entry, asm.Mov.Imm(asm.R0, 0), asm.Return())...),
				fn("writer", asm.StoreImm(asm.R1, 0, 0, asm.Word), asm.Mov.Imm(asm.R0, 0), asm.Return()),
				fn("below", st64(asm.R1, -8), asm.Mov.Imm(asm.R0, 0), asm.Return()),
				fn("helperbelow", asm.Add.Imm(asm.R1, -8), asm.Mov.Imm(asm.R2, 8), asm.Mov.Imm(asm.R3, 0), asm.FnProbeReadKernel.Call(), asm.Mov.Imm(asm.R0, 0), asm.Return()),
				fn("cb", st64(asm.R2, -32), asm.Mov.Imm(asm.R0, 0), asm.Return()),
				fn("hook", asm.Mov.Imm(asm.R0, 0), asm.Return()))
			if tc.entry[0].Reference() == "mid" {
				insns = append(insns, fn("mid", asm.Call.Label("hook"), asm.Mov.Imm(asm.R0, 0), asm.Return())...)
			}
			if got := ctxReachesCalls(insns, "hook"); got != tc.ok {
				t.Fatalf("ctxReachesCalls=%v, want %v\n%v", got, tc.ok, insns)
			}
		})
	}
	// Translated code has no references: a JIT-dumped call keeps its target in
	// Offset, a function pointer and gotol in Constant.
	pcall := func(off int16, imm int64) asm.Instruction {
		return asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call), Src: asm.PseudoCall, Offset: off, Constant: imm}
	}
	ret := func() []asm.Instruction { return []asm.Instruction{asm.Mov.Imm(asm.R0, 0), asm.Return()} }
	jit := func(first asm.Instruction) asm.Instructions { // entry 0-3, other 4-5, hook 6-7
		return cat(fn("entry", append([]asm.Instruction{first, pcall(4, 2)}, ret()...)...), fn("other", ret()...), fn("hook", ret()...))
	}
	big := make([]asm.Instruction, 33000)
	for i := range big {
		big[i] = asm.Mov.Imm(asm.R0, 0)
	}
	for _, tc := range []struct {
		name  string
		insns asm.Instructions
		ok    bool
	}{
		{"jit dump, ctx", jit(asm.Mov.Reg(asm.R6, asm.R1)), true},
		{"jit dump, no ctx", jit(asm.Mov.Imm(asm.R1, 0)), false},
		{"function pointer", cat(fn("entry", asm.Instruction{OpCode: asm.LoadImmOp(asm.DWord), Dst: asm.R2, Src: asm.PseudoFunc, Constant: 3}, asm.Mov.Imm(asm.R0, 0), asm.Return()),
			fn("hook", ret()...)), false},
		{"gotol skips the restore", cat(fn("entry", asm.Mov.Reg(asm.R6, asm.R1), asm.LoadMem(asm.R2, asm.R1, 0, asm.Word),
			asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.JEq), Dst: asm.R2, Offset: 2}, // to the restore
			asm.Mov.Imm(asm.R1, 0), asm.Instruction{OpCode: asm.OpCode(asm.Jump32Class).SetJumpOp(asm.Ja), Constant: 1}, // to the call
			asm.Mov.Reg(asm.R1, asm.R6), pcall(2, 1), asm.Mov.Imm(asm.R0, 0), asm.Return()), fn("hook", ret()...)), false},
		{"duplicate name", cat(fn("entry", asm.Call.Label("hook2"), asm.Call.Label("hook"), asm.Mov.Imm(asm.R0, 0), asm.Return()),
			fn("hook", ret()...), I(btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 0).WithSymbol("hook2"), &btf.Func{Name: "hook", Linkage: btf.StaticFunc}), asm.Return())), false},
		{"over 32K instructions", cat(jit(asm.Mov.Reg(asm.R6, asm.R1)), fn("filler", append(big, asm.Return())...)), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ctxReachesCalls(tc.insns, "hook"); got != tc.ok {
				t.Fatalf("ctxReachesCalls=%v, want %v", got, tc.ok)
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
