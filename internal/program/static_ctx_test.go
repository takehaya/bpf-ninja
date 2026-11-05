package program

import (
	"fmt"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/ctxflow"
	"github.com/takehaya/bpf-ninja/internal/hook"
)

func ctxReachesCalls(insns asm.Instructions, name string) bool {
	return ctxflow.CallsRefusal(insns, name) == ""
}

func TestStaticCtxReachesCalls(t *testing.T) {
	ctx := &btf.Struct{Name: "xdp_md", Size: 24}
	i32 := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	fn := func(name string, body ...asm.Instruction) asm.Instructions {
		linkage := btf.StaticFunc
		proto := &btf.FuncProto{Return: i32}
		if name == "entry" || name == "hook" {
			proto.Params = []btf.FuncParam{{Name: "ctx", Type: &btf.Pointer{Target: ctx}}}
		}
		if name == "entry" {
			linkage = btf.GlobalFunc
		}
		body[0] = btf.WithFuncMetadata(body[0].WithSymbol(name), &btf.Func{Name: name, Linkage: linkage, Type: proto})
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
	const probeAtomic, xchg, cmpxchg, loadAcquire = asm.Mode(0xe0), 0xe1, 0xf1, 0x100
	key := I(asm.StoreImm(asm.RFP, -4, 0, asm.Word), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4))
	lookup := I(asm.LoadImm(asm.R1, 0, asm.DWord), asm.FnMapLookupElem.Call())
	spill := I(asm.StoreMem(asm.RFP, -64, asm.R1, asm.DWord))
	reload := I(asm.LoadMem(asm.R1, asm.RFP, -64, asm.DWord))
	call := I(asm.Call.Label("hook"))
	ptrAt72 := I(asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -64), asm.StoreMem(asm.RFP, -72, asm.R3, asm.DWord))
	above := I(asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -56))
	fnptrTo := func(dst asm.Register, ref string) asm.Instruction {
		return asm.Instruction{OpCode: asm.LoadImmOp(asm.DWord), Dst: dst, Src: asm.PseudoFunc}.WithReference(ref)
	}
	fnptr := func(ref string) asm.Instruction { return fnptrTo(asm.R2, ref) }
	// kfunc(1) stands for bpf_dynptr_from_skb and kfunc(2) for
	// bpf_dynptr_slice_rdwr; the model treats a kfunc like a helper.
	kfunc := func(id int64) asm.Instruction {
		return asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call), Src: asm.PseudoKfuncCall, Constant: id}
	}
	// map_lookup_elem with a 4-byte key at fp-24: the helper write floor becomes
	// -24, so the floor clobber reaches a spill at fp-24..fp-8 above the fp-64 ctx.
	lookup24 := I(asm.StoreImm(asm.RFP, -24, 0, asm.Word), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -24),
		asm.LoadImm(asm.R1, 0, asm.DWord), asm.FnMapLookupElem.Call())
	// bpf_loop(4, R2, fp-32, 0) keeping the R2 the caller loaded; cb writes *(ctx-32), the fp-64 spill.
	loop := I(asm.Mov.Imm(asm.R1, 4), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -32), asm.Mov.Imm(asm.R4, 0), asm.FnLoop.Call())
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
		// Shape from Calico's calico_tc_skb_ipv4_frag, which loads
		// every callback after the hook. The timer registration before the hook
		// is added: a callback helper that gets no frame pointer leaves the spill.
		{"timer callback without a frame pointer before the hook", cat(spill, key, lookup, I(asm.JEq.Imm(asm.R0, 0, "out"), asm.Mov.Reg(asm.R1, asm.R0), fnptr("cb"), asm.FnTimerSetCallback.Call(),
			asm.LoadMem(asm.R1, asm.RFP, -64, asm.DWord).WithSymbol("out")), call, I(asm.Mov.Imm(asm.R1, 4), fnptr("cb"), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -32), asm.Mov.Imm(asm.R4, 0), asm.FnLoop.Call())), true},
		{"callback through a spilled function pointer", cat(spill, I(fnptr("cb"), asm.StoreMem(asm.RFP, -80, asm.R2, asm.DWord), asm.Mov.Imm(asm.R1, 4), asm.LoadMem(asm.R2, asm.RFP, -80, asm.DWord),
			asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -32), asm.Mov.Imm(asm.R4, 0), asm.FnLoop.Call()), reload, call), false},
		{"callback a static callee returns", cat(spill, I(asm.Call.Label("getcb"), asm.Mov.Reg(asm.R2, asm.R0), asm.Mov.Imm(asm.R1, 4),
			asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -32), asm.Mov.Imm(asm.R4, 0), asm.FnLoop.Call()), reload, call), false},
		{"callback a static callee after the hook returns", cat(spill, I(asm.Call.Label("getcblate"), asm.Mov.Reg(asm.R2, asm.R0)), loop, reload, call), false},
		{"callback on one path of a join", cat(spill, I(asm.LoadMem(asm.R4, asm.R1, 0, asm.Word), asm.Mov.Imm(asm.R2, 0), asm.JEq.Imm(asm.R4, 0, "join"), fnptr("cb"),
			asm.JEq.Imm(asm.R4, 0, "skip").WithSymbol("join"), asm.Mov.Imm(asm.R1, 4), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -32), asm.Mov.Imm(asm.R4, 0), asm.FnLoop.Call(),
			asm.LoadMem(asm.R1, asm.RFP, -64, asm.DWord).WithSymbol("skip")), call), false},
		// A helper given a stack pointer may write any slot above the floor but
		// leaves the slots it misses in place, so the floor clobber joins them
		// with a scalar instead of resetting them.
		{"function pointer spilled above a lookup key reaches a for_each_map_elem callback", cat(spill, I(fnptrTo(asm.R2, "cb4"), asm.StoreMem(asm.RFP, -16, asm.R2, asm.DWord)),
			lookup24, I(asm.LoadMem(asm.R2, asm.RFP, -16, asm.DWord), asm.LoadImm(asm.R1, 0, asm.DWord), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -32), asm.Mov.Imm(asm.R4, 0), asm.FnForEachMapElem.Call()), reload, call), false},
		{"frame pointer spilled above a lookup key is written through", cat(spill, I(asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -64), asm.StoreMem(asm.RFP, -16, asm.R3, asm.DWord), asm.Mov.Imm(asm.R3, 0)),
			lookup24, I(asm.LoadMem(asm.R3, asm.RFP, -16, asm.DWord), st64(asm.R3, 0)), reload, call), false},
		{"callback through a function pointer plus zero", cat(spill, I(fnptr("cb"), asm.Add.Imm(asm.R2, 0)), loop, reload, call), false},
		{"callback through a scalar plus a function pointer", cat(spill, I(fnptrTo(asm.R6, "cb"), asm.Mov.Imm(asm.R2, 0), asm.Add.Reg(asm.R2, asm.R6)), loop, reload, call), false},
		{"find_vma with the callback in r3", cat(spill, I(asm.Mov.Imm(asm.R1, 0), asm.Mov.Imm(asm.R2, 0), fnptrTo(asm.R3, "cb"),
			asm.Mov.Reg(asm.R4, asm.RFP), asm.Add.Imm(asm.R4, -32), asm.Mov.Imm(asm.R5, 0), asm.FnFindVma.Call()), reload, call), false},
		{"a frame pointer and a function pointer joined, then written through", cat(spill, I(asm.LoadMem(asm.R4, asm.R1, 0, asm.Word),
			asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -64), asm.JEq.Imm(asm.R4, 0, "join"), fnptrTo(asm.R1, "cb"),
			asm.Mov.Imm(asm.R2, 24).WithSymbol("join"), asm.Mov.Imm(asm.R3, 0), asm.FnProbeReadKernel.Call()), reload, call), false},
		{"static callee writes through its fifth argument", cat(spill, I(asm.Mov.Reg(asm.R5, asm.RFP), asm.Add.Imm(asm.R5, -56),
			asm.Mov.Imm(asm.R1, 0), asm.Mov.Imm(asm.R2, 0), asm.Mov.Imm(asm.R3, 0), asm.Mov.Imm(asm.R4, 0), asm.Call.Label("five")), reload, call), false},
		{"helper write buffer overlaps the spill", cat(spill, I(asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -72),
			asm.Mov.Imm(asm.R2, 24), asm.Mov.Imm(asm.R3, 0), asm.FnProbeReadKernel.Call()), reload, call), false},
		{"callback spills a function pointer above the floor, second loop reloads it", cat(I(asm.Mov.Reg(asm.R6, asm.R1), fnptr("putcb16")), loop,
			I(asm.StoreMem(asm.RFP, -200, asm.R6, asm.DWord), asm.LoadMem(asm.R2, asm.RFP, -16, asm.DWord)), loop, I(asm.LoadMem(asm.R1, asm.RFP, -200, asm.DWord)), call), false},
		// A JIT that inlines bpf_get_smp_processor_id keeps R1-R5, so a callback
		// the verifier still holds in R2 survives the call.
		{"callback in r2 across a fastcall helper", cat(spill, I(fnptr("cb"), asm.FnGetSmpProcessorId.Call()), loop, reload, call), false},
		// The keep is a join, not a restore: on a raw (un-inlined) dump the call
		// really clobbers R1, so the context in R1 must not be assumed to survive.
		{"context kept in r1 across a fastcall helper", cat(I(asm.FnGetSmpProcessorId.Call()), call), false},
		// A store to R11 is a 7.2+ stack argument (BPF_REG_PARAMS); the callee can
		// write it into this frame, so it is refused in the first scan. Here f6
		// writes through the &fp-32 it is passed, reaching the fp-64 ctx spill.
		{"stack argument stored through r11", cat(I(asm.Mov.Reg(asm.R6, asm.R1), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -32),
			asm.StoreMem(asm.Register(11), -8, asm.R3, asm.DWord), asm.StoreMem(asm.RFP, -64, asm.R6, asm.DWord),
			asm.Mov.Imm(asm.R1, 0), asm.Mov.Imm(asm.R2, 0), asm.Mov.Imm(asm.R3, 0), asm.Mov.Imm(asm.R4, 0), asm.Mov.Imm(asm.R5, 0), asm.Call.Label("f6")), reload, call), false},
		// The floor exists for a dynptr slice that aliases a stack buffer: an
		// untracked write through it can retarget a spilled frame pointer. R1-R5
		// must hold no frame pointer below the floor at the kfunc calls, or the
		// case is refused for another reason.
		{"dynptr slice alias retargets a spilled frame pointer", cat(spill, I(asm.Mov.Reg(asm.R6, asm.R1),
			asm.Mov.Imm(asm.R2, 0), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -16), kfunc(1),
			st64(asm.RFP, -32),
			asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -16), asm.Mov.Imm(asm.R2, 0), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -32), asm.Mov.Imm(asm.R4, 8), kfunc(2),
			asm.JEq.Imm(asm.R0, 0, "out"),
			asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -40), asm.StoreMem(asm.RFP, -32, asm.R3, asm.DWord),
			asm.Mov.Reg(asm.R4, asm.RFP), asm.Add.Imm(asm.R4, -64), asm.StoreMem(asm.R0, 0, asm.R4, asm.DWord),
			asm.LoadMem(asm.R5, asm.RFP, -32, asm.DWord), st64(asm.R5, 0),
			asm.LoadMem(asm.R1, asm.RFP, -64, asm.DWord).WithSymbol("out")), call), false},
		// A static callee returns the function pointer an argument held, so its
		// R0 may be a callback even with no function pointer loaded outside the entry.
		{"callback a static callee gets in r1 and returns", cat(spill, I(fnptrTo(asm.R1, "cb"), asm.Call.Label("id"), asm.Mov.Reg(asm.R2, asm.R0)), loop, reload, call), false},
		{"callback a static callee gets in r5 and returns", cat(spill, I(fnptrTo(asm.R5, "cb"), asm.Mov.Imm(asm.R1, 0), asm.Mov.Imm(asm.R2, 0), asm.Mov.Imm(asm.R3, 0), asm.Mov.Imm(asm.R4, 0),
			asm.Call.Label("id5"), asm.Mov.Reg(asm.R2, asm.R0)), loop, reload, call), false},
		// An exposed callee's R0 may alias the frame, which outranks a function pointer.
		{"exposed callee with a function-pointer argument, store through r0", cat(I(asm.Mov.Reg(asm.R6, asm.R1)), above, I(fnptr("cb"), asm.Call.Label("below"),
			asm.StoreMem(asm.RFP, -64, asm.R6, asm.DWord), st64(asm.R0, 0)), reload, call), false},
		// The call-site clobber must widen a spilled frame pointer, not only a
		// spilled context. r4 = 0 before the helper is load-bearing: with
		// r4 = fp-200 the floor drops to -200 and the case is refused for another reason.
		{"helper writes a frame address through a slice over a spilled frame pointer", cat(I(asm.StoreMem(asm.RFP, -200, asm.R1, asm.DWord),
			asm.Mov.Imm(asm.R2, 0), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -16), kfunc(1), st64(asm.RFP, -64),
			asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -16), asm.Mov.Imm(asm.R2, 0), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -64), asm.Mov.Imm(asm.R4, 8), kfunc(2),
			asm.JEq.Imm(asm.R0, 0, "out"), asm.Mov.Reg(asm.R7, asm.R0),
			asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -120), asm.StoreMem(asm.RFP, -64, asm.R3, asm.DWord),
			asm.Mov.Reg(asm.R4, asm.RFP), asm.Add.Imm(asm.R4, -200), asm.StoreMem(asm.RFP, -8, asm.R4, asm.DWord), asm.Mov.Imm(asm.R4, 0),
			asm.Mov.Reg(asm.R1, asm.R7), asm.Mov.Imm(asm.R2, 8), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -8), asm.FnProbeReadKernel.Call(),
			asm.LoadMem(asm.R3, asm.RFP, -64, asm.DWord), st64(asm.R3, 0),
			asm.LoadMem(asm.R1, asm.RFP, -200, asm.DWord).WithSymbol("out")), call), false},
		// The clobber covers a slot the floor only partly overlaps.
		{"helper buffer starts inside the spill", cat(spill, I(asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -60),
			asm.Mov.Imm(asm.R2, 4), asm.Mov.Imm(asm.R3, 0), asm.FnProbeReadKernel.Call()), reload, call), false},
		// The fastcall join covers R1 through R5, frame pointers included.
		{"fastcall helper keeps a frame pointer in r1", cat(spill, I(asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -56), asm.FnGetSmpProcessorId.Call(), st64(asm.R1, -8)), reload, call), false},
		{"fastcall helper keeps a frame pointer in r5", cat(spill, I(asm.Mov.Reg(asm.R5, asm.RFP), asm.Add.Imm(asm.R5, -56), asm.FnGetSmpProcessorId.Call(), st64(asm.R5, -8)), reload, call), false},
		// Accepted: a callback loaded only in the entry does not make a static
		// callee's R0 a function pointer, and an ordinary helper keeps no argument.
		{"store through a static callee's returned pointer after a timer callback in the entry", cat(spill, key, lookup, I(asm.JEq.Imm(asm.R0, 0, "out"), asm.Mov.Reg(asm.R1, asm.R0), fnptr("cb"), asm.FnTimerSetCallback.Call(),
			asm.Call.Label("getval"), asm.JEq.Imm(asm.R0, 0, "out"), asm.Add.Imm(asm.R0, 8), asm.StoreImm(asm.R0, 0, 1, asm.Word),
			asm.LoadMem(asm.R1, asm.RFP, -64, asm.DWord).WithSymbol("out")), call), true},
		// Accepted: the clobber joins a map value with ctxOther, which keeps it a non-frame pointer.
		{"map value spilled above a later key, reloaded and written", cat(spill, key, lookup, I(asm.JEq.Imm(asm.R0, 0, "out"), asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord)),
			lookup24, I(asm.LoadMem(asm.R3, asm.RFP, -8, asm.DWord), asm.StoreImm(asm.R3, 0, 1, asm.Word),
				asm.LoadMem(asm.R1, asm.RFP, -64, asm.DWord).WithSymbol("out")), call), true},
		{"xchg fetches a frame pointer from the frame", cat(spill, ptrAt72, I(asm.Mov.Imm(asm.R2, 0), atomic(asm.AtomicMode, asm.RFP, asm.R2, -72, int64(asm.Xchg)), st64(asm.R2, 0)), reload, call), false},
		{"load-acquire with a frame pointer in src", cat(spill, ptrAt72, I(asm.Mov.Reg(asm.R4, asm.RFP), asm.Add.Imm(asm.R4, -72), asm.Mov.Imm(asm.R2, 0),
			atomic(asm.AtomicMode, asm.R2, asm.R4, 0, loadAcquire), st64(asm.R2, 0)), reload, call), false},
		{"r0 frame pointer kept across a map-value atomic add", cat(spill, I(asm.Mov.Reg(asm.R0, asm.RFP), asm.Add.Imm(asm.R0, -64), asm.LoadImm(asm.R3, 0, asm.DWord), asm.Mov.Imm(asm.R2, 1),
			atomic(asm.AtomicMode, asm.R3, asm.R2, 0, int64(asm.Add)), st64(asm.R0, 0)), reload, call), false},
		{"xchg returns the old value", cat(I(asm.Mov.Reg(asm.R2, asm.R1), atomic(asm.AtomicMode, asm.RFP, asm.R2, -64, int64(asm.Xchg)), asm.Mov.Reg(asm.R1, asm.R2)), call), false},
		{"probe-atomic xchg overwrites r1", cat(I(asm.LoadImm(asm.R2, 0, asm.DWord), atomic(probeAtomic, asm.R2, asm.R1, 0, xchg)), call), false},
		{"probe-atomic cmpxchg overwrites r0", cat(I(asm.Mov.Reg(asm.R0, asm.R1), asm.LoadImm(asm.R2, 0, asm.DWord), asm.Mov.Imm(asm.R3, 0),
			atomic(probeAtomic, asm.R2, asm.R3, 0, cmpxchg), asm.Mov.Reg(asm.R1, asm.R0)), call), false},
		{"gotox hides a call", I(asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -8), asm.LoadImm(asm.R2, 0, asm.DWord),
			asm.Instruction{OpCode: asm.Ja.Op(asm.RegSource), Dst: asm.R2}, asm.Mov.Imm(asm.R0, 0), asm.Return(), asm.Call.Label("hook")), false},
		{"target as a function pointer", I(fnptr("hook"), asm.Call.Label("hook")), false},
		{"one path without context", I(asm.LoadMem(asm.R2, asm.R1, 0, asm.Word), asm.JEq.Imm(asm.R2, 0, "site"), asm.Mov.Imm(asm.R1, 0), asm.Call.Label("hook").WithSymbol("site")), false},
		{"called from another function", I(asm.Call.Label("mid")), false},
		{"jump out of the entry", I(asm.Mov.Reg(asm.R6, asm.R1), asm.JEq.Imm(asm.R1, 0, "L"), asm.Ja.Label("hook"),
			asm.Mov.Reg(asm.R1, asm.R6).WithSymbol("L"), asm.Call.Label("hook")), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refs := map[string]bool{}
			for _, in := range tc.entry {
				refs[in.Reference()] = true
			}
			var first asm.Instructions
			if refs["getcb"] { // right after the entry, where a function-pointer load is outside it
				first = fn("getcb", fnptrTo(asm.R0, "cb"), asm.Return())
			}
			insns := cat(fn("entry", append(tc.entry, asm.Mov.Imm(asm.R0, 0), asm.Return())...), first,
				fn("writer", asm.StoreImm(asm.R1, 0, 0, asm.Word), asm.Mov.Imm(asm.R0, 0), asm.Return()),
				fn("below", st64(asm.R1, -8), asm.Mov.Imm(asm.R0, 0), asm.Return()),
				fn("helperbelow", asm.Add.Imm(asm.R1, -8), asm.Mov.Imm(asm.R2, 8), asm.Mov.Imm(asm.R3, 0), asm.FnProbeReadKernel.Call(), asm.Mov.Imm(asm.R0, 0), asm.Return()),
				fn("cb", st64(asm.R2, -32), asm.Mov.Imm(asm.R0, 0), asm.Return()),
				fn("hook", asm.Mov.Imm(asm.R0, 0), asm.Return()))
			if refs["getcblate"] { // after the hook, so the load is past the target too
				insns = append(insns, fn("getcblate", fnptrTo(asm.R0, "cb"), asm.Return())...)
			}
			if refs["mid"] {
				insns = append(insns, fn("mid", asm.Call.Label("hook"), asm.Mov.Imm(asm.R0, 0), asm.Return())...)
			}
			if refs["id"] { // returns its first argument
				insns = append(insns, fn("id", asm.Mov.Reg(asm.R0, asm.R1), asm.Return())...)
			}
			if refs["id5"] { // returns its fifth argument
				insns = append(insns, fn("id5", asm.Mov.Reg(asm.R0, asm.R5), asm.Return())...)
			}
			if refs["getval"] { // returns a map value
				insns = append(insns, fn("getval", asm.StoreImm(asm.RFP, -4, 0, asm.Word), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
					asm.LoadImm(asm.R1, 0, asm.DWord), asm.FnMapLookupElem.Call(), asm.Return())...)
			}
			if refs["cb4"] { // a for_each_map_elem callback writing its callback_ctx (R4)
				insns = append(insns, fn("cb4", st64(asm.R4, -32), asm.Mov.Imm(asm.R0, 0), asm.Return())...)
			}
			if refs["five"] { // a static callee writing through its fifth argument
				insns = append(insns, fn("five", st64(asm.R5, -8), asm.Mov.Imm(asm.R0, 0), asm.Return())...)
			}
			if refs["f6"] { // a static callee writing through its sixth (r11 stack) argument
				insns = append(insns, fn("f6", asm.LoadMem(asm.R1, asm.Register(11), 8, asm.DWord), st64(asm.R1, -32), asm.Mov.Imm(asm.R0, 0), asm.Return())...)
			}
			if refs["putcb16"] { // a bpf_loop callback that spills a function pointer above the floor
				insns = append(insns, fn("putcb16", fnptrTo(asm.R3, "cb200"), asm.StoreMem(asm.R2, 16, asm.R3, asm.DWord), asm.Mov.Imm(asm.R0, 0), asm.Return())...)
				insns = append(insns, fn("cb200", st64(asm.R2, -168), asm.Mov.Imm(asm.R0, 0), asm.Return())...)
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
		{"function pointer", cat(fn("entry", asm.Instruction{OpCode: asm.LoadImmOp(asm.DWord), Dst: asm.R2, Src: asm.PseudoFunc, Constant: 1<<32 | 3}, asm.Mov.Imm(asm.R0, 0), asm.Return()), // imm[1] holds the subprog id
			fn("hook", ret()...)), false},
		{"gotol skips the restore", cat(fn("entry", asm.Mov.Reg(asm.R6, asm.R1), asm.LoadMem(asm.R2, asm.R1, 0, asm.Word),
			asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.JEq), Dst: asm.R2, Offset: 2}, // to the restore
			asm.Mov.Imm(asm.R1, 0), asm.Instruction{OpCode: asm.OpCode(asm.Jump32Class).SetJumpOp(asm.Ja), Constant: 1}, // to the call
			asm.Mov.Reg(asm.R1, asm.R6), pcall(2, 1), asm.Mov.Imm(asm.R0, 0), asm.Return()), fn("hook", ret()...)), false},
		{"duplicate name", cat(fn("entry", asm.Call.Label("hook2"), asm.Call.Label("hook"), asm.Mov.Imm(asm.R0, 0), asm.Return()),
			fn("hook", ret()...), I(btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 0).WithSymbol("hook2"), &btf.Func{Name: "hook", Linkage: btf.StaticFunc}), asm.Return())), false},
		// Prove resolves each call in its actual Offset or Constant encoding,
		// so program size alone is no longer a reason to refuse.
		{"over 32K instructions", cat(jit(asm.Mov.Reg(asm.R6, asm.R1)), fn("filler", append(big, asm.Return())...)), true},
		{"no function info", I(asm.Mov.Imm(asm.R0, 0), asm.Return()), false},
		// entry 0-5 calls pc 7, inside other (6-8), then the hook at 9 with the context restored.
		{"call into the middle of a function", cat(fn("entry", append([]asm.Instruction{asm.Mov.Reg(asm.R6, asm.R1), pcall(5, 0), asm.Mov.Reg(asm.R1, asm.R6), pcall(5, 0)}, ret()...)...),
			fn("other", asm.Mov.Imm(asm.R0, 0), asm.Mov.Imm(asm.R0, 0), asm.Return()), fn("hook", ret()...)), false},
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
	if got, want := fmt.Sprint(insns[len(insns)-2:]), fmt.Sprint(direct[len(direct)-2:]); got != want {
		t.Fatalf("tail %s, want %s", got, want)
	}
}

// A dump that zeroes helper IDs is refused only off amd64, where a JIT may
// inline bpf_get_smp_processor_id and keep R1-R5 across a call shown as call 0.
func TestStaticCtxHiddenHelperIDs(t *testing.T) {
	old := hostArch
	t.Cleanup(func() { hostArch = old })
	ctx := &btf.Struct{Name: "xdp_md", Size: 24}
	i32 := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	fn := func(name string, body ...asm.Instruction) asm.Instructions {
		linkage := btf.StaticFunc
		proto := &btf.FuncProto{Return: i32}
		if name == "entry" || name == "hook" {
			proto.Params = []btf.FuncParam{{Name: "ctx", Type: &btf.Pointer{Target: ctx}}}
		}
		if name == "entry" {
			linkage = btf.GlobalFunc
		}
		body[0] = btf.WithFuncMetadata(body[0].WithSymbol(name), &btf.Func{Name: name, Linkage: linkage, Type: proto})
		return body
	}
	prog := func(body ...asm.Instruction) asm.Instructions {
		body = append(append([]asm.Instruction{asm.StoreMem(asm.RFP, -64, asm.R1, asm.DWord)}, body...),
			asm.LoadMem(asm.R1, asm.RFP, -64, asm.DWord), asm.Call.Label("hook"), asm.Mov.Imm(asm.R0, 0), asm.Return())
		return append(append(fn("entry", body...), fn("cb", asm.Mov.Imm(asm.R0, 0), asm.Return())...), fn("hook", asm.Mov.Imm(asm.R0, 0), asm.Return())...)
	}
	// A callback kept in R2 across bpf_get_smp_processor_id, then bpf_loop,
	// both shown as call 0: ctxRefusal alone accepts it.
	cb := asm.Instruction{OpCode: asm.LoadImmOp(asm.DWord), Dst: asm.R2, Src: asm.PseudoFunc}.WithReference("cb")
	hidden := prog(cb, asm.BuiltinFunc(0).Call(), asm.Mov.Imm(asm.R1, 4), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -32), asm.Mov.Imm(asm.R4, 0), asm.BuiltinFunc(0).Call())
	shown := prog(asm.FnGetSmpProcessorId.Call())
	for _, tc := range []struct {
		arch, name string
		insns      asm.Instructions
		refused    bool
	}{
		{"arm64", "hook", hidden, true}, {"riscv64", "hook", hidden, true}, {"ppc64le", "hook", hidden, true},
		{"loong64", "hook", hidden, true}, {"s390x", "hook", hidden, true}, {"amd64", "hook", hidden, false},
		{"arm64", "hook", shown, false}, {"amd64", "nosuch", shown, true},
	} {
		hostArch = tc.arch
		if err := checkStaticCtxInsns(tc.insns, tc.name); (err != nil) != tc.refused {
			t.Errorf("%s %s: err=%v, want refused=%v", tc.arch, tc.name, err, tc.refused)
		}
	}
}

func TestStaticCtxCalledFromProvedSubprogram(t *testing.T) {
	ctx := &btf.Struct{Name: "xdp_md", Size: 24}
	i32 := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	fn := func(name string, linkage btf.FuncLinkage, body ...asm.Instruction) asm.Instructions {
		proto := &btf.FuncProto{Return: i32, Params: []btf.FuncParam{{Name: "ctx", Type: &btf.Pointer{Target: ctx}}}}
		body[0] = btf.WithFuncMetadata(body[0].WithSymbol(name), &btf.Func{Name: name, Linkage: linkage, Type: proto})
		return body
	}
	build := func(wrong bool) asm.Instructions {
		entry := fn("entry", btf.GlobalFunc, asm.Mov.Reg(asm.R6, asm.R1), asm.Call.Label("sub"), asm.Mov.Imm(asm.R0, 0), asm.Return())
		pass := asm.Mov.Reg(asm.R1, asm.R6)
		if wrong {
			pass = asm.Mov.Imm(asm.R1, 0)
		}
		sub := fn("sub", btf.StaticFunc, asm.Mov.Reg(asm.R6, asm.R1), asm.FnKtimeGetNs.Call(), pass, asm.Call.Label("hook"), asm.Mov.Imm(asm.R0, 0), asm.Return())
		hook := fn("hook", btf.StaticFunc, asm.Mov.Imm(asm.R0, 0), asm.Return())
		return append(append(entry, sub...), hook...)
	}
	if err := checkStaticCtxInsns(build(false), "hook"); err != nil {
		t.Fatal(err)
	}
	if err := checkStaticCtxInsns(build(true), "hook"); err == nil {
		t.Fatal("accepted a subprogram call without context in R1")
	}
}
