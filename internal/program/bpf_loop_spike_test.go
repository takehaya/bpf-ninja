package program

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

// TestBpfLoopSpikeVerifies proves the bpf_loop + bpf2bpf callback wiring
// cilium/ebpf needs for PR 5c (chain codegen via bpf_loop). A minimal
// fentry program invokes FnLoop(2, cb, scratch, 0); the callback is a
// bpf2bpf subprogram that just returns 0. If this passes the verifier,
// we know the real chain emitter can reuse the same Instruction shape
// without extra BTF plumbing — the loader synthesises func_info from
// the PseudoFunc-tagged DWord load that references the callback.
//
// Kept out of the main flow; spike only, delete once PR 5c lands a
// real chain codegen that exercises the same wiring.
func TestBpfLoopSpikeVerifies(t *testing.T) {
	xdpProg := loadDummyXDP(t)

	const cbSym = "bpf_loop_cb"

	// BTF types the kernel needs to validate the bpf2bpf subprogram.
	// The callback signature is `long (*)(u32 idx, void *ctx)`; main's
	// signature is only required to be present — the actual attach
	// target's BTF is what shapes the tracing context.
	longType := &btf.Int{Name: "long", Size: 8, Encoding: btf.Signed}
	u32Type := &btf.Int{Name: "u32", Size: 4, Encoding: btf.Unsigned}
	voidPtr := &btf.Pointer{Target: &btf.Void{}}
	mainFunc := &btf.Func{
		Name:    "bpf_loop_main",
		Type:    &btf.FuncProto{Return: longType},
		Linkage: btf.GlobalFunc,
	}
	cbFunc := &btf.Func{
		Name: cbSym,
		Type: &btf.FuncProto{
			Return: longType,
			Params: []btf.FuncParam{
				{Name: "index", Type: u32Type},
				{Name: "ctx", Type: voidPtr},
			},
		},
		Linkage: btf.StaticFunc,
	}

	main := asm.Instructions{
		// Preserve tracing-probe prologue: save args pointer to
		// stack[-48] like runFilter does so the verifier sees the
		// usual shape. FuncMetadata on the first instruction gives
		// the main program its BTF func_info entry.
		btf.WithFuncMetadata(
			asm.StoreMem(asm.R10, -48, asm.R1, asm.DWord),
			mainFunc,
		),

		// bpf_loop(max_iter=2, cb, ctx=scratch, flags=0) → R0 = iters
		asm.Mov.Imm(asm.R1, 2),
		// R2 = &cb via BPF_PSEUDO_FUNC. cilium/ebpf resolves the
		// reference to a function pointer at load time and writes
		// the matching BTF func_info.
		asm.Instruction{
			OpCode:   asm.LoadImmOp(asm.DWord),
			Dst:      asm.R2,
			Src:      asm.PseudoFunc,
			Constant: -1,
		}.WithReference(cbSym),
		// R3 = stack-resident 16-byte ctx slot; ends up at [-64..-48).
		// StoreImm is Byte/Half/Word only — park a 0 in a temp reg and
		// use StoreMem twice to zero the two DWords.
		asm.Mov.Imm(asm.R5, 0),
		asm.StoreMem(asm.R10, -64, asm.R5, asm.DWord),
		asm.StoreMem(asm.R10, -56, asm.R5, asm.DWord),
		asm.Mov.Reg(asm.R3, asm.R10),
		asm.Add.Imm(asm.R3, -64),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnLoop.Call(),

		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}

	// Callback: always return 0 (continue iterating). First instruction
	// owns both the symbol the main stream references and the BTF
	// func_info entry for the kernel verifier.
	callback := asm.Instructions{
		btf.WithFuncMetadata(
			asm.Mov.Imm(asm.R0, 0).WithSymbol(cbSym),
			cbFunc,
		),
		asm.Return(),
	}

	insns := append(asm.Instructions{}, main...)
	insns = append(insns, callback...)

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "bpf_loop_spike",
		Type:         ebpf.Tracing,
		AttachType:   ebpf.AttachTraceFEntry,
		AttachTo:     xdpFuncName,
		AttachTarget: xdpProg,
		Instructions: insns,
		License:      "GPL",
	})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier rejected spike:\n%+v", ve)
		}
		t.Fatalf("loading spike: %v", err)
	}
	t.Cleanup(func() { _ = prog.Close() })

	// Also confirm the trampoline accepts the attach.
	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		t.Fatalf("attaching spike: %v", err)
	}
	_ = l.Close()
}
