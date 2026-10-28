package program

import (
	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/internal/hook"
)

// Static BPF functions expose ctx as a scalar to tracing programs, including
// inject-run's static_untrusted hooks on kernels without arg:untrusted.
// Read the same xdp_buff layout as hook.xdpPacketPrologue through the fault-
// handled helper. The temporary stack is dead before set/packet filtering.
func staticXDPHook(h *hook.Hook, isFexit bool) *hook.Hook {
	clone := *h
	clone.PacketPrologue = func() (asm.Instructions, error) {
		return asm.Instructions{
			asm.StoreMem(asm.R10, -48, asm.R1, asm.DWord),
			asm.LoadMem(asm.R6, asm.R1, 0, asm.DWord),
			asm.Mov.Reg(asm.R3, asm.R6),
			asm.Mov.Reg(asm.R1, asm.R10), asm.Add.Imm(asm.R1, -160),
			asm.Mov.Imm(asm.R2, 16), asm.FnProbeReadKernel.Call(),
			asm.JNE.Imm(asm.R0, 0, "exit"),
			asm.LoadMem(asm.R7, asm.R10, -160, asm.DWord),
			asm.LoadMem(asm.R8, asm.R10, -152, asm.DWord),
			asm.Mov.Reg(asm.R9, asm.R8), asm.Sub.Reg(asm.R9, asm.R7),
		}, nil
	}
	clone.Identity = func(dst asm.Register) (asm.Instructions, error) {
		// Gated exit keeps its expected identity in R2. At entry R2 may
		// be uninitialized after ktime_get_ns, and must not be spilled.
		insns := asm.Instructions{asm.StoreMem(asm.R10, -136, asm.R0, asm.DWord)}
		if isFexit {
			insns = append(insns, asm.StoreMem(asm.R10, -144, asm.R2, asm.DWord))
		}
		insns = append(insns,
			asm.Mov.Reg(asm.R3, asm.R6), asm.Add.Imm(asm.R3, 24),
			asm.Mov.Reg(asm.R1, asm.R10), asm.Add.Imm(asm.R1, argMemberTmp),
			asm.Mov.Imm(asm.R2, 8), asm.FnProbeReadKernel.Call(),
			asm.JNE.Imm(asm.R0, 0, "exit"),
			asm.LoadMem(asm.R0, asm.R10, -136, asm.DWord),
		)
		if isFexit {
			insns = append(insns, asm.LoadMem(asm.R2, asm.R10, -144, asm.DWord))
		}
		return append(insns, asm.LoadMem(dst, asm.R10, argMemberTmp, asm.DWord)), nil
	}
	return &clone
}
