package program

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/hook"
)

// staticNeedsProbeRead checks the actual target instead of a kernel version:
// on 6.1, btf_check_subprog_arg_match can mark static hooks with non-ctx pointer
// arguments unreliable; bpf_check_attach_target then discards their prototype.
// args[0] becomes SCALAR_VALUE, so h's first ctx load (xdp_buff or sk_buff) is
// rejected with "R6 invalid mem access 'scalar'". Reproduced for XDP on matrix
// kernels 6.1, 6.6, 6.12, 6.15, 6.18, 7.0, 7.1, 7.2 and 7.3-rc4, while static
// ctx-only helpers accept direct loads on all of them. This is target
// dependent, so a tiny, unattached load probe preserves working targets'
// existing codegen and handles backports without guessing a version boundary.
// Other errors propagate.
func staticNeedsProbeRead(h *hook.Hook, target *ebpf.Program, name string, attachType ebpf.AttachType, availability attach.FuncAvailability) (bool, error) {
	if availability.Unavailable() {
		return false, fmt.Errorf("function %q: %s", name, availability.Explain())
	}
	insns, err := h.PacketPrologue()
	if err != nil {
		return false, err
	}
	insns = append(insns, asm.Mov.Imm(asm.R0, 0), asm.Return())
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.Tracing, AttachType: attachType, AttachTo: name,
		AttachTarget: target, Instructions: insns, License: "GPL",
	})
	if err == nil {
		return false, p.Close()
	}
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) && strings.Contains(strings.Join(ve.Log, "\n"), "R6 invalid mem access 'scalar'") {
		return true, nil
	}
	return false, tracingLoadError("direct context probe", name, availability, err)
}

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

// staticTCHook reads the sk_buff fields hook.skbPacketPrologue loads through
// the fault-handled helper; skbIdentity is a register move and stays valid.
// The temporary stack is dead before arg/set/packet filtering.
func staticTCHook(h *hook.Hook, name string) *hook.Hook {
	clone := *h
	clone.PacketPrologue = func() (asm.Instructions, error) {
		data, length, dataLen, err := hook.SkBuffPacketOffsets()
		if err != nil {
			return nil, fmt.Errorf("resolving struct sk_buff offsets via BTF: %w", err)
		}
		insns := asm.Instructions{
			asm.StoreMem(asm.R10, -48, asm.R1, asm.DWord),
			asm.LoadMem(asm.R6, asm.R1, 0, asm.DWord),
		}
		for _, field := range []struct {
			offset uint32
			slot   int32
			size   int32
		}{{data, -160, 8}, {length, -152, 4}, {dataLen, -148, 4}} {
			insns = append(insns,
				asm.Mov.Reg(asm.R3, asm.R6), asm.Add.Imm(asm.R3, int32(field.offset)),
				asm.Mov.Reg(asm.R1, asm.R10), asm.Add.Imm(asm.R1, field.slot),
				asm.Mov.Imm(asm.R2, field.size), asm.FnProbeReadKernel.Call(),
				asm.JNE.Imm(asm.R0, 0, "exit"),
			)
		}
		return append(insns,
			asm.LoadMem(asm.R7, asm.R10, -160, asm.DWord),
			asm.LoadMem(asm.R9, asm.R10, -152, asm.Word),
			asm.LoadMem(asm.R8, asm.R10, -148, asm.Word),
			asm.Sub.Reg(asm.R9, asm.R8), // only the linear head, as in skbPacketPrologue
			asm.Mov.Reg(asm.R8, asm.R7), asm.Add.Reg(asm.R8, asm.R9),
		), nil
	}
	// The tag loader reads sk_buff directly; only a wire-frame filter calls it.
	clone.OuterVlanTag = func() (asm.Instructions, error) {
		return nil, fmt.Errorf("--tc-vlan-reinsert is not supported at static tc function %q, whose context is read with bpf_probe_read_kernel; omit the flag or capture at a global function", name)
	}
	return &clone
}
