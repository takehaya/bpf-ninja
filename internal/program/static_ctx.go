package program

import (
	"fmt"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/internal/ctxflow"
)

// checkStaticCtxArg refuses a static function unless every call passes the
// program's context in R1. Once the kernel has discarded the prototype nothing
// checks args[0], and reading another pointer as the context would capture
// unrelated kernel memory as packets.
func checkStaticCtxArg(target *ebpf.Program, name string) error {
	info, err := target.Info()
	var insns asm.Instructions
	if err == nil {
		insns, err = info.Instructions()
	}
	if err != nil {
		return fmt.Errorf("static function %q: reading the target's translated instructions to check its context argument: %w; "+
			"lower kernel.kptr_restrict or net.core.bpf_jit_harden, or capture at its caller or at a global function", name, err)
	}
	return checkStaticCtxInsns(insns, name)
}

// checkStaticCtxInsns is checkStaticCtxArg on translated instructions already read.
func checkStaticCtxInsns(insns asm.Instructions, name string) error {
	if hidesHelperIDs(insns) {
		return fmt.Errorf("static function %q: the translated instructions hide helper IDs, so a helper call the %s JIT may inline, "+
			"which keeps R1-R5, cannot be told from one that clobbers them; grant CAP_SYSLOG and keep kernel.kptr_restrict below 2, "+
			"or capture at its caller or at a global function", name, hostArch)
	}
	if why := ctxflow.CallsRefusal(insns, name); why != "" {
		return fmt.Errorf("static function %q: cannot show that every call passes the program context as its first argument (%s), "+
			"which a context read with bpf_probe_read_kernel relies on; direct call chains with BTF context parameters "+
			"and a held register or 8-byte stack spill are accepted; capture at its caller or at a global function", name, why)
	}
	return nil
}

// hostArch is the architecture bpf-ninja was built for, which an emulated
// binary does not share with the kernel; a test pins it to cover both
// branches of hidesHelperIDs.
var hostArch = runtime.GOARCH

// hidesHelperIDs reports whether the dump zeroes helper IDs (the kernel does
// so for every call without bpf_dump_raw_ok, e.g. under kernel.kptr_restrict)
// on a host whose JIT may inline a helper call and keep R1-R5 across it. The
// x86-64 JIT inlines none, so a call there always clobbers R1-R5.
func hidesHelperIDs(insns asm.Instructions) bool {
	if hostArch == "amd64" {
		return false
	}
	for i := range insns {
		if insns[i].IsBuiltinCall() && insns[i].Constant == 0 {
			return true
		}
	}
	return false
}
