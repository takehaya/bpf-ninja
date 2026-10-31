//go:build linux && amd64

package syscallhook

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/pkg/inject"
	"golang.org/x/sys/unix"
)

// HookForm describes the policy for hooks that would take untrusted pointers.
// Ordinary typed hooks, including copied values, keep their existing form.
type HookForm struct {
	Form   string `json:"form"`
	Reason string `json:"reason"`
}

func chooseHookForm(force *bool, probe func() error) HookForm {
	if force != nil {
		if *force {
			return HookForm{"static", "config_static_untrusted_true"}
		}
		return HookForm{"global", "config_static_untrusted_false"}
	}
	if err := probe(); err != nil {
		if untrustedRejection(err) {
			return HookForm{"static", "probe_arg_untrusted_unsupported"}
		}
		// An inconclusive probe must not turn permissions or resource failures into
		// a claim of missing kernel support. The actual load remains authoritative.
		return HookForm{"global", "probe_inconclusive"}
	}
	return HookForm{"global", "probe_arg_untrusted_supported"}
}

func untrustedRejection(err error) bool {
	if !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.EOPNOTSUPP) && !errors.Is(err, unix.EACCES) {
		return false
	}
	var ve *ebpf.VerifierError
	if !errors.As(err, &ve) {
		return false
	}
	for _, line := range ve.Log {
		if strings.Contains(line, "arg#") && (strings.Contains(line, "has unsupported set of tags") || strings.Contains(line, "reference type('UNKNOWN ')") && strings.Contains(line, "size cannot be determined")) {
			return true
		}
	}
	return false
}

func retryStatic(force *bool, form HookForm, result *inject.LookupResultRaw, err error) bool {
	if force != nil || form.Form != "global" || result == nil || !untrustedRejection(err) {
		return false
	}
	return hasUntrustedHooks(result)
}

func hasUntrustedHooks(result *inject.LookupResultRaw) bool {
	for _, h := range result.Hooks {
		if h.Untrusted {
			return true
		}
	}
	return false
}

// Like a libbpf feature probe, load a minimal program exercising the exact ABI.
// No maps, attachments, version assumptions or external compiler are needed.
func globalUntrustedProbeSpec() *ebpf.ProgramSpec {
	integer := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	fn := &btf.Func{Name: "untrusted_arg", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{
		Return: integer, Params: []btf.FuncParam{{Name: "ptr", Type: &btf.Pointer{Target: &btf.Void{}}}},
	}, ParamTags: [][]string{{"arg:untrusted"}}}
	insns := asm.Instructions{
		asm.StoreImm(asm.RFP, -8, 0, asm.Word), asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -8),
		asm.Call.Label(fn.Name), asm.Mov.Imm(asm.R0, 2), asm.Return(),
		btf.WithFuncMetadata(asm.LoadMem(asm.R0, asm.R1, 0, asm.Byte).WithSymbol(fn.Name), fn), asm.Mov.Imm(asm.R0, 0), asm.Return(),
	}
	entry := &btf.Func{Name: "probe_entry", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{Return: integer, Params: []btf.FuncParam{{Name: "ctx", Type: &btf.Pointer{Target: &btf.Struct{Name: "xdp_md", Size: 24}}}}}}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol(entry.Name), entry)
	return &ebpf.ProgramSpec{Name: "untrusted_probe", Type: ebpf.XDP, License: "GPL", Instructions: insns}
}

func probeGlobalUntrusted() error {
	p, err := ebpf.NewProgram(globalUntrustedProbeSpec())
	if err != nil {
		return fmt.Errorf("global arg:untrusted probe: %w", err)
	}
	return p.Close()
}
