package program

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/attach"
)

func validateHookPoints(targets []attach.Target, stages []Stage) (*attach.ProgInfo, error) {
	if len(targets) == 0 || len(targets) > 255 || len(stages) != 1 || stages[0].IsFexit {
		return nil, fmt.Errorf("hook capture needs 1..255 subfunctions and entry mode only")
	}
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, err
	}
	if cpus > 1<<16 {
		return nil, fmt.Errorf("hook packet ids require CPU ids below 65536")
	}
	var id ebpf.ProgramID
	seen := map[string]bool{}
	for i, t := range targets {
		if (t.Type != ebpf.XDP && t.Type != ebpf.SchedCLS) || t.Program == nil {
			return nil, fmt.Errorf("hook capture requires one native XDP or SchedCLS program")
		}
		info, err := t.Program.Info()
		if err != nil {
			return nil, err
		}
		tid, ok := info.ID()
		if !ok {
			return nil, fmt.Errorf("hook target has no program id")
		}
		if i == 0 {
			id = tid
		}
		if tid != id {
			return nil, fmt.Errorf("hook capture cannot correlate different programs")
		}
		if seen[t.FuncName] {
			return nil, fmt.Errorf("duplicate hook %q", t.FuncName)
		}
		seen[t.FuncName] = true
	}
	// Fail closed: both the run boundary and its subprograms must be inspectable.
	// Tail-call destinations bypass their entry trampoline, and 7.0 also has a
	// multiple-attach trampoline bug. Do not attach anything to such a program.
	info, err := targets[0].Program.Info()
	if err != nil {
		return nil, err
	}
	insns, err := info.Instructions()
	if err != nil {
		return nil, fmt.Errorf("checking hook target instructions: %w", err)
	}
	for _, ins := range insns {
		if ins.IsBuiltinCall() && asm.BuiltinFunc(ins.Constant) == asm.FnTailCall {
			return nil, fmt.Errorf("hook capture does not support tail calls (including calls in subprograms)")
		}
	}
	root, err := attach.FindBPFProgramByID(uint32(id))
	if err != nil {
		return nil, err
	}
	if seen[root.FuncName] {
		_ = root.Program.Close()
		return nil, fmt.Errorf("select subfunction hooks, not root entry %q", root.FuncName)
	}
	spec, err := root.BTFSpecCached()
	if err == nil {
		for _, target := range targets {
			if err = validateHookRootContext(spec, root.FuncName, target.FuncName); err != nil {
				break
			}
		}
	}
	if err != nil {
		_ = root.Program.Close()
		return nil, err
	}
	return root, nil
}

// GetFuncParamsFromSpec deliberately skips parameter zero for argument filters,
// so inspect the complete BTF prototypes here instead.
func validateHookRootContext(spec *btf.Spec, root, name string) error {
	var r, h *btf.Func
	if err := spec.TypeByName(root, &r); err != nil {
		return err
	}
	if err := spec.TypeByName(name, &h); err != nil {
		return err
	}
	rp, rok := r.Type.(*btf.FuncProto)
	hp, hok := h.Type.(*btf.FuncProto)
	if rok && hok && len(rp.Params) > 0 && len(hp.Params) > 0 {
		rptr, ok := btf.UnderlyingType(rp.Params[0].Type).(*btf.Pointer)
		hptr, ok2 := btf.UnderlyingType(hp.Params[0].Type).(*btf.Pointer)
		if ok && ok2 && btf.UnderlyingType(rptr.Target) == btf.UnderlyingType(hptr.Target) {
			return nil
		}
	}
	return fmt.Errorf("hook %q parameter 0 must have the root ctx type", name)
}
