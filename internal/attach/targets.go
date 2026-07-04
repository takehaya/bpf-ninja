// Multi-target resolution for `-p` (repeatable) × `--func` (repeatable):
// expand program × function into the concrete (program, BTF func) pairs a
// fentry/fexit probe can attach to. Multi-stage dispatchers (cpu_dispatch →
// CPUMAP → per-direction handlers) put capture points in separate programs,
// and noinline subfunctions get one copy per calling program (e.g. a
// `upf_capture_point_dl` in both the v4 and the v6 handler), so covering
// UL+DL takes several attaches in one run.
package attach

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// Target is one (program, function) pair to attach a tracing probe to.
// Params carries the func's filterable integer parameters, resolved once
// from the program's cached BTF so downstream arg-filter / list-params /
// arg-echo consumers don't re-parse BTF per use.
type Target struct {
	Program  *ebpf.Program
	ProgID   uint32
	FuncName string
	Type     ebpf.ProgramType
	Params   []FuncParamInfo
}

// CloseTargets closes the programs of all targets. Each program handle is
// opened once per -p / -i even when several funcs target it, so dedup by
// pointer before closing.
func CloseTargets(targets []Target) {
	seen := map[*ebpf.Program]bool{}
	for _, t := range targets {
		if t.Program != nil && !seen[t.Program] {
			seen[t.Program] = true
			_ = t.Program.Close()
		}
	}
}

// ResolveTargets expands the given programs × funcNames into attachable
// (program, func) pairs.
//
// For each program: if funcNames is empty, its BTF-resolved entry function
// (already on ProgInfo) is the single target. Otherwise each requested func
// that exists in the program's BTF becomes a target; funcs missing from a
// program are skipped (multi-program setups rarely have every func in every
// program), but a func found in no program at all is an error listing the
// functions that do exist. Duplicate (progID, func) pairs collapse.
//
// The returned targets borrow the ProgInfo program handles; free them with
// CloseTargets. Program-type validation (uniform, supported) is owned by
// program.loadMulti, the single enforcement point every attach path passes
// through.
func ResolveTargets(infos []*ProgInfo, funcNames []string) ([]Target, error) {
	var targets []Target
	seenPair := map[string]bool{}
	funcFound := map[string]bool{}

	addTarget := func(info *ProgInfo, fn string, params []FuncParamInfo) {
		key := fmt.Sprintf("%d/%s", info.ProgID, fn)
		if seenPair[key] {
			return
		}
		seenPair[key] = true
		targets = append(targets, Target{
			Program: info.Program, ProgID: info.ProgID, FuncName: fn,
			Type: info.Type, Params: params,
		})
	}

	for _, info := range infos {
		if len(funcNames) == 0 {
			// Entry functions never take filterable args (their only
			// param is the ctx pointer), so no params to resolve.
			addTarget(info, info.FuncName, nil)
			continue
		}
		spec, err := info.BTFSpecCached()
		if err != nil {
			return nil, fmt.Errorf("program (id=%d): %w", info.ProgID, err)
		}
		for _, fn := range funcNames {
			var f *btf.Func
			if err := spec.TypeByName(fn, &f); err != nil {
				continue // this program doesn't carry fn — fine in multi setups
			}
			funcFound[fn] = true
			params, err := GetFuncParamsFromSpec(spec, fn)
			if err != nil {
				return nil, fmt.Errorf("program (id=%d) func %s: %w", info.ProgID, fn, err)
			}
			addTarget(info, fn, params)
		}
	}

	for _, fn := range funcNames {
		if !funcFound[fn] {
			return nil, fmt.Errorf("function %q not found in any target program's BTF; available functions: %v",
				fn, availableFuncs(infos))
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no attachable (program, function) pairs resolved")
	}
	return targets, nil
}

// availableFuncs collects the BTF function names across all target
// programs, for the not-found error message.
func availableFuncs(infos []*ProgInfo) []string {
	var names []string
	seen := map[string]bool{}
	for _, info := range infos {
		spec, err := info.BTFSpecCached()
		if err != nil {
			continue
		}
		funcs, err := ListFuncsFromSpec(spec)
		if err != nil {
			continue
		}
		for _, f := range funcs {
			if !seen[f.Name] {
				seen[f.Name] = true
				names = append(names, f.Name)
			}
		}
	}
	return names
}
