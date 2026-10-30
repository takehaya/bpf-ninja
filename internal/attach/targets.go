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
	"slices"

	"github.com/cilium/ebpf"
)

// Target is one (program, function) pair to attach a tracing probe to.
// Params carries the func's filterable integer parameters, resolved once
// from the program's cached BTF so downstream arg-filter / list-params /
// arg-echo consumers don't re-parse BTF per use.
type Target struct {
	Program             *ebpf.Program
	ProgID              uint32
	FuncName            string
	Type                ebpf.ProgramType
	HookType            ebpf.ProgramType
	Params              []FuncParamInfo
	Availability        FuncAvailability
	AllowDispatcherSlot bool
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

// TargetDiagnostic records a skipped or unreadable target.
type TargetDiagnostic struct {
	ProgID       uint32
	FuncName     string
	Availability FuncAvailability
	Skipped      bool
}

func (d TargetDiagnostic) String() string {
	return fmt.Sprintf("program (id=%d) function %q: %s", d.ProgID, d.FuncName, d.Availability)
}

// ResolveTargets expands programs × exact function names.
// A single distinct function in one program fails when absent. Multi-selections
// retain diagnostics for skipped functions; unknown membership proceeds to kernel validation.
// Targets borrow the ProgInfo handles; the caller owns their lifetime.
// Program-type validation (uniform, supported) is owned by program.loadMulti,
// the single enforcement point every attach path passes through.
func ResolveTargets(infos []*ProgInfo, funcNames []string, allowDispatcherSlot bool) ([]Target, []TargetDiagnostic, error) {
	var targets []Target
	var diagnostics []TargetDiagnostic
	seenPair := map[string]bool{}
	funcFound := map[string]bool{}
	names := make([]string, 0, len(funcNames))
	for _, name := range funcNames {
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	funcNames = names
	multi := len(infos) > 1 || len(funcNames) > 1
	for _, info := range infos {
		names := funcNames
		if len(names) == 0 {
			names = []string{info.FuncName}
		}
		for _, fn := range names {
			a := info.FuncAvailability(fn)
			if a.Reason == FuncMissing {
				if !multi {
					return nil, diagnostics, fmt.Errorf("program (id=%d) function %q: %s; available functions: %v", info.ProgID, fn, a.Explain(), availableFuncs(infos))
				}
				continue // Missing BTF names are expected across programs; check all below.
			}
			funcFound[fn] = true
			key := fmt.Sprintf("%d/%s", info.ProgID, fn)
			if seenPair[key] {
				continue
			}
			seenPair[key] = true
			d := TargetDiagnostic{ProgID: info.ProgID, FuncName: fn, Availability: a}
			if a.Unavailable() {
				if !multi {
					return nil, diagnostics, fmt.Errorf("program (id=%d) function %q: %s", info.ProgID, fn, a.Explain())
				}
				d.Skipped = true
				diagnostics = append(diagnostics, d)
				continue
			}
			if a.Reason == FuncUnknown {
				diagnostics = append(diagnostics, d)
			}
			var params []FuncParamInfo
			if len(funcNames) > 0 || info.Type == ebpf.Extension {
				spec, err := info.BTFSpecCached()
				if err != nil {
					return nil, diagnostics, fmt.Errorf("program (id=%d): %w", info.ProgID, err)
				}
				params, err = GetFuncParamsFromSpec(spec, fn)
				if err != nil {
					return nil, diagnostics, fmt.Errorf("program (id=%d) func %s: %w", info.ProgID, fn, err)
				}
			}
			target := Target{Program: info.Program, ProgID: info.ProgID, FuncName: fn,
				Type: info.Type, HookType: info.HookType, Params: params, AllowDispatcherSlot: allowDispatcherSlot, Availability: a}
			target.HookType = target.EffectiveHookType()
			targets = append(targets, target)
		}
	}
	for _, fn := range funcNames {
		if !funcFound[fn] {
			return nil, diagnostics, fmt.Errorf("%s: function %q not found in any target program's BTF; available functions: %v", FuncMissing, fn, availableFuncs(infos))
		}
	}
	if len(targets) == 0 {
		return nil, diagnostics, fmt.Errorf("no attachable (program, function) pairs resolved; see https://github.com/takehaya/bpf-ninja/blob/main/docs/en/attach-troubleshooting.md")
	}
	return targets, diagnostics, nil
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

// EffectiveHookType also supports hand-built non-EXT targets.
func (t Target) EffectiveHookType() ebpf.ProgramType {
	if t.HookType == 0 && t.Type != ebpf.Extension {
		return t.Type
	}
	return t.HookType
}
