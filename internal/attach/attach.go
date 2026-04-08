// Package attach finds existing XDP programs on network interfaces.
package attach

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/vishvananda/netlink"
)

// XDPInfo holds information about the existing XDP program on an interface.
type XDPInfo struct {
	ProgID    uint32
	Program   *ebpf.Program
	FuncName  string // BTF-resolved entry function name
	IfaceName string
}

// FindXDPProgramByID gets an XDP program by its BPF program ID.
func FindXDPProgramByID(progID uint32) (*XDPInfo, error) {
	prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(progID))
	if err != nil {
		return nil, fmt.Errorf("getting program (id=%d): %w", progID, err)
	}

	funcName, err := resolveEntryFunc(prog, progID)
	if err != nil {
		_ = prog.Close()
		return nil, err
	}

	return &XDPInfo{
		ProgID:   progID,
		Program:  prog,
		FuncName: funcName,
	}, nil
}

// FindXDPProgram finds the existing XDP program on the given interface.
func FindXDPProgram(ifaceName string) (*XDPInfo, error) {
	nl, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}

	xdp := nl.Attrs().Xdp
	if xdp == nil || xdp.ProgId == 0 {
		return nil, fmt.Errorf("no XDP program attached to %s", ifaceName)
	}

	prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(xdp.ProgId))
	if err != nil {
		return nil, fmt.Errorf("getting XDP program (id=%d): %w", xdp.ProgId, err)
	}

	funcName, err := resolveEntryFunc(prog, xdp.ProgId)
	if err != nil {
		_ = prog.Close()
		return nil, err
	}

	return &XDPInfo{
		ProgID:    xdp.ProgId,
		Program:   prog,
		FuncName:  funcName,
		IfaceName: ifaceName,
	}, nil
}

// TailCallTarget holds information about a program in a PROG_ARRAY map.
type TailCallTarget struct {
	Index    uint32
	ProgID   uint32
	ProgName string
}

// ListTailCallTargets finds all tail call targets reachable from the given program
// by scanning its PROG_ARRAY maps.
func ListTailCallTargets(prog *ebpf.Program) ([]TailCallTarget, error) {
	info, err := prog.Info()
	if err != nil {
		return nil, fmt.Errorf("getting program info: %w", err)
	}

	mapIDs, ok := info.MapIDs()
	if !ok {
		return nil, nil
	}

	var targets []TailCallTarget
	for _, mapID := range mapIDs {
		m, err := ebpf.NewMapFromID(mapID)
		if err != nil {
			return nil, fmt.Errorf("opening map %d: %w", mapID, err)
		}

		mapInfo, err := m.Info()
		if err != nil {
			_ = m.Close()
			return nil, fmt.Errorf("getting map %d info: %w", mapID, err)
		}
		if mapInfo.Type != ebpf.ProgramArray {
			_ = m.Close()
			continue
		}

		// Iterate PROG_ARRAY entries
		var key, val uint32
		iter := m.Iterate()
		for iter.Next(&key, &val) {
			progID := val
			targetProg, err := ebpf.NewProgramFromID(ebpf.ProgramID(progID))
			if err != nil {
				_ = m.Close()
				return nil, fmt.Errorf("opening tail call target (id=%d): %w", progID, err)
			}

			targetInfo, err := targetProg.Info()
			if err != nil {
				_ = targetProg.Close()
				_ = m.Close()
				return nil, fmt.Errorf("getting tail call target info (id=%d): %w", progID, err)
			}

			targets = append(targets, TailCallTarget{
				Index:    key,
				ProgID:   progID,
				ProgName: targetInfo.Name,
			})
			_ = targetProg.Close()
		}
		if err := iter.Err(); err != nil {
			_ = m.Close()
			return nil, fmt.Errorf("iterating program array map %d: %w", mapID, err)
		}
		_ = m.Close()
	}

	return targets, nil
}

// FuncInfo holds metadata about a BTF function in a BPF program.
type FuncInfo struct {
	Name    string
	Linkage string // "static", "global", "extern"
}

// FuncParamInfo holds metadata about a function parameter from BTF.
type FuncParamInfo struct {
	Name   string // Parameter name from BTF
	Index  int    // 0-based index in the parameter list
	Size   uint32 // Size in bytes
	Signed bool   // true if signed integer
}

// GetFuncParams returns the function parameters for the given function from BTF.
// Only integer parameters (excluding the first xdp_md/xdp_buff pointer) are returned,
// as those are the only types supported for argument filtering.
func GetFuncParams(prog *ebpf.Program, funcName string) ([]FuncParamInfo, error) {
	spec, err := BTFSpec(prog)
	if err != nil {
		return nil, err
	}
	return GetFuncParamsFromSpec(spec, funcName)
}

// GetFuncParamsFromSpec extracts function parameters from a BTF spec.
func GetFuncParamsFromSpec(spec *btf.Spec, funcName string) ([]FuncParamInfo, error) {
	var fn *btf.Func
	if err := spec.TypeByName(funcName, &fn); err != nil {
		return nil, fmt.Errorf("function %q not found in BTF: %w", funcName, err)
	}

	proto, ok := fn.Type.(*btf.FuncProto)
	if !ok {
		return nil, fmt.Errorf("function %q has unexpected type %T (expected FuncProto)", funcName, fn.Type)
	}

	var params []FuncParamInfo
	for i, p := range proto.Params {
		// Skip first parameter (xdp_md/xdp_buff pointer)
		if i == 0 {
			continue
		}

		// Unwrap qualifiers and typedefs to get the underlying type
		underlying := btf.UnderlyingType(p.Type)

		// Only support named integer types for filtering.
		// Unnamed parameters can't be targeted by --arg-filter.
		if p.Name == "" {
			continue
		}
		intType, ok := underlying.(*btf.Int)
		if !ok {
			continue
		}

		params = append(params, FuncParamInfo{
			Name:   p.Name,
			Index:  i,
			Size:   intType.Size,
			Signed: intType.Encoding == btf.Signed,
		})
	}

	return params, nil
}

// BTFSpec opens the BTF handle for a loaded program and returns its spec.
func BTFSpec(prog *ebpf.Program) (*btf.Spec, error) {
	handle, err := prog.Handle()
	if err != nil {
		return nil, fmt.Errorf("BTF unavailable: %w", err)
	}
	defer func() { _ = handle.Close() }()

	spec, err := handle.Spec(nil)
	if err != nil {
		return nil, fmt.Errorf("reading BTF: %w", err)
	}
	return spec, nil
}

// ListFuncs returns all BTF function entries found in the program.
func ListFuncs(prog *ebpf.Program) ([]FuncInfo, error) {
	spec, err := BTFSpec(prog)
	if err != nil {
		return nil, err
	}
	return ListFuncsFromSpec(spec)
}

// ValidateSubfunc checks that the given function name exists in the program's BTF.
// If the function is not found, the error message includes a list of available functions.
func ValidateSubfunc(prog *ebpf.Program, progID uint32, funcName string) error {
	spec, err := BTFSpec(prog)
	if err != nil {
		return fmt.Errorf("program (id=%d): %w", progID, err)
	}
	return ValidateSubfuncFromSpec(spec, progID, funcName)
}

// ValidateSubfuncFromSpec validates a subfunction name against a BTF spec.
func ValidateSubfuncFromSpec(spec *btf.Spec, progID uint32, funcName string) error {
	var fn *btf.Func
	if err := spec.TypeByName(funcName, &fn); err == nil {
		return nil
	}

	funcs, ferr := ListFuncsFromSpec(spec)
	if ferr != nil {
		return fmt.Errorf("function %q not found in program (id=%d) BTF (also failed to list functions: %v)", funcName, progID, ferr)
	}
	var names []string
	for _, f := range funcs {
		names = append(names, f.Name)
	}
	return fmt.Errorf(
		"function %q not found in program (id=%d) BTF; available functions: %v",
		funcName, progID, names,
	)
}

// ListFuncsFromSpec collects function entries from a BTF spec.
func ListFuncsFromSpec(spec *btf.Spec) ([]FuncInfo, error) {
	var funcs []FuncInfo
	for typ, err := range spec.All() {
		if err != nil {
			return funcs, err
		}
		if f, ok := typ.(*btf.Func); ok {
			funcs = append(funcs, FuncInfo{
				Name:    f.Name,
				Linkage: f.Linkage.String(),
			})
		}
	}
	return funcs, nil
}

// resolveEntryFunc resolves the entry function name from the program's BTF.
//
// fentry/fexit requires BTF, so this function errors if BTF is unavailable
// or the function name cannot be unambiguously resolved.
//
// Resolution order:
//  1. Exact match: prog.Info().Name matches a btf.Func
//  2. Prefix match: prog name is truncated (>=15 chars, BPF_OBJ_NAME_LEN limit)
//     and a btf.Func starts with that prefix — but only if exactly one matches
//  3. Single Func: BTF has exactly one Func entry
//  4. Error: ambiguous or no match
func resolveEntryFunc(prog *ebpf.Program, progID uint32) (string, error) {
	info, err := prog.Info()
	if err != nil {
		return "", fmt.Errorf("program id=%d: getting info: %w", progID, err)
	}
	progName := info.Name

	spec, err := BTFSpec(prog)
	if err != nil {
		return "", fmt.Errorf("program %q (id=%d): %w", progName, progID, err)
	}

	// 1. Exact match
	var fn *btf.Func
	if err := spec.TypeByName(progName, &fn); err == nil {
		return fn.Name, nil
	}

	// Collect all Func entries
	var funcs []string
	for typ, err := range spec.All() {
		if err != nil {
			break
		}
		if f, ok := typ.(*btf.Func); ok {
			funcs = append(funcs, f.Name)
		}
	}

	if len(funcs) == 0 {
		return "", fmt.Errorf("program %q (id=%d): no btf.Func found in BTF", progName, progID)
	}

	// 2. Prefix match (prog name may be truncated to 15 chars by kernel)
	if len(progName) >= 15 {
		var matches []string
		for _, name := range funcs {
			if strings.HasPrefix(name, progName) {
				matches = append(matches, name)
			}
		}
		if len(matches) == 1 {
			return matches[0], nil
		}
		if len(matches) > 1 {
			return "", fmt.Errorf(
				"program %q (id=%d): ambiguous BTF function name (truncated prog name matches %d funcs: %v)",
				progName, progID, len(matches), matches,
			)
		}
	}

	// 3. Single Func
	if len(funcs) == 1 {
		return funcs[0], nil
	}

	// 4. Ambiguous
	return "", fmt.Errorf(
		"program %q (id=%d): cannot resolve entry function from BTF (%d candidates: %v)",
		progName, progID, len(funcs), funcs,
	)
}
