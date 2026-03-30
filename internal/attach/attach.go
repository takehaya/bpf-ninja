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
		prog.Close()
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
		prog.Close()
		return nil, err
	}

	return &XDPInfo{
		ProgID:    xdp.ProgId,
		Program:   prog,
		FuncName:  funcName,
		IfaceName: ifaceName,
	}, nil
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

	handle, err := prog.Handle()
	if err != nil {
		return "", fmt.Errorf("program %q (id=%d): BTF unavailable (required for fentry/fexit): %w", progName, progID, err)
	}
	defer handle.Close()

	spec, err := handle.Spec(nil)
	if err != nil {
		return "", fmt.Errorf("program %q (id=%d): reading BTF: %w", progName, progID, err)
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
