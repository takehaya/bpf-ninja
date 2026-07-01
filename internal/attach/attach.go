// Package attach finds existing XDP programs on network interfaces.
package attach

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

// ProgInfo holds information about an existing BPF program targeted
// by a probe. `Type` discriminates between XDP and tc clsact targets
// so callers can route to the correct host adapter.
type ProgInfo struct {
	ProgID    uint32
	Program   *ebpf.Program
	FuncName  string // BTF-resolved entry function name
	IfaceName string
	Type      ebpf.ProgramType
}

// FindXDPProgramByID gets an XDP program by its BPF program ID. The
// type check is strict: tc clsact programs are rejected here so that
// `--mode entry/exit` callers don't accidentally attach to a TC
// target. Use FindBPFProgramByID for the type-permissive variant the
// `--mode tc-*` paths consume.
func FindXDPProgramByID(progID uint32) (*ProgInfo, error) {
	info, err := FindBPFProgramByID(progID)
	if err != nil {
		return nil, err
	}
	if info.Type != ebpf.XDP {
		_ = info.Program.Close()
		return nil, fmt.Errorf("program (id=%d) is %s, expected XDP", progID, info.Type)
	}
	return info, nil
}

// FindBPFProgramByID gets a BPF program by ID, accepting XDP /
// SchedCLS / SchedACT — the program types xdp-ninja can attach a
// fentry/fexit probe to. Returns the resolved entry func name and the
// program type so the caller can route to the correct host adapter.
func FindBPFProgramByID(progID uint32) (*ProgInfo, error) {
	prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(progID))
	if err != nil {
		return nil, fmt.Errorf("getting program (id=%d): %w", progID, err)
	}

	progInfo, err := prog.Info()
	if err != nil {
		_ = prog.Close()
		return nil, fmt.Errorf("reading program info (id=%d): %w", progID, err)
	}
	progType := progInfo.Type
	if progType != ebpf.XDP && progType != ebpf.SchedCLS && progType != ebpf.SchedACT {
		_ = prog.Close()
		return nil, fmt.Errorf("program (id=%d) type %s is not supported (need XDP, SchedCLS, or SchedACT)", progID, progType)
	}

	funcName, err := resolveEntryFunc(prog, progID)
	if err != nil {
		_ = prog.Close()
		return nil, err
	}

	return &ProgInfo{
		ProgID:   progID,
		Program:  prog,
		FuncName: funcName,
		Type:     progType,
	}, nil
}

// ExistingXDP describes an XDP program already attached to an interface.
type ExistingXDP struct {
	ProgID uint32
	Mode   string // "skb", "driver", "offload", or "unknown"
}

// InterfaceState is what the --mode xdp startup path reads from a
// single netlink lookup: the kernel ifindex and any existing XDP
// attachment.
type InterfaceState struct {
	IfIndex  int
	Existing *ExistingXDP
}

// InspectInterface looks up the interface once and returns ifindex +
// any attached XDP, in a single LinkByName.
func InspectInterface(ifaceName string) (*InterfaceState, error) {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}

	state := &InterfaceState{
		IfIndex: link.Attrs().Index,
	}
	if xdp := link.Attrs().Xdp; xdp != nil && xdp.Attached && xdp.ProgId != 0 {
		state.Existing = &ExistingXDP{
			ProgID: xdp.ProgId,
			Mode:   xdpAttachModeName(xdp.AttachMode),
		}
	}
	return state, nil
}

// xdpAttachModeName maps the IFLA_XDP_ATTACHED enum to a label.
// LinkXdp.Flags is the *request* flags (UPDATE_IF_NOEXIST/SKB_MODE/
// DRV_MODE bitfield) — not what mode is actually attached.
func xdpAttachModeName(mode uint32) string {
	switch mode {
	case nl.XDP_ATTACHED_DRV:
		return "driver"
	case nl.XDP_ATTACHED_SKB:
		return "skb"
	case nl.XDP_ATTACHED_HW:
		return "offload"
	default:
		return "unknown"
	}
}

// FindXDPProgram finds the existing XDP program on the given interface.
func FindXDPProgram(ifaceName string) (*ProgInfo, error) {
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

	return &ProgInfo{
		ProgID:    xdp.ProgId,
		Program:   prog,
		FuncName:  funcName,
		IfaceName: ifaceName,
		Type:      ebpf.XDP,
	}, nil
}

// ProgTarget describes a program reachable from another program: a
// tail-call target in a PROG_ARRAY, or an XDP program attached to a
// CPUMAP / DEVMAP entry the program can bpf_redirect_map() into.
type ProgTarget struct {
	Via      string // "tailcall", "cpumap", "devmap", or "devmap_hash"
	Key      uint32 // map key: tail-call index, CPU id, or devmap key
	ProgID   uint32
	ProgName string
}

// ListReachablePrograms scans the maps referenced by prog for downstream
// programs: tail-call targets in PROG_ARRAY maps, plus XDP programs
// attached to CPUMAP / DEVMAP / DEVMAP_HASH entries (the redirect_map
// datapath). Entries without an attached program are skipped.
func ListReachablePrograms(prog *ebpf.Program) ([]ProgTarget, error) {
	info, err := prog.Info()
	if err != nil {
		return nil, fmt.Errorf("getting program info: %w", err)
	}

	mapIDs, ok := info.MapIDs()
	if !ok {
		return nil, nil
	}

	var targets []ProgTarget
	for _, mapID := range mapIDs {
		m, err := ebpf.NewMapFromID(mapID)
		if err != nil {
			return nil, fmt.Errorf("opening map %d: %w", mapID, err)
		}

		found, err := scanMapForPrograms(m, mapID)
		_ = m.Close()
		if err != nil {
			return nil, err
		}
		targets = append(targets, found...)
	}

	return targets, nil
}

// scanMapForPrograms extracts program targets from a single map, routing
// on its type. Non-dispatch maps yield nothing.
func scanMapForPrograms(m *ebpf.Map, mapID ebpf.MapID) ([]ProgTarget, error) {
	mapInfo, err := m.Info()
	if err != nil {
		return nil, fmt.Errorf("getting map %d info: %w", mapID, err)
	}

	switch mapInfo.Type {
	case ebpf.ProgramArray:
		return scanProgArray(m, mapID)
	case ebpf.CPUMap:
		return scanRedirectMap(m, mapID, "cpumap", mapInfo.KeySize, mapInfo.ValueSize)
	case ebpf.DevMap:
		return scanRedirectMap(m, mapID, "devmap", mapInfo.KeySize, mapInfo.ValueSize)
	case ebpf.DevMapHash:
		return scanRedirectMap(m, mapID, "devmap_hash", mapInfo.KeySize, mapInfo.ValueSize)
	default:
		return nil, nil
	}
}

// scanProgArray reads tail-call targets from a PROG_ARRAY. Values are the
// target program IDs. Array-backed maps enumerate every slot, so unset
// entries surface as id 0 and are skipped.
func scanProgArray(m *ebpf.Map, mapID ebpf.MapID) ([]ProgTarget, error) {
	var targets []ProgTarget
	var key, val uint32
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		if val == 0 {
			continue // empty tail-call slot
		}
		t, err := resolveProgTarget("tailcall", key, val)
		if err != nil {
			return nil, err
		}
		targets = append(targets, *t)
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating program array map %d: %w", mapID, err)
	}
	return targets, nil
}

// scanRedirectMap reads the downstream XDP program attached to each
// CPUMAP / DEVMAP entry. Both bpf_cpumap_val and bpf_devmap_val lay out
// the attached program id as the u32 at offset 4 (a union bpf_prog after
// a leading u32 qsize / ifindex). Maps created before that field existed
// have a 4-byte value and carry no program.
//
// CPUMAP, DEVMAP and DEVMAP_HASH all use 4-byte u32 keys (the kernel
// enforces key_size == 4). The key and value are read as raw byte
// buffers sized from the map info and decoded explicitly, so an
// unexpected key/value width can't silently truncate or misread.
func scanRedirectMap(m *ebpf.Map, mapID ebpf.MapID, via string, keySize, valueSize uint32) ([]ProgTarget, error) {
	const progIDOffset = 4
	if keySize < 4 || valueSize < progIDOffset+4 {
		return nil, nil
	}

	var targets []ProgTarget
	key := make([]byte, int(keySize))
	val := make([]byte, int(valueSize))
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		progID := binary.NativeEndian.Uint32(val[progIDOffset : progIDOffset+4])
		if progID == 0 {
			continue // entry has no attached program
		}
		mapKey := binary.NativeEndian.Uint32(key[:4])
		t, err := resolveProgTarget(via, mapKey, progID)
		if err != nil {
			return nil, err
		}
		targets = append(targets, *t)
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating %s map %d: %w", via, mapID, err)
	}
	return targets, nil
}

// resolveProgTarget opens the target program to read its name.
func resolveProgTarget(via string, key, progID uint32) (*ProgTarget, error) {
	targetProg, err := ebpf.NewProgramFromID(ebpf.ProgramID(progID))
	if err != nil {
		return nil, fmt.Errorf("opening %s target (id=%d): %w", via, progID, err)
	}
	defer func() { _ = targetProg.Close() }()

	targetInfo, err := targetProg.Info()
	if err != nil {
		return nil, fmt.Errorf("getting %s target info (id=%d): %w", via, progID, err)
	}

	return &ProgTarget{
		Via:      via,
		Key:      key,
		ProgID:   progID,
		ProgName: targetInfo.Name,
	}, nil
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
