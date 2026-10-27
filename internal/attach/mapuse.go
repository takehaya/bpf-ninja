package attach

import (
	"bufio"
	"errors"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// Map operations MapUse.Op reports besides helper names.
const (
	MapOpLookup   = "lookup"
	MapOpUpdate   = "update"
	MapOpDelete   = "delete"
	MapOpTailCall = "tail_call"
	MapOpRedirect = "redirect"
	MapOpValue    = "value" // direct access to a global variable's map value
	MapOpRef      = "ref"   // the operation is unknown, see ProgMaps.Note
)

// MapUse is one reference to a map in the translated instructions of a
// loaded program. Op names the helper the reference reaches; Inlined marks
// a lookup the verifier replaced with instructions, which leaves no call.
type MapUse struct {
	MapID   uint32
	MapName string
	MapType ebpf.MapType // zero when the map cannot be opened
	Op      string
	Inlined bool
	File    string
	Line    uint32
	PC      int
}

// FuncMaps is one BPF function of a loaded program: the functions it calls,
// the callbacks it passes to helpers such as bpf_loop, and its map uses.
type FuncMaps struct {
	Name      string
	Calls     []string
	Callbacks []string
	Maps      []MapUse
}

// ProgMaps is the per-function map use of one loaded program. Note says
// why the result is incomplete; it is empty when every op was resolved.
type ProgMaps struct {
	Funcs []FuncMaps
	Note  string
}

// KernelSymbols resolves the helper calls of translated instructions. The
// kernel dumps a call as its address minus __bpf_call_base, and only to
// callers allowed raw addresses (bpf_dump_raw_ok); the rest see zero.
type KernelSymbols struct {
	base  uint64
	names map[uint64]string
}

// LoadKernelSymbols reads /proc/kallsyms. Without the privilege to see
// addresses it returns an empty table, and every helper stays unresolved.
func LoadKernelSymbols() (*KernelSymbols, error) {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	syms := &KernelSymbols{names: map[uint64]string{}}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || (fields[1] != "t" && fields[1] != "T") {
			continue
		}
		addr, err := strconv.ParseUint(fields[0], 16, 64)
		if err != nil || addr == 0 {
			continue
		}
		if fields[2] == "__bpf_call_base" {
			syms.base = addr
		}
		syms.names[addr] = fields[2]
	}
	return syms, scanner.Err()
}

// helper names the kernel function a translated helper call reaches.
func (s *KernelSymbols) helper(imm int64) string {
	if s == nil || s.base == 0 || imm == 0 {
		return ""
	}
	return s.names[s.base+uint64(int64(int32(imm)))]
}

// ProgramMaps lists the map uses of each function of prog. Reading the
// translated instructions needs CAP_SYS_ADMIN for function names and raw
// addresses for helper ops; with less, the result says what is missing in
// Note instead of failing.
func ProgramMaps(prog *ebpf.Program, syms *KernelSymbols) (ProgMaps, error) {
	info, err := prog.Info()
	if err != nil {
		return ProgMaps{}, err
	}
	insns, err := info.Instructions()
	if err != nil {
		if errors.Is(err, ebpf.ErrNotSupported) || errors.Is(err, ebpf.ErrRestrictedKernel) {
			return ProgMaps{Note: "translated instructions are not readable; run as root"}, nil
		}
		return ProgMaps{}, err
	}
	maps := map[uint32]mapIdentity{}
	lookup := func(id uint32) mapIdentity {
		if m, ok := maps[id]; ok {
			return m
		}
		var m mapIdentity
		if opened, err := ebpf.NewMapFromID(ebpf.MapID(id)); err == nil {
			if mi, err := opened.Info(); err == nil {
				m = mapIdentity{mi.Name, mi.Type}
			}
			_ = opened.Close()
		}
		maps[id] = m
		return m
	}
	result := ProgMaps{Funcs: analyzeXlated(insns, info.Name, lookup, syms.helper)}
	if syms == nil || syms.base == 0 {
		// A map passed to a BPF function stays MapOpRef even with symbols.
		for _, fn := range result.Funcs {
			for _, use := range fn.Maps {
				if use.Op == MapOpRef {
					result.Note = "some ops are unknown: kernel addresses are hidden from this user (kptr_restrict); run as root"
				}
			}
		}
	}
	return result, nil
}

type mapIdentity struct {
	name string
	typ  ebpf.MapType
}

// inlinedLookupKinds are the map kinds whose lookup the verifier inlines
// without a call (map_gen_lookup), starting by adding to the map pointer.
var inlinedLookupKinds = map[ebpf.MapType]bool{ebpf.Array: true, ebpf.PerCPUArray: true, ebpf.ArrayOfMaps: true}

// analyzeXlated walks translated instructions. A map pointer loaded into a
// register reaches the next helper call in the same basic block: R1 for map
// helpers, R2 for bpf_tail_call. A pointer that is used otherwise keeps
// MapOpRef, except the arithmetic an inlined array lookup starts with.
func analyzeXlated(insns asm.Instructions, progName string, lookup func(uint32) mapIdentity, helper func(int64) string) []FuncMaps {
	starts := map[int]int{}
	var funcs []FuncMaps
	it := insns.Iterate()
	for it.Next() {
		if fn := btf.FuncMetadata(it.Ins); fn != nil {
			starts[int(it.Offset)] = len(funcs)
			funcs = append(funcs, FuncMaps{Name: fn.Name})
		}
	}
	if len(funcs) == 0 {
		// Without BTF the program is one function named after itself.
		starts[0], funcs = 0, []FuncMaps{{Name: progName}}
	}
	// pending maps a register to the index of the use it holds.
	pending := map[asm.Register]int{}
	cur := 0
	var file string
	var line uint32
	addCall := func(list []string, pc int, rel int64) []string {
		if i, ok := starts[pc+int(rel)+1]; ok && !slices.Contains(list, funcs[i].Name) {
			list = append(list, funcs[i].Name)
		}
		return list
	}
	it = insns.Iterate()
	for it.Next() {
		pc, ins := int(it.Offset), it.Ins
		if i, ok := starts[pc]; ok {
			cur, file, line = i, "", 0
			clear(pending)
		}
		if src, ok := ins.Source().(*btf.Line); ok {
			file, line = src.FileName(), src.LineNumber()
		}
		fn := &funcs[cur]
		switch {
		case ins.IsLoadFromMap():
			id := uint32(ins.Constant)
			m := lookup(id)
			use := MapUse{MapID: id, MapName: m.name, MapType: m.typ, Op: MapOpRef, File: file, Line: line, PC: pc}
			if ins.Src == asm.PseudoMapValue {
				use.Op = MapOpValue
			}
			fn.Maps = append(fn.Maps, use)
			delete(pending, ins.Dst)
			if use.Op == MapOpRef {
				pending[ins.Dst] = len(fn.Maps) - 1
			}
			continue
		case ins.OpCode == asm.LoadImmOp(asm.DWord) && ins.Src == asm.PseudoFunc:
			fn.Callbacks = addCall(fn.Callbacks, pc, int64(int32(ins.Constant)))
		case ins.IsFunctionCall():
			// JIT-ed programs dump the subprogram index in imm and the
			// relative target in off; the interpreter keeps it in imm.
			rel := int64(ins.Offset)
			if rel == 0 {
				rel = ins.Constant
			}
			fn.Calls = addCall(fn.Calls, pc, rel)
		case ins.IsBuiltinCall():
			reg, op := asm.R1, ""
			if ins.Constant == int64(asm.FnTailCall) {
				reg, op = asm.R2, MapOpTailCall
			} else {
				op = helperOp(helper(ins.Constant))
			}
			if i, ok := pending[reg]; ok && op != "" {
				fn.Maps[i].Op = op
			}
		}
		class := ins.OpCode.Class()
		switch {
		case class.IsJump():
			clear(pending)
		case class.IsALU() || class == asm.LdXClass || class == asm.LdClass:
			if i, ok := pending[ins.Dst]; ok {
				if class == asm.ALU64Class && ins.OpCode.ALUOp() == asm.Add && inlinedLookupKinds[fn.Maps[i].MapType] {
					fn.Maps[i].Op, fn.Maps[i].Inlined = MapOpLookup, true
				}
				delete(pending, ins.Dst)
			}
		}
	}
	return funcs
}

// helperOp maps a kernel function a helper call reaches to a map operation.
// The verifier calls map ops directly (htab_map_update_elem,
// trie_lookup_elem, __htab_map_lookup_elem for an inlined hash lookup), so
// the name says what the call does; other helpers keep their own name.
func helperOp(sym string) string {
	switch {
	case sym == "":
		return ""
	case strings.Contains(sym, "lookup"):
		return MapOpLookup
	case strings.Contains(sym, "update"):
		return MapOpUpdate
	case strings.Contains(sym, "delete"):
		return MapOpDelete
	case strings.Contains(sym, "redirect"):
		return MapOpRedirect
	}
	return strings.TrimPrefix(sym, "bpf_")
}
