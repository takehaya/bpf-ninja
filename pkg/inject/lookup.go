package inject

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// LookupSite describes a map_lookup_elem helper in a flattened XDP program.
// Empty names or zero Line mean the ELF did not supply that information.
// Reason explains why a site cannot be injected; discovery still lists it.
type LookupSite struct {
	MapName          string
	KeyTypeName      string
	ValueTypeName    string
	FuncName         string
	File             string
	Line             uint32
	SitePC           uint32 // raw BPF slot index; LDIMM64 occupies two slots
	InstructionIndex int    // index in ProgramSpec.Instructions
	Reason           string
}

// LookupSelector identifies lookups of one map. FuncName and Line optionally
// filter the containing BTF function and effective BTF line_info. By default
// exactly one site must match.
type LookupSelector struct {
	MapName  string
	FuncName string
	Line     uint32
	// SitePCs selects explicit raw PCs, each of which must also match the filters.
	// Empty means unspecified; duplicates and missing PCs are refused.
	SitePCs []uint32
	// AllMatches selects every matching site. Mutually exclusive with SitePCs.
	AllMatches bool
}

// LookupRequest describes one hash-bound lookup transformation. Only sites in
// the entry function are supported: subprograms have independent stack frames.
// Stack certifies three reserved slots, including aliases and callee stacks.
// No caller-saved register liveness certification is required at helper calls.
type LookupRequest struct {
	ELFSHA256   string
	ProgramName string
	Site        LookupSelector
	HookName    string
	Stack       StackAudit
}

// LookupResult reports the selected original sites and the transformed clone.
// Result.InsertedAt is zero (the ctx spill); InsertedSlots includes that spill,
// the lookup instrumentation and generated hook. Checksums have Result's scope.
type LookupResult struct {
	Result
	Site  LookupSite   // first selected site, retained for single-site callers
	Sites []LookupSite // all selected sites in original instruction order
}

// DiscoverLookups lists every map_lookup_elem helper in programName, in raw
// instruction order, without loading BPF or requiring a stack audit. It resolves
// only direct R1 map loads in the same basic block. Unsupported relocation
// shapes refuse the listing. Callback loads must reference subprogram starts.
// Unresolved maps and unsupported sites get Reason.
func DiscoverLookups(elf []byte, programName string) ([]LookupSite, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bytes.Clone(elf)))
	if err != nil {
		return nil, fmt.Errorf("inject: parsing ELF: %w", err)
	}
	return discoverLookups(spec, programName)
}

// TransformLookup inserts int HOOK(struct xdp_md *ctx, const KEY *key,
// const VALUE *value) at each selected lookup and returns an independent clone.
// The hook is called only for non-null results. This never loads or attaches BPF.
func TransformLookup(elf []byte, req LookupRequest) (*LookupResult, error) {
	// Reuse the existing hash/name/stack validation, without its load contract.
	if err := validateRequest(Request{ELFSHA256: req.ELFSHA256, ProgramName: req.ProgramName,
		HookName: req.HookName, Stack: req.Stack, Load: LoadShape{PtrReg: asm.R0}}); err != nil {
		return nil, err
	}
	if req.Site.MapName == "" {
		return nil, refuse("lookup MapName is required")
	}
	elf = bytes.Clone(elf)
	sum := sha256.Sum256(elf)
	want, _ := hex.DecodeString(req.ELFSHA256)
	if !bytes.Equal(sum[:], want) {
		return nil, refuse("ELF hash %x does not match audited %s", sum, req.ELFSHA256)
	}
	src, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(elf))
	if err != nil {
		return nil, fmt.Errorf("inject: parsing ELF: %w", err)
	}
	work := src.Copy()
	sites, err := transformLookup(work, req)
	if err != nil {
		return nil, err
	}
	before, after := src.Programs[req.ProgramName].Instructions, work.Programs[req.ProgramName].Instructions
	sourceSum, err := checksum(before, src.ByteOrder)
	if err != nil {
		return nil, fmt.Errorf("inject: checksumming source: %w", err)
	}
	resultSum, err := checksum(after, work.ByteOrder)
	if err != nil {
		return nil, fmt.Errorf("inject: checksumming result: %w", err)
	}
	added := int(after.Size() - before.Size())
	return &LookupResult{Result: Result{Spec: work, HookName: req.HookName,
		SourceChecksum: sourceSum, TransformedChecksum: resultSum,
		InsertedAt: 0, InsertedSlots: added / asm.InstructionSize, AddedBytes: added}, Site: sites[0], Sites: sites}, nil
}

func discoverLookups(spec *ebpf.CollectionSpec, name string) ([]LookupSite, error) {
	prog := spec.Programs[name]
	if prog == nil {
		return nil, refuse("program %q not found", name)
	}
	if prog.Type != ebpf.XDP {
		return nil, refuse("only native XDP programs are supported")
	}
	indices := make(map[int]int)
	it := prog.Instructions.Iterate()
	for it.Next() {
		indices[int(it.Offset)] = it.Index
	}
	starts := map[int]bool{0: true}
	it = prog.Instructions.Iterate()
	for it.Next() {
		pc, ins := int(it.Offset), it.Ins
		if btf.FuncMetadata(ins) != nil {
			starts[pc] = true
		}
		target, relative, _, err := relocTarget(ins, pc, indices, prog.Instructions)
		if err != nil {
			return nil, err
		}
		if relative {
			starts[target] = true
		}
		if ins.OpCode.Class().IsJump() {
			starts[pc+1] = true
		}
	}
	var sites []LookupSite
	var mapName, funcName, file string
	var line uint32
	funcStart := -1
	it = prog.Instructions.Iterate()
	for it.Next() {
		pc, ins := int(it.Offset), it.Ins
		if starts[pc] {
			mapName = ""
		}
		if fn := btf.FuncMetadata(ins); fn != nil {
			funcName, funcStart, file, line = fn.Name, pc, "", 0
		}
		if src, ok := ins.Source().(*btf.Line); ok {
			file, line = src.FileName(), src.LineNumber()
		}
		if ins.IsBuiltinCall() && ins.Constant == int64(asm.FnMapLookupElem) {
			site := LookupSite{MapName: mapName, FuncName: funcName, File: file, Line: line,
				SitePC: uint32(pc), InstructionIndex: it.Index}
			m := spec.Maps[mapName]
			if m != nil {
				site.KeyTypeName, site.ValueTypeName = lookupTypeName(m.Key), lookupTypeName(m.Value)
			}
			switch {
			case mapName == "":
				site.Reason = "R1 is not a direct map reference in this basic block"
			case m == nil:
				site.Reason = "map reference is not defined in the collection"
			case funcStart != 0:
				site.Reason = "lookup is not in the entry function; ctx belongs to another stack frame"
			default:
				if err := checkLookupMap(m); err != nil {
					site.Reason = err.Error()
				}
			}
			sites = append(sites, site)
		}
		// Track direct R1 definitions only; calls also clobber R1. Atomic
		// operations and legacy packet loads are conservatively barriers.
		class := ins.OpCode.Class()
		if class.IsJump() || (class == asm.LdClass && (ins.OpCode != asm.LoadImmOp(asm.DWord) || ins.Dst == asm.R1)) ||
			((class.IsALU() || class == asm.LdXClass) && ins.Dst == asm.R1) ||
			(class == asm.StXClass && ins.OpCode.Mode() == asm.AtomicMode) {
			mapName = ""
		}
		if ins.IsLoadFromMap() && ins.Src == asm.PseudoMapFD && ins.Dst == asm.R1 {
			mapName = ins.Reference()
		}
	}
	return sites, nil
}

func lookupTypeName(t btf.Type) string {
	if t == nil {
		return ""
	}
	if name := t.TypeName(); name != "" {
		return name
	}
	return btf.UnderlyingType(t).TypeName()
}

func checkLookupMap(m *ebpf.MapSpec) error {
	// These maps return ordinary value memory. Other map kinds can return
	// special objects (notably map-in-map), so do not infer their pointer ABI.
	switch m.Type {
	case ebpf.Hash, ebpf.Array, ebpf.PerCPUHash, ebpf.PerCPUArray, ebpf.LRUHash, ebpf.LRUCPUHash:
	default:
		return refuse("map type %s is unsupported", m.Type)
	}
	for _, field := range []struct {
		name string
		typ  btf.Type
		size uint32
	}{{"key", m.Key, m.KeySize}, {"value", m.Value, m.ValueSize}} {
		if field.typ == nil {
			return refuse("map %s BTF is missing", field.name)
		}
		size, err := btf.Sizeof(field.typ)
		if err != nil || size <= 0 || uint64(size) != uint64(field.size) {
			return refuse("map %s BTF size does not match map size %d", field.name, field.size)
		}
		if s, ok := btf.UnderlyingType(field.typ).(*btf.Struct); ok && (s.Name == "xdp_md" || s.Name == "bpf_dynptr") {
			return refuse("map %s type %q has a special global-function pointer ABI", field.name, s.Name)
		}
	}
	return nil
}

func transformLookup(work *ebpf.CollectionSpec, req LookupRequest) ([]LookupSite, error) {
	var selected []LookupSite
	if req.Site.MapName == "" {
		return nil, refuse("lookup MapName is required")
	}
	if req.Site.AllMatches && len(req.Site.SitePCs) != 0 {
		return nil, refuse("SitePCs and AllMatches are mutually exclusive")
	}
	pcs := make(map[uint32]bool, len(req.Site.SitePCs))
	for _, pc := range req.Site.SitePCs {
		if pcs[pc] {
			return nil, refuse("duplicate SitePC %d", pc)
		}
		pcs[pc] = true
	}
	sites, err := discoverLookups(work, req.ProgramName)
	if err != nil {
		return nil, err
	}
	for _, site := range sites {
		if site.MapName == req.Site.MapName && (req.Site.FuncName == "" || site.FuncName == req.Site.FuncName) &&
			(req.Site.Line == 0 || site.Line == req.Site.Line) && (len(pcs) == 0 || pcs[site.SitePC]) {
			selected = append(selected, site)
		}
	}
	if len(pcs) != 0 && len(selected) != len(pcs) {
		return nil, refuse("every SitePC must identify a lookup matching MapName/FuncName/Line")
	}
	if len(selected) == 0 || (!req.Site.AllMatches && len(pcs) == 0 && len(selected) != 1) {
		return nil, refuse("lookup selector matches %d sites, need exactly one unless SitePCs or AllMatches is set", len(selected))
	}
	var sitePCs []uint32
	for _, site := range selected {
		if site.Reason != "" {
			return nil, refuse("lookup at %d: %s", site.SitePC, site.Reason)
		}
		sitePCs = append(sitePCs, site.SitePC)
	}
	prog := work.Programs[req.ProgramName]
	for _, check := range []func() error{
		func() error { return checkNoCollision(work, req.HookName) },
		func() error { return checkReferences(work, prog, req.HookName) },
		func() error { return checkExtInfo(prog.Instructions) },
		func() error { return checkStackBound(prog.Instructions, req.Stack.LowestOffset) },
	} {
		if err := check(); err != nil {
			return selected, err
		}
	}
	fn := btf.FuncMetadata(&prog.Instructions[0])
	proto, ok := fn.Type.(*btf.FuncProto)
	if !ok || len(proto.Params) != 1 {
		return selected, refuse("entry BTF must take one struct xdp_md pointer")
	}
	ctx, ok := btf.UnderlyingType(proto.Params[0].Type).(*btf.Pointer)
	if !ok {
		return selected, refuse("entry BTF context is not a pointer")
	}
	ctxStruct, ok := btf.UnderlyingType(ctx.Target).(*btf.Struct)
	if !ok || ctxStruct.Name != "xdp_md" {
		return selected, refuse("entry BTF context is not struct xdp_md")
	}
	spliced, err := spliceLookup(prog.Instructions, sitePCs, req)
	if err != nil {
		return selected, err
	}
	m := work.Maps[req.Site.MapName]
	prog.Instructions = appendLookupHook(spliced, req.HookName, proto.Params[0].Type, m.Key, m.Value)
	return selected, nil
}

func spliceLookup(input asm.Instructions, sitePCs []uint32, req LookupRequest) (asm.Instructions, error) {
	if req.Stack.LowestOffset < -512 || req.Stack.LowestOffset > 0 {
		return nil, refuse("StackAudit.LowestOffset must be in [-512, 0]")
	}
	ctx, key, err := spillSlots(req.Stack.LowestOffset)
	if err != nil {
		return nil, err
	}
	result := int(key) - 8
	if result < -512 {
		return nil, refuse("three lookup spill slots exceed the 512-byte stack")
	}
	spillR0 := int16(result)
	null := asm.JEq.Imm(asm.R0, 0, "")
	null.Offset = 4 // skip argument setup and hook; restore R0 on both paths
	after := asm.Instructions{
		asm.StoreMem(asm.RFP, spillR0, asm.R0, asm.DWord), null,
		asm.LoadMem(asm.R1, asm.RFP, ctx, asm.DWord),
		asm.LoadMem(asm.R2, asm.RFP, key, asm.DWord),
		asm.Mov.Reg(asm.R3, asm.R0), asm.Call.Label(req.HookName),
		asm.LoadMem(asm.R0, asm.RFP, spillR0, asm.DWord),
	}
	sites := make(map[uint32]bool, len(sitePCs))
	for _, pc := range sitePCs {
		sites[pc] = true
	}
	indices, mapped := map[int]int{}, map[int]int{}
	pc := 1 // entry ctx spill
	it := input.Iterate()
	for it.Next() {
		old := int(it.Offset)
		indices[old], mapped[old] = it.Index, pc
		if sites[uint32(old)] {
			pc++ // branch to helper must execute the key spill first
		}
		pc += int(it.Ins.Size() / asm.InstructionSize)
		if sites[uint32(old)] {
			pc += len(after)
		}
	}
	entry := btf.WithFuncMetadata(asm.StoreMem(asm.RFP, ctx, asm.R1, asm.DWord).
		WithSymbol(input[0].Symbol()).WithSource(input[0].Source()), btf.FuncMetadata(&input[0]))
	out := asm.Instructions{entry}
	it = input.Iterate()
	for it.Next() {
		old, ins := int(it.Offset), *it.Ins
		if ins.IsFunctionCall() && ins.Reference() != "" && ins.Reference() == input[0].Symbol() {
			return nil, refuse("call to program entry is unsupported")
		}
		newPC := mapped[old]
		if sites[uint32(old)] {
			out = append(out, asm.StoreMem(asm.RFP, key, asm.R2, asm.DWord))
			newPC++
		}
		target, relative, function, err := relocTarget(&ins, old, indices, input)
		if err != nil {
			return nil, err
		}
		if relative {
			if function && target == 0 {
				return nil, refuse("call to program entry is unsupported")
			}
			// A branch to original slot zero skips the one-time ctx spill.
			if err := relocateOffset(&ins, newPC, mapped[target], function); err != nil {
				return nil, err
			}
		}
		if old == 0 {
			ins = btf.WithFuncMetadata(ins.WithSymbol(""), nil)
		}
		out = append(out, ins)
		if sites[uint32(old)] {
			out = append(out, after...)
		}
	}
	return out, nil
}

func appendLookupHook(insns asm.Instructions, name string, ctx, key, value btf.Type) asm.Instructions {
	fn := &btf.Func{Name: name, Linkage: btf.GlobalFunc, Type: &btf.FuncProto{
		Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed},
		Params: []btf.FuncParam{
			{Name: "ctx", Type: ctx},
			{Name: "key", Type: &btf.Pointer{Target: &btf.Const{Type: key}}},
			{Name: "value", Type: &btf.Pointer{Target: &btf.Const{Type: value}}},
		},
	}}
	// Global functions are verified independently with nullable memory args.
	// Actual reads keep every argument live, even after dead-register pruning.
	head := btf.WithFuncMetadata(asm.LoadMem(asm.R0, asm.R1, 0, asm.Word).WithSymbol(name).
		WithSource(asm.Comment("generated lookup observation hook "+name)), fn)
	keyNull, valueNull := asm.JEq.Imm(asm.R2, 0, ""), asm.JEq.Imm(asm.R3, 0, "")
	keyNull.Offset, valueNull.Offset = 1, 1
	return append(insns, head, keyNull, asm.LoadMem(asm.R0, asm.R2, 0, asm.Byte),
		valueNull, asm.LoadMem(asm.R0, asm.R3, 0, asm.Byte),
		asm.Mov.Imm(asm.R0, 0), asm.Return())
}
