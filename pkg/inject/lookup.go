package inject

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// LookupSite describes a map_lookup_elem helper in a flattened XDP program.
// Empty names or zero Line mean the input did not supply that information.
// Reason explains why a site cannot be injected; discovery still lists it.
type LookupSite struct {
	MapName          string
	KeyTypeName      string
	ValueTypeName    string
	FuncName         string
	File             string
	Line             uint32
	SitePC           uint32 // raw BPF slot index; LDIMM64 occupies two slots
	InstructionIndex int    // index in the decoded instruction slice
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
//
// Auto instruments every supported lookup instead of Site, which must then be
// empty. HookName becomes a prefix: each map identity gets its own hook,
// int PREFIX_MAP(struct xdp_md *ctx, u32 site, const KEY *key, const VALUE *value),
// where site is the original SitePC. Unsupported sites are reported in
// Skipped instead of refusing the transform.
type LookupRequest struct {
	ELFSHA256   string
	ProgramName string
	Site        LookupSelector
	Auto        bool
	HookName    string
	Stack       StackAudit
}

// LookupHook is one generated hook and the sites that call it, in original
// instruction order. TypeID and FuncInfo are set by TransformLookupRaw only.
type LookupHook struct {
	Name     string
	MapName  string
	Sites    []LookupSite
	TypeID   btf.TypeID
	FuncInfo []byte
}

// LookupResult reports the selected original sites and the transformed clone.
// Result.InsertedAt is zero (the ctx spill); InsertedSlots includes that spill,
// the lookup instrumentation and generated hooks. Checksums have Result's scope.
type LookupResult struct {
	Result
	Site    LookupSite   // first selected site, retained for single-site callers
	Sites   []LookupSite // all selected sites in original instruction order
	Hooks   []LookupHook // one hook, or one per map identity with Auto
	Skipped []LookupSite // with Auto, discovered sites that were not instrumented
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
	plan, err := transformLookup(work, req)
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
		InsertedAt: 0, InsertedSlots: added / asm.InstructionSize, AddedBytes: added},
		Site: plan.sites[0], Sites: plan.sites, Hooks: plan.hooks, Skipped: plan.skipped}, nil
}

func discoverLookups(spec *ebpf.CollectionSpec, name string) ([]LookupSite, error) {
	prog := spec.Programs[name]
	if prog == nil {
		return nil, refuse("program %q not found", name)
	}
	sites, err := discoverLookupProgram(prog.Instructions, prog.Type, elfLookupMaps(spec))
	return publicLookupSites(sites), err
}

// lookupMapResolver returns identity separately from the selectable map name.
type lookupMapResolver func(*asm.Instruction) (string, *RawMap)

type discoveredLookup struct {
	LookupSite
	mapID   string
	mapInfo *RawMap
}

func publicLookupSites(sites []discoveredLookup) []LookupSite {
	var result []LookupSite
	for _, site := range sites {
		result = append(result, site.LookupSite)
	}
	return result
}

func elfLookupMaps(spec *ebpf.CollectionSpec) lookupMapResolver {
	return func(ins *asm.Instruction) (string, *RawMap) {
		name := ins.Reference()
		m := spec.Maps[name]
		if m == nil {
			return name, nil
		}
		return name, &RawMap{Name: name, Type: m.Type, KeySize: m.KeySize, ValueSize: m.ValueSize, Key: m.Key, Value: m.Value}
	}
}

func discoverLookupProgram(insns asm.Instructions, typ ebpf.ProgramType, resolve lookupMapResolver) ([]discoveredLookup, error) {
	if typ != ebpf.XDP {
		return nil, refuse("only native XDP programs are supported")
	}
	indices := make(map[int]int)
	it := insns.Iterate()
	for it.Next() {
		indices[int(it.Offset)] = it.Index
	}
	starts := map[int]bool{0: true}
	it = insns.Iterate()
	for it.Next() {
		pc, ins := int(it.Offset), it.Ins
		if btf.FuncMetadata(ins) != nil {
			starts[pc] = true
		}
		target, relative, _, err := relocTarget(ins, pc, indices, insns)
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
	var sites []discoveredLookup
	var mapID, mapName, funcName, file string
	var m *RawMap
	var line uint32
	funcStart := -1
	it = insns.Iterate()
	for it.Next() {
		pc, ins := int(it.Offset), it.Ins
		if starts[pc] {
			mapID, mapName, m = "", "", nil
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
			if m != nil {
				site.KeyTypeName, site.ValueTypeName = lookupTypeName(m.Key), lookupTypeName(m.Value)
			}
			switch {
			case mapID == "":
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
			sites = append(sites, discoveredLookup{site, mapID, m})
		}
		// Track direct R1 definitions only; calls also clobber R1. Atomic
		// operations and legacy packet loads are conservatively barriers.
		class := ins.OpCode.Class()
		if class.IsJump() || (class == asm.LdClass && (ins.OpCode != asm.LoadImmOp(asm.DWord) || ins.Dst == asm.R1)) ||
			((class.IsALU() || class == asm.LdXClass) && ins.Dst == asm.R1) ||
			(class == asm.StXClass && ins.OpCode.Mode() == asm.AtomicMode) {
			mapID, mapName, m = "", "", nil
		}
		if ins.IsLoadFromMap() && ins.Src == asm.PseudoMapFD && ins.Dst == asm.R1 {
			mapID, m = resolve(ins)
			mapName = ins.Reference()
			if m != nil {
				mapName = m.Name
			}
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

func checkLookupMap(m *RawMap) error {
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

// lookupPlan is what transformLookupProgram selected and generated.
type lookupPlan struct {
	sites   []LookupSite
	hooks   []LookupHook
	skipped []LookupSite
}

func transformLookup(work *ebpf.CollectionSpec, req LookupRequest) (lookupPlan, error) {
	prog := work.Programs[req.ProgramName]
	if prog == nil {
		return lookupPlan{}, refuse("program %q not found", req.ProgramName)
	}
	out, plan, err := transformLookupProgram(prog.Instructions, prog.Type, work.Types, elfLookupMaps(work), req)
	if err != nil {
		return plan, err
	}
	for _, hook := range plan.hooks {
		if err := checkNoCollision(work, hook.Name); err != nil {
			return plan, err
		}
	}
	prog.Instructions = out
	return plan, nil
}

// lookupGroup is one generated hook and its selected sites.
type lookupGroup struct {
	name  string
	sites []discoveredLookup
}

func selectLookups(sites []discoveredLookup, req LookupRequest) ([]lookupGroup, []LookupSite, error) {
	if req.Auto {
		if req.Site.MapName != "" || req.Site.FuncName != "" || req.Site.Line != 0 || len(req.Site.SitePCs) != 0 || req.Site.AllMatches {
			return nil, nil, refuse("Auto selects every supported lookup; Site must be empty")
		}
		var groups []lookupGroup
		var skipped []LookupSite
		index := map[string]int{}
		for _, site := range sites {
			if site.Reason != "" {
				skipped = append(skipped, site.LookupSite)
				continue
			}
			i, ok := index[site.mapID]
			if !ok {
				i = len(groups)
				index[site.mapID] = i
				groups = append(groups, lookupGroup{})
			}
			groups[i].sites = append(groups[i].sites, site)
		}
		if len(groups) == 0 {
			return nil, skipped, refuse("no supported lookup sites (%d skipped)", len(skipped))
		}
		used := map[string]bool{}
		for i := range groups {
			groups[i].name = autoHookName(req.HookName, groups[i].sites[0].MapName, i, used)
		}
		return groups, skipped, nil
	}
	if req.Site.MapName == "" {
		return nil, nil, refuse("lookup MapName is required")
	}
	if req.Site.AllMatches && len(req.Site.SitePCs) != 0 {
		return nil, nil, refuse("SitePCs and AllMatches are mutually exclusive")
	}
	pcs := make(map[uint32]bool, len(req.Site.SitePCs))
	for _, pc := range req.Site.SitePCs {
		if pcs[pc] {
			return nil, nil, refuse("duplicate SitePC %d", pc)
		}
		pcs[pc] = true
	}
	var selected []discoveredLookup
	for _, site := range sites {
		if site.MapName == req.Site.MapName && (req.Site.FuncName == "" || site.FuncName == req.Site.FuncName) &&
			(req.Site.Line == 0 || site.Line == req.Site.Line) && (len(pcs) == 0 || pcs[site.SitePC]) {
			selected = append(selected, site)
		}
	}
	if len(pcs) != 0 && len(selected) != len(pcs) {
		return nil, nil, refuse("every SitePC must identify a lookup matching MapName/FuncName/Line")
	}
	if len(selected) == 0 || (!req.Site.AllMatches && len(pcs) == 0 && len(selected) != 1) {
		return nil, nil, refuse("lookup selector matches %d sites, need exactly one unless SitePCs or AllMatches is set", len(selected))
	}
	for _, site := range selected {
		if site.Reason != "" {
			return nil, nil, refuse("lookup at %d: %s", site.SitePC, site.Reason)
		}
		if site.mapID != selected[0].mapID {
			return nil, nil, refuse("selected lookups refer to different map identities")
		}
	}
	return []lookupGroup{{name: req.HookName, sites: selected}}, nil, nil
}

// autoHookName derives PREFIX_MAP, falling back to PREFIX_<index> when the
// map name does not make a valid, unused identifier.
func autoHookName(prefix, mapName string, index int, used map[string]bool) string {
	var b strings.Builder
	for _, r := range mapName {
		if r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	name := prefix + "_" + b.String()
	if b.Len() == 0 || !validIdent(name) || used[name] {
		name = fmt.Sprintf("%s_%d", prefix, index)
	}
	for used[name] {
		name += "_"
	}
	used[name] = true
	return name
}

func transformLookupProgram(insns asm.Instructions, typ ebpf.ProgramType, types *btf.Spec, resolve lookupMapResolver, req LookupRequest) (asm.Instructions, lookupPlan, error) {
	var plan lookupPlan
	if !req.Auto && req.Site.MapName == "" {
		return nil, plan, refuse("lookup MapName is required")
	}
	sites, err := discoverLookupProgram(insns, typ, resolve)
	if err != nil {
		return nil, plan, err
	}
	groups, skipped, err := selectLookups(sites, req)
	plan.skipped = skipped
	if err != nil {
		return nil, plan, err
	}
	var selected []discoveredLookup
	for _, group := range groups {
		selected = append(selected, group.sites...)
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].SitePC < selected[j].SitePC })
	plan.sites = publicLookupSites(selected)
	checks := []func() error{
		func() error { return checkExtInfo(insns) },
		func() error { return checkStackBound(insns, req.Stack.LowestOffset) },
	}
	for _, group := range groups {
		name := group.name
		checks = append(checks,
			func() error { return checkInstructionCollision(insns, name) },
			func() error { return checkBTFCollision(types, name) },
			func() error {
				return checkInstructionReferences(insns, name, func(ins *asm.Instruction) bool { _, m := resolve(ins); return m != nil })
			})
	}
	for _, check := range checks {
		if err := check(); err != nil {
			return nil, plan, err
		}
	}
	fn := btf.FuncMetadata(&insns[0])
	proto, ok := fn.Type.(*btf.FuncProto)
	if !ok || len(proto.Params) != 1 {
		return nil, plan, refuse("entry BTF must take one struct xdp_md pointer")
	}
	ctx, ok := btf.UnderlyingType(proto.Params[0].Type).(*btf.Pointer)
	if !ok {
		return nil, plan, refuse("entry BTF context is not a pointer")
	}
	ctxStruct, ok := btf.UnderlyingType(ctx.Target).(*btf.Struct)
	if !ok || ctxStruct.Name != "xdp_md" {
		return nil, plan, refuse("entry BTF context is not struct xdp_md")
	}
	var hooks asm.Instructions
	calls := map[uint32]siteCall{}
	for _, group := range groups {
		m := group.sites[0].mapInfo
		hooks = append(hooks, lookupHook(group.name, proto.Params[0].Type, m.Key, m.Value, req.Auto)...)
		hook := LookupHook{Name: group.name, MapName: group.sites[0].MapName, Sites: publicLookupSites(group.sites)}
		plan.hooks = append(plan.hooks, hook)
		for _, site := range group.sites {
			calls[site.SitePC] = siteCall{hook: group.name, withSite: req.Auto}
		}
	}
	spliced, err := spliceLookupCalls(insns, calls, req.Stack, hooks)
	if err != nil {
		return nil, plan, err
	}
	return spliced, plan, nil
}

// siteCall is the hook a lookup site calls, and whether it passes its SitePC.
type siteCall struct {
	hook     string
	withSite bool
}

func spliceLookup(input asm.Instructions, sitePCs []uint32, req LookupRequest) (asm.Instructions, error) {
	calls := make(map[uint32]siteCall, len(sitePCs))
	for _, pc := range sitePCs {
		calls[pc] = siteCall{hook: req.HookName}
	}
	return spliceLookupCalls(input, calls, req.Stack, nil)
}

func spliceLookupCalls(input asm.Instructions, calls map[uint32]siteCall, stack StackAudit, hook asm.Instructions) (asm.Instructions, error) {
	if stack.LowestOffset < -512 || stack.LowestOffset > 0 {
		return nil, refuse("StackAudit.LowestOffset must be in [-512, 0]")
	}
	ctx, key, err := spillSlots(stack.LowestOffset)
	if err != nil {
		return nil, err
	}
	result := int(key) - 8
	if result < -512 {
		return nil, refuse("three lookup spill slots exceed the 512-byte stack")
	}
	spillR0 := int16(result)
	// Every site of every hook shares the three slots: sites run one at a time.
	afterFor := func(pc uint32, call siteCall) asm.Instructions {
		args := asm.Instructions{asm.LoadMem(asm.R1, asm.RFP, ctx, asm.DWord)}
		if call.withSite {
			args = append(args, asm.Mov.Imm32(asm.R2, int32(pc)),
				asm.LoadMem(asm.R3, asm.RFP, key, asm.DWord), asm.Mov.Reg(asm.R4, asm.R0))
		} else {
			args = append(args, asm.LoadMem(asm.R2, asm.RFP, key, asm.DWord), asm.Mov.Reg(asm.R3, asm.R0))
		}
		args = append(args, asm.Call.Label(call.hook))
		null := asm.JEq.Imm(asm.R0, 0, "")
		null.Offset = int16(len(args)) // skip argument setup and hook; restore R0 on both paths
		out := asm.Instructions{asm.StoreMem(asm.RFP, spillR0, asm.R0, asm.DWord), null}
		out = append(out, args...)
		return append(out, asm.LoadMem(asm.R0, asm.RFP, spillR0, asm.DWord))
	}
	after := make(map[uint32]asm.Instructions, len(calls))
	for pc, call := range calls {
		after[pc] = afterFor(pc, call)
	}
	sites := make(map[uint32]bool, len(calls))
	for pc := range calls {
		sites[pc] = true
	}
	hookSlots := int(hook.Size() / asm.InstructionSize)
	hookAt := -1
	indices, mapped := map[int]int{}, map[int]int{}
	pc := 1 // entry ctx spill
	it := input.Iterate()
	for it.Next() {
		old := int(it.Offset)
		if hookAt < 0 && old > 0 && btf.FuncMetadata(it.Ins) != nil {
			hookAt = old
			pc += hookSlots
		}
		indices[old], mapped[old] = it.Index, pc
		if sites[uint32(old)] {
			pc++ // branch to helper must execute the key spill first
		}
		pc += int(it.Ins.Size() / asm.InstructionSize)
		if sites[uint32(old)] {
			pc += len(after[uint32(old)])
		}
	}
	entry := btf.WithFuncMetadata(asm.StoreMem(asm.RFP, ctx, asm.R1, asm.DWord).
		WithSymbol(input[0].Symbol()).WithSource(input[0].Source()), btf.FuncMetadata(&input[0]))
	out := asm.Instructions{entry}
	it = input.Iterate()
	for it.Next() {
		old, ins := int(it.Offset), *it.Ins
		if old == hookAt {
			out = append(out, hook...)
		}
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
			out = append(out, after[uint32(old)]...)
		}
	}
	if hookAt < 0 {
		out = append(out, hook...)
	}
	return out, nil
}

func lookupHook(name string, ctx, key, value btf.Type, withSite bool) asm.Instructions {
	params := []btf.FuncParam{{Name: "ctx", Type: ctx}}
	keyReg, valueReg := asm.R2, asm.R3
	if withSite {
		params = append(params, btf.FuncParam{Name: "site", Type: &btf.Int{Name: "u32", Size: 4}})
		keyReg, valueReg = asm.R3, asm.R4
	}
	params = append(params,
		btf.FuncParam{Name: "key", Type: &btf.Pointer{Target: &btf.Const{Type: key}}},
		btf.FuncParam{Name: "value", Type: &btf.Pointer{Target: &btf.Const{Type: value}}})
	fn := &btf.Func{Name: name, Linkage: btf.GlobalFunc, Type: &btf.FuncProto{
		Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}, Params: params,
	}}
	// Global functions are verified independently with nullable memory args.
	// Actual reads keep every argument live, even after dead-register pruning.
	head := btf.WithFuncMetadata(asm.LoadMem(asm.R0, asm.R1, 0, asm.Word).WithSymbol(name).
		WithSource(asm.Comment("generated lookup observation hook "+name)), fn)
	keyNull, valueNull := asm.JEq.Imm(keyReg, 0, ""), asm.JEq.Imm(valueReg, 0, "")
	keyNull.Offset, valueNull.Offset = 1, 1
	return asm.Instructions{head, keyNull, asm.LoadMem(asm.R0, keyReg, 0, asm.Byte),
		valueNull, asm.LoadMem(asm.R0, valueReg, 0, asm.Byte),
		asm.Mov.Imm(asm.R0, 0), asm.Return()}
}
