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
//
// Entry also calls int HOOKNAME_entry(struct xdp_md *ctx) once at program
// entry, which runs when the program is entered through a tail call, unlike an
// fentry on the program itself. TailCalls calls int HOOKNAME_tail_call(
// struct xdp_md *ctx, u32 site, u32 index) whenever a bpf_tail_call in the
// entry function returns, that is, when the tail call failed. With either,
// Site may be empty to instrument no lookup.
//
// CopyReadOnly gives a BPF_F_RDONLY_PROG map a typed hook instead of an
// untrusted one: each site copies the value to the stack below the spill
// slots and passes the copy. Kernels without arg:untrusted load it.
//
// StaticUntrusted gives every hook that would take arg:untrusted pointers
// (see LookupHook.Untrusted, and the generic hook) static linkage and an empty
// body instead. The verifier checks a static function at each call with the
// caller's registers, so the hook needs no tag and kernels without
// arg:untrusted load it. With CopyReadOnly, a read-only map still gets the
// typed hook.
type LookupRequest struct {
	ELFSHA256       string
	ProgramName     string
	Site            LookupSelector
	Auto            bool
	Entry           bool
	TailCalls       bool
	CopyReadOnly    bool
	StaticUntrusted bool
	HookName        string
	Stack           StackAudit
}

// HookKind is what a generated hook observes.
type HookKind string

const (
	HookLookup   HookKind = "lookup"
	HookEntry    HookKind = "entry"
	HookTailCall HookKind = "tail_call"
)

// LookupHook is one generated hook and the sites that call it, in original
// instruction order. An entry hook has no sites; a tail-call hook's sites are
// bpf_tail_call helpers with only location fields set. TypeID and FuncInfo are
// set by TransformLookupRaw only.
//
// Untrusted is set for a lookup hook on a map that programs cannot write or
// cannot read (BPF_F_RDONLY_PROG or BPF_F_WRONLY_PROG). Its key and value are const void * tagged
// arg:untrusted, so an observer reads them by the map's sizes.
//
// Copied is set for a typed hook on a BPF_F_RDONLY_PROG map with
// CopyReadOnly: its value points to a stack copy, not into the map.
//
// Static is set instead of Untrusted with StaticUntrusted. The kernel may then
// ignore the hook's BTF, as 7.0 does: an fentry observer gets every argument,
// ctx included, as a u64 and reads through them with bpf_probe_read_kernel.
//
// Generic is set for Auto's one hook over lookups whose map is not known
// statically (R1 is not a direct map reference) or is a map-in-map. It has no
// MapName and takes the map pointer as a fifth argument; see genericHook.
type LookupHook struct {
	Name      string
	Kind      HookKind
	MapName   string
	Sites     []LookupSite
	Untrusted bool
	Copied    bool
	Static    bool
	Generic   bool
	TypeID    btf.TypeID
	FuncInfo  []byte
}

// LookupResult reports the selected original sites and the transformed clone.
// Result.InsertedAt is zero (the ctx spill); InsertedSlots includes that spill,
// the lookup instrumentation and generated hooks. Checksums have Result's scope.
type LookupResult struct {
	Result
	Site    LookupSite   // first selected lookup, retained for single-site callers; zero without lookups
	Sites   []LookupSite // all selected lookups in original instruction order
	Hooks   []LookupHook // lookup hooks (one, or one per map with Auto), then entry and tail-call hooks
	Skipped []LookupSite // with Auto or TailCalls, discovered sites that were not instrumented
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
	return &LookupResult{Result: Result{Spec: work, HookName: plan.hooks[0].Name, // first generated hook, as in the raw API
		SourceChecksum: sourceSum, TransformedChecksum: resultSum,
		InsertedAt: 0, InsertedSlots: added / asm.InstructionSize, AddedBytes: added},
		Site: plan.first(), Sites: plan.sites, Hooks: plan.hooks, Skipped: plan.skipped}, nil
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

// generic marks a lookup whose map Auto passes at run time to the generic
// hook: R1 is not a direct map reference, or the map is a map-in-map.
type discoveredLookup struct {
	LookupSite
	mapID   string
	mapInfo *RawMap
	generic bool
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
		return name, &RawMap{Name: name, Type: m.Type, KeySize: m.KeySize, ValueSize: m.ValueSize, Flags: m.Flags, Key: m.Key, Value: m.Value}
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
			generic := false
			switch {
			case funcStart < 0:
				site.Reason = "program lacks BTF function info"
			case funcStart != 0:
				site.Reason = "lookup is not in the entry function; ctx belongs to another stack frame"
			case mapID == "":
				site.Reason, generic = "R1 is not a direct map reference in this basic block", true
			case m == nil:
				site.Reason = "map reference is not defined in the collection"
			case m.Type == ebpf.HashOfMaps || m.Type == ebpf.ArrayOfMaps:
				site.Reason, generic = "map-in-map lookup returns an inner map", true
			default:
				if err := checkLookupMap(m); err != nil {
					site.Reason = err.Error()
				}
			}
			sites = append(sites, discoveredLookup{site, mapID, m, generic})
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

// bpfFRdonlyProg and bpfFWronlyProg are BPF_F_RDONLY_PROG and
// BPF_F_WRONLY_PROG from the BPF UAPI.
const (
	bpfFRdonlyProg = 1 << 7
	bpfFWronlyProg = 1 << 8
)

func checkLookupMap(m *RawMap) error {
	// These maps return ordinary value memory. Other map kinds can return
	// special objects (notably map-in-map), so do not infer their pointer ABI.
	switch m.Type {
	case ebpf.Hash, ebpf.Array, ebpf.PerCPUHash, ebpf.PerCPUArray, ebpf.LRUHash, ebpf.LRUCPUHash, ebpf.LPMTrie:
	default:
		return refuse("map type %s is unsupported", m.Type)
	}
	for _, field := range []struct {
		name string
		typ  btf.Type
		size uint32
	}{{"key", m.Key, m.KeySize}, {"value", m.Value, m.ValueSize}} {
		if field.typ == nil {
			continue // lookupABI passes it as opaque bytes
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

// lookupABI returns the hook's key and value types. A side the map declares
// only by size, without BTF, is passed as struct { u8 bytes[size]; }.
func lookupABI(m *RawMap) (key, value btf.Type) {
	return orBytes(m.Key, m.KeySize), orBytes(m.Value, m.ValueSize)
}

func orBytes(typ btf.Type, size uint32) btf.Type {
	if typ != nil {
		return typ
	}
	bytes := &btf.Array{Index: &btf.Int{Name: "u32", Size: 4}, Type: &btf.Int{Name: "u8", Size: 1}, Nelems: size}
	return &btf.Struct{Size: size, Members: []btf.Member{{Name: "bytes", Type: bytes}}}
}

// lookupPlan is what transformLookupProgram selected and generated.
type lookupPlan struct {
	sites   []LookupSite
	hooks   []LookupHook
	skipped []LookupSite
}

func (p lookupPlan) first() LookupSite {
	if len(p.sites) == 0 {
		return LookupSite{}
	}
	return p.sites[0]
}

// tailCallSite is a bpf_tail_call helper. A site outside the entry function
// cannot reach the entry frame's ctx spill, so it saves its own R1 (the ctx
// the helper takes) in its own frame.
type tailCallSite struct {
	LookupSite
	local bool
}

// tailCallSites lists bpf_tail_call helpers in every function.
func tailCallSites(insns asm.Instructions) []tailCallSite {
	var sites []tailCallSite
	var funcName, file string
	var line uint32
	funcStart := -1
	it := insns.Iterate()
	for it.Next() {
		pc, ins := int(it.Offset), it.Ins
		if fn := btf.FuncMetadata(ins); fn != nil {
			funcName, funcStart, file, line = fn.Name, pc, "", 0
		}
		if src, ok := ins.Source().(*btf.Line); ok {
			file, line = src.FileName(), src.LineNumber()
		}
		if ins.IsBuiltinCall() && ins.Constant == int64(asm.FnTailCall) {
			site := LookupSite{FuncName: funcName, File: file, Line: line, SitePC: uint32(pc), InstructionIndex: it.Index}
			sites = append(sites, tailCallSite{site, funcStart != 0})
		}
	}
	return sites
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
	name    string
	sites   []discoveredLookup
	generic bool
}

// selectLookups groups the selected lookups by hook. Auto hook names avoid
// reserved, the entry and tail-call hook names.
func selectLookups(sites []discoveredLookup, req LookupRequest, reserved []string) ([]lookupGroup, []LookupSite, error) {
	if req.Auto {
		if req.Site.MapName != "" || req.Site.FuncName != "" || req.Site.Line != 0 || len(req.Site.SitePCs) != 0 || req.Site.AllMatches {
			return nil, nil, refuse("Auto selects every supported lookup; Site must be empty")
		}
		var groups []lookupGroup
		var skipped []LookupSite
		var generic []discoveredLookup
		index := map[string]int{}
		for _, site := range sites {
			if site.generic {
				site.Reason = ""
				generic = append(generic, site)
				continue
			}
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
		if len(generic) != 0 {
			groups = append(groups, lookupGroup{sites: generic, generic: true})
		}
		if len(groups) == 0 {
			return nil, skipped, refuse("no supported lookup sites (%d skipped)", len(skipped))
		}
		used := map[string]bool{}
		for _, name := range reserved {
			used[name] = true
		}
		for i := range groups {
			mapName := groups[i].sites[0].MapName
			if groups[i].generic {
				mapName = "any"
			}
			groups[i].name = autoHookName(req.HookName, mapName, i, used)
			if !validIdent(groups[i].name) {
				return nil, skipped, refuse("hook name %q is longer than %d bytes; use a shorter HookName", groups[i].name, maxHookName)
			}
		}
		return groups, skipped, nil
	}
	if req.Site.MapName == "" {
		if (req.Entry || req.TailCalls) && req.Site.FuncName == "" && req.Site.Line == 0 && len(req.Site.SitePCs) == 0 && !req.Site.AllMatches {
			return nil, nil, nil
		}
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
	// Missing function metadata would otherwise surface as "not in the entry function".
	if err := checkExtInfo(insns); err != nil {
		return nil, plan, err
	}
	sites, err := discoverLookupProgram(insns, typ, resolve)
	if err != nil {
		return nil, plan, err
	}
	var reserved []string
	entryName, tailName := req.HookName+"_entry", req.HookName+"_tail_call"
	if req.Entry {
		reserved = append(reserved, entryName)
	}
	if req.TailCalls {
		reserved = append(reserved, tailName)
	}
	groups, skipped, err := selectLookups(sites, req, reserved)
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
	var tails []tailCallSite
	if req.TailCalls {
		if tails = tailCallSites(insns); len(tails) == 0 {
			return nil, plan, refuse("TailCalls: no bpf_tail_call in the program")
		}
	}
	names := map[string]bool{}
	for _, group := range groups {
		names[group.name] = true
	}
	for _, name := range reserved {
		if names[name] || !validIdent(name) {
			return nil, plan, refuse("hook name %q is invalid or used twice", name)
		}
		names[name] = true
	}
	checks := []func() error{
		func() error { return checkStackBound(insns, req.Stack.LowestOffset) },
	}
	sorted := make([]string, 0, len(names))
	for name := range names {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted) // report the same collision on every run
	for _, name := range sorted {
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
	ctxType := proto.Params[0].Type
	var hooks asm.Instructions
	calls := map[uint32]siteCall{}
	for _, group := range groups {
		if group.generic {
			hook := genericHook(group.name, ctxType)
			if req.StaticUntrusted {
				hook = staticHook(hook)
			}
			hooks = append(hooks, hook...)
			plan.hooks = append(plan.hooks, LookupHook{Name: group.name, Kind: HookLookup, Sites: publicLookupSites(group.sites),
				Untrusted: !req.StaticUntrusted, Static: req.StaticUntrusted, Generic: true})
			for _, site := range group.sites {
				calls[site.SitePC] = siteCall{hook: group.name, withSite: true, withMap: true}
			}
			continue
		}
		m := group.sites[0].mapInfo
		key, value := lookupABI(m)
		// The verifier checks an ordinary memory argument for both reads and
		// writes, so either restriction needs untrusted arguments, unless a
		// readable value is copied to the stack.
		untrusted := m.Flags&(bpfFRdonlyProg|bpfFWronlyProg) != 0
		var copySize uint32
		if untrusted && req.CopyReadOnly && m.Flags&bpfFWronlyProg == 0 {
			untrusted, copySize = false, m.ValueSize
		}
		static := untrusted && req.StaticUntrusted
		body := lookupHook(group.name, ctxType, key, value, req.Auto, untrusted && !static)
		if static {
			untrusted, body = false, staticHook(body)
		}
		hooks = append(hooks, body...)
		hook := LookupHook{Name: group.name, Kind: HookLookup, MapName: group.sites[0].MapName, Sites: publicLookupSites(group.sites),
			Untrusted: untrusted, Copied: copySize > 0, Static: static}
		plan.hooks = append(plan.hooks, hook)
		for _, site := range group.sites {
			calls[site.SitePC] = siteCall{hook: group.name, withSite: req.Auto, copySize: copySize}
		}
	}
	var entryHook string
	if req.Entry {
		entryHook = entryName
		hooks = append(hooks, scalarHook(entryName, ctxType)...)
		plan.hooks = append(plan.hooks, LookupHook{Name: entryName, Kind: HookEntry})
	}
	if req.TailCalls {
		hooks = append(hooks, scalarHook(tailName, ctxType, "site", "index")...)
		hook := LookupHook{Name: tailName, Kind: HookTailCall}
		for _, site := range tails {
			hook.Sites = append(hook.Sites, site.LookupSite)
			calls[site.SitePC] = siteCall{hook: tailName, withSite: true, tailCall: true, localCtx: site.local}
		}
		plan.hooks = append(plan.hooks, hook)
	}
	spliced, err := spliceLookupCalls(insns, calls, req.Stack, hooks, entryHook)
	if err != nil {
		return nil, plan, err
	}
	return spliced, plan, nil
}

// siteCall is the hook a helper site calls, whether it passes its SitePC and
// the lookup's map pointer, and whether the site is a bpf_tail_call rather
// than a lookup. A localCtx tail call saves its own ctx before the helper. A
// nonzero copySize passes a stack copy of that many value bytes.
type siteCall struct {
	hook     string
	withSite bool
	withMap  bool
	tailCall bool
	localCtx bool
	copySize uint32
}

func spliceLookup(input asm.Instructions, sitePCs []uint32, req LookupRequest) (asm.Instructions, error) {
	calls := make(map[uint32]siteCall, len(sitePCs))
	for _, pc := range sitePCs {
		calls[pc] = siteCall{hook: req.HookName}
	}
	return spliceLookupCalls(input, calls, req.Stack, nil, "")
}

// spliceLookupCalls instruments each helper in calls and places hook right
// after the entry function. A non-empty entryHook is called with ctx right
// after the entry ctx spill.
func spliceLookupCalls(input asm.Instructions, calls map[uint32]siteCall, stack StackAudit, hook asm.Instructions, entryHook string) (asm.Instructions, error) {
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
	// A generic hook's map pointer takes a fourth slot.
	mapSlot := int16(result - 8)
	// A value copy goes below the map slot, in 8-byte units.
	copyAt := func(call siteCall) int { return int(mapSlot) - int((call.copySize+7)/8*8) }
	for _, call := range calls {
		if call.withMap && result-8 < -512 {
			return nil, refuse("four lookup spill slots exceed the 512-byte stack")
		}
		if call.copySize > 0 && copyAt(call) < -512 {
			return nil, refuse("a %d-byte value copy below the spill slots exceeds the 512-byte stack", call.copySize)
		}
	}
	// Every site of every hook shares the slots: sites run one at a time.
	// A tail-call site keeps its index (R3) in the key slot.
	afterFor := func(pc uint32, call siteCall) asm.Instructions {
		if call.tailCall {
			// bpf_tail_call returned, so the tail call failed. The verifier
			// leaves R0-R5 unreadable after it, so nothing needs restoring.
			return asm.Instructions{
				asm.LoadMem(asm.R1, asm.RFP, ctx, asm.DWord),
				asm.Mov.Imm32(asm.R2, int32(pc)),
				asm.LoadMem(asm.R3, asm.RFP, key, asm.DWord), asm.Mov.Reg32(asm.R3, asm.R3),
				asm.Call.Label(call.hook),
			}
		}
		var args asm.Instructions
		if call.copySize > 0 {
			args = copyValue(asm.R0, int16(copyAt(call)), call.copySize)
		}
		args = append(args, asm.LoadMem(asm.R1, asm.RFP, ctx, asm.DWord))
		if call.withSite {
			args = append(args, asm.Mov.Imm32(asm.R2, int32(pc)),
				asm.LoadMem(asm.R3, asm.RFP, key, asm.DWord), asm.Mov.Reg(asm.R4, asm.R0))
			if call.withMap {
				args = append(args, asm.LoadMem(asm.R5, asm.RFP, mapSlot, asm.DWord))
			}
		} else {
			args = append(args, asm.LoadMem(asm.R2, asm.RFP, key, asm.DWord), asm.Mov.Reg(asm.R3, asm.R0))
		}
		if call.copySize > 0 {
			value := args[len(args)-1].Dst // the register given R0
			args = append(args, asm.Mov.Reg(value, asm.RFP), asm.Add.Imm(value, int32(copyAt(call))))
		}
		args = append(args, asm.Call.Label(call.hook))
		null := asm.JEq.Imm(asm.R0, 0, "")
		null.Offset = int16(len(args)) // skip argument setup and hook; restore R0 on both paths
		out := asm.Instructions{asm.StoreMem(asm.RFP, spillR0, asm.R0, asm.DWord), null}
		out = append(out, args...)
		return append(out, asm.LoadMem(asm.R0, asm.RFP, spillR0, asm.DWord))
	}
	before := func(call siteCall) asm.Instructions {
		if call.tailCall {
			spill := asm.Instructions{asm.StoreMem(asm.RFP, key, asm.R3, asm.DWord)}
			if call.localCtx {
				// The slot offsets are the same in every frame; the stack
				// audit covers direct R10 references in all functions.
				spill = append(spill, asm.StoreMem(asm.RFP, ctx, asm.R1, asm.DWord))
			}
			return spill
		}
		spill := asm.Instructions{asm.StoreMem(asm.RFP, key, asm.R2, asm.DWord)}
		if call.withMap {
			spill = append(spill, asm.StoreMem(asm.RFP, mapSlot, asm.R1, asm.DWord))
		}
		return spill
	}
	after := make(map[uint32]asm.Instructions, len(calls))
	for pc, call := range calls {
		after[pc] = afterFor(pc, call)
	}
	// At entry only R1 and R10 are initialized, so the entry hook may clobber
	// R0-R5; ctx is reloaded into R1.
	prologue := asm.Instructions{}
	if entryHook != "" {
		prologue = asm.Instructions{asm.Call.Label(entryHook), asm.LoadMem(asm.R1, asm.RFP, ctx, asm.DWord)}
	}
	hookSlots := int(hook.Size() / asm.InstructionSize)
	hookAt := -1
	indices, mapped := map[int]int{}, map[int]int{}
	pc := 1 + len(prologue) // entry ctx spill and entry hook call
	it := input.Iterate()
	for it.Next() {
		old := int(it.Offset)
		if hookAt < 0 && old > 0 && btf.FuncMetadata(it.Ins) != nil {
			hookAt = old
			pc += hookSlots
		}
		indices[old], mapped[old] = it.Index, pc
		call, site := calls[uint32(old)]
		if site {
			pc += len(before(call)) // branch to helper must execute the spills first
		}
		pc += int(it.Ins.Size() / asm.InstructionSize)
		if site {
			pc += len(after[uint32(old)])
		}
	}
	entry := btf.WithFuncMetadata(asm.StoreMem(asm.RFP, ctx, asm.R1, asm.DWord).
		WithSymbol(input[0].Symbol()).WithSource(input[0].Source()), btf.FuncMetadata(&input[0]))
	out := append(asm.Instructions{entry}, prologue...)
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
		call, site := calls[uint32(old)]
		if site {
			spill := before(call)
			out = append(out, spill...)
			newPC += len(spill)
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
		if site {
			out = append(out, after[uint32(old)]...)
		}
	}
	if hookAt < 0 {
		out = append(out, hook...)
	}
	return out, nil
}

// copyValue copies size bytes from src to the stack at off with R1 as scratch,
// widest loads first, so every stack access stays aligned.
func copyValue(src asm.Register, off int16, size uint32) asm.Instructions {
	var out asm.Instructions
	done := int16(0)
	for _, width := range []struct {
		n    uint32
		size asm.Size
	}{{8, asm.DWord}, {4, asm.Word}, {2, asm.Half}, {1, asm.Byte}} {
		for size-uint32(done) >= width.n {
			out = append(out, asm.LoadMem(asm.R1, src, done, width.size), asm.StoreMem(asm.RFP, off+done, asm.R1, width.size))
			done += int16(width.n)
		}
	}
	return out
}

// genericHook is int NAME(struct xdp_md *ctx, u32 site, const void *key,
// const void *value, const void *map), the pointers tagged arg:untrusted like
// lookupHook's. map is the lookup's R1 at run time: the map itself, or for an
// inner lookup the inner map an outer lookup returned. For an outer map-in-map
// lookup, value is that inner map rather than value memory.
func genericHook(name string, ctx btf.Type) asm.Instructions {
	void := func() btf.Type { return &btf.Pointer{Target: &btf.Const{Type: &btf.Void{}}} }
	params := []btf.FuncParam{{Name: "ctx", Type: ctx}, {Name: "site", Type: &btf.Int{Name: "u32", Size: 4}},
		{Name: "key", Type: void()}, {Name: "value", Type: void()}, {Name: "map", Type: void()}}
	untrusted := []string{"arg:untrusted"}
	fn := &btf.Func{Name: name, Linkage: btf.GlobalFunc, Type: &btf.FuncProto{
		Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}, Params: params,
	}, ParamTags: [][]string{nil, nil, untrusted, untrusted, untrusted}}
	head := btf.WithFuncMetadata(asm.LoadMem(asm.R0, asm.R1, 0, asm.Word).WithSymbol(name).
		WithSource(asm.Comment("generated generic lookup observation hook "+name)), fn)
	return append(asm.Instructions{head}, untrustedReads(asm.R3, asm.R4, asm.R5)...)
}

// staticHook gives a generated hook static linkage and replaces its body with
// return 0. The reads that keep a global hook's arguments live are not
// needed, and through a pointer into a write-only map or to a map itself the
// verifier would reject them.
func staticHook(hook asm.Instructions) asm.Instructions {
	fn := *btf.FuncMetadata(&hook[0])
	fn.Linkage, fn.ParamTags = btf.StaticFunc, nil
	head := btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 0).WithSymbol(hook[0].Symbol()).WithSource(hook[0].Source()), &fn)
	return asm.Instructions{head, asm.Return()}
}

// untrustedReads reads one byte through each arg:untrusted pointer, then
// returns zero. Such a pointer is not nullable, so comparing it with zero is
// a pointer comparison that loaders without CAP_PERFMON may not make. The
// reads need no null check: the verifier turns them into fault-handled
// loads, which read zero from a NULL pointer.
func untrustedReads(regs ...asm.Register) asm.Instructions {
	var out asm.Instructions
	for _, reg := range regs {
		out = append(out, asm.LoadMem(asm.R0, reg, 0, asm.Byte))
	}
	return append(out, asm.Mov.Imm(asm.R0, 0), asm.Return())
}

// scalarHook is int NAME(struct xdp_md *ctx, u32 scalars...): it reads ctx
// like lookupHook and returns zero.
func scalarHook(name string, ctx btf.Type, scalars ...string) asm.Instructions {
	params := []btf.FuncParam{{Name: "ctx", Type: ctx}}
	for _, scalar := range scalars {
		params = append(params, btf.FuncParam{Name: scalar, Type: &btf.Int{Name: "u32", Size: 4}})
	}
	fn := &btf.Func{Name: name, Linkage: btf.GlobalFunc, Type: &btf.FuncProto{
		Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}, Params: params,
	}}
	head := btf.WithFuncMetadata(asm.LoadMem(asm.R0, asm.R1, 0, asm.Word).WithSymbol(name).
		WithSource(asm.Comment("generated observation hook "+name)), fn)
	return asm.Instructions{head, asm.Mov.Imm(asm.R0, 0), asm.Return()}
}

// lookupHook generates a hook taking const KEY * and const VALUE *. With
// untrusted, both are const void * tagged arg:untrusted instead: the verifier
// checks an ordinary global-function memory argument for writes, even through
// const, which a value of a BPF_F_RDONLY_PROG map fails; an untrusted one is
// not checked at the call and is read with fault-handled loads.
func lookupHook(name string, ctx, key, value btf.Type, withSite, untrusted bool) asm.Instructions {
	params := []btf.FuncParam{{Name: "ctx", Type: ctx}}
	keyReg, valueReg := asm.R2, asm.R3
	if withSite {
		params = append(params, btf.FuncParam{Name: "site", Type: &btf.Int{Name: "u32", Size: 4}})
		keyReg, valueReg = asm.R3, asm.R4
	}
	if untrusted {
		key, value = &btf.Void{}, &btf.Void{}
	}
	params = append(params,
		btf.FuncParam{Name: "key", Type: &btf.Pointer{Target: &btf.Const{Type: key}}},
		btf.FuncParam{Name: "value", Type: &btf.Pointer{Target: &btf.Const{Type: value}}})
	fn := &btf.Func{Name: name, Linkage: btf.GlobalFunc, Type: &btf.FuncProto{
		Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}, Params: params,
	}}
	if untrusted {
		fn.ParamTags = make([][]string, len(params))
		fn.ParamTags[len(params)-2] = []string{"arg:untrusted"}
		fn.ParamTags[len(params)-1] = []string{"arg:untrusted"}
	}
	// Global functions are verified independently with nullable memory args.
	// Actual reads keep every argument live, even after dead-register pruning.
	head := btf.WithFuncMetadata(asm.LoadMem(asm.R0, asm.R1, 0, asm.Word).WithSymbol(name).
		WithSource(asm.Comment("generated lookup observation hook "+name)), fn)
	if untrusted {
		return append(asm.Instructions{head}, untrustedReads(keyReg, valueReg)...)
	}
	keyNull, valueNull := asm.JEq.Imm(keyReg, 0, ""), asm.JEq.Imm(valueReg, 0, "")
	keyNull.Offset, valueNull.Offset = 1, 1
	return asm.Instructions{head, keyNull, asm.LoadMem(asm.R0, keyReg, 0, asm.Byte),
		valueNull, asm.LoadMem(asm.R0, valueReg, 0, asm.Byte),
		asm.Mov.Imm(asm.R0, 0), asm.Return()}
}
