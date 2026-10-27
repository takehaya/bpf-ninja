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

// LookupSite describes a map_lookup_elem helper in a flattened XDP or tc
// program.
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

// empty reports whether s sets no field, so it selects no lookup.
func (s LookupSelector) empty() bool {
	return s.MapName == "" && s.FuncName == "" && s.Line == 0 && len(s.SitePCs) == 0 && !s.AllMatches
}

// LookupRequest describes one hash-bound lookup transformation. Lookups are
// instrumented only in the entry function: a subprogram has its own frame and
// cannot reach the entry frame's ctx spill (TailCalls does reach subprograms,
// see below). Stack certifies the reserved spill slots below the audited
// bound, three, four when a hook takes the map pointer (generic or Dispatch),
// plus the value copy with CopyReadOnly, including aliases and callee stacks.
// No caller-saved register liveness certification is required at helper calls.
//
// Auto instruments every supported lookup instead of Site, which must then be
// empty. HookName becomes a prefix: each statically known map gets its own hook,
// int PREFIX_MAP(struct xdp_md *ctx, u32 site, const KEY *key, const VALUE *value),
// where site is the original SitePC. Lookups whose map Auto cannot bind to a
// typed hook (a map-in-map, an indirect map reference, an XSK map or a devmap)
// share one PREFIX_any generic hook (see LookupHook.Generic). Sites that
// cannot be instrumented are reported in Skipped instead of refusing the
// transform: an unsupported site or map kind, a hook name past MaxHookName,
// slots past the audited stack, or, when the instrumented program would break
// a kernel call-chain stack limit, first the sites that need the map slot or
// a value copy and then every lookup. Auto refuses only when nothing at all
// would be instrumented.
//
// Maps limits Auto to lookups on the named maps (exact kernel names); the
// others are reported in Skipped. A name that matches no discovered lookup is
// a refusal, so a typo cannot silently instrument nothing. A lookup whose map
// is known only at run time has no name and is never selected.
//
// The hooks take the entry function's context: struct xdp_md * in an XDP
// program, struct __sk_buff * in a tc program (SchedCLS or SchedACT). The
// signatures below show the XDP form.
//
// Entry also calls int HOOKNAME_entry(struct xdp_md *ctx) once at program
// entry, which runs when the program is entered through a tail call, unlike an
// fentry on the program itself. TailCalls calls int HOOKNAME_tail_call(
// struct xdp_md *ctx, u32 site, u32 index) whenever a bpf_tail_call returns,
// that is, when the tail call failed. This covers tail calls in subprograms,
// whose hook gets the ctx that subprogram passed to the helper. With either,
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
//
// Dispatch sends every instrumented site, lookups, the entry and failed tail
// calls, to one hook named HookName with the generic hook's signature (see
// genericHook), so one observer attach sees them all. A lookup passes its
// SitePC, key, value and map. A failed tail call passes its SitePC, a pointer
// to the spilled index register in key (a u64 whose low 32 bits the helper
// used), a NULL value and the prog array in map. The entry passes
// DispatchEntrySite and NULL pointers. With StaticUntrusted the hook is
// static. Dispatch does not combine with CopyReadOnly.
type LookupRequest struct {
	ELFSHA256       string
	ProgramName     string
	Site            LookupSelector
	Auto            bool
	Maps            []string
	Entry           bool
	TailCalls       bool
	CopyReadOnly    bool
	StaticUntrusted bool
	Dispatch        bool
	HookName        string
	Stack           StackAudit
}

// DispatchEntrySite is the site a Dispatch hook reports for the entry call. A
// raw slot index cannot reach it.
const DispatchEntrySite = ^uint32(0)

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
// ReadOnly is set for a typed lookup hook on a BPF_F_RDONLY_PROG map, which
// CopyReadOnly turns from an untrusted hook into a copied one.
//
// Generic is set for Auto's one hook over lookups whose map is not known
// statically (R1 is not a direct map reference), is a map-in-map, or is of a
// genericKinds kind, which a typed hook refuses. It has no MapName and takes
// the map pointer as a fifth argument; see genericHook.
//
// Dispatch is set on every hook of a Dispatch request. They all share Name and
// the one hook's Untrusted and Static flags; Kind, MapName and Sites still
// group the sites, so an observer maps a site to its kind, map and key and
// value types from them.
type LookupHook struct {
	Name      string
	Kind      HookKind
	MapName   string
	Sites     []LookupSite
	Untrusted bool
	Copied    bool
	Static    bool
	ReadOnly  bool
	Generic   bool
	Dispatch  bool
	TypeID    btf.TypeID
	FuncInfo  []byte
}

// LookupResult reports the selected original sites and the transformed clone.
// Result.HookName and Site describe the first hook and the first selected
// lookup: exact for a single-site request, but with Auto, Entry, TailCalls or
// Dispatch the first hook is the first lookup hook in Hooks (the entry or
// tail-call hook when there is no lookup), so use Hooks and Sites.
// Result.InsertedAt is zero (the ctx spill); InsertedSlots includes that spill,
// the lookup instrumentation and generated hooks. Checksums have Result's scope.
type LookupResult struct {
	Result
	Site    LookupSite   // first element of Sites; zero without lookups
	Sites   []LookupSite // all selected lookups in original instruction order
	Hooks   []LookupHook // lookup hooks (one; with Auto one per map, then the generic hook), then the entry and tail-call hooks; with Dispatch all share one name
	Skipped []LookupSite // with Auto, discovered lookups that were not instrumented
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

// TransformLookup instruments the program req describes and returns an
// independent clone. A selected lookup calls
// int HOOK(CTX *ctx, const KEY *key, const VALUE *value) for non-null results,
// where CTX is the program's context type: struct xdp_md for XDP, struct
// __sk_buff for tc (SchedCLS or SchedACT). See LookupRequest for the Auto,
// Entry, TailCalls and Dispatch hooks. This never loads or attaches BPF.
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
// typedOnly marks a direct lookup that a typed hook refuses (checkLookupMap)
// on a map of a genericKinds kind; Auto also sends it to the generic hook.
type discoveredLookup struct {
	LookupSite
	mapID     string
	mapInfo   *RawMap
	generic   bool
	typedOnly bool
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

// ContextType names the BTF struct the ctx argument of every hook in a
// program of type typ points to, empty if TransformLookup does not support
// the type.
func ContextType(typ ebpf.ProgramType) string { return lookupContext(typ) }

// lookupContext names the context struct the hooks of a program of type typ
// take, and whose first word they read: struct xdp_md for XDP, struct
// __sk_buff (len) for tc. Empty means the type is not supported.
func lookupContext(typ ebpf.ProgramType) string {
	switch typ {
	case ebpf.XDP:
		return "xdp_md"
	case ebpf.SchedCLS, ebpf.SchedACT:
		return "__sk_buff"
	}
	return ""
}

func discoverLookupProgram(insns asm.Instructions, typ ebpf.ProgramType, resolve lookupMapResolver) ([]discoveredLookup, error) {
	if lookupContext(typ) == "" {
		return nil, refuse("only XDP and tc programs are supported")
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
			generic, typedOnly := false, false
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
				if reason := checkLookupMap(m); reason != "" {
					site.Reason, typedOnly = reason, genericKinds[m.Type]
				}
			}
			sites = append(sites, discoveredLookup{site, mapID, m, generic, typedOnly})
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

// genericKinds are the map kinds a typed hook refuses whose direct lookups Auto
// passes to the generic hook; testGenericKinds loads each one, XDP and tc, with
// and without Dispatch, on the kernel matrix. A sockmap or sockhash lookup
// returns a socket reference; the hook only reads it, and the verifier still
// demands the program's own release. Auto skips a lookup on any other refused
// kind (a cpumap or reuseport array lookup does not load at all). Add a kind
// only together with its kernel test.
var genericKinds = map[ebpf.MapType]bool{
	ebpf.XSKMap: true, ebpf.DevMap: true, ebpf.DevMapHash: true, ebpf.SockMap: true, ebpf.SockHash: true,
}

// bpfFRdonlyProg and bpfFWronlyProg are BPF_F_RDONLY_PROG and
// BPF_F_WRONLY_PROG from the BPF UAPI.
const (
	bpfFRdonlyProg = 1 << 7
	bpfFWronlyProg = 1 << 8
)

// lookupLayout is where the transform's slots sit below the 8-byte-aligned
// floor of the audited mark: ctx, key and result (the three base slots), and
// mapSlot (the fourth, for a hook that takes the map pointer). A CopyReadOnly
// value copy goes below mapSlot, at copyAt. spliceLookupCalls places the slots
// by this layout, and CheckLookupStack and groupStackReach measure it.
type lookupLayout struct {
	ctx, key, result, mapSlot int
}

func lookupSlots(lowest int16) lookupLayout {
	floor := int(lowest)
	if m := floor % 8; m != 0 {
		floor -= 8 + m
	}
	return lookupLayout{ctx: floor - 8, key: floor - 16, result: floor - 24, mapSlot: floor - 32}
}

// copyAt is where a size-byte value copy starts, in 8-byte units below mapSlot.
func (l lookupLayout) copyAt(size uint32) int {
	return l.mapSlot - int((size+7)/8*8)
}

// copiesValue reports whether a typed hook on m gets a stack copy of the value
// instead of a pointer into the map: m is BPF_F_RDONLY_PROG and req asks for
// CopyReadOnly.
func copiesValue(m *RawMap, req LookupRequest) bool {
	return req.CopyReadOnly && m.Flags&bpfFRdonlyProg != 0 && m.Flags&bpfFWronlyProg == 0
}

// LookupStackReserve reports the bytes the transform reserves strictly below
// the audited floor, as far as a request's flags determine it statically. The
// entry always spills ctx (8 bytes); a tail-call site also keeps its index in
// the key slot (16); a lookup site, possible with Site or Auto, also spills R0
// (24). With Dispatch, lookup and tail-call sites also pass the map, so they
// need the map slot (32); a dispatch entry call passes only constants. A
// generic hook's map slot and a CopyReadOnly value copy are program-dependent
// and enforced during the transform (Auto skips the site, explicit selection
// refuses), not here.
func LookupStackReserve(req LookupRequest) int {
	lookups := req.Auto || !req.Site.empty()
	switch {
	case req.Dispatch && (lookups || req.TailCalls):
		return 32
	case lookups:
		return 24
	case req.TailCalls:
		return 16
	case req.Entry:
		return 8
	}
	// Nothing is selected: the transform refuses ("lookup MapName is
	// required"), so reserve as for a lookup.
	return 24
}

// CheckLookupStack validates an audited LowestOffset against the statically
// known reservation of req's flags. transformLookupProgram and
// syscallhook.Validate both call it, so Validate cannot drift from the
// transform's slot layout.
func CheckLookupStack(req LookupRequest) error {
	lo := int(req.Stack.LowestOffset)
	if lo > 0 || lo < -512 {
		return refuse("StackAudit.LowestOffset must be in [-512, 0]")
	}
	// Every reserved slot is in a frame that calls a hook (the entry hook, a
	// tail-call or a lookup hook), so the slots must stay within
	// siteFrameLimit, not the full 512 bytes.
	floor := lookupSlots(req.Stack.LowestOffset).ctx + 8
	if reserve := LookupStackReserve(req); floor-reserve < -siteFrameLimit {
		return refuse("Stack.LowestOffset %d leaves no room for %d reserved bytes below the audited floor", lo, reserve)
	}
	return nil
}

// siteFrameLimit is how deep a frame holding a lookup site may reach. The
// site calls its hook, a frame that kernels rounding to 32 bytes count as 32
// even without stack, so a deeper site frame crosses the 512-byte combined
// limit checkStackLimits enforces.
const siteFrameLimit = maxCombinedStack - 32

// groupStackReach returns the most-negative stack offset instrumenting group
// needs. A generic or dispatch hook needs the map slot; a CopyReadOnly value
// copy goes below it; a plain typed hook uses only the three base slots, which
// CheckLookupStack already keeps within siteFrameLimit.
func groupStackReach(group lookupGroup, req LookupRequest) int {
	slots := lookupSlots(req.Stack.LowestOffset)
	if group.generic || req.Dispatch {
		return slots.mapSlot
	}
	if m := group.sites[0].mapInfo; copiesValue(m, req) {
		return slots.copyAt(m.ValueSize)
	}
	return slots.result
}

// siteFrameReason says why group's slots pass siteFrameLimit. Only the map
// slot or a value copy can reach that far (groupStackReach). With Dispatch
// every group, typed or not, passes the map, but CheckLookupStack already
// reserves its slot then, so the dispatch reason is kept only for accuracy.
func siteFrameReason(group lookupGroup, req LookupRequest) string {
	switch {
	case req.Dispatch:
		return fmt.Sprintf("dispatch hook needs the 4th spill slot for the map pointer; Stack.LowestOffset %d too low", req.Stack.LowestOffset)
	case group.generic:
		return fmt.Sprintf("runtime-map hook needs the 4th spill slot; Stack.LowestOffset %d too low", req.Stack.LowestOffset)
	}
	return fmt.Sprintf("read-only value copy needs %d bytes below the spill slots; Stack.LowestOffset %d too low",
		group.sites[0].mapInfo.ValueSize, req.Stack.LowestOffset)
}

// reachesBelowBase reports whether group uses slots below the three base ones:
// the generic or dispatch hook's map slot, or a value copy. Under Dispatch
// that is every lookup group, so Auto's first retry already drops them all.
func reachesBelowBase(group lookupGroup, req LookupRequest) bool {
	return groupStackReach(group, req) < lookupSlots(req.Stack.LowestOffset).result
}

// checkLookupMap returns why a typed hook cannot take m's key and value, or
// "". The two consumers wrap it: the explicit-selection refusal adds the
// ErrRefused prefix once, and discovery leaves it bare in LookupSite.Reason.
func checkLookupMap(m *RawMap) string {
	// These maps return ordinary value memory. Other map kinds can return
	// special objects (notably map-in-map), so do not infer their pointer ABI.
	switch m.Type {
	case ebpf.Hash, ebpf.Array, ebpf.PerCPUHash, ebpf.PerCPUArray, ebpf.LRUHash, ebpf.LRUCPUHash, ebpf.LPMTrie:
	default:
		return fmt.Sprintf("map type %s is unsupported", m.Type)
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
			return fmt.Sprintf("map %s BTF size does not match map size %d", field.name, field.size)
		}
		if s, ok := btf.UnderlyingType(field.typ).(*btf.Struct); ok && (s.Name == "xdp_md" || s.Name == "__sk_buff" || s.Name == "bpf_dynptr") {
			return fmt.Sprintf("map %s type %q has a special global-function pointer ABI", field.name, s.Name)
		}
	}
	return ""
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
// reserved, the entry and tail-call hook names; with Dispatch every group is
// named HookName.
func selectLookups(sites []discoveredLookup, req LookupRequest, reserved []string) ([]lookupGroup, []LookupSite, error) {
	if req.Auto {
		if !req.Site.empty() {
			return nil, nil, refuse("Auto selects every supported lookup; Site must be empty")
		}
		selected := make(map[string]bool, len(req.Maps))
		for _, name := range req.Maps {
			if _, dup := selected[name]; name == "" || dup {
				return nil, nil, refuse("Maps names must be non-empty and unique; got %q", name)
			}
			selected[name] = false
		}
		var groups []lookupGroup
		var skipped []LookupSite
		var generic []discoveredLookup
		index := map[string]int{}
		for _, site := range sites {
			if len(selected) != 0 {
				if _, ok := selected[site.MapName]; !ok || site.MapName == "" {
					site.Reason = "map not selected by Maps"
					skipped = append(skipped, site.LookupSite)
					continue
				}
				selected[site.MapName] = true
			}
			if site.generic || site.typedOnly {
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
		for _, name := range req.Maps {
			if !selected[name] {
				return nil, nil, refuse("Maps name %q matches no lookup", name)
			}
		}
		if len(generic) != 0 {
			groups = append(groups, lookupGroup{sites: generic, generic: true})
		}
		used := map[string]bool{}
		for _, name := range reserved {
			used[name] = true
		}
		// A group whose hook name cannot be formed is skipped like any other
		// site Auto cannot instrument. With Dispatch every group is HookName.
		var named []lookupGroup
		for i, group := range groups {
			if req.Dispatch {
				group.name = req.HookName
				named = append(named, group)
				continue
			}
			mapName := group.sites[0].MapName
			if group.generic {
				mapName = "any"
			}
			if group.name = autoHookName(req.HookName, mapName, i, used); validIdent(group.name) {
				named = append(named, group)
				continue
			}
			skipped = skipGroup(skipped, group, fmt.Sprintf("hook name %q is longer than %d bytes", group.name, MaxHookName))
		}
		if len(named) == 0 && !req.Entry && !req.TailCalls {
			return nil, skipped, refuse("no supported lookup sites (%d skipped)", len(skipped))
		}
		return named, skipped, nil
	}
	if len(req.Maps) != 0 {
		return nil, nil, refuse("Maps filters Auto and needs it")
	}
	if req.Site.MapName == "" {
		if (req.Entry || req.TailCalls) && req.Site.empty() {
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
	if req.Dispatch && req.CopyReadOnly {
		return nil, plan, refuse("Dispatch passes untrusted pointers; it does not combine with CopyReadOnly")
	}
	var reserved []string
	entryName, tailName := req.HookName+"_entry", req.HookName+"_tail_call"
	if req.Dispatch {
		entryName, tailName = req.HookName, req.HookName
	} else {
		if req.Entry {
			reserved = append(reserved, entryName)
		}
		if req.TailCalls {
			reserved = append(reserved, tailName)
		}
	}
	groups, skipped, err := selectLookups(sites, req, reserved)
	plan.skipped = skipped
	if err != nil {
		return nil, plan, err
	}
	if err := CheckLookupStack(req); err != nil {
		return nil, plan, err
	}
	// Drop groups whose slots reach past siteFrameLimit. Auto skips the
	// sites and lists them; explicit selection refuses, since the user named
	// them. Dropping the one generic group means no hook takes the map pointer.
	var kept []lookupGroup
	for _, group := range groups {
		if groupStackReach(group, req) >= -siteFrameLimit {
			kept = append(kept, group)
			continue
		}
		reason := siteFrameReason(group, req)
		if !req.Auto {
			return nil, plan, refuse("%s", reason)
		}
		plan.skipped = skipGroup(plan.skipped, group, reason)
	}
	groups = kept
	if len(groups) == 0 && !req.Entry && !req.TailCalls {
		return nil, plan, refuse("no lookup site fits the audited stack (%d skipped)", len(plan.skipped))
	}
	allTails := tailCallSites(insns)
	var tails []tailCallSite
	if req.TailCalls {
		if tails = allTails; len(tails) == 0 {
			return nil, plan, refuse("TailCalls: no bpf_tail_call in the program")
		}
	}
	names := map[string]bool{}
	for _, group := range groups {
		names[group.name] = true
	}
	if req.Dispatch {
		names[req.HookName] = true
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
	ctxName := lookupContext(typ)
	if !ok || len(proto.Params) != 1 {
		return nil, plan, refuse("entry BTF must take one struct %s pointer", ctxName)
	}
	ctx, ok := btf.UnderlyingType(proto.Params[0].Type).(*btf.Pointer)
	if !ok {
		return nil, plan, refuse("entry BTF context is not a pointer")
	}
	ctxStruct, ok := btf.UnderlyingType(ctx.Target).(*btf.Struct)
	if !ok || ctxStruct.Name != ctxName {
		return nil, plan, refuse("entry BTF context is not struct %s", ctxName)
	}
	emit := lookupEmitter{insns: insns, req: req, ctxType: proto.Params[0].Type, tails: tails, entryName: entryName, tailName: tailName}
	spliced, hooks, err := emit.splice(groups)
	if err != nil {
		return nil, plan, err
	}
	// Deeper frames and the hook frames count toward the kernel's limits on
	// call chains; refuse rather than emit a program the verifier would reject.
	broken, err := stackLimitsBroken(insns, spliced, req.Stack.LowestOffset)
	if err != nil {
		return nil, plan, err
	}
	// Auto gives up lookups before the whole rule: first the groups that
	// reach below the base slots (the generic hook's map slot, a value copy),
	// then every lookup group, keeping the entry and tail-call hooks. Each
	// dropped site is skipped with the limit it broke. Splicing is pure, so
	// each retry starts again from insns.
	for _, keep := range []func(lookupGroup) bool{
		func(group lookupGroup) bool { return !reachesBelowBase(group, req) },
		func(lookupGroup) bool { return false },
	} {
		if broken == "" || !req.Auto {
			break
		}
		var fewer []lookupGroup
		for _, group := range groups {
			if keep(group) {
				fewer = append(fewer, group)
			} else {
				plan.skipped = skipGroup(plan.skipped, group, broken)
			}
		}
		if len(fewer) == len(groups) {
			continue
		}
		if groups = fewer; len(groups) == 0 && !req.Entry && !req.TailCalls {
			return nil, plan, refuse("no lookup site fits the audited stack (%d skipped): %s", len(plan.skipped), broken)
		}
		if spliced, hooks, err = emit.splice(groups); err != nil {
			return nil, plan, err
		}
		if broken, err = stackLimitsBroken(insns, spliced, req.Stack.LowestOffset); err != nil {
			return nil, plan, err
		}
	}
	if broken != "" {
		return nil, plan, refuse("%s", broken)
	}
	var selected []discoveredLookup
	for _, group := range groups {
		selected = append(selected, group.sites...)
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].SitePC < selected[j].SitePC })
	plan.sites, plan.hooks = publicLookupSites(selected), hooks
	return spliced, plan, nil
}

// skipGroup appends group's sites to skipped with reason.
func skipGroup(skipped []LookupSite, group lookupGroup, reason string) []LookupSite {
	for _, site := range group.sites {
		s := site.LookupSite
		s.Reason = reason
		skipped = append(skipped, s)
	}
	return skipped
}

// lookupEmitter generates the hooks for a set of lookup groups, plus the
// entry and tail-call hooks req asks for, and splices their calls into insns.
type lookupEmitter struct {
	insns               asm.Instructions
	req                 LookupRequest
	ctxType             btf.Type
	tails               []tailCallSite
	entryName, tailName string
}

func (e lookupEmitter) splice(groups []lookupGroup) (asm.Instructions, []LookupHook, error) {
	req := e.req
	var hooks asm.Instructions
	var plan []LookupHook
	calls := map[uint32]siteCall{}
	// A hook with the generic signature: the generic group's, or with Dispatch
	// the one hook every site calls.
	untrustedABI := func(name string) asm.Instructions {
		hook := genericHook(name, e.ctxType)
		if req.StaticUntrusted {
			hook = staticHook(hook)
		}
		return hook
	}
	shared := LookupHook{Untrusted: !req.StaticUntrusted, Static: req.StaticUntrusted, Dispatch: req.Dispatch}
	if req.Dispatch {
		hooks = untrustedABI(req.HookName)
	}
	for _, group := range groups {
		if group.generic || req.Dispatch {
			if !req.Dispatch {
				hooks = append(hooks, untrustedABI(group.name)...)
			}
			hook := shared
			hook.Name, hook.Kind, hook.Sites, hook.Generic = group.name, HookLookup, publicLookupSites(group.sites), group.generic
			if !group.generic {
				hook.MapName = group.sites[0].MapName
			}
			plan = append(plan, hook)
			for _, site := range group.sites {
				calls[site.SitePC] = siteCall{hook: group.name, withSite: true, withMap: true, dispatch: req.Dispatch}
			}
			continue
		}
		m := group.sites[0].mapInfo
		key, value := lookupABI(m)
		// The verifier checks an ordinary memory argument for both reads and
		// writes, so either restriction needs untrusted arguments, unless a
		// readable value is copied to the stack, or the hook is static.
		restricted := m.Flags&(bpfFRdonlyProg|bpfFWronlyProg) != 0
		copied := copiesValue(m, req)
		static := restricted && !copied && req.StaticUntrusted
		untrusted := restricted && !copied && !static
		var copySize uint32
		if copied {
			copySize = m.ValueSize
		}
		body := lookupHook(group.name, e.ctxType, key, value, req.Auto, untrusted)
		if static {
			body = staticHook(body) // keeps the typed proto; the kernel need not trust it
		}
		hooks = append(hooks, body...)
		plan = append(plan, LookupHook{Name: group.name, Kind: HookLookup, MapName: group.sites[0].MapName, Sites: publicLookupSites(group.sites),
			Untrusted: untrusted, Copied: copied, Static: static, ReadOnly: m.Flags&bpfFRdonlyProg != 0 && m.Flags&bpfFWronlyProg == 0})
		for _, site := range group.sites {
			calls[site.SitePC] = siteCall{hook: group.name, withSite: req.Auto, copySize: copySize}
		}
	}
	// With Dispatch the entry and tail-call hooks are the shared hook; otherwise
	// each gets its own scalar hook.
	kindHook := func(name string, kind HookKind, scalars ...string) LookupHook {
		if req.Dispatch {
			hook := shared
			hook.Name, hook.Kind = name, kind
			return hook
		}
		hooks = append(hooks, scalarHook(name, e.ctxType, scalars...)...)
		return LookupHook{Name: name, Kind: kind}
	}
	if req.Entry {
		plan = append(plan, kindHook(e.entryName, HookEntry))
	}
	if req.TailCalls {
		hook := kindHook(e.tailName, HookTailCall, "site", "index")
		for _, site := range e.tails {
			hook.Sites = append(hook.Sites, site.LookupSite)
			calls[site.SitePC] = siteCall{hook: e.tailName, withSite: true, withMap: req.Dispatch, dispatch: req.Dispatch, tailCall: true, localCtx: site.local}
		}
		plan = append(plan, hook)
	}
	entry := entryCall{name: e.entryName, on: req.Entry, dispatch: req.Dispatch}
	out, err := spliceLookupCalls(e.insns, calls, req.Stack, hooks, entry)
	return out, plan, err
}

// entryCall is the hook called right after the entry ctx spill, if on. A
// dispatch entry call also passes DispatchEntrySite and NULL pointers.
type entryCall struct {
	name     string
	on       bool
	dispatch bool
}

// siteCall is the hook a helper site calls, whether it passes its SitePC and
// the helper's map pointer (R1 of a lookup, R2 of a tail call), and whether
// the site is a bpf_tail_call rather than a lookup. A localCtx tail call saves
// its own ctx before the helper. dispatch selects the dispatch hook's argument
// layout: a dispatch tail call passes the index by pointer, a NULL value and
// the prog array. A nonzero copySize passes a stack copy of that many value
// bytes.
type siteCall struct {
	hook     string
	withSite bool
	withMap  bool
	tailCall bool
	dispatch bool
	localCtx bool
	copySize uint32
}

// spliceLookup splices one plain typed hook's calls, the narrow entry point
// the splicing tests drive. Without CheckLookupStack in front of it, it checks
// that the three base slots stay within the 512-byte stack itself.
func spliceLookup(input asm.Instructions, sitePCs []uint32, req LookupRequest) (asm.Instructions, error) {
	if req.Stack.LowestOffset < -512 || req.Stack.LowestOffset > 0 {
		return nil, refuse("StackAudit.LowestOffset must be in [-512, 0]")
	}
	if lookupSlots(req.Stack.LowestOffset).result < -512 {
		return nil, refuse("three lookup spill slots exceed the 512-byte stack")
	}
	calls := make(map[uint32]siteCall, len(sitePCs))
	for _, pc := range sitePCs {
		calls[pc] = siteCall{hook: req.HookName}
	}
	return spliceLookupCalls(input, calls, req.Stack, nil, entryCall{})
}

// spliceLookupCalls instruments each helper in calls and places hook right
// after the entry function. An entry hook is called with ctx right after the
// entry ctx spill. The caller has checked that every slot the calls use lies
// within the stack (CheckLookupStack and groupStackReach, or spliceLookup).
func spliceLookupCalls(input asm.Instructions, calls map[uint32]siteCall, stack StackAudit, hook asm.Instructions, entryHook entryCall) (asm.Instructions, error) {
	slots := lookupSlots(stack.LowestOffset)
	ctx, key, spillR0, mapSlot := int16(slots.ctx), int16(slots.key), int16(slots.result), int16(slots.mapSlot)
	copyAt := func(call siteCall) int { return slots.copyAt(call.copySize) }
	// Every site of every hook shares the slots: sites run one at a time.
	// A tail-call site keeps its index (R3) in the key slot.
	afterFor := func(pc uint32, call siteCall) asm.Instructions {
		if call.tailCall && call.dispatch {
			// A dispatch hook takes the index by pointer to its spill and the
			// prog array as the map.
			return asm.Instructions{
				asm.LoadMem(asm.R1, asm.RFP, ctx, asm.DWord),
				asm.Mov.Imm32(asm.R2, int32(pc)),
				asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, int32(key)),
				asm.Mov.Imm(asm.R4, 0),
				asm.LoadMem(asm.R5, asm.RFP, mapSlot, asm.DWord),
				asm.Call.Label(call.hook),
			}
		}
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
			if call.withMap {
				spill = append(spill, asm.StoreMem(asm.RFP, mapSlot, asm.R2, asm.DWord))
			}
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
	if entryHook.dispatch && entryHook.on {
		// The callee reads every argument register, so none may be left
		// uninitialized.
		prologue = asm.Instructions{asm.Mov.Imm32(asm.R2, -1) /* DispatchEntrySite */, asm.Mov.Imm(asm.R3, 0),
			asm.Mov.Imm(asm.R4, 0), asm.Mov.Imm(asm.R5, 0)}
	}
	if entryHook.on {
		prologue = append(prologue, asm.Call.Label(entryHook.name), asm.LoadMem(asm.R1, asm.RFP, ctx, asm.DWord))
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
			if old > 0 && (ins.Symbol() != "" || btf.FuncMetadata(&ins) != nil) {
				// A function that starts at the site starts at its spills.
				spill[0] = btf.WithFuncMetadata(spill[0].WithSymbol(ins.Symbol()).WithSource(ins.Source()), btf.FuncMetadata(&ins))
				ins = btf.WithFuncMetadata(ins.WithSymbol("").WithSource(nil), nil)
			}
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
