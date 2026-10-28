package inject

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// LookupSite describes a map_lookup_elem helper in a flattened XDP or tc
// program, or with Op another map helper (DiscoverMapCalls).
// Empty names or zero Line mean the input did not supply that information.
// Reason explains why a site cannot be injected; discovery still lists it.
type LookupSite struct {
	Op               HookKind // HookLookup, HookUpdate, HookDelete, HookPush, HookPop or HookPeek; HookTailCall on a tail call
	MapName          string
	KeyTypeName      string
	ValueTypeName    string
	FuncName         string
	File             string
	Line             uint32
	SitePC           uint32 // raw BPF slot index; LDIMM64 occupies two slots
	InstructionIndex int    // index in the decoded instruction slice
	Reason           string
	// Generic marks a lookup with a Reason that Auto still instruments,
	// through the generic hook (see LookupHook.Generic).
	Generic bool
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
// slots and passes the copy. Kernels without arg:untrusted load it. A value
// with a special field (see LookupHook.Untrusted) is never copied.
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
//
// Lookups picks the lookup results the hooks observe: LookupHit (the
// default) calls them when the lookup found an entry, LookupMiss when it
// returned NULL, LookupAny on both. A typed hook cannot take a NULL value, so
// a miss calls int NAME_miss(struct xdp_md *ctx, u32 site, const KEY *key)
// (without site when Auto is off) instead; with LookupAny both are generated.
// A generic or Dispatch hook is called with a NULL value on a miss.
// LookupNone instruments no lookup, for a request that observes only
// updates or deletes.
//
// Updates and Deletes, which need Auto, also instrument map_update_elem and
// map_delete_elem in the entry function: CallError calls the hook when the
// helper failed, CallAny after every call. Each map gets
// int PREFIX_MAP_update(struct xdp_md *ctx, u32 site, const KEY *key,
// const VALUE *value, u64 status) and int PREFIX_MAP_delete(struct xdp_md
// *ctx, u32 site, const KEY *key, u64 status), where status is
// (u32)ret | flags << 32 (flags is zero for a delete). An update or delete
// on a map known only at run time goes to the generic hook PREFIX_any_update
// or PREFIX_any_delete. A generic or Dispatch hook gets the result in its
// info argument instead (see genericHook); a delete passes a NULL value.
//
// Pushes, Pops and Peeks, which need Auto too, instrument map_push_elem,
// map_pop_elem and map_peek_elem on queue, stack and bloom filter maps the
// same way. They take no key: each map gets int PREFIX_MAP_push(struct
// xdp_md *ctx, u32 site, const VALUE *value, u64 status), and _pop and _peek
// alike, where status is (u32)ret | flags << 32 (flags is zero for a pop or
// peek). A pop or peek's value is what the helper wrote, zeroes when the
// queue or stack was empty; on another error, such as EBUSY, the kernel
// writes nothing. A bloom filter peek's value is the one tested. A push, pop
// or peek on a map known only at run time goes to PREFIX_any_push,
// PREFIX_any_pop or PREFIX_any_peek. A generic or Dispatch hook gets a NULL
// key and the value. A key or value that points into a BPF_F_RDONLY_PROG
// map's value makes its map's hooks for that op untrusted, or static with
// StaticUntrusted. bpf_map_lookup_percpu_elem counts as a lookup: its hooks
// do not get the CPU.
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
	Lookups         LookupWhen
	Updates         CallWhen
	Deletes         CallWhen
	Pushes          CallWhen
	Pops            CallWhen
	Peeks           CallWhen
	HookName        string
	Stack           StackAudit
}

// LookupWhen is a set of lookup results; see LookupRequest.Lookups.
type LookupWhen string

const (
	LookupHit  LookupWhen = "hit"
	LookupMiss LookupWhen = "miss"
	LookupAny  LookupWhen = "any"
	LookupNone LookupWhen = "none"
)

// hit and miss say whether w observes found entries and misses; the empty
// set is LookupHit.
func (w LookupWhen) hit() bool  { return w == "" || w == LookupHit || w == LookupAny }
func (w LookupWhen) miss() bool { return w == LookupMiss || w == LookupAny }

func (w LookupWhen) valid() bool {
	return w == "" || w == LookupHit || w == LookupMiss || w == LookupAny || w == LookupNone
}

// CallWhen is a set of results of a map call other than a lookup (update,
// delete, push, pop or peek); see LookupRequest.Updates. The empty set observes none.
type CallWhen string

const (
	CallError CallWhen = "error"
	CallAny   CallWhen = "any"
)

func (w CallWhen) valid() bool { return w == "" || w == CallError || w == CallAny }

// calls returns the results req observes for op, a map call other than a
// lookup, or "".
func (req LookupRequest) calls(op HookKind) CallWhen {
	return map[HookKind]CallWhen{HookUpdate: req.Updates, HookDelete: req.Deletes,
		HookPush: req.Pushes, HookPop: req.Pops, HookPeek: req.Peeks}[op]
}

// mapCalls reports whether req observes any map call other than a lookup.
func (req LookupRequest) mapCalls() bool {
	return req.Updates != "" || req.Deletes != "" || req.Pushes != "" || req.Pops != "" || req.Peeks != ""
}

// observes reports whether req instruments sites of op.
func (req LookupRequest) observes(op HookKind) bool {
	if op.MapCall() {
		return req.calls(op) != ""
	}
	return req.Lookups != LookupNone
}

// checkOps refuses result sets req cannot instrument.
func checkOps(req LookupRequest) error {
	if !req.Lookups.valid() {
		return refuse("Lookups must be hit, miss, any or none; got %q", req.Lookups)
	}
	if !req.Updates.valid() || !req.Deletes.valid() {
		return refuse("Updates and Deletes must be error or any; got %q and %q", req.Updates, req.Deletes)
	}
	if !req.Pushes.valid() || !req.Pops.valid() || !req.Peeks.valid() {
		return refuse("Pushes, Pops and Peeks must be error or any; got %q, %q and %q", req.Pushes, req.Pops, req.Peeks)
	}
	if req.mapCalls() && !req.Auto {
		return refuse("Updates, Deletes, Pushes, Pops and Peeks need Auto")
	}
	if req.Lookups == LookupNone && !req.Site.empty() {
		return refuse("Lookups none selects no lookup; Site must be empty")
	}
	return nil
}

// normal is w with the empty set spelled LookupHit.
func (w LookupWhen) normal() LookupWhen {
	if w == "" {
		return LookupHit
	}
	return w
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
	// HookUpdate and HookDelete observe map_update_elem and map_delete_elem
	// (LookupRequest.Updates and Deletes).
	HookUpdate HookKind = "update"
	HookDelete HookKind = "delete"
	// HookPush, HookPop and HookPeek observe map_push_elem, map_pop_elem and
	// map_peek_elem (LookupRequest.Pushes, Pops and Peeks).
	HookPush HookKind = "push"
	HookPop  HookKind = "pop"
	HookPeek HookKind = "peek"
)

// MapCall reports whether k is a map helper other than a lookup: an update,
// delete, push, pop or peek, which takes a CallWhen and an info op.
func (k HookKind) MapCall() bool {
	switch k {
	case HookUpdate, HookDelete, HookPush, HookPop, HookPeek:
		return true
	}
	return false
}

// keyless reports whether k's helper takes a value in R2 instead of a key.
func (k HookKind) keyless() bool { return k == HookPush || k == HookPop || k == HookPeek }

// LookupHook is one generated hook and the sites that call it, in original
// instruction order. An entry hook has no sites; a tail-call hook's sites are
// bpf_tail_call helpers with only location fields set. TypeID and FuncInfo are
// set by TransformLookupRaw only.
//
// Untrusted is set for a lookup hook on a map that programs cannot write or
// cannot read (BPF_F_RDONLY_PROG or BPF_F_WRONLY_PROG), or whose value holds a
// field the verifier lets programs reach only through helpers and kfuncs: a
// bpf_spin_lock, bpf_timer, kptr and the like. Its key and value are const void * tagged
// arg:untrusted, so an observer reads them by the map's sizes. Update and
// delete hooks stay typed: their key and value are the program's memory.
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
	When      string // the results that call it: a LookupWhen for a lookup hook, a CallWhen for any other map call's hook
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

// DiscoverLookups lists every map_lookup_elem and map_lookup_percpu_elem
// helper in programName, in raw
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

// DiscoverMapCalls is DiscoverLookups for every map_lookup_elem,
// map_lookup_percpu_elem, map_update_elem, map_delete_elem, map_push_elem,
// map_pop_elem and map_peek_elem helper, told apart by Op. Each site gets the
// Reason and Generic its hook would (see LookupRequest.Updates and Pushes).
func DiscoverMapCalls(elf []byte, programName string) ([]LookupSite, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bytes.Clone(elf)))
	if err != nil {
		return nil, fmt.Errorf("load collection spec: %w", err)
	}
	prog := spec.Programs[programName]
	if prog == nil {
		return nil, refuse("program %q not found", programName)
	}
	sites, err := discoverMapCalls(prog.Instructions, prog.Type, elfLookupMaps(spec))
	return publicLookupSites(sites), err
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
// readOnlyArg marks a site whose key or value pointer points into the value
// of a BPF_F_RDONLY_PROG map, such as a .rodata constant: a typed hook cannot
// take it as memory, so its hook takes untrusted pointers.
type discoveredLookup struct {
	LookupSite
	mapID       string
	mapInfo     *RawMap
	generic     bool
	typedOnly   bool
	readOnlyArg bool
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

// mapCallOps are the helpers discoverMapCalls lists.
var mapCallOps = map[asm.BuiltinFunc]HookKind{
	asm.FnMapLookupElem: HookLookup, asm.FnMapUpdateElem: HookUpdate, asm.FnMapDeleteElem: HookDelete,
	asm.FnMapPushElem: HookPush, asm.FnMapPopElem: HookPop, asm.FnMapPeekElem: HookPeek,
	// The value of the CPU the program names, as typed as a lookup's.
	asm.FnMapLookupPercpuElem: HookLookup,
}

func discoverLookupProgram(insns asm.Instructions, typ ebpf.ProgramType, resolve lookupMapResolver) ([]discoveredLookup, error) {
	sites, err := discoverMapCalls(insns, typ, resolve)
	return slices.DeleteFunc(sites, func(site discoveredLookup) bool { return site.Op != HookLookup }), err
}

func discoverMapCalls(insns asm.Instructions, typ ebpf.ProgramType, resolve lookupMapResolver) ([]discoveredLookup, error) {
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
	// readOnly[r] is set while R2 or R3 holds a pointer into the value of a
	// BPF_F_RDONLY_PROG map, loaded directly in this basic block and moved
	// only by adding a constant.
	var readOnly [asm.R4]bool
	funcStart := -1
	it = insns.Iterate()
	for it.Next() {
		pc, ins := int(it.Offset), it.Ins
		if starts[pc] {
			mapID, mapName, m = "", "", nil
			readOnly = [asm.R4]bool{}
		}
		if fn := btf.FuncMetadata(ins); fn != nil {
			funcName, funcStart, file, line = fn.Name, pc, "", 0
		}
		if src, ok := ins.Source().(*btf.Line); ok {
			file, line = src.FileName(), src.LineNumber()
		}
		if op := mapCallOps[asm.BuiltinFunc(ins.Constant)]; ins.IsBuiltinCall() && op != "" {
			site := LookupSite{Op: op, MapName: mapName, FuncName: funcName, File: file, Line: line,
				SitePC: uint32(pc), InstructionIndex: it.Index}
			if m != nil {
				site.KeyTypeName, site.ValueTypeName = lookupTypeName(m.Key), lookupTypeName(m.Value)
			}
			generic, typedOnly := false, false
			switch {
			case funcStart < 0:
				site.Reason = "program lacks BTF function info"
			case funcStart != 0:
				site.Reason = string(op) + " is not in the entry function; ctx belongs to another stack frame"
			case mapID == "":
				site.Reason, generic = "R1 is not a direct map reference in this basic block", true
			case m == nil:
				site.Reason = "map reference is not defined in the collection"
			case op == HookLookup && (m.Type == ebpf.HashOfMaps || m.Type == ebpf.ArrayOfMaps):
				site.Reason, generic = "map-in-map lookup returns an inner map", true
			default:
				// A program cannot update or delete in a map-in-map, a devmap
				// or an xskmap, so those sites fail here too. A socket map's
				// update takes a socket, which only the generic hook's
				// untyped value accepts; its delete goes along.
				if op.keyless() {
					site.Reason = checkQueueMap(m)
				} else if reason := checkLookupMap(m); reason != "" {
					site.Reason, typedOnly = reason, genericKinds[m.Type] && (op == HookLookup || sockKinds[m.Type])
				}
			}
			site.Generic = generic || typedOnly
			// The key is in R2, or for a push, pop or peek the value; an
			// update's value is in R3.
			readOnlyArg := readOnly[asm.R2] || (op == HookUpdate && readOnly[asm.R3])
			sites = append(sites, discoveredLookup{site, mapID, m, generic, typedOnly, readOnlyArg})
		}
		for r := asm.R2; r <= asm.R3; r++ {
			if !readOnly[r] || ins.Dst != r {
				continue
			}
			if class := ins.OpCode.Class(); class.IsALU() || class == asm.LdXClass || class == asm.LdClass {
				readOnly[r] = class == asm.ALU64Class && ins.OpCode.ALUOp() == asm.Add && ins.OpCode.Source() == asm.ImmSource
			}
		}
		if ins.OpCode.Class().IsJump() { // calls too
			readOnly = [asm.R4]bool{}
		}
		if ins.IsLoadFromMap() && ins.Src == asm.PseudoMapValue && (ins.Dst == asm.R2 || ins.Dst == asm.R3) {
			_, value := resolve(ins)
			readOnly[ins.Dst] = value != nil && value.Flags&bpfFRdonlyProg != 0
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

// sockKinds are the genericKinds whose updates and deletes Auto also passes to
// the generic hook; testSockUpdate updates a sockhash from tc.
var sockKinds = map[ebpf.MapType]bool{ebpf.SockMap: true, ebpf.SockHash: true}

// bpfFRdonlyProg and bpfFWronlyProg are BPF_F_RDONLY_PROG and
// BPF_F_WRONLY_PROG from the BPF UAPI.
const (
	bpfFRdonlyProg = 1 << 7
	bpfFWronlyProg = 1 << 8
)

// lookupLayout is where the transform's slots sit below the 8-byte-aligned
// floor of the audited mark: ctx, key and result (the three base slots), and
// mapSlot (the fourth, for a hook that takes the map pointer). A CopyReadOnly
// value copy goes below mapSlot, at copyAt. An update site keeps its flags in
// the result slot until the helper returns, and its value pointer in the map
// slot, or with a hook that takes the map in value, the fifth slot. A push
// keeps its flags in the result slot too, and a push, pop or peek its value
// pointer in the key slot. spliceLookupCalls places the slots by this layout, and CheckLookupStack and
// groupStackReach measure it.
type lookupLayout struct {
	ctx, key, result, mapSlot, value int
}

func lookupSlots(lowest int16) lookupLayout {
	floor := int(lowest)
	if m := floor % 8; m != 0 {
		floor -= 8 + m
	}
	return lookupLayout{ctx: floor - 8, key: floor - 16, result: floor - 24, mapSlot: floor - 32, value: floor - 40}
}

// updateValue is the slot an update site keeps its value pointer in.
func (l lookupLayout) updateValue(withMap bool) int {
	if withMap {
		return l.value
	}
	return l.mapSlot
}

// copyAt is where a size-byte value copy starts, in 8-byte units below mapSlot.
func (l lookupLayout) copyAt(size uint32) int {
	return l.mapSlot - int((size+7)/8*8)
}

// copiesValue reports whether a typed hook on m gets a stack copy of the value
// instead of a pointer into the map: m is BPF_F_RDONLY_PROG and req asks for
// CopyReadOnly.
func copiesValue(m *RawMap, req LookupRequest) bool {
	return req.CopyReadOnly && m.Flags&bpfFRdonlyProg != 0 && m.Flags&bpfFWronlyProg == 0 && specialField(m.Value) == ""
}

// LookupStackReserve reports the bytes the transform reserves strictly below
// the audited floor, as far as a request's flags determine it statically. The
// entry always spills ctx (8 bytes); a tail-call site also keeps its index in
// the key slot (16); a lookup site, possible with Site or Auto, also spills R0
// (24). With Dispatch, lookup and tail-call sites also pass the map, so they
// need the map slot (32); a dispatch entry call passes only constants. An
// update site also keeps its value pointer (32), with Dispatch in the fifth
// slot (40). A generic hook's map and value slots and a CopyReadOnly value
// copy are program-dependent and enforced during the transform (Auto skips
// the site, explicit selection refuses), not here.
func LookupStackReserve(req LookupRequest) int {
	lookups := req.Auto || !req.Site.empty()
	updates := req.Auto && req.Updates != ""
	switch {
	case req.Dispatch && updates:
		return 40
	case updates || req.Dispatch && (lookups || req.TailCalls):
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
// copy goes below it; an update keeps its value pointer below the map slot or
// in it; a plain typed lookup, delete, push, pop or peek uses only the three
// base slots, which CheckLookupStack already keeps within siteFrameLimit.
func groupStackReach(group lookupGroup, req LookupRequest) int {
	slots := lookupSlots(req.Stack.LowestOffset)
	withMap := group.generic || req.Dispatch
	if group.op == HookUpdate {
		return slots.updateValue(withMap)
	}
	if withMap {
		return slots.mapSlot
	}
	if group.op != HookLookup {
		return slots.result
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
	case group.op == HookUpdate:
		slots := 4
		if group.generic || req.Dispatch {
			slots = 5
		}
		return fmt.Sprintf("update hook needs %d spill slots for the value pointer; Stack.LowestOffset %d too low", slots, req.Stack.LowestOffset)
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
	if reason := checkMapField("key", m.Key, m.KeySize); reason != "" {
		return reason
	}
	return checkMapField("value", m.Value, m.ValueSize)
}

// checkQueueMap returns why a typed push, pop or peek hook cannot take m's
// value, or "". Only queue, stack and bloom filter maps take these helpers;
// the verifier refuses them on any other kind.
func checkQueueMap(m *RawMap) string {
	switch m.Type {
	case ebpf.Queue, ebpf.Stack, ebpf.BloomFilter:
	default:
		return fmt.Sprintf("map type %s is unsupported", m.Type)
	}
	return checkMapField("value", m.Value, m.ValueSize)
}

// checkMapField returns why a typed hook cannot take a pointer to typ, a map's
// key or value of size bytes, or "". A nil typ is fine: lookupABI passes it as
// opaque bytes.
func checkMapField(name string, typ btf.Type, size uint32) string {
	if typ == nil {
		return ""
	}
	if n, err := btf.Sizeof(typ); err != nil || n <= 0 || uint64(n) != uint64(size) {
		return fmt.Sprintf("map %s BTF size does not match map size %d", name, size)
	}
	if s, ok := btf.UnderlyingType(typ).(*btf.Struct); ok && (s.Name == "xdp_md" || s.Name == "__sk_buff" || s.Name == "bpf_dynptr") {
		return fmt.Sprintf("map %s type %q has a special global-function pointer ABI", name, s.Name)
	}
	return ""
}

// specialStructs are the value fields the verifier lets a program reach only
// through their helpers and kfuncs, never as memory passed to a function.
var specialStructs = map[string]bool{
	"bpf_spin_lock": true, "bpf_res_spin_lock": true, "bpf_timer": true, "bpf_wq": true, "bpf_task_work": true,
	"bpf_list_head": true, "bpf_list_node": true, "bpf_rb_root": true, "bpf_rb_node": true, "bpf_refcount": true,
}

// specialField returns the name of the first special field (see
// specialStructs) or kptr in typ, a map value type, or "". A typed lookup hook
// passes the value as memory, which the verifier refuses for these fields
// ("bpf_spin_lock cannot be accessed directly by load/store", "kptr cannot be
// accessed indirectly by helper").
func specialField(typ btf.Type) string {
	var walk func(t btf.Type, depth int) string
	walk = func(t btf.Type, depth int) string {
		if depth > 8 {
			return ""
		}
		switch t := btf.UnderlyingType(t).(type) {
		case *btf.Struct:
			if specialStructs[t.Name] {
				return t.Name
			}
			for _, m := range t.Members {
				if name := walk(m.Type, depth+1); name != "" {
					return name
				}
			}
		case *btf.Union:
			for _, m := range t.Members {
				if name := walk(m.Type, depth+1); name != "" {
					return name
				}
			}
		case *btf.Array:
			return walk(t.Type, depth+1)
		case *btf.Pointer:
			for target := t.Target; ; {
				tag, ok := target.(*btf.TypeTag)
				if !ok {
					break
				}
				switch tag.Value {
				case "kptr", "kptr_untrusted", "kptr_ref", "percpu_kptr", "uptr":
					return tag.Value
				}
				target = tag.Type
			}
		}
		return ""
	}
	if typ == nil {
		return ""
	}
	return walk(typ, 0)
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
			site := LookupSite{Op: HookTailCall, FuncName: funcName, File: file, Line: line, SitePC: uint32(pc), InstructionIndex: it.Index}
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

// lookupGroup is one generated hook and its selected sites, all of one op.
type lookupGroup struct {
	name     string
	missName string // a typed lookup group's NAME_miss hook, with Lookups observing misses
	op       HookKind
	sites    []discoveredLookup
	generic  bool
}

// kernelObjName is the name the kernel keeps for an object named name: an ELF
// map's symbol cut to BPF_OBJ_NAME_LEN-1 bytes.
func kernelObjName(name string) string {
	if len(name) > 15 {
		return name[:15]
	}
	return name
}

// selectLookups groups the selected map calls by hook: one group per map and
// op, and one generic group per op. Auto hook names avoid reserved, the entry
// and tail-call hook names; with Dispatch every group is named HookName.
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
		var groups, generic []lookupGroup
		var skipped []LookupSite
		index := map[string]int{}
		add := func(groups []lookupGroup, key string, site discoveredLookup, isGeneric bool) []lookupGroup {
			op := site.Op
			if op == "" {
				op = HookLookup
			}
			key += "\x00" + string(op)
			i, ok := index[key]
			if !ok {
				i = len(groups)
				index[key] = i
				groups = append(groups, lookupGroup{op: op, generic: isGeneric})
			}
			groups[i].sites = append(groups[i].sites, site)
			return groups
		}
		for _, site := range sites {
			if len(selected) != 0 {
				match := false
				for _, name := range []string{site.MapName, kernelObjName(site.MapName)} {
					if _, ok := selected[name]; ok {
						selected[name] = true
						match = true
					}
				}
				if !match {
					site.Reason = "map not selected by Maps"
					skipped = append(skipped, site.LookupSite)
					continue
				}
			}
			if site.generic || site.typedOnly {
				site.Reason = ""
				generic = add(generic, "generic", site, true)
				continue
			}
			if site.Reason != "" {
				skipped = append(skipped, site.LookupSite)
				continue
			}
			groups = add(groups, site.mapID, site, false)
		}
		for _, name := range req.Maps {
			if !selected[name] {
				what := "lookup"
				if req.mapCalls() {
					what = "map call"
				}
				return nil, nil, refuse("Maps name %q matches no %s", name, what)
			}
		}
		groups = append(groups, generic...)
		used := map[string]bool{}
		for _, name := range reserved {
			used[name] = true
		}
		// Every op of a map shares its PREFIX_MAP name: the lookup hook is
		// PREFIX_MAP itself, the others add a suffix. A group whose hook name
		// cannot be formed is skipped like any other site Auto cannot
		// instrument. With Dispatch every group is HookName.
		bases := map[string]string{}
		var named []lookupGroup
		for _, group := range groups {
			if req.Dispatch {
				group.name = req.HookName
				named = append(named, group)
				continue
			}
			id, mapName := group.sites[0].mapID, group.sites[0].MapName
			if group.generic {
				id, mapName = "\x00generic", "any"
			}
			base, ok := bases[id]
			if !ok {
				base = autoHookName(req.HookName, mapName, len(bases), used)
				bases[id] = base
			}
			names := []*string{&group.name}
			switch {
			case group.op != HookLookup:
				group.name = suffixedHookName(base, "_"+string(group.op), used)
			case !group.generic && req.Lookups.miss():
				group.name, group.missName = base, suffixedHookName(base, "_miss", used)
				names = append(names, &group.missName)
			default:
				group.name = base
			}
			if i := slices.IndexFunc(names, func(name *string) bool { return !validIdent(*name) }); i >= 0 {
				skipped = skipGroup(skipped, group, fmt.Sprintf("hook name %q is longer than %d bytes", *names[i], MaxHookName))
				continue
			}
			named = append(named, group)
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
	group := lookupGroup{name: req.HookName, op: HookLookup, sites: selected}
	if req.Lookups.miss() && !req.Dispatch {
		group.missName = req.HookName + "_miss"
	}
	return []lookupGroup{group}, nil, nil
}

// suffixedHookName is name+suffix, made unused like autoHookName's names.
func suffixedHookName(name, suffix string, used map[string]bool) string {
	name += suffix
	for used[name] {
		name += "_"
	}
	used[name] = true
	return name
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
	sites, err := discoverMapCalls(insns, typ, resolve)
	if err != nil {
		return nil, plan, err
	}
	sites = slices.DeleteFunc(sites, func(site discoveredLookup) bool { return !req.observes(site.Op) })
	if req.Dispatch && req.CopyReadOnly {
		return nil, plan, refuse("Dispatch passes untrusted pointers; it does not combine with CopyReadOnly")
	}
	if err := checkOps(req); err != nil {
		return nil, plan, err
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
		if group.missName != "" {
			if names[group.missName] || !validIdent(group.missName) {
				return nil, plan, refuse("hook name %q is invalid or used twice", group.missName)
			}
			names[group.missName] = true
		}
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
		results := req.calls(group.op)
		when := string(results)
		if group.op == HookLookup {
			when = string(req.Lookups.normal())
		}
		if group.generic || req.Dispatch {
			if !req.Dispatch {
				hooks = append(hooks, untrustedABI(group.name)...)
			}
			hook := shared
			hook.Name, hook.Kind, hook.Sites, hook.Generic = group.name, group.op, publicLookupSites(group.sites), group.generic
			hook.When = when
			if !group.generic {
				hook.MapName = group.sites[0].MapName
			}
			plan = append(plan, hook)
			for _, site := range group.sites {
				calls[site.SitePC] = siteCall{hook: group.name, op: group.op, withSite: true, withMap: true, dispatch: req.Dispatch, when: req.Lookups, results: results}
			}
			continue
		}
		m := group.sites[0].mapInfo
		key, value := lookupABI(m)
		// A key or value pointer into a read-only map's value fails a typed
		// hook's memory check like a read-only map's own value does.
		readOnlyArg := slices.ContainsFunc(group.sites, func(site discoveredLookup) bool { return site.readOnlyArg })
		if group.op != HookLookup {
			// The key and value are usually the program's memory, never the
			// map's, so the hook is typed even on a write-only map.
			static := readOnlyArg && req.StaticUntrusted
			untrusted := readOnlyArg && !static
			var hook asm.Instructions
			switch {
			case group.op.keyless():
				hook = valueHook(group.name, e.ctxType, value, untrusted)
			case group.op == HookDelete:
				hook = lookupHook(group.name, e.ctxType, key, nil, true, untrusted, "status")
			default:
				hook = lookupHook(group.name, e.ctxType, key, value, true, untrusted, "status")
			}
			if static {
				hook = staticHook(hook)
			}
			hooks = append(hooks, hook...)
			plan = append(plan, LookupHook{Name: group.name, Kind: group.op, When: when, MapName: group.sites[0].MapName, Sites: publicLookupSites(group.sites),
				Untrusted: untrusted, Static: static})
			for _, site := range group.sites {
				calls[site.SitePC] = siteCall{hook: group.name, op: group.op, results: results, withSite: true}
			}
			continue
		}
		// The verifier checks an ordinary memory argument for both reads and
		// writes, so either restriction needs untrusted arguments, unless a
		// readable value is copied to the stack, or the hook is static. A
		// value with a special field cannot be passed as memory at all, nor
		// copied.
		restricted := m.Flags&(bpfFRdonlyProg|bpfFWronlyProg) != 0 || specialField(m.Value) != "" || readOnlyArg
		copied := copiesValue(m, req) && !readOnlyArg
		static := restricted && !copied && req.StaticUntrusted
		untrusted := restricted && !copied && !static
		var copySize uint32
		if copied {
			copySize = m.ValueSize
		}
		readOnly := m.Flags&bpfFRdonlyProg != 0 && m.Flags&bpfFWronlyProg == 0
		if req.Lookups.hit() {
			body := lookupHook(group.name, e.ctxType, key, value, req.Auto, untrusted)
			if static {
				body = staticHook(body) // keeps the typed proto; the kernel need not trust it
			}
			hooks = append(hooks, body...)
			plan = append(plan, LookupHook{Name: group.name, Kind: HookLookup, When: string(LookupHit), MapName: group.sites[0].MapName, Sites: publicLookupSites(group.sites),
				Untrusted: untrusted, Copied: copied, Static: static, ReadOnly: readOnly})
		}
		if group.missName != "" {
			// The key is usually program memory, never the map's, so the
			// miss hook needs no untrusted arguments even on a restricted map.
			missStatic := readOnlyArg && req.StaticUntrusted
			missUntrusted := readOnlyArg && !missStatic
			miss := lookupHook(group.missName, e.ctxType, key, nil, req.Auto, missUntrusted)
			if missStatic {
				miss = staticHook(miss)
			}
			hooks = append(hooks, miss...)
			plan = append(plan, LookupHook{Name: group.missName, Kind: HookLookup, When: string(LookupMiss), MapName: group.sites[0].MapName,
				Sites: publicLookupSites(group.sites), ReadOnly: readOnly, Untrusted: missUntrusted, Static: missStatic})
		}
		for _, site := range group.sites {
			calls[site.SitePC] = siteCall{hook: group.name, missHook: group.missName, when: req.Lookups, withSite: req.Auto, copySize: copySize}
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
// bytes. when selects the lookup results that call a hook; on a miss a typed
// lookup calls missHook without a value, a generic one hook with NULL. An
// update, delete, push, pop or peek site (op) calls hook on results.
type siteCall struct {
	hook     string
	missHook string     // a typed lookup's NAME_miss hook
	when     LookupWhen // the lookup results that call a hook
	op       HookKind   // the helper: a lookup when empty
	results  CallWhen   // the results of another map call that call hook
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
		if call.op.MapCall() {
			return mapCallAfter(pc, call, slots)
		}
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
		// hit calls the hook with the value in R0; on a miss a generic hook
		// gets R0 too, which is then NULL, and a typed one its miss hook.
		hit := func(copySize uint32) asm.Instructions {
			var args asm.Instructions
			if copySize > 0 {
				args = copyValue(asm.R0, int16(copyAt(call)), copySize)
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
			if copySize > 0 {
				value := args[len(args)-1].Dst // the register given R0
				args = append(args, asm.Mov.Reg(value, asm.RFP), asm.Add.Imm(value, int32(copyAt(call))))
			}
			return append(args, asm.Call.Label(call.hook))
		}
		miss := func() asm.Instructions {
			if call.withMap {
				return hit(0)
			}
			args := asm.Instructions{asm.LoadMem(asm.R1, asm.RFP, ctx, asm.DWord)}
			if call.withSite {
				args = append(args, asm.Mov.Imm32(asm.R2, int32(pc)), asm.LoadMem(asm.R3, asm.RFP, key, asm.DWord))
			} else {
				args = append(args, asm.LoadMem(asm.R2, asm.RFP, key, asm.DWord))
			}
			return append(args, asm.Call.Label(call.missHook))
		}
		// Each path tests R0 first, so a hook gets a value the verifier knows
		// to be either a map value or zero. Both paths end by restoring R0.
		out := asm.Instructions{asm.StoreMem(asm.RFP, spillR0, asm.R0, asm.DWord)}
		switch {
		case call.when.hit() && call.when.miss():
			onHit, onMiss := hit(call.copySize), miss()
			null := asm.JEq.Imm(asm.R0, 0, "")
			null.Offset = int16(len(onHit) + 1)
			done := asm.Ja.Label("")
			done.Offset = int16(len(onMiss))
			out = append(append(append(append(out, null), onHit...), done), onMiss...)
		case call.when.miss():
			onMiss := miss()
			found := asm.JNE.Imm(asm.R0, 0, "")
			found.Offset = int16(len(onMiss))
			out = append(append(out, found), onMiss...)
		default:
			onHit := hit(call.copySize)
			null := asm.JEq.Imm(asm.R0, 0, "")
			null.Offset = int16(len(onHit))
			out = append(append(out, null), onHit...)
		}
		return append(out, asm.LoadMem(asm.R0, asm.RFP, spillR0, asm.DWord))
	}
	before := func(call siteCall) asm.Instructions {
		if call.op.MapCall() {
			// R2 is the key, or the value of a push, pop or peek; the key
			// slot keeps either.
			spill := asm.Instructions{asm.StoreMem(asm.RFP, key, asm.R2, asm.DWord)}
			switch call.op {
			case HookUpdate:
				// The flags wait in the result slot until the helper returns.
				spill = append(spill, asm.StoreMem(asm.RFP, spillR0, asm.R4, asm.DWord),
					asm.StoreMem(asm.RFP, int16(slots.updateValue(call.withMap)), asm.R3, asm.DWord))
			case HookPush:
				spill = append(spill, asm.StoreMem(asm.RFP, spillR0, asm.R3, asm.DWord))
			}
			if call.withMap {
				spill = append(spill, asm.StoreMem(asm.RFP, mapSlot, asm.R1, asm.DWord))
			}
			return spill
		}
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

// InfoOpUpdate, InfoOpDelete, InfoOpPush, InfoOpPop and InfoOpPeek are the
// ops in bits 32-35 of a generic or Dispatch hook's info argument. A lookup,
// the entry and a failed tail call leave bits 32-63 zero, so their info is
// the site alone.
const (
	InfoOpUpdate = 1
	InfoOpDelete = 2
	InfoOpPush   = 3
	InfoOpPop    = 4
	InfoOpPeek   = 5
)

var infoOps = map[HookKind]int32{HookUpdate: InfoOpUpdate, HookDelete: InfoOpDelete,
	HookPush: InfoOpPush, HookPop: InfoOpPop, HookPeek: InfoOpPeek}

// mapCallAfter calls a map call site's hook after the helper, on every
// result or (CallError) when R0 is negative, then restores R0. A typed hook
// gets status = (u32)ret | flags << 32 after its key and value (a push, pop
// or peek: its value alone). A generic or dispatch hook gets info = site |
// op << 32 | (flags & 0xff) << 36 | (u16)ret << 48, the key or NULL, the
// value or NULL, and the map.
func mapCallAfter(pc uint32, call siteCall, slots lookupLayout) asm.Instructions {
	update, keyless := call.op == HookUpdate, call.op.keyless()
	flags := update || call.op == HookPush
	ctx, key, spillR0 := int16(slots.ctx), int16(slots.key), int16(slots.result)
	value := int16(slots.updateValue(call.withMap))
	// word builds status or info. An update or push loads its flags into it
	// before R0 takes their slot.
	word := asm.R4
	switch {
	case call.withMap:
		word = asm.R2
	case update:
		word = asm.R5
	}
	var out asm.Instructions
	if flags {
		out = append(out, asm.LoadMem(word, asm.RFP, spillR0, asm.DWord))
	}
	out = append(out, asm.StoreMem(asm.RFP, spillR0, asm.R0, asm.DWord))
	var args asm.Instructions
	if call.withMap {
		if flags {
			args = append(args, asm.And.Imm(word, 0xff), asm.LSh.Imm(word, 36))
		} else {
			args = append(args, asm.Mov.Imm(word, 0))
		}
		args = append(args,
			asm.Mov.Reg(asm.R3, asm.R0), asm.LSh.Imm(asm.R3, 48), asm.Or.Reg(word, asm.R3),
			asm.Mov.Imm(asm.R3, infoOps[call.op]), asm.LSh.Imm(asm.R3, 32), asm.Or.Reg(word, asm.R3),
			asm.Mov.Imm32(asm.R3, int32(pc)), asm.Or.Reg(word, asm.R3),
			asm.LoadMem(asm.R1, asm.RFP, ctx, asm.DWord))
		switch {
		case keyless:
			args = append(args, asm.Mov.Imm(asm.R3, 0), asm.LoadMem(asm.R4, asm.RFP, key, asm.DWord))
		case update:
			args = append(args, asm.LoadMem(asm.R3, asm.RFP, key, asm.DWord), asm.LoadMem(asm.R4, asm.RFP, value, asm.DWord))
		default:
			args = append(args, asm.LoadMem(asm.R3, asm.RFP, key, asm.DWord), asm.Mov.Imm(asm.R4, 0))
		}
		args = append(args, asm.LoadMem(asm.R5, asm.RFP, int16(slots.mapSlot), asm.DWord))
	} else {
		if flags {
			args = append(args, asm.LSh.Imm(word, 32), asm.Mov.Reg32(asm.R2, asm.R0), asm.Or.Reg(word, asm.R2))
		} else {
			args = append(args, asm.Mov.Reg32(word, asm.R0))
		}
		args = append(args,
			asm.LoadMem(asm.R1, asm.RFP, ctx, asm.DWord),
			asm.Mov.Imm32(asm.R2, int32(pc)),
			asm.LoadMem(asm.R3, asm.RFP, key, asm.DWord))
		if update {
			args = append(args, asm.LoadMem(asm.R4, asm.RFP, value, asm.DWord))
		}
	}
	args = append(args, asm.Call.Label(call.hook))
	if call.results == CallError {
		// The sign of W0, not R0: on 6.1 the kernel replaces the helper
		// with the map's own int-returning op, so an error leaves the upper
		// half of R0 zero.
		ok := asm.JSGE.Imm32(asm.R0, 0, "")
		ok.Offset = int16(len(args))
		out = append(out, ok)
	}
	out = append(out, args...)
	return append(out, asm.LoadMem(asm.R0, asm.RFP, spillR0, asm.DWord))
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

// genericHook is int NAME(struct xdp_md *ctx, u64 info, const void *key,
// const void *value, const void *map), the pointers tagged arg:untrusted like
// lookupHook's. The low 32 bits of info are the site; any other map call
// adds its op, flags and result (see mapCallAfter and InfoOpUpdate). A push,
// pop or peek passes a NULL key and its value. map is the
// helper's R1 at run time: the map itself, or for an inner lookup the inner
// map an outer lookup returned. For an outer map-in-map lookup, value is that
// inner map rather than value memory.
func genericHook(name string, ctx btf.Type) asm.Instructions {
	void := func() btf.Type { return &btf.Pointer{Target: &btf.Const{Type: &btf.Void{}}} }
	params := []btf.FuncParam{{Name: "ctx", Type: ctx}, {Name: "info", Type: &btf.Int{Name: "u64", Size: 8}},
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

// valueHook is a push, pop or peek hook, int NAME(ctx, u32 site, const VALUE
// *value, u64 status): lookupHook's miss hook with the pointer named value.
func valueHook(name string, ctx, value btf.Type, untrusted bool) asm.Instructions {
	return pointerHook(name, ctx, []btf.FuncParam{{Name: "value", Type: value}}, true, untrusted, "status")
}

// lookupHook generates a hook taking const KEY * and const VALUE *. With
// untrusted, both are const void * tagged arg:untrusted instead: the verifier
// checks an ordinary global-function memory argument for writes, even through
// const, which a value of a BPF_F_RDONLY_PROG map fails; an untrusted one is
// not checked at the call and is read with fault-handled loads. A nil value
// makes a miss hook, which takes only the key. scalars are u64 parameters
// after the pointers, such as an update hook's status.
func lookupHook(name string, ctx, key, value btf.Type, withSite, untrusted bool, scalars ...string) asm.Instructions {
	ptrs := []btf.FuncParam{{Name: "key", Type: key}}
	if value != nil {
		ptrs = append(ptrs, btf.FuncParam{Name: "value", Type: value})
	}
	return pointerHook(name, ctx, ptrs, withSite, untrusted, scalars...)
}

// pointerHook generates lookupHook's hooks with one const pointer parameter
// per ptrs entry, each a pointer to that entry's type.
func pointerHook(name string, ctx btf.Type, ptrs []btf.FuncParam, withSite, untrusted bool, scalars ...string) asm.Instructions {
	params := []btf.FuncParam{{Name: "ctx", Type: ctx}}
	regs := []asm.Register{asm.R2, asm.R3}
	if withSite {
		params = append(params, btf.FuncParam{Name: "site", Type: &btf.Int{Name: "u32", Size: 4}})
		regs = []asm.Register{asm.R3, asm.R4}
	}
	regs = regs[:len(ptrs)]
	pointers := len(params)
	for _, ptr := range ptrs {
		typ := ptr.Type
		if untrusted {
			typ = &btf.Void{}
		}
		params = append(params, btf.FuncParam{Name: ptr.Name, Type: &btf.Pointer{Target: &btf.Const{Type: typ}}})
	}
	for _, scalar := range scalars {
		params = append(params, btf.FuncParam{Name: scalar, Type: &btf.Int{Name: "u64", Size: 8}})
	}
	fn := &btf.Func{Name: name, Linkage: btf.GlobalFunc, Type: &btf.FuncProto{
		Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}, Params: params,
	}}
	if untrusted {
		fn.ParamTags = make([][]string, len(params))
		for i := pointers; i < pointers+len(regs); i++ {
			fn.ParamTags[i] = []string{"arg:untrusted"}
		}
	}
	// Global functions are verified independently with nullable memory args.
	// Actual reads keep every argument live, even after dead-register pruning.
	head := btf.WithFuncMetadata(asm.LoadMem(asm.R0, asm.R1, 0, asm.Word).WithSymbol(name).
		WithSource(asm.Comment("generated lookup observation hook "+name)), fn)
	if untrusted {
		return append(asm.Instructions{head}, untrustedReads(regs...)...)
	}
	out := asm.Instructions{head}
	for _, reg := range regs {
		null := asm.JEq.Imm(reg, 0, "")
		null.Offset = 1
		out = append(out, null, asm.LoadMem(asm.R0, reg, 0, asm.Byte))
	}
	return append(out, asm.Mov.Imm(asm.R0, 0), asm.Return())
}
