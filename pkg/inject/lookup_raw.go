package inject

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// RawMap is the identity and ABI obtained from a map fd. Key and Value may
// belong to a different BTF object from the program. Type preserves the same
// map-kind restrictions as TransformLookup; Name is used by LookupSelector.
type RawMap struct {
	Name               string
	Type               ebpf.MapType
	KeySize, ValueSize uint32
	Flags              uint32 // map_flags; BPF_F_RDONLY_PROG or BPF_F_WRONLY_PROG makes the hook untrusted (see LookupHook)
	InnerFlags         uint32 // map_flags of a map-in-map's inner-map template; BPF_F_RDONLY_PROG when unknown, so its values count as read-only
	Key, Value         btf.Type
}

// RawProgram describes one BPF_PROG_LOAD, with no ELF sections or collection.
// Instructions are already flattened and CO-RE relocated. Maps is keyed by
// the fd in the low 32 bits of each LDIMM64 map reference, including map-value
// references. No map fds are queried or owned by this package.
//
// BTF is the standalone program BTF referenced by prog_btf_fd. FuncInfo and
// LineInfo contain native-endian kernel wire records (8 and 16 bytes each,
// respectively), without record-size headers. Offsets count raw BPF slots,
// not bytes or Go instruction indices. Other record sizes must be normalized
// by the caller. These buffers override instruction function/source metadata.
// Symbolic function references are also accepted, with the ELF path's rules.
type RawProgram struct {
	Instructions asm.Instructions
	Type         ebpf.ProgramType
	BTF          *btf.Spec
	FuncInfo     []byte
	LineInfo     []byte
	Maps         map[int32]RawMap
}

// LookupRequestRaw selects sites in a single raw program. The caller certifies
// the supplied instructions, map identities, BTF and stack audit together;
// there is no ELF hash binding. Checksums only cover instruction encoding.
type LookupRequestRaw struct {
	Site            LookupSelector
	Auto            bool       // see LookupRequest.Auto
	Maps            []string   // see LookupRequest.Maps
	Entry           bool       // see LookupRequest.Entry
	TailCalls       bool       // see LookupRequest.TailCalls
	CopyReadOnly    bool       // see LookupRequest.CopyReadOnly
	StaticUntrusted bool       // see LookupRequest.StaticUntrusted
	Dispatch        bool       // see LookupRequest.Dispatch
	Lookups         LookupWhen // see LookupRequest.Lookups
	Updates         CallWhen   // see LookupRequest.Updates
	Deletes         CallWhen   // see LookupRequest.Deletes
	Pushes          CallWhen   // see LookupRequest.Pushes
	Pops            CallWhen   // see LookupRequest.Pops
	Peeks           CallWhen   // see LookupRequest.Peeks
	HookName        string
	Stack           StackAudit
}

// LookupResultRaw contains a transformed instruction slice and matching load
// metadata. Instructions.Marshal resolves the generated symbolic hook calls;
// marshal a copy if retaining the unresolved checksum representation.
//
// BTFBytes is an extended standalone BTF blob for a future BPF_BTF_LOAD. BTF
// is its parsed form. Original type IDs are preserved; hook types and any
// map types from other BTF objects are appended. The string table is rebuilt,
// so the returned native-endian FuncInfo and LineInfo MUST be used with this
// blob, not the original BTF. HookFuncInfo is the hook's 8-byte func_info row
// and HookTypeID is its BTF FUNC ID; with several hooks they describe the first
// element of Hooks, and Hooks lists each one. No BTF or program is loaded here.
//
// Site, Sites, Hooks, Skipped, insertion counts and checksums have
// LookupResult's semantics.
// Input slices and BTF types are not modified. Function and map BTF types
// used by the transform are copied. Other instruction metadata is retained.
type LookupResultRaw struct {
	Instructions                        asm.Instructions
	BTF                                 *btf.Spec
	BTFBytes                            []byte
	FuncInfo, LineInfo                  []byte
	HookFuncInfo                        []byte
	HookTypeID                          btf.TypeID
	HookName                            string
	Site                                LookupSite
	Sites                               []LookupSite
	Hooks                               []LookupHook
	Skipped                             []LookupSite
	SourceChecksum, TransformedChecksum string
	InsertedAt                          uint32
	InsertedSlots, AddedBytes           int
}

// Request is the ELF-side request r stands for, without ELFSHA256 and
// ProgramName; every field is forwarded (TestRawRequestForwardsOptions guards
// against a dropped field).
func (r LookupRequestRaw) Request() LookupRequest {
	return LookupRequest{Site: r.Site, Auto: r.Auto, Maps: r.Maps, Entry: r.Entry, TailCalls: r.TailCalls,
		CopyReadOnly: r.CopyReadOnly, StaticUntrusted: r.StaticUntrusted, Dispatch: r.Dispatch, Lookups: r.Lookups, Updates: r.Updates, Deletes: r.Deletes,
		Pushes: r.Pushes, Pops: r.Pops, Peeks: r.Peeks, HookName: r.HookName, Stack: r.Stack}
}

// hookSuffix is the longest fixed suffix the transform appends to HookName
// for req: none with Dispatch, whose one hook is HookName itself,
// "_tail_call" with TailCalls, "_entry" with Entry, "_0" with Auto, whose
// per-map names that would pass MaxHookName fall back to HOOKNAME_<index> (a
// group whose name still does not fit is skipped), and "_miss", "_update" or
// "_delete" after a map's name for the ops r observes.
func hookSuffix(r LookupRequest) string {
	if r.Dispatch {
		return ""
	}
	lookup := ""
	if r.Auto {
		lookup = "_0"
	}
	suffixes := []string{lookup}
	for _, op := range []struct {
		suffix string
		on     bool
	}{{"_miss", r.Lookups.miss()}, {"_update", r.Updates != ""}, {"_delete", r.Deletes != ""},
		{"_push", r.Pushes != ""}, {"_pop", r.Pops != ""}, {"_peek", r.Peeks != ""}} {
		if op.on {
			suffixes = append(suffixes, lookup+op.suffix)
		}
	}
	if r.TailCalls {
		suffixes = append(suffixes, "_tail_call")
	}
	if r.Entry {
		suffixes = append(suffixes, "_entry")
	}
	return slices.MaxFunc(suffixes, func(a, b string) int { return len(a) - len(b) })
}

// ValidateRaw checks the parts of req that do not depend on the program: the
// hook name, with room for the suffix the transform appends (hookSuffix),
// Dispatch without CopyReadOnly, the result sets (checkOps), and the audited
// stack bound (CheckLookupStack). syscallhook.Validate calls it, so a
// configuration check and the transform share these limits.
func ValidateRaw(req LookupRequestRaw) error {
	r := req.Request()
	if !validIdent(r.HookName) {
		return refuse("HookName %q must be a valid C/BTF identifier (1-%d chars, [A-Za-z_][A-Za-z0-9_]*)", r.HookName, MaxHookName)
	}
	if r.Dispatch && r.CopyReadOnly {
		return refuse("Dispatch passes untrusted pointers; it does not combine with CopyReadOnly")
	}
	if err := checkOps(r); err != nil {
		return err
	}
	if suffix := hookSuffix(r); len(r.HookName)+len(suffix) > MaxHookName {
		return refuse("HookName %q with the suffix %q exceeds %d bytes", r.HookName, suffix, MaxHookName)
	}
	return CheckLookupStack(r)
}

// DiscoverLookupsRaw lists lookup sites using map-fd identity and raw load
// metadata. It performs no syscalls and requires no stack audit.
func DiscoverLookupsRaw(p RawProgram) ([]LookupSite, error) {
	insns, _, resolve, err := prepareRawLookup(p)
	if err != nil {
		return nil, err
	}
	sites, err := discoverLookupProgram(insns, p.Type, resolve)
	return publicLookupSites(sites), err
}

// DiscoverMapCallsRaw is DiscoverLookupsRaw for every map call; see
// DiscoverMapCalls.
func DiscoverMapCallsRaw(p RawProgram) ([]LookupSite, error) {
	insns, _, resolve, err := prepareRawLookup(p)
	if err != nil {
		return nil, err
	}
	sites, err := discoverMapCalls(insns, p.Type, resolve)
	return publicLookupSites(sites), err
}

// TransformLookupRaw applies the same instruction-level transform as
// TransformLookup, including hook placement before existing subprograms.
// Any refusal returns nil and leaves the caller's inputs untouched.
func TransformLookupRaw(p RawProgram, req LookupRequestRaw) (*LookupResultRaw, error) {
	if !validIdent(req.HookName) {
		return nil, refuse("HookName must be a valid C/BTF identifier (1-%d chars)", MaxHookName)
	}
	insns, types, resolve, err := prepareRawLookup(p)
	if err != nil {
		return nil, err
	}
	// Numeric map loads have no Reference metadata for checkReferences to see.
	// Maps are told apart by fd, so an unnamed map only fails to match a
	// MapName selector.
	for i := range insns {
		if insns[i].IsLoadFromMap() {
			if _, m := resolve(&insns[i]); m == nil {
				return nil, refuse("map fd %d lacks identity", int32(insns[i].Constant))
			}
		}
	}
	out, plan, err := transformLookupProgram(insns, p.Type, types, resolve, req.Request())
	if err != nil {
		return nil, err
	}
	builder, err := rawBTFBuilder(types)
	if err != nil {
		return nil, err
	}
	fi, li, err := btf.MarshalExtInfos(out, builder)
	if err != nil {
		return nil, refuse("encoding load metadata: %v", err)
	}
	blob, err := marshalRawBTF(builder, types)
	if err != nil {
		return nil, refuse("extending program BTF: %v", err)
	}
	extended, err := btf.LoadSpecFromReader(bytes.NewReader(blob))
	if err != nil {
		return nil, refuse("parsing extended BTF: %v", err)
	}
	hookIDs := map[string]btf.TypeID{}
	for i := range out {
		if fn := btf.FuncMetadata(&out[i]); fn != nil {
			for _, hook := range plan.hooks {
				if fn.Name == hook.Name {
					if hookIDs[hook.Name], err = builder.Add(fn); err != nil {
						return nil, refuse("hook BTF ID: %v", err)
					}
				}
			}
		}
	}
	for i := range plan.hooks {
		hook := &plan.hooks[i]
		hook.TypeID = hookIDs[hook.Name]
		for off := 0; off < len(fi); off += 8 {
			if btf.TypeID(binary.NativeEndian.Uint32(fi[off+4:])) == hook.TypeID {
				hook.FuncInfo = bytes.Clone(fi[off : off+8])
			}
		}
	}
	sourceSum, err := checksum(insns, rawByteOrder())
	if err != nil {
		return nil, fmt.Errorf("inject: checksumming source: %w", err)
	}
	resultSum, err := checksum(out, rawByteOrder())
	if err != nil {
		return nil, fmt.Errorf("inject: checksumming result: %w", err)
	}
	added := int(out.Size() - insns.Size())
	return &LookupResultRaw{Instructions: out, BTF: extended, BTFBytes: blob, FuncInfo: fi, LineInfo: li,
		HookFuncInfo: plan.hooks[0].FuncInfo, HookTypeID: plan.hooks[0].TypeID, HookName: plan.hooks[0].Name,
		Site: plan.first(), Sites: plan.sites, Hooks: plan.hooks, Skipped: plan.skipped,
		SourceChecksum: sourceSum, TransformedChecksum: resultSum, InsertedSlots: added / asm.InstructionSize, AddedBytes: added}, nil
}

// Seed every original ID, including unnamed types, before adding hook types.
func rawBTFBuilder(spec *btf.Spec) (*btf.Builder, error) {
	builder := new(btf.Builder)
	for id := btf.TypeID(1); ; id++ {
		typ, err := spec.TypeByID(id)
		if errors.Is(err, btf.ErrNotFound) {
			break
		}
		if err != nil {
			return nil, refuse("reading BTF type %d: %v", id, err)
		}
		got, err := builder.Add(typ)
		if err != nil || got != id {
			return nil, refuse("cannot preserve BTF type ID %d: %v", id, err)
		}
	}
	return builder, nil
}

// Existing DECL_TAG records already occupy IDs in the builder. Suppress the
// synthetic tags the encoder would otherwise emit from their decoded fields.
func marshalRawBTF(builder *btf.Builder, spec *btf.Spec) ([]byte, error) {
	var fields []*[]string
	for typ, err := range spec.All() {
		if err != nil {
			return nil, err
		}
		switch t := typ.(type) {
		case *btf.Func:
			fields = append(fields, &t.Tags)
			for i := range t.ParamTags {
				fields = append(fields, &t.ParamTags[i])
			}
		case *btf.Struct:
			fields = append(fields, &t.Tags)
			for i := range t.Members {
				fields = append(fields, &t.Members[i].Tags)
			}
		case *btf.Union:
			fields = append(fields, &t.Tags)
			for i := range t.Members {
				fields = append(fields, &t.Members[i].Tags)
			}
		case *btf.Typedef:
			fields = append(fields, &t.Tags)
		case *btf.Var:
			fields = append(fields, &t.Tags)
		}
	}
	saved := make([][]string, len(fields))
	for i, field := range fields {
		saved[i], *field = *field, nil
	}
	defer func() {
		for i, field := range fields {
			*field = saved[i]
		}
	}()
	return builder.Marshal(nil, nil)
}

func prepareRawLookup(p RawProgram) (asm.Instructions, *btf.Spec, lookupMapResolver, error) {
	if p.BTF == nil {
		return nil, nil, nil, refuse("program BTF is required")
	}
	insns := append(asm.Instructions(nil), p.Instructions...)
	types := p.BTF.Copy()
	indices := make(map[uint32]int)
	it := insns.Iterate()
	for it.Next() {
		indices[uint32(it.Offset)] = it.Index
		*it.Ins = btf.WithFuncMetadata(it.Ins.WithSource(nil), nil)
	}
	for _, info := range []struct {
		name string
		data []byte
		size int
	}{{"func_info", p.FuncInfo, 8}, {"line_info", p.LineInfo, 16}} {
		if len(info.data)%info.size != 0 {
			return nil, nil, nil, refuse("invalid %s record size", info.name)
		}
		var prev uint32
		for off := 0; off < len(info.data); off += info.size {
			pc := binary.NativeEndian.Uint32(info.data[off:])
			if _, ok := indices[pc]; !ok || (off > 0 && pc <= prev) {
				return nil, nil, nil, refuse("%s offsets must be increasing instruction boundaries", info.name)
			}
			prev = pc
		}
	}
	funcs, err := btf.LoadFuncInfos(bytes.NewReader(p.FuncInfo), binary.NativeEndian, uint32(len(p.FuncInfo)/8), types)
	if err != nil {
		return nil, nil, nil, refuse("decoding func_info: %v", err)
	}
	lines, err := btf.LoadLineInfos(bytes.NewReader(p.LineInfo), binary.NativeEndian, uint32(len(p.LineInfo)/16), types)
	if err != nil {
		return nil, nil, nil, refuse("decoding line_info: %v", err)
	}
	for _, fn := range funcs {
		idx := indices[uint32(fn.Offset)]
		insns[idx] = btf.WithFuncMetadata(insns[idx], fn.Func)
	}
	for _, line := range lines {
		idx := indices[uint32(line.Offset)]
		insns[idx] = insns[idx].WithSource(line.Line)
	}
	maps := make(map[int32]RawMap, len(p.Maps))
	copyType := func(typ btf.Type) btf.Type {
		if typ == nil {
			return nil
		}
		if id, err := p.BTF.TypeID(typ); err == nil {
			if copied, err := types.TypeByID(id); err == nil {
				return copied
			}
		}
		return btf.Copy(typ)
	}
	for fd, m := range p.Maps {
		m.Key, m.Value = copyType(m.Key), copyType(m.Value)
		maps[fd] = m
	}
	resolve := func(ins *asm.Instruction) (string, *RawMap) {
		fd := int32(ins.Constant)
		id := fmt.Sprintf("fd:%d", fd)
		m, ok := maps[fd]
		if !ok {
			return id, nil
		}
		return id, &m
	}
	return insns, types, resolve, nil
}

// asm requires the concrete LittleEndian or BigEndian implementation.
func rawByteOrder() binary.ByteOrder {
	if binary.NativeEndian.Uint16([]byte{1, 0}) == 1 {
		return binary.LittleEndian
	}
	return binary.BigEndian
}
