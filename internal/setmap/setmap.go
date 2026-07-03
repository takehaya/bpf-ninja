// Package setmap resolves pinned BPF HASH maps used as match sets: the
// map key IS the value (or composite of values) to match, the map value
// is a small tag (unused by lookup — presence means match). Filters
// reference a set by name (`--arg-filter "@subs"`) and the set's key
// schema comes from the map's own BTF, so entries can be added and
// removed at runtime without re-attaching the probe.
//
// Semantics: fields of a composite key AND together (one lookup); OR is
// expressed by inserting more entries (the set is the union). Partial
// keys are rejected — every key field must be bound to a source.
package setmap

import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

// MaxKeySize caps the composite key width: the BPF-side key buffer lives
// in a fixed 64-byte stack window (see program.emitSetFilters).
const MaxKeySize = 64

// KeyField is one member of the set's key schema, resolved from the
// map's BTF key type.
type KeyField struct {
	Name string
	Off  uint32 // byte offset within the key
	Size uint32 // 1, 2, 4 or 8
}

// Definition is an opened set map plus its resolved key schema.
type Definition struct {
	Map      *ebpf.Map
	KeySize  uint32
	Fields   []KeyField
	IsScalar bool // key is a bare integer (single pseudo-field)
}

// Close releases the map handle. The pin (and the map, while pinned or
// referenced by a program) survives.
func (d *Definition) Close() {
	if d.Map != nil {
		_ = d.Map.Close()
	}
}

// Field returns the key field with the given name.
func (d *Definition) Field(name string) (KeyField, bool) {
	for _, f := range d.Fields {
		if f.Name == name {
			return f, true
		}
	}
	return KeyField{}, false
}

// Set is a named set: the parsed spec (name, path, field->source mapping,
// promoted) plus the opened map definition.
type Set struct {
	SpecRef
	Def *Definition
}

// MapEntry binds one key field to a source ("arg:<param>" in v1).
type MapEntry struct {
	Field  string
	Source string
}

// SpecRef is a parsed --set specification, before the map is opened.
type SpecRef struct {
	Name    string
	Path    string
	Mapping []MapEntry
}

// ParseSetSpec parses `NAME=/pinned/path[,key(f1=arg:p1,f2,...)]`.
// The shorthand `key(imsi)` means `key(imsi=arg:imsi)`.
func ParseSetSpec(s string) (SpecRef, error) {
	var ref SpecRef
	name, rest, ok := strings.Cut(s, "=")
	if !ok || name == "" {
		return ref, fmt.Errorf("--set %q: want NAME=/pinned/path[,key(...)]", s)
	}
	ref.Name = name

	path, keySpec, hasKey := strings.Cut(rest, ",")
	if path == "" {
		return ref, fmt.Errorf("--set %q: empty pinned map path", s)
	}
	ref.Path = path
	if !hasKey {
		return ref, nil
	}

	inner, ok := strings.CutPrefix(keySpec, "key(")
	if !ok || !strings.HasSuffix(inner, ")") {
		return ref, fmt.Errorf("--set %q: expected key(field=source,...) after the path, got %q", s, keySpec)
	}
	inner = strings.TrimSuffix(inner, ")")
	for ent := range strings.SplitSeq(inner, ",") {
		ent = strings.TrimSpace(ent)
		if ent == "" {
			continue
		}
		field, source, hasSource := strings.Cut(ent, "=")
		field = strings.TrimSpace(field)
		source = strings.TrimSpace(source)
		if field == "" {
			return ref, fmt.Errorf("--set %q: empty key field name in %q", s, ent)
		}
		for _, prev := range ref.Mapping {
			if prev.Field == field {
				return ref, fmt.Errorf("--set %q: key field %q mapped twice", s, field)
			}
		}
		if !hasSource {
			source = "arg:" + field // shorthand: key(imsi) = key(imsi=arg:imsi)
		}
		if !strings.HasPrefix(source, "arg:") || len(source) <= len("arg:") {
			return ref, fmt.Errorf("--set %q: source %q must be arg:<param> (pkt: sources are not supported yet)", s, source)
		}
		ref.Mapping = append(ref.Mapping, MapEntry{Field: field, Source: source})
	}
	if len(ref.Mapping) == 0 {
		return ref, fmt.Errorf("--set %q: empty key(...) mapping", s)
	}
	return ref, nil
}

// OpenSet opens the pinned map behind a parsed spec and resolves its key
// schema. Callers own the returned Set's map handle (Set.Def.Close).
//
// For a scalar key whose BTF name is synthetic ("key") the mapping's field
// name is adopted as the canonical scalar field name, so both consumers of
// the schema — filter resolution and `set add`/`del` — see one name.
func OpenSet(ref SpecRef) (*Set, error) {
	def, err := Open(ref.Path)
	if err != nil {
		return nil, fmt.Errorf("set %q: %w", ref.Name, err)
	}
	if def.IsScalar && def.Fields[0].Name == scalarUnnamed && len(ref.Mapping) == 1 {
		def.Fields[0].Name = ref.Mapping[0].Field
	}
	return &Set{SpecRef: ref, Def: def}, nil
}

// Open loads a pinned map and resolves its key schema from the map's BTF.
func Open(path string) (*Definition, error) {
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return nil, fmt.Errorf("opening pinned map %s: %w", path, err)
	}
	def, err := describe(m)
	if err != nil {
		_ = m.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return def, nil
}

// describe validates the map and extracts the key schema from its BTF.
func describe(m *ebpf.Map) (*Definition, error) {
	if m.Type() != ebpf.Hash {
		return nil, fmt.Errorf("map type %s is not supported (need hash: the key is the match value)", m.Type())
	}
	if m.KeySize() > MaxKeySize {
		return nil, fmt.Errorf("key size %d exceeds the %d-byte limit", m.KeySize(), MaxKeySize)
	}

	keyType, err := mapKeyBTF(m)
	if err != nil {
		return nil, err
	}

	def := &Definition{Map: m, KeySize: m.KeySize()}
	switch t := btf.UnderlyingType(keyType).(type) {
	case *btf.Int:
		if !validFieldSize(t.Size) {
			return nil, fmt.Errorf("scalar key size %d is not 1/2/4/8", t.Size)
		}
		name := scalarKeyName(keyType)
		def.Fields = []KeyField{{Name: name, Off: 0, Size: t.Size}}
		def.IsScalar = true
	case *btf.Struct:
		for _, mem := range t.Members {
			if mem.BitfieldSize != 0 {
				return nil, fmt.Errorf("key field %s: bitfields are not supported", mem.Name)
			}
			it, ok := btf.UnderlyingType(mem.Type).(*btf.Int)
			if !ok {
				return nil, fmt.Errorf("key field %s: only integer fields are supported (got %s)", mem.Name, mem.Type)
			}
			if !validFieldSize(it.Size) {
				return nil, fmt.Errorf("key field %s: size %d is not 1/2/4/8", mem.Name, it.Size)
			}
			off := mem.Offset.Bytes()
			// emitSetFilters stores each field with a naturally-aligned,
			// in-bounds store; reject layouts (e.g. __attribute__((packed)))
			// that would otherwise produce a misaligned or OOB stack write.
			if off%it.Size != 0 {
				return nil, fmt.Errorf("key field %s: offset %d is not aligned to its %d-byte width (packed keys are not supported)", mem.Name, off, it.Size)
			}
			if off+it.Size > def.KeySize {
				return nil, fmt.Errorf("key field %s: extends past the %d-byte key", mem.Name, def.KeySize)
			}
			def.Fields = append(def.Fields, KeyField{Name: mem.Name, Off: off, Size: it.Size})
		}
		if len(def.Fields) == 0 {
			return nil, fmt.Errorf("key struct %s has no fields", t.Name)
		}
	default:
		return nil, fmt.Errorf("key BTF type %s is not a struct or integer", keyType)
	}
	return def, nil
}

// scalarUnnamed is the placeholder name for a bare-integer key with no
// typedef; OpenSet may rename it from the --set key(...) mapping.
const scalarUnnamed = "key"

// scalarKeyName picks a match name for a bare-integer key: the typedef
// name when the key is declared through one (typedef __u64 imsi_t), else
// scalarUnnamed (which then requires an explicit key(...) mapping).
func scalarKeyName(t btf.Type) string {
	if td, ok := t.(*btf.Typedef); ok {
		return td.Name
	}
	return scalarUnnamed
}

func validFieldSize(n uint32) bool {
	return n == 1 || n == 2 || n == 4 || n == 8
}

// mapKeyBTF returns the map's BTF key type. cilium/ebpf exposes the map's
// BTF handle but not btf_key_type_id (it lives in the internal sys
// package), so read struct bpf_map_info via a raw BPF_OBJ_GET_INFO_BY_FD
// and look the type up in the handle's spec.
func mapKeyBTF(m *ebpf.Map) (btf.Type, error) {
	keyTypeID, err := mapKeyBTFTypeID(m.FD())
	if err != nil {
		return nil, err
	}
	if keyTypeID == 0 {
		return nil, fmt.Errorf("map has no key BTF; create it with `xdp-ninja set create` (or load it with BTF key/value types)")
	}

	h, err := m.Handle()
	if err != nil {
		return nil, fmt.Errorf("map BTF handle: %w", err)
	}
	defer func() { _ = h.Close() }()
	spec, err := h.Spec(nil)
	if err != nil {
		return nil, fmt.Errorf("reading map BTF: %w", err)
	}
	t, err := spec.TypeByID(btf.TypeID(keyTypeID))
	if err != nil {
		return nil, fmt.Errorf("resolving key type id %d: %w", keyTypeID, err)
	}
	return t, nil
}

// bpfMapInfo mirrors the leading fields of UAPI struct bpf_map_info up to
// and including the BTF ids (see include/uapi/linux/bpf.h). The layout is
// kernel ABI and append-only.
type bpfMapInfo struct {
	MapType               uint32 // 0
	ID                    uint32 // 4
	KeySize               uint32 // 8
	ValueSize             uint32 // 12
	MaxEntries            uint32 // 16
	MapFlags              uint32 // 20
	Name                  [16]byte
	Ifindex               uint32 // 40
	BTFVmlinuxValueTypeID uint32 // 44
	NetnsDev              uint64 // 48
	NetnsIno              uint64 // 56
	BTFID                 uint32 // 64
	BTFKeyTypeID          uint32 // 68
	BTFValueTypeID        uint32 // 72
	BTFVmlinuxID          uint32 // 76
	MapExtra              uint64 // 80
}

// bpfObjGetInfoByFDAttr mirrors the info union member of union bpf_attr.
type bpfObjGetInfoByFDAttr struct {
	BpfFD   uint32
	InfoLen uint32
	Info    uint64 // pointer
}

const bpfObjGetInfoByFD = 15 // BPF_OBJ_GET_INFO_BY_FD

// mapKeyBTFTypeID reads btf_key_type_id from bpf_map_info.
func mapKeyBTFTypeID(fd int) (uint32, error) {
	var info bpfMapInfo
	attr := bpfObjGetInfoByFDAttr{
		BpfFD:   uint32(fd),
		InfoLen: uint32(unsafe.Sizeof(info)),
		Info:    uint64(uintptr(unsafe.Pointer(&info))),
	}
	_, _, errno := unix.Syscall(unix.SYS_BPF, bpfObjGetInfoByFD,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return 0, fmt.Errorf("BPF_OBJ_GET_INFO_BY_FD: %w", errno)
	}
	return info.BTFKeyTypeID, nil
}
