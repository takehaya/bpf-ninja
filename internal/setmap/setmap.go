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
	Name    string
	Off     uint32 // byte offset within the key
	Size    uint32 // 1, 2, 4, 8, or 16 (ipv6)
	IsBytes bool   // network-order byte string (ipv6): copied verbatim
}

// Align is the field's layout/store alignment: its width for numeric
// fields, 8 for a 16-byte ipv6 field (extracted as two 8-byte DWord
// stores, which need an 8-aligned offset).
func (f KeyField) Align() uint32 { return fieldAlign(f.Size, f.IsBytes) }

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
	case *btf.Int, *btf.Array:
		size, isBytes, ok := resolveFieldType(keyType)
		if !ok {
			return nil, fmt.Errorf("scalar key BTF %s is not a supported key field (u8/u16/u32/u64 or __u8[16])", keyType)
		}
		def.Fields = []KeyField{{Name: scalarKeyName(keyType), Off: 0, Size: size, IsBytes: isBytes}}
		def.IsScalar = true
	case *btf.Struct:
		for _, mem := range t.Members {
			if mem.BitfieldSize != 0 {
				return nil, fmt.Errorf("key field %s: bitfields are not supported", mem.Name)
			}
			size, isBytes, ok := resolveFieldType(mem.Type)
			if !ok {
				return nil, fmt.Errorf("key field %s: only u8/u16/u32/u64 or __u8[16] fields are supported (got %s)", mem.Name, mem.Type)
			}
			f := KeyField{Name: mem.Name, Off: mem.Offset.Bytes(), Size: size, IsBytes: isBytes}
			// The extraction stores each field with a naturally-aligned,
			// in-bounds store; reject layouts (e.g. __attribute__((packed)),
			// or an ipv6 member not at an 8-aligned offset) that would
			// otherwise produce a misaligned or OOB stack write.
			if f.Off%f.Align() != 0 {
				return nil, fmt.Errorf("key field %s: offset %d is not aligned to %d (packed keys are not supported)", mem.Name, f.Off, f.Align())
			}
			if f.Off+f.Size > def.KeySize {
				return nil, fmt.Errorf("key field %s: extends past the %d-byte key", mem.Name, def.KeySize)
			}
			def.Fields = append(def.Fields, f)
		}
		if len(def.Fields) == 0 {
			return nil, fmt.Errorf("key struct %s has no fields", t.Name)
		}
	default:
		return nil, fmt.Errorf("key BTF type %s is not a struct, integer, or byte array", keyType)
	}
	return def, nil
}

// resolveFieldType classifies a key field's BTF type: a 1/2/4/8-byte
// unsigned integer, or a `__u8[16]` array (an IPv6 address / SRv6 SID,
// treated as a network-order byte string). Must stay in lockstep with
// fieldType (the synthesis side) — the round-trip test guards it.
func resolveFieldType(t btf.Type) (size uint32, isBytes, ok bool) {
	switch u := btf.UnderlyingType(t).(type) {
	case *btf.Int:
		if validValueFieldSize(u.Size) { // 1/2/4/8 — a __u128 int is not a key field
			return u.Size, false, true
		}
	case *btf.Array:
		if el, isInt := btf.UnderlyingType(u.Type).(*btf.Int); isInt && el.Size == 1 && u.Nelems == 16 {
			return 16, true, true
		}
	}
	return 0, false, false
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

// validValueFieldSize gates a value (tag) field width: the tag round-trips
// through putUint/getUint as a uint64, so only 1/2/4/8. The key side uses
// resolveFieldType, which additionally admits the 16-byte ipv6 array.
func validValueFieldSize(n uint32) bool {
	return n == 1 || n == 2 || n == 4 || n == 8
}

// mapKeyBTF returns the map's BTF key type. cilium/ebpf exposes the map's
// BTF handle but not btf_key_type_id (it lives in the internal sys
// package), so read struct bpf_map_info via a raw BPF_OBJ_GET_INFO_BY_FD
// and look the type up in the handle's spec.
func mapKeyBTF(m *ebpf.Map) (btf.Type, error) {
	key, _, err := mapBTFTypes(m)
	return key, err
}

// mapBTFTypes returns the map's BTF key and value types.
func mapBTFTypes(m *ebpf.Map) (key, value btf.Type, err error) {
	keyTypeID, valueTypeID, err := mapBTFTypeIDs(m.FD())
	if err != nil {
		return nil, nil, err
	}
	if keyTypeID == 0 {
		return nil, nil, fmt.Errorf("map has no key BTF; create it with `xdp-ninja set create` (or load it with BTF key/value types)")
	}

	h, err := m.Handle()
	if err != nil {
		return nil, nil, fmt.Errorf("map BTF handle: %w", err)
	}
	defer func() { _ = h.Close() }()
	spec, err := h.Spec(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("reading map BTF: %w", err)
	}
	key, err = spec.TypeByID(btf.TypeID(keyTypeID))
	if err != nil {
		return nil, nil, fmt.Errorf("resolving key type id %d: %w", keyTypeID, err)
	}
	if valueTypeID != 0 {
		value, err = spec.TypeByID(btf.TypeID(valueTypeID))
		if err != nil {
			return nil, nil, fmt.Errorf("resolving value type id %d: %w", valueTypeID, err)
		}
	}
	return key, value, nil
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

// mapBTFTypeIDs reads btf_key_type_id and btf_value_type_id from
// bpf_map_info.
func mapBTFTypeIDs(fd int) (keyID, valueID uint32, err error) {
	var info bpfMapInfo
	attr := bpfObjGetInfoByFDAttr{
		BpfFD:   uint32(fd),
		InfoLen: uint32(unsafe.Sizeof(info)),
		Info:    uint64(uintptr(unsafe.Pointer(&info))),
	}
	_, _, errno := unix.Syscall(unix.SYS_BPF, bpfObjGetInfoByFD,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return 0, 0, fmt.Errorf("BPF_OBJ_GET_INFO_BY_FD: %w", errno)
	}
	return info.BTFKeyTypeID, info.BTFValueTypeID, nil
}
