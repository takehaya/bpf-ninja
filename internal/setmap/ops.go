// Management operations behind `xdp-ninja set ...`: create a pinned set
// map with synthesized BTF, and add/delete/list entries by field name so
// nobody has to hand-assemble zero-padded little-endian hex like bpftool
// requires (the exact error class behind the IMSI-encoding saga).
package setmap

import (
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// FieldSpec is one `name:type` element of a --key/--value schema string.
type FieldSpec struct {
	Name string
	Size uint32
}

// ParseSchema parses "imsi:u64,teid:u32" into field specs.
func ParseSchema(s string) ([]FieldSpec, error) {
	var out []FieldSpec
	for ent := range strings.SplitSeq(s, ",") {
		ent = strings.TrimSpace(ent)
		if ent == "" {
			continue
		}
		name, typ, ok := strings.Cut(ent, ":")
		if !ok || name == "" {
			return nil, fmt.Errorf("schema entry %q: want name:type (e.g. imsi:u64)", ent)
		}
		size, err := typeSize(typ)
		if err != nil {
			return nil, fmt.Errorf("schema entry %q: %w", ent, err)
		}
		out = append(out, FieldSpec{Name: name, Size: size})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty schema")
	}
	return out, nil
}

func typeSize(t string) (uint32, error) {
	switch t {
	case "u8":
		return 1, nil
	case "u16":
		return 2, nil
	case "u32":
		return 4, nil
	case "u64":
		return 8, nil
	}
	return 0, fmt.Errorf("unsupported type %q (u8/u16/u32/u64)", t)
}

// layout assigns naturally-aligned offsets and returns the padded total
// size, mirroring C struct layout so BTF offsets match what a C writer of
// the same struct would produce.
func layout(fields []FieldSpec) ([]KeyField, uint32) {
	var out []KeyField
	var cur, maxAlign uint32
	maxAlign = 1
	for _, f := range fields {
		align := f.Size
		if align > maxAlign {
			maxAlign = align
		}
		cur = (cur + align - 1) &^ (align - 1)
		out = append(out, KeyField{Name: f.Name, Off: cur, Size: f.Size})
		cur += f.Size
	}
	total := (cur + maxAlign - 1) &^ (maxAlign - 1)
	return out, total
}

// intType builds a BTF unsigned integer of the given byte width.
func intType(size uint32) *btf.Int {
	return &btf.Int{Name: fmt.Sprintf("__u%d", size*8), Size: size, Encoding: btf.Unsigned}
}

// synthesizeStruct builds the BTF struct for a schema.
func synthesizeStruct(name string, fields []KeyField, size uint32) *btf.Struct {
	st := &btf.Struct{Name: name, Size: size}
	for _, f := range fields {
		st.Members = append(st.Members, btf.Member{
			Name:   f.Name,
			Type:   intType(f.Size),
			Offset: btf.Bits(f.Off * 8),
		})
	}
	return st
}

// synthesizeType builds the BTF for a key or value schema: a single scalar
// keeps its field name reachable via a typedef (so implicit name matching
// works); anything else becomes a struct named structName.
func synthesizeType(structName string, fields []KeyField, size uint32) btf.Type {
	if len(fields) == 1 && fields[0].Off == 0 && fields[0].Size == size {
		return &btf.Typedef{Name: fields[0].Name, Type: intType(size)}
	}
	return synthesizeStruct(structName, fields, size)
}

// Create builds a BTF-carrying HASH set map and pins it at path. The key
// schema comes from keySchema ("imsi:u64,teid:u32"); the value defaults
// to a __u32 tag when valueSchema is empty.
func Create(path, keySchema, valueSchema string, maxEntries uint32) error {
	keySpecs, err := ParseSchema(keySchema)
	if err != nil {
		return fmt.Errorf("--key: %w", err)
	}
	keyFields, keySize := layout(keySpecs)
	if keySize > MaxKeySize {
		return fmt.Errorf("key size %d exceeds the %d-byte limit", keySize, MaxKeySize)
	}
	// "tag" is reserved for the value assignment in `set add`, so a key
	// field of that name could never be addressed on the CLI.
	for _, f := range keyFields {
		if f.Name == reservedTagName {
			return fmt.Errorf("key field name %q is reserved (used for the value in `set add`)", f.Name)
		}
	}

	if valueSchema == "" {
		valueSchema = "tag:u32"
	}
	valSpecs, err := ParseSchema(valueSchema)
	if err != nil {
		return fmt.Errorf("--value: %w", err)
	}
	valFields, valSize := layout(valSpecs)

	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name: "xdpninja_set", Type: ebpf.Hash,
		KeySize: keySize, ValueSize: valSize, MaxEntries: maxEntries,
		Key:   synthesizeType("xdpninja_set_key", keyFields, keySize),
		Value: synthesizeType("xdpninja_set_val", valFields, valSize),
	})
	if err != nil {
		return fmt.Errorf("creating map: %w", err)
	}
	defer func() { _ = m.Close() }()
	if err := m.Pin(path); err != nil {
		return fmt.Errorf("pinning at %s: %w", path, err)
	}
	return nil
}

// reservedTagName is the field=value key that `set add`/`del` treat as
// the entry value (tag) rather than a key field.
const reservedTagName = "tag"

// ParseFieldValues parses `field=value` CLI args (decimal or 0x hex) and
// splits off the reserved `tag=` value assignment.
func ParseFieldValues(args []string) (fields map[string]uint64, tag uint64, hasTag bool, err error) {
	fields = map[string]uint64{}
	for _, a := range args {
		name, vs, ok := strings.Cut(a, "=")
		if !ok || name == "" || vs == "" {
			return nil, 0, false, fmt.Errorf("argument %q: want field=value", a)
		}
		v, perr := parseUint(vs)
		if perr != nil {
			return nil, 0, false, fmt.Errorf("argument %q: %w", a, perr)
		}
		if name == reservedTagName {
			tag, hasTag = v, true
			continue
		}
		if _, dup := fields[name]; dup {
			return nil, 0, false, fmt.Errorf("field %q given twice", name)
		}
		fields[name] = v
	}
	return fields, tag, hasTag, nil
}

// parseUint is a deliberate copy of filter.parseValue (hex/dec): filter
// imports setmap, so setmap can't import filter without a cycle. Keep in
// sync; setmap has no need for the signed/negative branch.
func parseUint(s string) (uint64, error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return strconv.ParseUint(s[2:], 16, 64)
	}
	return strconv.ParseUint(s, 10, 64)
}

// BuildKey assembles the zero-padded key bytes for the definition from
// named field values. Every key field must be present (full-key rule) and
// every provided name must be a key field; values must fit their field.
// Padding is zeroed — hash maps hash all key_size bytes, so a non-zero
// pad byte would make lookups silently miss.
func (d *Definition) BuildKey(values map[string]uint64) ([]byte, error) {
	key := make([]byte, int(d.KeySize))
	used := map[string]bool{}
	for _, f := range d.Fields {
		v, ok := values[f.Name]
		if !ok {
			return nil, fmt.Errorf("missing key field %s (u%d at offset %d) — partial keys are not supported", f.Name, f.Size*8, f.Off)
		}
		if f.Size < 8 && v >= 1<<(8*f.Size) {
			return nil, fmt.Errorf("value %d does not fit key field %s (u%d)", v, f.Name, f.Size*8)
		}
		putUint(key[f.Off:f.Off+f.Size], v)
		used[f.Name] = true
	}
	for name := range values {
		if !used[name] {
			return nil, fmt.Errorf("unknown key field %q (key has: %s)", name, d.fieldNames())
		}
	}
	return key, nil
}

func (d *Definition) fieldNames() string {
	names := make([]string, len(d.Fields))
	for i, f := range d.Fields {
		names[i] = fmt.Sprintf("%s:u%d", f.Name, f.Size*8)
	}
	return strings.Join(names, ", ")
}

// putUint writes v into buf in native endianness at the field's width.
func putUint(buf []byte, v uint64) {
	switch len(buf) {
	case 1:
		buf[0] = byte(v)
	case 2:
		binary.NativeEndian.PutUint16(buf, uint16(v))
	case 4:
		binary.NativeEndian.PutUint32(buf, uint32(v))
	case 8:
		binary.NativeEndian.PutUint64(buf, v)
	}
}

// Add inserts (or updates) one entry. The value is the tag zero-extended
// to the map's value size (default tag 1 = plain presence).
func (d *Definition) Add(values map[string]uint64, tag uint64) error {
	key, err := d.BuildKey(values)
	if err != nil {
		return err
	}
	valSize := d.Map.ValueSize()
	if valSize < 8 && tag >= 1<<(8*valSize) {
		return fmt.Errorf("tag %d does not fit the map's %d-byte value", tag, valSize)
	}
	val := make([]byte, int(valSize))
	n := min(len(val), 8)
	putUint(val[:n], tag)
	return d.Map.Put(key, val)
}

// Delete removes one entry.
func (d *Definition) Delete(values map[string]uint64) error {
	key, err := d.BuildKey(values)
	if err != nil {
		return err
	}
	return d.Map.Delete(key)
}

// List writes all entries as `field=value ... tag=N` lines.
func (d *Definition) List(w io.Writer) error {
	key := make([]byte, int(d.KeySize))
	val := make([]byte, int(d.Map.ValueSize()))
	iter := d.Map.Iterate()
	for iter.Next(&key, &val) {
		var parts []string
		for _, f := range d.Fields {
			parts = append(parts, fmt.Sprintf("%s=%d", f.Name, getUint(key[f.Off:f.Off+f.Size])))
		}
		n := min(len(val), 8)
		parts = append(parts, fmt.Sprintf("tag=%d", getUint(val[:n])))
		_, _ = fmt.Fprintln(w, strings.Join(parts, " "))
	}
	return iter.Err()
}

func getUint(buf []byte) uint64 {
	switch len(buf) {
	case 1:
		return uint64(buf[0])
	case 2:
		return uint64(binary.NativeEndian.Uint16(buf))
	case 4:
		return uint64(binary.NativeEndian.Uint32(buf))
	case 8:
		return binary.NativeEndian.Uint64(buf)
	}
	return 0
}

// Schema writes the key layout, one field per line.
func (d *Definition) Schema(w io.Writer) {
	_, _ = fmt.Fprintf(w, "hash map: key %d B, value %d B, max_entries %d\n",
		d.KeySize, d.Map.ValueSize(), d.Map.MaxEntries())
	for _, f := range d.Fields {
		_, _ = fmt.Fprintf(w, "  %-20s u%-3d offset %d\n", f.Name, f.Size*8, f.Off)
	}
	_, _ = fmt.Fprintf(w, "note: entries must zero all padding bytes (hash covers the full key)\n")
}
