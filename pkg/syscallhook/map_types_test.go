package syscallhook

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"github.com/takehaya/bpf-ninja/pkg/inject"
)

func TestMapTypesDuplicateDeclaredLayout(t *testing.T) {
	for _, side := range []string{"key", "value"} {
		t.Run(side, func(t *testing.T) {
			p, rule, spec := mapTypesFixture()
			declared := spec.Maps["m"].Value
			if side == "key" {
				declared = spec.Maps["m"].Key
			}
			builder, err := btf.NewBuilder([]btf.Type{btf.Copy(declared), declared}, nil)
			if err != nil {
				t.Fatal(err)
			}
			id, err := builder.Add(declared)
			if err != nil {
				t.Fatal(err)
			}
			blob, err := builder.Marshal(nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			spec.Types, err = btf.LoadSpecFromReader(bytes.NewReader(blob))
			if err != nil {
				t.Fatal(err)
			}
			declared, err = spec.Types.TypeByID(id)
			if err != nil {
				t.Fatal(err)
			}
			if side == "key" {
				spec.Maps["m"].Key, rule.MapBTF.KeyType = declared, declared.TypeName()
			} else {
				spec.Maps["m"].Value, rule.MapBTF.ValueType = declared, declared.TypeName()
			}
			size, err := btf.Sizeof(declared)
			if err != nil {
				t.Fatal(err)
			}
			selected, err := mapType(spec.Types, declared.TypeName(), declared, uint32(size), side)
			if err != nil || selected != declared {
				t.Fatalf("declared BTF ID %d: selected %v, err=%v", id, selected, err)
			}
			if err := supplyMapTypesFromSpec(&p, rule, spec); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func mapTypesFixture() (inject.RawProgram, Rule, *ebpf.CollectionSpec) {
	u32 := &btf.Int{Name: "u32", Size: 4}
	value := &btf.Struct{Name: "record", Size: 8, Members: []btf.Member{{Name: "identity", Type: u32}, {Name: "action", Type: u32, Offset: 32}}}
	return inject.RawProgram{Maps: map[int32]inject.RawMap{7: {Name: "long_map_name_1", Type: ebpf.Hash, KeySize: 4, ValueSize: 8}}},
		Rule{Map: "long_map_name_1", MapBTF: &MapBTF{}}, &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{"m": {Name: "long_map_name_1", Type: ebpf.Hash, KeySize: 4, ValueSize: 8, Key: u32, Value: value}}}
}

func TestMapTypesSpec(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*inject.RawProgram, *ebpf.CollectionSpec)
		want   string
	}{
		{"success", func(_ *inject.RawProgram, s *ebpf.CollectionSpec) { s.Maps["m"].Name = "long_map_name_123456" }, ""},
		{"missing-map", func(_ *inject.RawProgram, s *ebpf.CollectionSpec) { s.Maps["m"].Name = "other" }, "map \"long_map_name_1\" missing"},
		{"ambiguous-ELF", func(_ *inject.RawProgram, s *ebpf.CollectionSpec) {
			s.Maps["m"].Name = "long_map_name_123a"
			s.Maps["n"] = s.Maps["m"].Copy()
			s.Maps["n"].Name = "long_map_name_123b"
		}, "ambiguous kernel map"},
		{"missing-live", func(p *inject.RawProgram, _ *ebpf.CollectionSpec) { p.Maps = nil }, "live map"},
		{"ambiguous-live", func(p *inject.RawProgram, _ *ebpf.CollectionSpec) { p.Maps[8] = p.Maps[7] }, "ambiguous live map"},
		{"type", func(_ *inject.RawProgram, s *ebpf.CollectionSpec) { s.Maps["m"].Type = ebpf.Array }, "type mismatch"},
		{"key-size", func(_ *inject.RawProgram, s *ebpf.CollectionSpec) { s.Maps["m"].KeySize = 8 }, "sizes mismatch"},
		{"value-size", func(_ *inject.RawProgram, s *ebpf.CollectionSpec) { s.Maps["m"].ValueSize = 4 }, "sizes mismatch"},
		{"flags", func(_ *inject.RawProgram, s *ebpf.CollectionSpec) { s.Maps["m"].Flags = 1 }, "flags mismatch"},
		{"missing-key", func(_ *inject.RawProgram, s *ebpf.CollectionSpec) { s.Maps["m"].Key = nil }, "lacks key BTF"},
		{"missing-value", func(_ *inject.RawProgram, s *ebpf.CollectionSpec) { s.Maps["m"].Value = nil }, "lacks value BTF"},
		{"key-BTF-size", func(_ *inject.RawProgram, s *ebpf.CollectionSpec) { s.Maps["m"].Key = &btf.Int{Size: 8} }, "key BTF size mismatch"},
		{"value-BTF-size", func(_ *inject.RawProgram, s *ebpf.CollectionSpec) { s.Maps["m"].Value = &btf.Int{Size: 4} }, "value BTF size mismatch"},
		{"unsized-BTF", func(_ *inject.RawProgram, s *ebpf.CollectionSpec) { s.Maps["m"].Value = &btf.Fwd{Name: "record"} }, "value BTF type has no size"},
		{"existing-key", func(p *inject.RawProgram, s *ebpf.CollectionSpec) {
			m := p.Maps[7]
			m.Key = s.Maps["m"].Key
			p.Maps[7] = m
		}, "already has BTF"},
		{"existing-value", func(p *inject.RawProgram, s *ebpf.CollectionSpec) {
			m := p.Maps[7]
			m.Value = s.Maps["m"].Value
			p.Maps[7] = m
		}, "already has BTF"},
		{"existing-BTF-ID", func(p *inject.RawProgram, _ *ebpf.CollectionSpec) { m := p.Maps[7]; m.BTFID = 1; p.Maps[7] = m }, "already has BTF"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, r, s := mapTypesFixture()
			tc.change(&p, s)
			before := make(map[int32]inject.RawMap)
			for fd, m := range p.Maps {
				before[fd] = m
			}
			err := supplyMapTypesFromSpec(&p, r, s)
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("got %v, want %s", err, tc.want)
				}
				for fd, m := range before {
					if !reflect.DeepEqual(p.Maps[fd], m) {
						t.Fatal("mutated map on refusal")
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			m := p.Maps[7]
			if m.Key == nil || m.Value.TypeName() != "record" {
				t.Fatalf("missing schema: %+v", m)
			}
			if m.Key == s.Maps["m"].Key || m.Value == s.Maps["m"].Value {
				t.Fatal("shared source types")
			}
		})
	}
}

func TestMapTypesNamed(t *testing.T) {
	u32 := &btf.Int{Name: "u32", Size: 4}
	record := &btf.Struct{Name: "record", Size: 8}
	oldKey := &btf.Int{Name: "u32___old", Size: 4}
	otherKey := &btf.Int{Name: "u32___other", Size: 4}
	oldValue := &btf.Struct{Name: "record___old", Size: 8}
	otherValue := &btf.Struct{Name: "record___other", Size: 8}
	for _, tc := range []struct {
		name             string
		types            []btf.Type
		key, value, want string
	}{
		{"success", []btf.Type{u32, record}, "u32", "record", ""},
		{"explicit-key-flavor", []btf.Type{oldKey, otherKey, u32, record}, "u32___old", "record", ""},
		{"explicit-value-flavor", []btf.Type{u32, oldValue, otherValue, record}, "u32", "record___old", ""},
		{"explicit-key-flavor-missing", []btf.Type{oldKey, otherKey, u32, record}, "u32___new", "record", "map_btf.key_type \"u32___new\" missing"},
		{"explicit-value-flavor-missing", []btf.Type{u32, oldValue, otherValue, record}, "u32", "record___new", "map_btf.value_type \"record___new\" missing"},
		{"key-flavors-only", []btf.Type{oldKey, otherKey, record}, "u32", "record", "map_btf.key_type \"u32\" missing"},
		{"value-flavors-only", []btf.Type{u32, oldValue, otherValue}, "u32", "record", "map_btf.value_type \"record\" missing"},
		{"exact-key-after-flavors", []btf.Type{oldKey, otherKey, u32, record}, "u32", "record", ""},
		{"exact-value-after-flavors", []btf.Type{u32, oldValue, otherValue, record}, "u32", "record", ""},
		{"exact-key-between-flavors", []btf.Type{oldKey, u32, otherKey, record}, "u32", "record", ""},
		{"exact-value-between-flavors", []btf.Type{u32, oldValue, record, otherValue}, "u32", "record", ""},
		{"ambiguous-key-with-flavors", []btf.Type{oldKey, otherKey, u32, &btf.Int{Name: "u32", Size: 4, Encoding: btf.Signed}, record}, "u32", "record", "ambiguous map_btf.key_type"},
		{"ambiguous-value-with-flavors", []btf.Type{u32, oldValue, otherValue, record, &btf.Struct{Name: "record", Size: 16}}, "u32", "record", "ambiguous map_btf.value_type"},
		{"missing", []btf.Type{u32, record}, "u32", "missing", "map_btf.value_type \"missing\" missing"},
		{"ambiguous", []btf.Type{u32, record, &btf.Struct{Name: "record", Size: 16}}, "u32", "record", "ambiguous map_btf.value_type"},
		{"same-name-typedef", []btf.Type{u32, record, &btf.Typedef{Name: "record", Type: record}}, "u32", "record", ""},
		{"same-name-qualified-typedef", []btf.Type{u32, &btf.Typedef{Name: "record", Type: &btf.Const{Type: record}}, record}, "u32", "record", ""},
		{"forward-and-definition", []btf.Type{u32, &btf.Fwd{Name: "record"}, record}, "u32", "record", ""},
		{"struct-union-clash", []btf.Type{u32, record, &btf.Union{Name: "record", Size: 8}}, "u32", "record", "ambiguous map_btf.value_type"},
		{"same-layout", []btf.Type{u32, record, &btf.Struct{Name: "record", Size: 8}}, "u32", "record", ""},
		{"wrong-size", []btf.Type{u32, record}, "record", "record", "key BTF size mismatch"},
		{"no-types", nil, "u32", "record", "no BTF"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, r, s := mapTypesFixture()
			s.Maps["m"].Key = nil
			s.Maps["m"].Value = nil
			if tc.types != nil {
				b, err := btf.NewBuilder(tc.types, nil)
				if err != nil {
					t.Fatal(err)
				}
				blob, err := b.Marshal(nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				s.Types, err = btf.LoadSpecFromReader(strings.NewReader(string(blob)))
				if err != nil {
					t.Fatal(err)
				}
			}
			r.MapBTF.KeyType, r.MapBTF.ValueType = tc.key, tc.value
			err := supplyMapTypesFromSpec(&p, r, s)
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("got %v", err)
				}
				if p.Maps[7].Key != nil || p.Maps[7].Value != nil {
					t.Fatal("partial supply on error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if p.Maps[7].Key.TypeName() != tc.key || p.Maps[7].Value.TypeName() != tc.value {
				t.Fatal("named type not supplied")
			}
		})
	}
}

func TestMapTypesConfig(t *testing.T) {
	base := testRule()
	base.MapBTF = &MapBTF{ELF: "loader.o", SHA256: strings.Repeat("a", 64)}
	for _, tc := range []struct {
		name   string
		change func(*Rule)
		want   string
	}{
		{"valid", func(*Rule) {}, ""},
		{"uppercase", func(r *Rule) { r.MapBTF.SHA256 = strings.Repeat("A", 64) }, ""},
		{"no-hash", func(r *Rule) { r.MapBTF.SHA256 = "" }, "64 hexadecimal"},
		{"short-hash", func(r *Rule) { r.MapBTF.SHA256 = "aa" }, "64 hexadecimal"},
		{"invalid-hash", func(r *Rule) { r.MapBTF.SHA256 = strings.Repeat("z", 64) }, "64 hexadecimal"},
		{"hash-only", func(r *Rule) { r.MapBTF.ELF = "" }, "map_btf.elf is required"},
		{"key-only", func(r *Rule) { r.MapBTF.ELF = ""; r.MapBTF.SHA256 = ""; r.MapBTF.KeyType = "key" }, "map_btf.elf is required"},
		{"value-only", func(r *Rule) { r.MapBTF.ELF = ""; r.MapBTF.SHA256 = ""; r.MapBTF.ValueType = "record" }, "map_btf.elf is required"},
		{"auto", func(r *Rule) { r.Auto = true; r.Map = ""; r.Func = ""; r.Line = 0 }, "single explicit map"},
		{"entry-only", func(r *Rule) { r.Map = ""; r.Func = ""; r.Line = 0; r.Entry = true }, "single explicit map"},
		{"dispatch", func(r *Rule) { r.Dispatch = true }, "requires typed lookup hooks"},
		{"lookup-miss", func(r *Rule) { r.Ops = []string{"lookup:miss"} }, ""},
		{"non-lookup", func(r *Rule) { r.Ops = []string{"update"} }, "lookup hooks only"},
		{"long-map", func(r *Rule) { r.Map = strings.Repeat("a", 16) }, "single explicit map"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			source := *base.MapBTF
			r.MapBTF = &source
			tc.change(&r)
			err := Validate([]Rule{r})
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v", err)
			}
		})
	}
	want := &MapBTF{ELF: "loader.o", SHA256: base.MapBTF.SHA256, KeyType: "u32", ValueType: "record"}
	rules, err := ParseConfig(strings.NewReader(`[{"program":"p","map":"sessions","hook":"h","stack_lowest_offset":-8,"map_btf":{"elf":"loader.o","sha256":"` + want.SHA256 + `","key_type":"u32","value_type":"record"}}]`))
	if err != nil || !reflect.DeepEqual(rules[0].MapBTF, want) {
		t.Fatalf("parse: %+v %v", rules, err)
	}
}

func TestMapBTFConfigShape(t *testing.T) {
	for _, tc := range []struct {
		name, field, want string
	}{
		{"absent", "", ""},
		{"null", `,"map_btf":null`, ""},
		{"empty", `,"map_btf":{}`, "rule 0: map_btf.elf is required"},
		{"elf-only", `,"map_btf":{"elf":"loader.o"}`, "rule 0: map_btf.sha256 must contain exactly 64 hexadecimal digits"},
		{"unknown-nested-key", `,"map_btf":{"elf":"loader.o","sha256":"` + strings.Repeat("a", 64) + `","typo":true}`, `injection config: json: unknown field "typo"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := `[{"program":"p","map":"sessions","hook":"h","stack_lowest_offset":-8` + tc.field + `}]`
			rules, err := ParseConfig(strings.NewReader(input))
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("got %v, want %s", err, tc.want)
				}
				return
			}
			if err != nil || rules[0].MapBTF != nil {
				t.Fatalf("expected absent map_btf: %+v %v", rules, err)
			}
		})
	}
}

func TestMapTypesFile(t *testing.T) {
	var p inject.RawProgram
	if err := supplyMapTypes(&p, Rule{}); err != nil {
		t.Fatal(err)
	}
	p, r, _ := mapTypesFixture()
	r.MapBTF.ELF = filepath.Join(t.TempDir(), "missing")
	if err := supplyMapTypes(&p, r); err == nil {
		t.Fatal("accepted missing file")
	}
	path := filepath.Join(t.TempDir(), "invalid.o")
	data := []byte("invalid ELF")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	r.MapBTF.ELF = path
	r.MapBTF.SHA256 = strings.Repeat("0", 64)
	if err := supplyMapTypes(&p, r); err == nil || !strings.Contains(err.Error(), "map_btf.sha256") {
		t.Fatalf("got %v", err)
	}
	r.MapBTF.SHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
	if err := supplyMapTypes(&p, r); err == nil || !strings.Contains(err.Error(), "map types ELF:") {
		t.Fatalf("got %v", err)
	}
	src, err := os.ReadFile("testdata/maptypes/program.c")
	if err != nil {
		t.Fatal(err)
	}
	obj := testutil.CompileBPFSource(t, string(src))
	data, err = os.ReadFile(obj)
	if err != nil {
		t.Fatal(err)
	}
	p = inject.RawProgram{Maps: map[int32]inject.RawMap{7: {Name: "sessions", Type: ebpf.Hash, KeySize: 4, ValueSize: 8}}}
	r = Rule{Map: "sessions", MapBTF: &MapBTF{ELF: obj, SHA256: strings.ToUpper(fmt.Sprintf("%x", sha256.Sum256(data)))}}
	if err := supplyMapTypes(&p, r); err != nil {
		t.Fatal(err)
	}
	if p.Maps[7].Value.TypeName() != "record" {
		t.Fatal("ELF type not supplied")
	}
}

func TestMapTypesLegacyELF(t *testing.T) {
	src, err := os.ReadFile("testdata/maptypes/legacy.c")
	if err != nil {
		t.Fatal(err)
	}
	obj := testutil.CompileBPFSource(t, string(src))
	spec, err := ebpf.LoadCollectionSpec(obj)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Maps["sessions"].Key != nil || spec.Maps["sessions"].Value != nil {
		t.Fatal("fixture is not a legacy map")
	}
	p := inject.RawProgram{Maps: map[int32]inject.RawMap{7: {Name: "sessions", Type: ebpf.Hash, KeySize: 4, ValueSize: 8}}}
	r := Rule{Map: "sessions", MapBTF: &MapBTF{}}
	if err := supplyMapTypesFromSpec(&p, r, spec); err == nil || !strings.Contains(err.Error(), "lacks key BTF") {
		t.Fatalf("got %v", err)
	}
	r.MapBTF.KeyType, r.MapBTF.ValueType = "u32", "record___new"
	if err := supplyMapTypesFromSpec(&p, r, spec); err == nil || !strings.Contains(err.Error(), "map_btf.value_type \"record___new\" missing") {
		t.Fatalf("got %v", err)
	}
	if p.Maps[7].Key != nil || p.Maps[7].Value != nil {
		t.Fatal("partial supply on error")
	}
	r.MapBTF.ValueType = "record"
	if err := supplyMapTypesFromSpec(&p, r, spec); err != nil {
		t.Fatal(err)
	}
	if p.Maps[7].Value.TypeName() != "record" {
		t.Fatal("missing named legacy type")
	}
}

func TestMapTypesByteOrder(t *testing.T) {
	src, err := os.ReadFile("testdata/maptypes/program.c")
	if err != nil {
		t.Fatal(err)
	}
	// The normal fixture first establishes the compiler availability contract.
	testutil.CompileBPFSource(t, string(src))
	dir := t.TempDir()
	source := filepath.Join(dir, "source.c")
	obj := filepath.Join(dir, "big-endian.o")
	if err := os.WriteFile(source, src, 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("clang", "-O2", "-g", "-target", "bpfeb", "-c", source, "-o", obj).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v %s", err, out)
	}
	data, err := os.ReadFile(obj)
	if err != nil {
		t.Fatal(err)
	}
	p, r, _ := mapTypesFixture()
	r.MapBTF.ELF = obj
	r.MapBTF.SHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
	if err := supplyMapTypes(&p, r); err == nil || !strings.Contains(err.Error(), "byte order") {
		t.Fatalf("got %v", err)
	}
}

func TestMapTypesFillOnly(t *testing.T) {
	src, err := os.ReadFile("testdata/maptypes/program.c")
	if err != nil {
		t.Fatal(err)
	}
	obj := testutil.CompileBPFSource(t, string(src)+"\nstruct other { u32 action, identity; }; struct other retained SEC(\".bss\");\n")
	for _, tc := range []struct {
		name, key, value         string
		missingKey, missingValue bool
		want                     string
	}{
		{"key-only", "u32", "", true, false, ""},
		{"value-only", "", "record", false, true, ""},
		{"same-key", "u32", "", false, false, ""},
		{"same-value", "", "record", false, false, ""},
		{"same-both", "u32", "record", false, false, ""},
		{"replace-value", "", "other", false, false, "would replace"},
		{"replace-key", "record", "", false, false, "would replace"},
		{"missing-value-on-miss", "", "", false, true, "lacks value BTF"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := ebpf.LoadCollectionSpec(obj)
			if err != nil {
				t.Fatal(err)
			}
			if tc.missingKey {
				s.Maps["sessions"].Key = nil
			}
			if tc.missingValue {
				s.Maps["sessions"].Value = nil
			}
			p, r, _ := mapTypesFixture()
			m := p.Maps[7]
			m.Name = "sessions"
			p.Maps[7] = m
			r.Map, r.MapBTF.KeyType, r.MapBTF.ValueType = "sessions", tc.key, tc.value
			if tc.name == "missing-value-on-miss" {
				r.Ops = []string{"lookup:miss"}
			}
			err = supplyMapTypesFromSpec(&p, r, s)
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("got %v, want %s", err, tc.want)
				}
				if p.Maps[7].Key != nil || p.Maps[7].Value != nil {
					t.Fatal("partial supply on refusal")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if p.Maps[7].Key.TypeName() != "u32" || p.Maps[7].Value.TypeName() != "record" {
				t.Fatalf("wrong types: %+v", p.Maps[7])
			}
		})
	}
}

func TestMapTypesFileLimits(t *testing.T) {
	p, r, _ := mapTypesFixture()
	dir := t.TempDir()
	large := filepath.Join(dir, "large.o")
	f, err := os.Create(large)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate((64 << 20) + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, want string }{
		{dir, "regular file"}, {large, "exceeds 64 MiB"},
	} {
		r.MapBTF.ELF = tc.path
		if err := supplyMapTypes(&p, r); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: %v", tc.path, err)
		}
	}
	// A nonexistent file must not hide cheap live-map refusals.
	r.MapBTF.ELF = filepath.Join(dir, "missing")
	for _, tc := range []struct {
		name string
		maps map[int32]inject.RawMap
		want string
	}{
		{"missing", nil, "live map \"long_map_name_1\" missing"},
		{"existing", map[int32]inject.RawMap{7: {Name: r.Map, BTFID: 1}}, "already has BTF"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p.Maps = tc.maps
			if err := supplyMapTypes(&p, r); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestMapTypesGate(t *testing.T) {
	for _, tc := range []struct {
		name  string
		kind  ebpf.MapType
		value btf.Type
		want  string
	}{
		{"unsupported-map", ebpf.SockHash, &btf.Int{Size: 8}, "map type SockHash is unsupported"},
		{"datasec", ebpf.Hash, &btf.Datasec{Name: ".bss", Size: 8}, "not a data kind"},
		{"special", ebpf.Hash, &btf.Struct{Name: "bpf_timer", Size: 8}, "special field"},
		{"special-abi", ebpf.Hash, &btf.Struct{Name: "xdp_md", Size: 8}, "special global-function pointer ABI"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, r, s := mapTypesFixture()
			m := p.Maps[7]
			m.Type = tc.kind
			p.Maps[7] = m
			s.Maps["m"].Type, s.Maps["m"].Value = tc.kind, tc.value
			if err := supplyMapTypesFromSpec(&p, r, s); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %s", err, tc.want)
			}
			if !reflect.DeepEqual(p.Maps[7], m) {
				t.Fatal("partial supply on refusal")
			}
		})
	}
}
