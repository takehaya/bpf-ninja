package syscallhook

import (
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

func mapTypesFixture() (inject.RawProgram, Rule, *ebpf.CollectionSpec) {
	u32 := &btf.Int{Name: "u32", Size: 4}
	value := &btf.Struct{Name: "record", Size: 8, Members: []btf.Member{{Name: "identity", Type: u32}, {Name: "action", Type: u32, Offset: 32}}}
	return inject.RawProgram{Maps: map[int32]inject.RawMap{7: {Name: "long_map_name_1", Type: ebpf.Hash, KeySize: 4, ValueSize: 8}}},
		Rule{Map: "long_map_name_1"}, &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{"m": {Name: "long_map_name_1", Type: ebpf.Hash, KeySize: 4, ValueSize: 8, Key: u32, Value: value}}}
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
		{"unsized-BTF", func(_ *inject.RawProgram, s *ebpf.CollectionSpec) { s.Maps["m"].Value = &btf.Fwd{Name: "record"} }, "value BTF size mismatch"},
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
		{"key-flavors-only", []btf.Type{oldKey, otherKey, record}, "u32", "record", "key type \"u32\" missing"},
		{"value-flavors-only", []btf.Type{u32, oldValue, otherValue}, "u32", "record", "value type \"record\" missing"},
		{"exact-key-after-flavors", []btf.Type{oldKey, otherKey, u32, record}, "u32", "record", ""},
		{"exact-value-after-flavors", []btf.Type{u32, oldValue, otherValue, record}, "u32", "record", ""},
		{"exact-key-between-flavors", []btf.Type{oldKey, u32, otherKey, record}, "u32", "record", ""},
		{"exact-value-between-flavors", []btf.Type{u32, oldValue, record, otherValue}, "u32", "record", ""},
		{"ambiguous-key-with-flavors", []btf.Type{oldKey, otherKey, u32, &btf.Int{Name: "u32", Size: 4}, record}, "u32", "record", "ambiguous key type"},
		{"ambiguous-value-with-flavors", []btf.Type{u32, oldValue, otherValue, record, &btf.Struct{Name: "record", Size: 8}}, "u32", "record", "ambiguous value type"},
		{"missing", []btf.Type{u32, record}, "u32", "missing", "value type \"missing\" missing"},
		{"ambiguous", []btf.Type{u32, record, &btf.Struct{Name: "record", Size: 8}}, "u32", "record", "ambiguous value type"},
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
			r.MapKeyType, r.MapValueType = tc.key, tc.value
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
	base.MapTypesELF = "loader.o"
	base.MapTypesSHA256 = strings.Repeat("a", 64)
	for _, tc := range []struct {
		name   string
		change func(*Rule)
		want   string
	}{
		{"valid", func(*Rule) {}, ""},
		{"uppercase", func(r *Rule) { r.MapTypesSHA256 = strings.Repeat("A", 64) }, ""},
		{"no-hash", func(r *Rule) { r.MapTypesSHA256 = "" }, "64 hexadecimal"},
		{"short-hash", func(r *Rule) { r.MapTypesSHA256 = "aa" }, "64 hexadecimal"},
		{"invalid-hash", func(r *Rule) { r.MapTypesSHA256 = strings.Repeat("z", 64) }, "64 hexadecimal"},
		{"hash-only", func(r *Rule) { r.MapTypesELF = "" }, "require map_types_elf"},
		{"key-only", func(r *Rule) { r.MapTypesELF = ""; r.MapTypesSHA256 = ""; r.MapKeyType = "key" }, "require map_types_elf"},
		{"value-only", func(r *Rule) { r.MapTypesELF = ""; r.MapTypesSHA256 = ""; r.MapValueType = "record" }, "require map_types_elf"},
		{"auto", func(r *Rule) { r.Auto = true; r.Map = ""; r.Func = ""; r.Line = 0 }, "single explicit map"},
		{"entry-only", func(r *Rule) { r.Map = ""; r.Func = ""; r.Line = 0; r.Entry = true }, "single explicit map"},
		{"long-map", func(r *Rule) { r.Map = strings.Repeat("a", 16) }, "single explicit map"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base
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
	rules, err := ParseConfig(strings.NewReader(`[{"program":"p","map":"sessions","hook":"h","stack_lowest_offset":-8,"map_types_elf":"loader.o","map_types_sha256":"` + base.MapTypesSHA256 + `","map_key_type":"u32","map_value_type":"record"}]`))
	if err != nil || rules[0].MapValueType != "record" {
		t.Fatalf("parse: %+v %v", rules, err)
	}
}

func TestMapTypesFile(t *testing.T) {
	var p inject.RawProgram
	if err := supplyMapTypes(&p, Rule{}); err != nil {
		t.Fatal(err)
	}
	r := Rule{MapTypesELF: filepath.Join(t.TempDir(), "missing")}
	if err := supplyMapTypes(&p, r); err == nil {
		t.Fatal("accepted missing file")
	}
	path := filepath.Join(t.TempDir(), "invalid.o")
	data := []byte("invalid ELF")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	r.MapTypesELF = path
	r.MapTypesSHA256 = strings.Repeat("0", 64)
	if err := supplyMapTypes(&p, r); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("got %v", err)
	}
	r.MapTypesSHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
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
	r = Rule{Map: "sessions", MapTypesELF: obj, MapTypesSHA256: strings.ToUpper(fmt.Sprintf("%x", sha256.Sum256(data)))}
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
	r := Rule{Map: "sessions"}
	if err := supplyMapTypesFromSpec(&p, r, spec); err == nil || !strings.Contains(err.Error(), "lacks key BTF") {
		t.Fatalf("got %v", err)
	}
	r.MapKeyType, r.MapValueType = "u32", "record"
	if err := supplyMapTypesFromSpec(&p, r, spec); err != nil {
		t.Fatal(err)
	}
	if p.Maps[7].Value.TypeName() != "record" {
		t.Fatal("missing named legacy type")
	}
}

func TestMapTypesELFByteOrder(t *testing.T) {
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
	p := inject.RawProgram{}
	r := Rule{MapTypesELF: obj, MapTypesSHA256: fmt.Sprintf("%x", sha256.Sum256(data))}
	if err := supplyMapTypes(&p, r); err == nil || !strings.Contains(err.Error(), "byte order") {
		t.Fatalf("got %v", err)
	}
}
