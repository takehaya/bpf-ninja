package inject

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

func parsedPointeeRecord(t *testing.T, kind string) btf.Type {
	t.Helper()
	var target btf.Type = &btf.Int{Name: "u32", Size: 4}
	switch kind {
	case "direct-cycle":
		tag := &btf.TypeTag{Value: "ordinary_annotation"}
		tag.Type = tag
		target = tag
	case "qualified-cycle":
		q := &btf.Const{}
		q.Type = &btf.TypeTag{Value: "ordinary_annotation", Type: q}
		target = q
	case "depth-32", "depth-33":
		depth := 32
		if kind == "depth-33" {
			depth++
		}
		for range depth {
			target = &btf.TypeTag{Value: "ordinary_annotation", Type: target}
		}
	default:
		target = &btf.TypeTag{Value: "outer_annotation", Type: &btf.Typedef{Name: "alias", Type: &btf.Const{
			Type: &btf.Volatile{Type: &btf.Restrict{Type: &btf.TypeTag{Value: kind, Type: target}}},
		}}}
	}
	record := &btf.Struct{Name: "record", Size: 8, Members: []btf.Member{{Name: "ptr", Type: &btf.Pointer{Target: target}}}}
	builder, err := btf.NewBuilder([]btf.Type{record}, nil)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := builder.Marshal(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := btf.LoadSpecFromReader(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := spec.AnyTypeByName("record")
	if err != nil {
		t.Fatal(err)
	}
	target = parsed.(*btf.Struct).Members[0].Type.(*btf.Pointer).Target
	switch kind {
	case "direct-cycle":
		if target.(*btf.TypeTag).Type != target {
			t.Fatal("direct cycle lost during BTF round trip")
		}
	case "qualified-cycle":
		if target.(*btf.Const).Type.(*btf.TypeTag).Type != target {
			t.Fatal("qualified cycle lost during BTF round trip")
		}
	}
	return parsed
}

func TestCheckSuppliedMapTypesPointeeChains(t *testing.T) {
	// Bound regressions even when the package is run without -timeout.
	timer := time.AfterFunc(5*time.Second, func() { panic("supplied pointee traversal did not terminate") })
	defer timer.Stop()
	for _, tc := range []struct{ kind, want string }{
		{"direct-cycle", "cyclic pointer pointee"},
		{"qualified-cycle", "cyclic pointer pointee"},
		{"ordinary_annotation", ""},
		{"depth-32", ""},
		{"depth-33", "exceeds depth 32"},
		{"kptr", "special field \"kptr\""},
		{"kptr_untrusted", "special field \"kptr_untrusted\""},
		{"kptr_ref", "special field \"kptr_ref\""},
		{"percpu_kptr", "special field \"percpu_kptr\""},
		{"uptr", "special field \"uptr\""},
	} {
		for _, side := range []string{"key", "value"} {
			t.Run(tc.kind+"/"+side, func(t *testing.T) {
				u32 := &btf.Int{Name: "u32", Size: 4}
				m := RawMap{Type: ebpf.Hash, Key: u32, Value: u32, KeySize: 4, ValueSize: 4}
				if side == "key" {
					m.Key, m.KeySize = parsedPointeeRecord(t, tc.kind), 8
				} else {
					m.Value, m.ValueSize = parsedPointeeRecord(t, tc.kind), 8
				}
				err := CheckSuppliedMapTypes(m)
				if tc.want == "" {
					if err != nil {
						t.Fatal(err)
					}
				} else if err == nil || !strings.Contains(err.Error(), "map "+side+" type") || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("got %v, want %s refusal containing %q", err, side, tc.want)
				}
			})
		}
	}
}
