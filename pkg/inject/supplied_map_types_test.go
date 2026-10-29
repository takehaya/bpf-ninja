package inject

import (
	"bytes"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

func TestCheckSuppliedMapTypes(t *testing.T) {
	u32 := &btf.Int{Name: "u32", Size: 4}
	lock, _ := specialValue("spin_lock")
	timer, _ := specialValue("timer")
	kptr, _ := specialValue("kptr")
	for _, tc := range []struct {
		name string
		typ  btf.Type
		want string
	}{
		{"integer", u32, ""},
		{"enum", &btf.Enum{Name: "e", Size: 4}, ""},
		{"float", &btf.Float{Name: "f", Size: 4}, ""},
		{"pointer", &btf.Pointer{Target: &btf.Void{}}, ""},
		{"struct", &btf.Struct{Name: "s", Size: 4, Members: []btf.Member{{Name: "x", Type: u32}}}, ""},
		{"union", &btf.Union{Name: "u", Size: 4, Members: []btf.Member{{Name: "x", Type: u32}}}, ""},
		{"array", &btf.Array{Type: u32, Index: u32, Nelems: 2}, ""},
		{"datasec", &btf.Datasec{Name: ".bss", Size: 4}, "not a data kind"},
		{"pointer-datasec", &btf.Pointer{Target: &btf.Datasec{Size: 4}}, "not a data kind"},
		{"pointer-proto", &btf.Pointer{Target: &btf.FuncProto{Return: u32}}, "not a data kind"},
		{"var", &btf.Var{Name: "v", Type: u32}, "not a data kind"},
		{"func", &btf.Func{Name: "f", Type: &btf.FuncProto{Return: u32}}, "not a data kind"},
		{"proto", &btf.FuncProto{Return: u32}, "not a data kind"},
		{"fwd", &btf.Fwd{Name: "s"}, "not a data kind"},
		{"void", &btf.Void{}, "not a data kind"},
		{"nested-datasec", &btf.Struct{Size: 4, Members: []btf.Member{{Type: &btf.Datasec{Size: 4}}}}, "not a data kind"},
		{"spin-lock", lock, "special field"},
		{"timer", timer, "special field"},
		{"kptr", kptr, "special field"},
		{"array-lock", &btf.Array{Type: lock, Index: u32, Nelems: 2}, "special field"},
		{"union-lock", &btf.Union{Size: 24, Members: []btf.Member{{Type: lock}}}, "special field"},
		{"xdp-abi", &btf.Struct{Name: "xdp_md", Size: 24}, "special global-function pointer ABI"},
		{"skb-abi", &btf.Struct{Name: "__sk_buff", Size: 24}, "special global-function pointer ABI"},
		{"dynptr-abi", &btf.Struct{Name: "bpf_dynptr", Size: 16}, "special global-function pointer ABI"},
	} {
		for _, wrapped := range []bool{false, true} {
			typ := tc.typ
			name := tc.name
			if wrapped {
				name += "-qualified-typedef"
				typ = &btf.Typedef{Name: "alias", Type: &btf.Const{Type: &btf.Volatile{Type: &btf.Restrict{Type: typ}}}}
			}
			for _, side := range []string{"key", "value"} {
				t.Run(name+"-"+side, func(t *testing.T) {
					size, _ := btf.Sizeof(typ)
					m := RawMap{Type: ebpf.Hash, Key: u32, Value: u32, KeySize: 4, ValueSize: 4}
					if side == "key" {
						m.Key, m.KeySize = typ, uint32(size)
					} else {
						m.Value, m.ValueSize = typ, uint32(size)
					}
					err := CheckSuppliedMapTypes(m)
					if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
						t.Fatalf("got %v, want %q", err, tc.want)
					}
				})
			}
		}
	}
	m := RawMap{Type: ebpf.Hash, Key: u32, Value: u32, KeySize: 8, ValueSize: 4}
	if err := CheckSuppliedMapTypes(m); err == nil || !strings.Contains(err.Error(), "size") {
		t.Fatalf("size: %v", err)
	}
}

// Ordinary supplied types change BTF, with identical emitted instructions,
// including when a read-only value is copied onto the stack.
func TestSuppliedMapTypesMetadataOnly(t *testing.T) {
	for _, copied := range []bool{false, true} {
		spec := lookupFixture()
		if copied {
			spec.Maps["sessions"].Flags = bpfFRdonlyProg
		}
		p := rawLookupFixture(t, spec, "p", true)
		req := rawLookupRequest(autoReq())
		req.CopyReadOnly = copied
		typed, err := TransformLookupRaw(p, req)
		if err != nil {
			t.Fatal(err)
		}
		for fd, m := range p.Maps {
			if err := CheckSuppliedMapTypes(m); err != nil {
				t.Fatal(err)
			}
			m.Key, m.Value = nil, nil
			p.Maps[fd] = m
		}
		opaque, err := TransformLookupRaw(p, req)
		if err != nil {
			t.Fatal(err)
		}
		if typed.TransformedChecksum != opaque.TransformedChecksum {
			t.Fatal("supplied types changed instructions")
		}
		if bytes.Equal(typed.BTFBytes, opaque.BTFBytes) {
			t.Fatal("supplied types did not change hook BTF")
		}
	}
}
