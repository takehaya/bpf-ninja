package hookabi

import (
	"maps"
	"testing"

	"github.com/cilium/ebpf/btf"
)

func TestSizeTags(t *testing.T) {
	got := SizeTags([]string{HookTag, SizeTag("key", 4), SizeTag("value", 16),
		"bpf-ninja:key_size=abc", "bpf-ninja:value_size=4294967296", "bpf-ninja:other=1", "key_size=8"})
	if want := map[string]uint32{"key": 4, "value": 16}; !maps.Equal(got, want) {
		t.Fatalf("SizeTags = %v, want %v", got, want)
	}
	if got := SizeTags([]string{"bpf-ninja:key_size=abc", "bpf-ninja:value_size=4294967296"}); len(got) != 0 {
		t.Fatalf("malformed tags parsed: %v", got)
	}
}

func TestPlain(t *testing.T) {
	u32 := &btf.Int{Name: "u32", Size: 4}
	ptr := &btf.Pointer{Target: u32}
	st := func(name string, members ...btf.Type) *btf.Struct {
		s := &btf.Struct{Name: name}
		for i, m := range members {
			s.Members = append(s.Members, btf.Member{Name: string(rune('a' + i)), Type: m})
		}
		return s
	}
	deep := btf.Type(u32)
	for range 40 {
		deep = st("d", deep)
	}
	hdr := st("bpf_lpm_trie_key_hdr", u32)
	for _, c := range []struct {
		name string
		typ  btf.Type
		want bool
	}{
		{"int", u32, true},
		{"enum", &btf.Enum{Name: "e", Size: 4}, true},
		{"bool", &btf.Int{Name: "bool", Size: 1, Encoding: btf.Bool}, true},
		{"bitfield struct", &btf.Struct{Name: "b", Size: 4, Members: []btf.Member{{Name: "x", Type: u32, BitfieldSize: 3}}}, true},
		{"typedef const struct", &btf.Typedef{Name: "t", Type: &btf.Const{Type: st("s", u32, &btf.Array{Type: u32, Nelems: 2})}}, true},
		{"float", &btf.Float{Name: "f", Size: 4}, false},
		{"pointer", ptr, false},
		{"pointer array", &btf.Array{Type: ptr, Nelems: 2}, false},
		{"union with a pointer", &btf.Union{Name: "u", Members: []btf.Member{{Name: "x", Type: u32}, {Name: "p", Type: ptr}}}, false},
		{"bpf_* through a typedef", &btf.Typedef{Name: "t", Type: st("bpf_timer", u32)}, false},
		{"nested anonymous struct with a pointer", &btf.Struct{Name: "o", Members: []btf.Member{{Name: "x", Type: u32}, {Type: st("", ptr)}}}, false},
		{"deeper than 32", deep, false},
		{"lpm key header", hdr, true},
		{"lpm key", st("lpm_key", hdr, &btf.Array{Type: &btf.Int{Name: "u8", Size: 1}, Nelems: 4}), true},
	} {
		if got := Plain(c.typ); got != c.want {
			t.Errorf("%s: Plain = %v, want %v", c.name, got, c.want)
		}
	}
}
