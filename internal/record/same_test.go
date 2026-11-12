package record

import (
	"testing"

	"github.com/cilium/ebpf/btf"
)

// TestSameComment covers the layouts a later program may bring to a site:
// the same fields found elsewhere decode alike; a renamed, re-signed,
// resized or retyped field does not.
func TestSameComment(t *testing.T) {
	u32 := &btf.Int{Name: "u32", Size: 4}
	u16 := &btf.Int{Name: "u16", Size: 2}
	boolean := &btf.Int{Name: "_Bool", Size: 1, Encoding: btf.Bool}
	pol := func(second string, third btf.Type) *btf.Struct {
		return &btf.Struct{Name: "pol", Size: 8, Members: []btf.Member{
			{Name: "rc", Type: u32}, {Name: second, Type: third, Offset: 32},
		}}
	}
	filter := func(fields ...Field) *Layout { return &Layout{Mode: ModeFilter, Fields: fields} }
	entry := func(value btf.Type, valueLen uint32) *Layout {
		return &Layout{Mode: ModeEntry,
			Site:   Scalar{Name: "site", ParamIndex: 1, Size: 4},
			Status: Scalar{ParamIndex: -1},
			Key:    Bytes{Name: "key", ParamIndex: 2, Pointer: true, Size: 4, Len: 4, Type: u32},
			Value:  Bytes{Name: "value", ParamIndex: 3, Pointer: true, Size: 8, Len: valueLen, Type: value},
		}
	}
	moved := entry(pol("port", u16), 8)
	moved.Site.ParamIndex, moved.Key.ParamIndex, moved.Value.ParamIndex = 2, 3, 1
	base := Field{Name: "value->rc", ParamIndex: 2, Size: 4, Deref: true}
	at := func(f Field, change func(*Field)) Field { change(&f); return f }
	cases := []struct {
		name string
		a, b *Layout
		want bool
	}{
		{"both nil", nil, nil, true},
		{"one nil", filter(base), nil, false},
		{"filter same", filter(base), filter(base), true},
		{"filter moved read", filter(base), filter(at(base, func(f *Field) { f.ParamIndex, f.Offset = 3, 4 })), true},
		{"filter renamed", filter(base), filter(at(base, func(f *Field) { f.Name = "value->rd" })), false},
		{"filter signed", filter(base), filter(at(base, func(f *Field) { f.Signed = true })), false},
		{"filter null test", filter(base), filter(at(base, func(f *Field) { f.Pointer = true })), false},
		{"filter field count", filter(base), filter(base, base), false},
		{"filter and entry", filter(base), entry(pol("port", u16), 8), false},
		{"entry same", entry(pol("port", u16), 8), entry(pol("port", u16), 8), true},
		{"entry moved arguments", entry(pol("port", u16), 8), moved, true},
		{"entry member renamed", entry(pol("port", u16), 8), entry(pol("dport", u16), 8), false},
		{"entry member resized", entry(pol("port", u16), 8), entry(pol("port", u32), 8), false},
		{"entry capped differently", entry(pol("port", u16), 8), entry(pol("port", u16), 4), false},
		{"entry bool moved", entry(&btf.Struct{Name: "pol", Size: 8, Members: []btf.Member{{Name: "allow", Type: boolean}}}, 8), entry(&btf.Struct{Name: "pol", Size: 8, Members: []btf.Member{{Name: "allow", Type: boolean, Offset: 8}}}, 8), false},
	}
	for _, c := range cases {
		if got := SameComment(c.a, c.b); got != c.want {
			t.Errorf("%s: SameComment = %v, want %v", c.name, got, c.want)
		}
		if got := SameComment(c.b, c.a); got != c.want {
			t.Errorf("%s (swapped): SameComment = %v, want %v", c.name, got, c.want)
		}
	}
}
