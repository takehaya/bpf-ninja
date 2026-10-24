package attach

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
)

func memberTestParams(t *testing.T) []FuncParamInfo {
	t.Helper()
	u64 := &btf.Int{Name: "u64", Size: 8}
	i32 := &btf.Int{Name: "i32", Size: 4, Encoding: btf.Signed}
	query := &btf.Struct{Name: "classifier_query", Size: 64, Members: []btf.Member{
		{Name: "imsi", Type: u64},
		{Name: "target", Offset: 64, Type: &btf.Typedef{Name: "target_t", Type: &btf.Struct{Size: 8, Members: []btf.Member{
			{Name: "pdr_id", Type: i32, Offset: 32},
		}}}},
		{Offset: 128, Type: &btf.Union{Size: 8, Members: []btf.Member{
			{Name: "seid", Type: u64},
			{Name: "tag", Type: &btf.Enum{Name: "tag", Size: 4, Signed: true}},
		}}},
		{Name: "bits", Type: i32, Offset: 192, BitfieldSize: 3},
		{Name: "next", Type: &btf.Pointer{Target: i32}, Offset: 256},
		{Name: "array", Type: &btf.Array{Type: i32, Index: i32, Nelems: 2}, Offset: 320},
		{Name: "odd", Type: &btf.Int{Name: "odd", Size: 3}, Offset: 384},
		{Name: "small", Type: &btf.Int{Name: "i8", Size: 1, Encoding: btf.Signed}, Offset: 416},
		{Name: "half", Type: &btf.Int{Name: "u16", Size: 2}, Offset: 432},
	}}
	ptr := &btf.Typedef{Name: "query_ptr", Type: &btf.Const{Type: &btf.Pointer{Target: &btf.Volatile{Type: query}}}}
	fn := &btf.Func{Name: "sdf_classify", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{Return: i32, Params: []btf.FuncParam{
		{Name: "ctx", Type: &btf.Pointer{Target: &btf.Struct{Name: "xdp_md", Size: 4}}},
		{Name: "q", Type: ptr}, {Name: "n", Type: i32},
		{Name: "u", Type: &btf.Pointer{Target: &btf.Union{Name: "choice", Size: 8, Members: []btf.Member{{Name: "value", Type: u64}}}}},
	}}}
	builder, err := btf.NewBuilder([]btf.Type{fn}, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := builder.Marshal(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	params, err := GetFuncParamsFromSpec(spec, "sdf_classify")
	if err != nil {
		t.Fatal(err)
	}
	return params
}

func TestMemberParamDiscovery(t *testing.T) {
	params := memberTestParams(t)
	if len(params) != 3 || params[0].Kind != "ptr-struct" || params[0].TypeName != "classifier_query" || params[0].Index != 1 || params[2].Kind != "ptr-union" {
		t.Fatalf("params: %+v", params)
	}
	if want := (FuncParamInfo{Name: "n", Index: 2, Size: 4, Signed: true}); !reflect.DeepEqual(params[1], want) {
		t.Fatalf("integer metadata changed: %+v", params[1])
	}
}

func TestResolveArgMember(t *testing.T) {
	params := memberTestParams(t)
	for _, tt := range []struct {
		expr         string
		offset, size uint32
		signed       bool
	}{
		{"q->imsi", 0, 8, false}, {"q->target.pdr_id", 12, 4, true},
		{"q->seid", 16, 8, false}, {"q->tag", 16, 4, true},
		{"q->small", 52, 1, true}, {"q->half", 54, 2, false},
		{"u->value", 0, 8, false},
	} {
		t.Run(tt.expr, func(t *testing.T) {
			got, err := ResolveArg(tt.expr, params)
			if err != nil {
				t.Fatal(err)
			}
			if !got.Deref || got.Name != tt.expr || got.Offset != tt.offset || got.Size != tt.size || got.Signed != tt.signed {
				t.Fatalf("resolved: %+v", got)
			}
		})
	}
	for _, tt := range []struct{ expr, want string }{
		{"q", "select an integer member"}, {"n->imsi", "must be a pointer"},
		{"missing->imsi", "available parameters: [q n u]"},
		{"q->missing", "available members: [imsi target seid tag bits next array odd small half]"},
		{"q->target.bad", "available members: [pdr_id]"},
		{"q->bits", "bitfield"}, {"q->next", "integer or enum"},
		{"q->next.value", "expected struct/union"}, {"q->target", "integer or enum"},
		{"q->array", "integer or enum"}, {"q->odd", "unsupported member size 3"},
		{"q->", "invalid argument expression"}, {"q->target..pdr_id", "invalid argument expression"},
		{"q->next->value", "invalid argument expression"},
	} {
		t.Run(tt.expr, func(t *testing.T) {
			_, err := ResolveArg(tt.expr, params)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestResolveEchoMembers(t *testing.T) {
	params := memberTestParams(t)
	got, err := ResolveEchoArgs(nil, params)
	if err != nil || len(got) != 1 || got[0].Name != "n" {
		t.Fatalf("default echo: %+v, %v", got, err)
	}
	got, err = ResolveEchoArgs([]string{"q->imsi", "n", "q->target.pdr_id"}, params)
	if err != nil || len(got) != 3 || !got[0].Deref || got[1].Deref || !got[2].Signed {
		t.Fatalf("selected echo: %+v, %v", got, err)
	}
	if _, err := ResolveEchoArgs([]string{"q->bad"}, params); err == nil {
		t.Fatal("invalid member accepted")
	}
}
