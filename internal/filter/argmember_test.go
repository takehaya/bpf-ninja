package filter

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/setmap"
)

func TestParseMemberFilters(t *testing.T) {
	params := []attach.FuncParamInfo{{Name: "q", Index: 1, Kind: "ptr-struct", Type: &btf.Pointer{Target: &btf.Struct{Size: 16, Members: []btf.Member{
		{Name: "imsi", Type: &btf.Int{Size: 8}},
		{Name: "target", Offset: 64, Type: &btf.Struct{Size: 4, Members: []btf.Member{{Name: "pdr_id", Type: &btf.Int{Size: 4, Encoding: btf.Signed}}}}},
	}}}}}
	for _, tt := range []struct {
		expr   string
		op     ArgFilterOp
		offset uint32
		signed bool
	}{
		{"q->imsi=262010000000001", OpEqual, 0, false},
		{"q->target.pdr_id=3", OpEqual, 8, true},
		{"q->target.pdr_id>=-3", OpGreaterEqual, 8, true},
		{"q->imsi<=9", OpLessEqual, 0, false},
		{"q->imsi=1..9", OpRange, 0, false},
		{"q->target.pdr_id=-9..3", OpRange, 8, true},
	} {
		t.Run(tt.expr, func(t *testing.T) {
			fs, err := ParseAndValidateFilters([]string{tt.expr}, params)
			if err != nil {
				t.Fatal(err)
			}
			f := fs[0]
			if !f.Deref || f.ParamIndex != 1 || f.Offset != tt.offset || f.Signed != tt.signed || f.Op != tt.op || f.String() != tt.expr {
				t.Fatalf("filter: %+v", f)
			}
		})
	}
	for _, expr := range []string{"q->=1", "q->a..b=1", "q->a->b=1", "q.imsi=1", "q->target.pdr_id=2147483648", "q->target.pdr_id=3..-9"} {
		if _, err := ParseAndValidateFilters([]string{expr}, params); err == nil {
			t.Errorf("accepted %q", expr)
		}
	}
}

func TestRejectMemberNullComparison(t *testing.T) {
	params := []attach.FuncParamInfo{{Name: "value", Index: 1, Kind: "ptr-struct", Type: &btf.Pointer{Target: &btf.Struct{
		Size: 4, Members: []btf.Member{{Name: "action", Type: &btf.Int{Size: 4}}},
	}}}}
	for _, expr := range []string{"value->action==null", "value->action=null", "value->action!=null"} {
		t.Run(expr, func(t *testing.T) {
			_, err := ParseAndValidateFilters([]string{expr}, params)
			if err == nil || !strings.Contains(err.Error(), "null comparison requires a pointer parameter") {
				t.Fatalf("got %v, want pointer parameter rejection", err)
			}
		})
	}
	if _, err := ParseAndValidateFilters([]string{"value==null"}, params); err != nil {
		t.Fatalf("bare pointer NULL comparison: %v", err)
	}
	if _, err := ParseAndValidateFilters([]string{"value->action==0"}, params); err != nil {
		t.Fatalf("integer member comparison: %v", err)
	}
}

func TestSetMemberMappings(t *testing.T) {
	for _, ref := range []string{"flows->imsi", "flows.imsi"} {
		if _, err := ResolveSetFilters(nil, []string{ref}, nil); err == nil || !strings.Contains(err.Error(), "member syntax") {
			t.Fatalf("reference: %v", err)
		}
	}
	params := []attach.FuncParamInfo{
		{Name: "q", Index: 1, Kind: "ptr-struct", Type: &btf.Pointer{Target: &btf.Struct{Size: 16, Members: []btf.Member{
			{Name: "imsi", Type: &btf.Int{Size: 8}},
			{Name: "teid", Offset: 64, Type: &btf.Int{Size: 4}},
		}}}},
		{Name: "scalar", Index: 2, Kind: "ptr", Type: &btf.Pointer{Target: &btf.Int{Size: 8}}},
	}
	for _, mapping := range [][]setmap.MapEntry{nil, {{Field: "imsi", Source: "arg:q->imsi"}}, {{Field: "imsi", Source: "arg:scalar[0]"}}} {
		set := flowSet(mapping)
		fs, err := ResolveSetFilters([]*setmap.Set{set}, []string{"flows"}, params)
		if err != nil {
			t.Fatal(err)
		}
		if len(fs[0].Fields) != 2 || !fs[0].Fields[0].Deref || fs[0].Fields[1].Offset != 8 {
			t.Fatalf("fields: %+v", fs)
		}
	}
	if _, err := setmap.ParseSetSpec("flows=/unused,key(imsi=arg:q->imsi,teid=arg:scalar[0])"); err != nil {
		t.Fatal(err)
	}
	params = append(params, attach.FuncParamInfo{Name: "other", Index: 3, Kind: "ptr-struct", Type: params[0].Type})
	if _, err := ResolveSetFilters([]*setmap.Set{flowSet(nil)}, []string{"flows"}, params); err == nil || !strings.Contains(err.Error(), "multiple pointer members") {
		t.Fatalf("ambiguity: %v", err)
	}
	explicit := flowSet([]setmap.MapEntry{{Field: "imsi", Source: "arg:q->imsi"}, {Field: "teid", Source: "arg:q->teid"}})
	if _, err := ResolveSetFilters([]*setmap.Set{explicit}, []string{"flows"}, params); err != nil {
		t.Fatal(err)
	}
	explicit.Mapping[0].Source = "arg:q->missing"
	if _, err := ResolveSetFilters([]*setmap.Set{explicit}, []string{"flows"}, params); err == nil {
		t.Fatal("accepted missing member")
	}
	explicit.Mapping[0].Source = "arg:q"
	if _, err := ResolveSetFilters([]*setmap.Set{explicit}, []string{"flows"}, params); err == nil {
		t.Fatal("accepted bare pointer")
	}
}

func TestSetImplicitScalarPointer(t *testing.T) {
	set := flowSet(nil)
	set.Def.KeySize = 8
	set.Def.Fields = set.Def.Fields[:1]
	params := []attach.FuncParamInfo{{Name: "imsi", Index: 1, Kind: "ptr", Type: &btf.Pointer{Target: &btf.Int{Size: 8}}}}
	fs, err := ResolveSetFilters([]*setmap.Set{set}, []string{"flows"}, params)
	if err != nil {
		t.Fatal(err)
	}
	if f := fs[0].Fields[0]; !f.Deref || f.ParamName != "imsi[0]" {
		t.Fatalf("field: %+v", f)
	}
}
