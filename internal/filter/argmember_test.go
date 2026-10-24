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

func TestSetRejectsMembers(t *testing.T) {
	for _, ref := range []string{"flows->imsi", "flows.imsi"} {
		if _, err := ResolveSetFilters(nil, []string{ref}, nil); err == nil || !strings.Contains(err.Error(), "member syntax") {
			t.Fatalf("reference: %v", err)
		}
	}
	s := flowSet([]setmap.MapEntry{{Field: "imsi", Source: "arg:q->imsi"}})
	if _, err := ResolveSetFilters([]*setmap.Set{s}, []string{"flows"}, nil); err == nil || !strings.Contains(err.Error(), "member syntax") {
		t.Fatalf("mapping: %v", err)
	}
	for _, source := range []string{"q->imsi", "q.target"} {
		if _, err := setmap.ParseSetSpec("flows=/unused,key(imsi=arg:" + source + ")"); err == nil || !strings.Contains(err.Error(), "member syntax") {
			t.Fatalf("parse mapping: %v", err)
		}
	}
	p := []attach.FuncParamInfo{{Name: "imsi", Size: 8, Kind: "ptr-struct"}}
	if _, err := ResolveSetFilters([]*setmap.Set{flowSet(nil)}, []string{"flows"}, p); err == nil || !strings.Contains(err.Error(), "must be an integer") {
		t.Fatalf("pointer: %v", err)
	}
}
