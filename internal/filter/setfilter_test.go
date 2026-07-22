package filter

import (
	"strings"
	"testing"

	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/setmap"
)

func flowSet(mapping []setmap.MapEntry) *setmap.Set {
	return &setmap.Set{
		SpecRef: setmap.SpecRef{Name: "flows", Mapping: mapping},
		Def: &setmap.Definition{
			KeySize: 16,
			Fields: []setmap.KeyField{
				{Name: "imsi", Off: 0, Size: 8},
				{Name: "teid", Off: 8, Size: 4},
			},
		},
	}
}

var ulParams = []attach.FuncParamInfo{
	{Name: "imsi", Index: 1, Size: 8},
	{Name: "teid", Index: 2, Size: 4},
}

func TestSplitFilterExprs(t *testing.T) {
	refs, plain := SplitFilterExprs([]string{"imsi=5", "@subs", "teid>=7", "@cells"})
	if len(refs) != 2 || refs[0] != "subs" || refs[1] != "cells" {
		t.Errorf("refs = %v", refs)
	}
	if len(plain) != 2 || plain[0] != "imsi=5" {
		t.Errorf("plain = %v", plain)
	}
}

func TestResolveSetFiltersImplicit(t *testing.T) {
	sf, err := ResolveSetFilters([]*setmap.Set{flowSet(nil)}, []string{"flows"}, ulParams)
	if err != nil {
		t.Fatalf("ResolveSetFilters: %v", err)
	}
	if len(sf) != 1 || len(sf[0].Fields) != 2 {
		t.Fatalf("resolved = %+v", sf)
	}
	f := sf[0].Fields[0]
	if f.FieldName != "imsi" || f.ParamIdx != 1 || f.FieldOff != 0 || f.FieldSize != 8 {
		t.Errorf("imsi field = %+v", f)
	}
	f = sf[0].Fields[1]
	if f.FieldName != "teid" || f.ParamIdx != 2 || f.FieldOff != 8 || f.FieldSize != 4 {
		t.Errorf("teid field = %+v", f)
	}
}

func TestResolveSetFiltersExplicitMapping(t *testing.T) {
	// key field imsi sourced from a differently-named arg.
	set := flowSet([]setmap.MapEntry{{Field: "imsi", Source: "arg:subscriber"}})
	params := []attach.FuncParamInfo{
		{Name: "subscriber", Index: 1, Size: 8},
		{Name: "teid", Index: 2, Size: 4},
	}
	sf, err := ResolveSetFilters([]*setmap.Set{set}, []string{"flows"}, params)
	if err != nil {
		t.Fatalf("ResolveSetFilters: %v", err)
	}
	if sf[0].Fields[0].ParamName != "subscriber" || sf[0].Fields[0].ParamIdx != 1 {
		t.Errorf("explicit mapping field = %+v", sf[0].Fields[0])
	}
}

func TestResolveSetFiltersErrors(t *testing.T) {
	// unknown set name
	if _, err := ResolveSetFilters(nil, []string{"nope"}, ulParams); err == nil || !strings.Contains(err.Error(), "no such set") {
		t.Errorf("unknown set err = %v", err)
	}
	// missing param → mentions the field and the fix
	params := []attach.FuncParamInfo{{Name: "imsi", Index: 1, Size: 8}} // no teid
	if _, err := ResolveSetFilters([]*setmap.Set{flowSet(nil)}, []string{"flows"}, params); err == nil || !strings.Contains(err.Error(), "teid") {
		t.Errorf("missing param err = %v", err)
	}
	// arg wider than field → truncation rejected
	wide := []attach.FuncParamInfo{
		{Name: "imsi", Index: 1, Size: 8},
		{Name: "teid", Index: 2, Size: 8}, // u64 arg into u32 field
	}
	if _, err := ResolveSetFilters([]*setmap.Set{flowSet(nil)}, []string{"flows"}, wide); err == nil || !strings.Contains(err.Error(), "truncation") {
		t.Errorf("truncation err = %v", err)
	}
	// mapping names a field the key doesn't have
	bad := flowSet([]setmap.MapEntry{{Field: "bogus", Source: "arg:imsi"}})
	if _, err := ResolveSetFilters([]*setmap.Set{bad}, []string{"flows"}, ulParams); err == nil || !strings.Contains(err.Error(), "bogus") {
		t.Errorf("bad mapping err = %v", err)
	}
}

func TestResolveSetFiltersScalarPositional(t *testing.T) {
	// scalar key with a non-matching BTF name binds positionally via a
	// single-entry mapping. OpenSet reconciles a scalar key's synthetic
	// name with the mapping's field name; represent that post-open state.
	set := &setmap.Set{
		SpecRef: setmap.SpecRef{Name: "subs", Mapping: []setmap.MapEntry{{Field: "imsi", Source: "arg:imsi"}}},
		Def: &setmap.Definition{
			KeySize:  8,
			Fields:   []setmap.KeyField{{Name: "imsi", Off: 0, Size: 8}},
			IsScalar: true,
		},
	}
	sf, err := ResolveSetFilters([]*setmap.Set{set}, []string{"subs"}, ulParams)
	if err != nil {
		t.Fatalf("ResolveSetFilters scalar: %v", err)
	}
	if sf[0].Fields[0].ParamName != "imsi" {
		t.Errorf("scalar positional field = %+v", sf[0].Fields[0])
	}
}
