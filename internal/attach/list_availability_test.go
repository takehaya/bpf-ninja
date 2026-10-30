package attach

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cilium/ebpf/btf"
)

func TestListFuncsAvailability(t *testing.T) {
	info := fakeFuncInfo(t)
	wantReasons := map[string]string{
		"entry": "present", "live": "present",
		"dead": "absent_from_loaded_func_info", "other": "absent_from_loaded_func_info",
		"flavored___local": "absent_from_loaded_func_info", "external": "not_in_target_program",
	}
	for _, unknown := range []bool{false, true} {
		if unknown {
			info.loadedFuncs.err = errors.New("permission denied")
		}
		funcs, err := info.ListFuncs()
		if err != nil || len(funcs) != len(wantReasons) {
			t.Fatalf("%+v %v", funcs, err)
		}
		seen := map[string]bool{}
		for _, f := range funcs {
			want, ok := wantReasons[f.Name]
			if !ok || seen[f.Name] {
				t.Fatalf("unexpected row: %+v", f)
			}
			seen[f.Name] = true
			detail := ""
			if unknown {
				want, detail = "unknown", "permission denied"
			}
			a := f.Availability
			if a.Reason != want || !a.BTFFuncPresent || a.FuncTypeID == 0 || a.Detail != detail {
				t.Fatalf("%+v want reason=%s detail=%s", f, want, detail)
			}
		}
	}
}

func TestListFuncsDuplicateNames(t *testing.T) {
	proto := &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}}
	builder, err := btf.NewBuilder([]btf.Type{
		&btf.Func{Name: "helper", Type: proto, Linkage: btf.StaticFunc},
		&btf.Func{Name: "helper", Type: &btf.FuncProto{Return: proto.Return, Params: []btf.FuncParam{{Name: "arg", Type: proto.Return}}}, Linkage: btf.StaticFunc},
	}, nil)
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
	// Both FUNCs were supplied as roots, so their exact BTF IDs are 1 and 2.
	for _, secondLoaded := range []bool{true, false} {
		info := &ProgInfo{Spec: spec, loadedFuncs: &loadedFuncInfo{ids: map[btf.TypeID]bool{1: true, 2: secondLoaded}}}
		funcs, err := info.ListFuncs()
		if err != nil || len(funcs) != 2 {
			t.Fatalf("%+v %v", funcs, err)
		}
		for i, f := range funcs {
			want := "present"
			if i == 1 && !secondLoaded {
				want = "absent_from_loaded_func_info"
			}
			if f.Name != "helper" || f.Linkage != "static" || f.Availability != (FuncAvailability{
				Reason: want, BTFFuncPresent: true, FuncTypeID: btf.TypeID(i + 1),
			}) {
				t.Fatalf("secondLoaded=%t row=%+v want reason=%s id=%d", secondLoaded, f, want, i+1)
			}
		}
		if a := info.FuncAvailability("helper"); a.Reason != "unknown" || a.BTFFuncPresent || a.Detail == "" {
			t.Fatalf("name lookup must remain ambiguous: %+v", a)
		}
	}
}
