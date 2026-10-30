package attach

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

func fakeFuncInfo(t *testing.T) *ProgInfo {
	t.Helper()
	proto := &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}}
	types := []btf.Type{}
	for _, name := range []string{"entry", "live", "dead", "other", "flavored___local"} {
		types = append(types, &btf.Func{Name: name, Type: proto, Linkage: btf.GlobalFunc})
	}
	types = append(types, &btf.Func{Name: "external", Type: proto, Linkage: btf.ExternFunc})
	builder, err := btf.NewBuilder(types, nil)
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
	ids := map[btf.TypeID]bool{}
	for _, name := range []string{"entry", "live"} {
		var fn *btf.Func
		if err := spec.TypeByName(name, &fn); err != nil {
			t.Fatal(err)
		}
		id, err := spec.TypeID(fn)
		if err != nil {
			t.Fatal(err)
		}
		ids[id] = true
	}
	return &ProgInfo{ProgID: 42, FuncName: "entry", Type: ebpf.XDP, Spec: spec, loadedFuncs: &loadedFuncInfo{ids: ids}}
}

func TestFuncAvailability(t *testing.T) {
	info := fakeFuncInfo(t)
	for _, tc := range []struct {
		name, reason string
		present      bool
	}{
		{"live", FuncPresent, true}, {"dead", FuncAbsent, true},
		{"other", FuncAbsent, true}, {"missing", FuncMissing, false},
		{"external", FuncNotInTarget, true}, {"flavored", FuncMissing, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := info.FuncAvailability(tc.name)
			t.Logf("%s: %s", tc.name, a)
			if a.Reason != tc.reason || a.BTFFuncPresent != tc.present {
				t.Fatalf("got %+v", a)
			}
			if tc.present && a.FuncTypeID == 0 {
				t.Fatal("missing type ID")
			}
		})
	}
	info.loadedFuncs.err = errors.New("permission denied")
	a := info.FuncAvailability("live")
	t.Logf("unreadable: %s", a)
	if a.Reason != FuncUnknown || a.Unavailable() || !strings.Contains(a.Explain(), "permission denied") {
		t.Fatalf("got %+v", a)
	}
	// Known absence of a BTF name remains distinct from unreadable func_info.
	if a := info.FuncAvailability("missing"); a.Reason != FuncMissing {
		t.Fatalf("got %+v", a)
	}
}

func TestResolveTargetsAvailability(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		funcs                    []string
		wantTargets, wantSkipped int
		wantErr                  string
	}{
		{"entry", nil, 1, 0, ""},
		{"live", []string{"live"}, 1, 0, ""},
		{"single absent", []string{"dead"}, 0, 0, (FuncAvailability{Reason: FuncAbsent}).Explain()},
		{"duplicate absent", []string{"dead", "dead"}, 0, 0, (FuncAvailability{Reason: FuncAbsent}).Explain()},
		{"external", []string{"external"}, 0, 0, FuncNotInTarget},
		{"missing", []string{"missing"}, 0, 0, FuncMissing},
		{"list", []string{"dead", "live"}, 1, 1, ""},
		{"dedup", []string{"dead", "live", "dead"}, 1, 1, ""},
		{"all absent", []string{"dead", "other"}, 0, 2, "no attachable"},
		{"duplicate live", []string{"live", "live"}, 1, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			targets, ds, err := ResolveTargets([]*ProgInfo{fakeFuncInfo(t)}, tc.funcs, false)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err=%v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if tc.name == "all absent" && strings.Count(err.Error(), "attach-troubleshooting.md") != 1 {
				t.Fatalf("missing single docs pointer: %v", err)
			}
			if len(targets) != tc.wantTargets || len(ds) != tc.wantSkipped {
				t.Fatalf("targets=%d diagnostics=%+v", len(targets), ds)
			}
			for _, d := range ds {
				if !d.Skipped {
					t.Fatalf("not skipped: %+v", d)
				}
			}
		})
	}
	info := fakeFuncInfo(t)
	info.loadedFuncs.err = errors.New("restricted func_info")
	targets, ds, err := ResolveTargets([]*ProgInfo{info}, []string{"dead"}, false)
	if err != nil || len(targets) != 1 || len(ds) != 1 || ds[0].Skipped || ds[0].Availability.Reason != FuncUnknown {
		t.Fatalf("%v %+v %v", targets, ds, err)
	}
}

func TestResolveTargetsMultiplePrograms(t *testing.T) {
	for _, missingBTF := range []bool{false, true} {
		t.Run(fmt.Sprintf("missing_btf=%t", missingBTF), func(t *testing.T) {
			a, b := fakeFuncInfo(t), fakeFuncInfo(t)
			b.ProgID = 43
			name := "live"
			wantDiagnostics := 1
			if missingBTF {
				// B's BTF has no FUNCs, while A still carries the requested name.
				builder, err := btf.NewBuilder([]btf.Type{&btf.Int{Name: "int", Size: 4}}, nil)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := builder.Marshal(nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				b.Spec, err = btf.LoadSpecFromReader(bytes.NewReader(raw))
				if err != nil {
					t.Fatal(err)
				}
				wantDiagnostics = 0
			} else {
				b.loadedFuncs = &loadedFuncInfo{ids: map[btf.TypeID]bool{}}
			}
			targets, ds, err := ResolveTargets([]*ProgInfo{a, b}, []string{name}, false)
			if err != nil || len(targets) != 1 || targets[0].ProgID != 42 || len(ds) != wantDiagnostics {
				t.Fatalf("targets=%+v diagnostics=%+v err=%v", targets, ds, err)
			}
			if len(ds) > 0 && (!ds[0].Skipped || ds[0].ProgID != 43 || ds[0].Availability.Reason != FuncAbsent) {
				t.Fatalf("diagnostics=%+v", ds)
			}
		})
	}
}

func TestDecodeFuncInfo(t *testing.T) {
	for _, tc := range []struct {
		name        string
		count, size uint32
		records     []funcInfoRecord
		detail      string
	}{
		{"zero count", 0, 8, nil, "CAP_BPF"},
		{"record size", 1, 16, []funcInfoRecord{{TypeID: 2}}, "record size"},
		{"short read", 2, 8, []funcInfoRecord{{TypeID: 2}}, "incomplete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loaded := decodeFuncInfo(tc.count, tc.size, tc.records)
			if loaded.err == nil || !strings.Contains(loaded.err.Error(), tc.detail) {
				t.Fatalf("%+v", loaded)
			}
			info := fakeFuncInfo(t)
			info.loadedFuncs = &loaded
			targets, ds, err := ResolveTargets([]*ProgInfo{info}, []string{"live"}, false)
			if err != nil || len(targets) != 1 || targets[0].Availability.Reason != FuncUnknown || len(ds) != 1 || ds[0].Skipped {
				t.Fatalf("%+v %+v %v", targets, ds, err)
			}
		})
	}
	loaded := decodeFuncInfo(2, 8, []funcInfoRecord{{TypeID: 2}, {TypeID: 5}})
	if loaded.err != nil || len(loaded.ids) != 2 || !loaded.ids[2] || !loaded.ids[5] {
		t.Fatalf("%+v", loaded)
	}
}

func TestAvailabilityExplanation(t *testing.T) {
	a := FuncAvailability{Reason: FuncAbsent, BTFFuncPresent: true, FuncTypeID: 99}
	if a.String() != FuncAbsent {
		t.Fatal(a.String())
	}
	for _, text := range []string{"absent from this program's func_info", "unreachable in this load", "feature disabled by configuration", "nothing in it can run now", "again with that feature enabled", "lazy verification of global subprogs", "first shipped in Linux v6.8", "2afae08c9dcb8ac648414277cec70c2fe6a34d9e", "Our tests on 6.1 kept them and on 7.0 removed them", "Shared BTF"} {
		if !strings.Contains(a.Explain(), text) {
			t.Fatalf("missing %q in %s", text, a.Explain())
		}
	}
}

func TestFuncAvailabilityCache(t *testing.T) {
	first, second := fakeFuncInfo(t), fakeFuncInfo(t)
	first.loadedFuncs, second.loadedFuncs = nil, nil
	// A nil program produces a read failure without privileges. Failures must
	// also be cached so each requested name does not retry the same read.
	a := first.FuncAvailability("live")
	if a.Reason != FuncUnknown || a.Detail != "no loaded program handle" || first.loadedFuncs == nil {
		t.Fatalf("availability=%+v cache=%+v", a, first.loadedFuncs)
	}
	cached := first.loadedFuncs
	cached.err = errors.New("cached read")
	for _, name := range []string{"live", "dead", "other"} {
		if a := first.FuncAvailability(name); a.Detail != "cached read" || first.loadedFuncs != cached {
			t.Fatalf("%s: availability=%+v cache=%+v", name, a, first.loadedFuncs)
		}
	}
	if a := second.FuncAvailability("live"); a.Detail != "no loaded program handle" || second.loadedFuncs == nil || second.loadedFuncs == cached {
		t.Fatalf("second program: availability=%+v cache=%+v", a, second.loadedFuncs)
	}
}

func TestQueryLoadedFuncInfoZeroCount(t *testing.T) {
	queries := 0
	loaded := queryLoadedFuncInfo(func(info *progFuncInfo) error {
		queries++
		info.Count, info.RecSize = 0, 8
		return nil
	})
	if queries != 1 || loaded.err == nil || !strings.Contains(loaded.err.Error(), "count=0") {
		t.Fatalf("queries=%d result=%+v", queries, loaded)
	}
}

func TestAvailabilityExplanationWithoutDetail(t *testing.T) {
	want := "unknown: cannot determine loaded func_info membership"
	for _, a := range []FuncAvailability{{}, {Reason: FuncUnknown}} {
		if got := a.Explain(); got != want {
			t.Fatalf("got %q want %q", got, want)
		}
	}
}
