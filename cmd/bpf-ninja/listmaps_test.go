package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/internal/attach"
)

func TestMatchLoadCalls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lookups.json")
	// Two loads of entry: the last one counts.
	data := `{"version":1,"programs":[{"func":"entry","calls":[]},{"func":"entry","calls":[
		{"kind":"lookup","pc":6,"map":"stats","func":"entry","file":"p.c","line":29},
		{"kind":"lookup","pc":9,"map":"flows","func":"classify","file":"p.c","line":11,"reason":"lookup is not in the entry function"},
		{"kind":"update","pc":20,"map":"flows","func":"classify","file":"p.c","line":14},
		{"kind":"update","pc":25,"map":"flows","func":"classify","file":"p.c","line":14}]}]}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	load, err := readLoadCalls(path)
	if err != nil {
		t.Fatal(err)
	}
	maps := attach.ProgMaps{Funcs: []attach.FuncMaps{
		{Name: "entry", Maps: []attach.MapUse{
			{MapName: "stats", MapType: ebpf.Array, Op: attach.MapOpLookup, Inlined: true, File: "p.c", Line: 29},
			{MapName: "jmp", Op: attach.MapOpTailCall, File: "p.c", Line: 35},
		}},
		{Name: "classify", Maps: []attach.MapUse{
			{MapName: "flows", Op: attach.MapOpLookup, File: "p.c", Line: 11},
			{MapName: "flows", Op: attach.MapOpUpdate, File: "p.c", Line: 14},
			{MapName: "flows", Op: attach.MapOpUpdate, File: "p.c", Line: 14},
			{MapName: "flows", Op: attach.MapOpUpdate, File: "p.c", Line: 14}, // dropped at load
		}},
	}}
	n := nodeMaps{maps: maps, sites: matchLoadCalls(maps, load["entry"])}
	want := [][]string{{" site=6", ""}, {" site=9 [lookup is not in the entry function]", " site=20", " site=25", ""}}
	for i := range want {
		for j, w := range want[i] {
			if got := siteText(n.site(i, j)); got != w {
				t.Errorf("use %d/%d: %q, want %q", i, j, got, w)
			}
		}
	}
	if uses := mapsToJSON(n)[0].Uses; uses[0].Site == nil || *uses[0].Site != 6 || uses[1].Site != nil {
		t.Errorf("JSON uses = %+v", uses)
	}
	if err := os.WriteFile(path, []byte(`{"version":2,"programs":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readLoadCalls(path); err == nil {
		t.Error("accepted version 2")
	}
}
