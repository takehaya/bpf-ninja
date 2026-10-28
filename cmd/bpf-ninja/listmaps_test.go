package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/internal/attach"
)

func TestMatchLoadCalls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lookups.json")
	// Two loads of entry: the last one counts.
	data := `{"version":1,"programs":[{"func":"entry","calls":[]},{"func":"entry","calls":[
		{"kind":"lookup","pc":6,"map":"stats","func":"entry","file":"p.c","line":29},
		{"kind":"lookup","pc":9,"map":"flows","func":"classify","file":"p.c","line":11,"reason":"lookup is not in the entry function; ctx belongs to another stack frame"},
		{"kind":"lookup","pc":30,"map":"ids","func":"classify","file":"p.c","line":16,"reason":"sockhash has no typed hook","generic":true},
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
		{Name: "entry", Calls: []string{"classify"}, Maps: []attach.MapUse{
			{MapName: "stats", MapType: ebpf.Array, Op: attach.MapOpLookup, Inlined: true, File: "p.c", Line: 29},
			{MapID: 9, MapName: "jmp", MapType: ebpf.ProgramArray, Op: attach.MapOpTailCall, File: "p.c", Line: 35},
			{MapID: 10, MapName: "alt", MapType: ebpf.ProgramArray, Op: attach.MapOpTailCall, File: "p.c", Line: 36},
		}},
		{Name: "classify", Maps: []attach.MapUse{
			{MapName: "flows", MapType: ebpf.Hash, Op: attach.MapOpLookup, File: "p.c", Line: 11},
			{MapName: "flows", MapType: ebpf.Hash, Op: attach.MapOpUpdate, File: "p.c", Line: 14},
			{MapName: "flows", MapType: ebpf.Hash, Op: attach.MapOpUpdate, File: "p.c", Line: 14},
			{MapName: "flows", MapType: ebpf.Hash, Op: attach.MapOpUpdate, File: "p.c", Line: 14}, // dropped at load
			{MapName: "ids", MapType: ebpf.Hash, Op: attach.MapOpLookup, File: "p.c", Line: 16},
		}},
	}}
	n := nodeMaps{maps: maps, sites: matchLoadCalls(maps, load["entry"])}
	// Two maps reach next_stage: each keeps its own keys.
	children := []attach.ReachableProgram{{ProgID: 3, ProgName: "next_stage", Via: "tailcall", MapID: 9, Keys: []uint32{0, 1, 7},
		Maps: []attach.MapKeys{{MapID: 9, Keys: []uint32{0, 1}}, {MapID: 10, Keys: []uint32{7}}}}}
	tree := progNode(2, "entry", "", n, children, func(c attach.ReachableProgram, edge string) treeNode {
		return progNode(c.ProgID, c.ProgName, edge, nodeMaps{maps: attach.ProgMaps{Funcs: []attach.FuncMaps{{Name: "next_stage"}}}}, nil, nil)
	})
	var out strings.Builder
	printTree(&out, tree)
	want := `prog 2  entry
├─ func entry  (calls: classify)
│  ├─ map stats  Array         lookup     p.c:29  ✓ injectable  (inlined, pc 6)
│  ├─ map jmp    ProgramArray  tail_call  p.c:35  → prog 3
│  └─ map alt    ProgramArray  tail_call  p.c:36  → prog 3
├─ func classify
│  ├─ map flows  Hash          lookup     p.c:11  ✗ not in the entry function  (pc 9)
│  ├─ map flows  Hash          update     p.c:14  - no hook yet  (pc 20)
│  ├─ map flows  Hash          update     p.c:14  - no hook yet  (pc 25)
│  ├─ map flows  Hash          update     p.c:14  ? not in the lookups file
│  └─ map ids    Hash          lookup     p.c:16  ✓ injectable (generic hook)  (pc 30)
└─ prog 3  next_stage  (tail call: jmp[0-1], alt[7])
   └─ func next_stage
`
	if out.String() != want {
		t.Errorf("tree:\n%s\nwant:\n%s", out.String(), want)
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
