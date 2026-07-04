package attach

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/xdp-ninja/internal/testutil"
)

func TestFindXDPProgramNoInterface(t *testing.T) {
	_, err := FindXDPProgram("nonexistent_iface_xyz")
	if err == nil {
		t.Fatal("expected error for nonexistent interface, got nil")
	}
}

func TestListFuncs(t *testing.T) {
	prog := loadTestXDP(t)
	funcs, err := ListFuncs(prog)
	if err != nil {
		t.Fatalf("ListFuncs: %v", err)
	}

	found := map[string]bool{}
	for _, f := range funcs {
		found[f.Name] = true
	}

	if !found["xdp_subfunc_test"] {
		t.Error("expected xdp_subfunc_test in function list")
	}
	if !found["process_packet"] {
		t.Error("expected process_packet in function list")
	}
}

func TestValidateSubfuncValid(t *testing.T) {
	prog := loadTestXDP(t)
	if err := ValidateSubfunc(prog, 0, "process_packet"); err != nil {
		t.Fatalf("ValidateSubfunc for valid func: %v", err)
	}
}

func TestValidateSubfuncNotFound(t *testing.T) {
	prog := loadTestXDP(t)
	err := ValidateSubfunc(prog, 0, "nonexistent_func")
	if err == nil {
		t.Fatal("expected error for nonexistent function, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found', got: %v", err)
	}
	if !strings.Contains(err.Error(), "process_packet") {
		t.Errorf("error should list available functions, got: %v", err)
	}
}

// loadCPUMapProg loads an XDP program eligible to be attached to a CPUMAP
// entry (expected_attach_type BPF_XDP_CPUMAP).
func loadCPUMapProg(t *testing.T) *ebpf.Program {
	t.Helper()
	testutil.SkipIfNotRoot(t)

	spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, testutil.XDPSubfuncSource))
	if err != nil {
		t.Fatalf("loading collection spec: %v", err)
	}
	spec.Programs["xdp_subfunc_test"].AttachType = ebpf.AttachXDPCPUMap

	var objs struct {
		Prog *ebpf.Program `ebpf:"xdp_subfunc_test"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Skipf("loading CPUMAP XDP program (kernel may lack BPF_XDP_CPUMAP): %v", err)
	}
	t.Cleanup(func() { _ = objs.Prog.Close() })
	return objs.Prog
}

// TestScanRedirectMapCPUMap verifies that a downstream XDP program
// attached to a CPUMAP entry is discovered via the redirect_map path.
func TestScanRedirectMapCPUMap(t *testing.T) {
	prog := loadCPUMapProg(t)

	progInfo, err := prog.Info()
	if err != nil {
		t.Fatalf("prog info: %v", err)
	}
	wantID, ok := progInfo.ID()
	if !ok {
		t.Fatal("program has no ID")
	}

	// value layout: struct bpf_cpumap_val { u32 qsize; u32 bpf_prog.fd }
	cpumap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.CPUMap,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
	})
	if err != nil {
		t.Skipf("creating CPUMAP (kernel may lack support): %v", err)
	}
	t.Cleanup(func() { _ = cpumap.Close() })

	val := make([]byte, 8)
	binary.NativeEndian.PutUint32(val[0:4], 192) // qsize
	binary.NativeEndian.PutUint32(val[4:8], uint32(prog.FD()))
	if err := cpumap.Put(uint32(0), val); err != nil {
		t.Skipf("populating CPUMAP with program (kernel may lack support): %v", err)
	}

	targets, err := scanMapForPrograms(cpumap, 0, progNameCache{})
	if err != nil {
		t.Fatalf("scanMapForPrograms: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d: %+v", len(targets), targets)
	}
	got := targets[0]
	if got.Via != "cpumap" {
		t.Errorf("Via = %q, want cpumap", got.Via)
	}
	if got.Key != 0 {
		t.Errorf("Key = %d, want 0", got.Key)
	}
	if got.ProgID != uint32(wantID) {
		t.Errorf("ProgID = %d, want %d", got.ProgID, uint32(wantID))
	}
}

// TestScanRedirectMapSkipsEmptyEntry verifies that a CPUMAP entry with no
// attached program (prog id 0) yields no target.
func TestScanRedirectMapSkipsEmptyEntry(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	cpumap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.CPUMap,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
	})
	if err != nil {
		t.Skipf("creating CPUMAP (kernel may lack support): %v", err)
	}
	t.Cleanup(func() { _ = cpumap.Close() })

	val := make([]byte, 8)
	binary.NativeEndian.PutUint32(val[0:4], 192) // qsize, no program
	if err := cpumap.Put(uint32(0), val); err != nil {
		t.Skipf("populating CPUMAP: %v", err)
	}

	targets, err := scanMapForPrograms(cpumap, 0, progNameCache{})
	if err != nil {
		t.Fatalf("scanMapForPrograms: %v", err)
	}
	if len(targets) != 0 {
		t.Fatalf("expected 0 targets for empty entry, got %d: %+v", len(targets), targets)
	}
}

// TestListReachableProgramsCPUMap exercises the full discovery path: a
// dispatcher XDP program references a CPUMAP, and ListReachablePrograms
// walks prog.Info().MapIDs() to surface the downstream program attached
// to that CPUMAP entry.
func TestListReachableProgramsCPUMap(t *testing.T) {
	down := loadCPUMapProg(t)
	downInfo, err := down.Info()
	if err != nil {
		t.Fatalf("downstream prog info: %v", err)
	}
	wantID, ok := downInfo.ID()
	if !ok {
		t.Fatal("downstream program has no ID")
	}

	cpumap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.CPUMap,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
	})
	if err != nil {
		t.Skipf("creating CPUMAP (kernel may lack support): %v", err)
	}
	t.Cleanup(func() { _ = cpumap.Close() })

	val := make([]byte, 8)
	binary.NativeEndian.PutUint32(val[0:4], 192) // qsize
	binary.NativeEndian.PutUint32(val[4:8], uint32(down.FD()))
	if err := cpumap.Put(uint32(0), val); err != nil {
		t.Skipf("populating CPUMAP with program: %v", err)
	}

	// Minimal dispatcher: load the CPUMAP pointer (creating the used_map
	// relationship that surfaces it in MapIDs), then XDP_PASS.
	dispatcher, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.XDP,
		Instructions: asm.Instructions{
			asm.LoadMapPtr(asm.R1, cpumap.FD()),
			asm.Mov.Imm(asm.R0, 2), // XDP_PASS
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		t.Fatalf("loading dispatcher program: %v", err)
	}
	t.Cleanup(func() { _ = dispatcher.Close() })

	targets, err := ListReachablePrograms(dispatcher)
	if err != nil {
		t.Fatalf("ListReachablePrograms: %v", err)
	}

	var found *ProgTarget
	for i := range targets {
		if targets[i].Via == "cpumap" && targets[i].ProgID == uint32(wantID) {
			found = &targets[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("downstream cpumap program (id=%d) not discovered; got %+v", uint32(wantID), targets)
	}
	if found.Key != 0 {
		t.Errorf("Key = %d, want 0", found.Key)
	}
}

// loadDevMapProg loads an XDP program eligible to be attached to a DEVMAP
// entry (expected_attach_type BPF_XDP_DEVMAP).
func loadDevMapProg(t *testing.T) *ebpf.Program {
	t.Helper()
	testutil.SkipIfNotRoot(t)

	spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, testutil.XDPSubfuncSource))
	if err != nil {
		t.Fatalf("loading collection spec: %v", err)
	}
	spec.Programs["xdp_subfunc_test"].AttachType = ebpf.AttachXDPDevMap

	var objs struct {
		Prog *ebpf.Program `ebpf:"xdp_subfunc_test"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Skipf("loading DEVMAP XDP program (kernel may lack BPF_XDP_DEVMAP): %v", err)
	}
	t.Cleanup(func() { _ = objs.Prog.Close() })
	return objs.Prog
}

// TestScanRedirectMapDevMap verifies that a downstream XDP program attached
// to a DEVMAP entry is discovered. The value layout (bpf_devmap_val) puts
// the program id at the same offset 4 as CPUMAP; the entry targets the
// loopback interface.
func TestScanRedirectMapDevMap(t *testing.T) {
	prog := loadDevMapProg(t)

	progInfo, err := prog.Info()
	if err != nil {
		t.Fatalf("prog info: %v", err)
	}
	wantID, ok := progInfo.ID()
	if !ok {
		t.Fatal("program has no ID")
	}

	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("looking up loopback: %v", err)
	}

	devmap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.DevMap,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
	})
	if err != nil {
		t.Skipf("creating DEVMAP (kernel may lack support): %v", err)
	}
	t.Cleanup(func() { _ = devmap.Close() })

	// value layout: struct bpf_devmap_val { u32 ifindex; u32 bpf_prog.fd }
	val := make([]byte, 8)
	binary.NativeEndian.PutUint32(val[0:4], uint32(lo.Index))
	binary.NativeEndian.PutUint32(val[4:8], uint32(prog.FD()))
	if err := devmap.Put(uint32(0), val); err != nil {
		t.Skipf("populating DEVMAP with program (device may not support XDP): %v", err)
	}

	targets, err := scanMapForPrograms(devmap, 0, progNameCache{})
	if err != nil {
		t.Fatalf("scanMapForPrograms: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d: %+v", len(targets), targets)
	}
	got := targets[0]
	if got.Via != "devmap" {
		t.Errorf("Via = %q, want devmap", got.Via)
	}
	if got.ProgID != uint32(wantID) {
		t.Errorf("ProgID = %d, want %d", got.ProgID, uint32(wantID))
	}
}

// TestScanRedirectMapDevMapHash covers the DEVMAP_HASH routing branch.
// Like DEVMAP and CPUMAP, DEVMAP_HASH requires key_size == 4 (u32 keys),
// so the shared uint32 iteration in scanRedirectMap applies. The value
// layout (bpf_devmap_val) is identical to DEVMAP.
func TestScanRedirectMapDevMapHash(t *testing.T) {
	prog := loadDevMapProg(t)

	progInfo, err := prog.Info()
	if err != nil {
		t.Fatalf("prog info: %v", err)
	}
	wantID, ok := progInfo.ID()
	if !ok {
		t.Fatal("program has no ID")
	}

	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("looking up loopback: %v", err)
	}

	devmap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.DevMapHash,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 4,
	})
	if err != nil {
		t.Skipf("creating DEVMAP_HASH (kernel may lack support): %v", err)
	}
	t.Cleanup(func() { _ = devmap.Close() })

	val := make([]byte, 8)
	binary.NativeEndian.PutUint32(val[0:4], uint32(lo.Index))
	binary.NativeEndian.PutUint32(val[4:8], uint32(prog.FD()))
	// DEVMAP_HASH keys are arbitrary u32; use a non-zero sparse key.
	const key = uint32(42)
	if err := devmap.Put(key, val); err != nil {
		t.Skipf("populating DEVMAP_HASH with program (device may not support XDP): %v", err)
	}

	targets, err := scanMapForPrograms(devmap, 0, progNameCache{})
	if err != nil {
		t.Fatalf("scanMapForPrograms: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d: %+v", len(targets), targets)
	}
	got := targets[0]
	if got.Via != "devmap_hash" {
		t.Errorf("Via = %q, want devmap_hash", got.Via)
	}
	if got.Key != key {
		t.Errorf("Key = %d, want %d", got.Key, key)
	}
	if got.ProgID != uint32(wantID) {
		t.Errorf("ProgID = %d, want %d", got.ProgID, uint32(wantID))
	}
}

// TestScanProgArraySkipsEmptySlot verifies that a sparse PROG_ARRAY (only
// some slots populated) does not abort discovery on the empty slots, which
// enumerate as id 0.
func TestScanProgArraySkipsEmptySlot(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	// A tiny XDP program to serve as the single populated tail-call target.
	target, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "tc_target",
		Type: ebpf.XDP,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 2), // XDP_PASS
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		t.Fatalf("target prog: %v", err)
	}
	t.Cleanup(func() { _ = target.Close() })
	tInfo, err := target.Info()
	if err != nil {
		t.Fatalf("target prog info: %v", err)
	}
	wantID, ok := tInfo.ID()
	if !ok {
		t.Fatal("target program has no ID")
	}

	progArray, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.ProgramArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 4, // slots 0,1,3 stay empty
	})
	if err != nil {
		t.Skipf("creating PROG_ARRAY: %v", err)
	}
	t.Cleanup(func() { _ = progArray.Close() })

	if err := progArray.Put(uint32(2), uint32(target.FD())); err != nil {
		t.Skipf("populating PROG_ARRAY: %v", err)
	}

	targets, err := scanMapForPrograms(progArray, 0, progNameCache{})
	if err != nil {
		t.Fatalf("scanMapForPrograms on sparse PROG_ARRAY: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d: %+v", len(targets), targets)
	}
	got := targets[0]
	if got.Via != "tailcall" {
		t.Errorf("Via = %q, want tailcall", got.Via)
	}
	if got.Key != 2 {
		t.Errorf("Key = %d, want 2", got.Key)
	}
	if got.ProgID != uint32(wantID) {
		t.Errorf("ProgID = %d, want %d", got.ProgID, uint32(wantID))
	}
}

// TestWalkReachableProgramsTransitive builds a two-stage dispatch chain
// (dispatcher -> CPUMAP -> mid -> PROG_ARRAY -> leaf) and verifies the
// walk descends through both hops, deduping and assigning depths.
func TestWalkReachableProgramsTransitive(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	// leaf: final tail-call target.
	leaf, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "leaf_prog",
		Type:         ebpf.XDP,
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()},
		License:      "GPL",
	})
	if err != nil {
		t.Fatalf("leaf prog: %v", err)
	}
	t.Cleanup(func() { _ = leaf.Close() })
	leafInfo, _ := leaf.Info()
	leafID, ok := leafInfo.ID()
	if !ok {
		t.Fatal("leaf has no ID")
	}

	progArray, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.ProgramArray, KeySize: 4, ValueSize: 4, MaxEntries: 4,
	})
	if err != nil {
		t.Skipf("prog array: %v", err)
	}
	t.Cleanup(func() { _ = progArray.Close() })
	if err := progArray.Put(uint32(1), uint32(leaf.FD())); err != nil {
		t.Skipf("prog array put: %v", err)
	}

	// mid: a CPUMAP-eligible program that references the PROG_ARRAY.
	mid, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:       "mid_jump",
		Type:       ebpf.XDP,
		AttachType: ebpf.AttachXDPCPUMap,
		Instructions: asm.Instructions{
			asm.LoadMapPtr(asm.R1, progArray.FD()),
			asm.Mov.Imm(asm.R0, 2),
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		t.Skipf("mid prog (kernel may lack BPF_XDP_CPUMAP): %v", err)
	}
	t.Cleanup(func() { _ = mid.Close() })
	midInfo, _ := mid.Info()
	midID, ok := midInfo.ID()
	if !ok {
		t.Fatal("mid has no ID")
	}

	cpumap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.CPUMap, KeySize: 4, ValueSize: 8, MaxEntries: 2,
	})
	if err != nil {
		t.Skipf("cpumap: %v", err)
	}
	t.Cleanup(func() { _ = cpumap.Close() })
	cval := make([]byte, 8)
	binary.NativeEndian.PutUint32(cval[0:4], 192)
	binary.NativeEndian.PutUint32(cval[4:8], uint32(mid.FD()))
	// two slots -> same mid prog, must collapse to one entry.
	if err := cpumap.Put(uint32(0), cval); err != nil {
		t.Skipf("cpumap put: %v", err)
	}
	if err := cpumap.Put(uint32(1), cval); err != nil {
		t.Skipf("cpumap put: %v", err)
	}

	dispatcher, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "root_dispatch",
		Type: ebpf.XDP,
		Instructions: asm.Instructions{
			asm.LoadMapPtr(asm.R1, cpumap.FD()),
			asm.Mov.Imm(asm.R0, 2),
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		t.Fatalf("dispatcher prog: %v", err)
	}
	t.Cleanup(func() { _ = dispatcher.Close() })
	dInfo, _ := dispatcher.Info()
	dID, _ := dInfo.ID()

	progs, err := WalkReachablePrograms(dispatcher, uint32(dID))
	if err != nil {
		t.Fatalf("WalkReachablePrograms: %v", err)
	}

	byID := map[uint32]ReachableProgram{}
	for _, p := range progs {
		byID[p.ProgID] = p
	}

	m, ok := byID[uint32(midID)]
	if !ok {
		t.Fatalf("mid (id=%d) not reached; got %+v", uint32(midID), progs)
	}
	if m.Via != "cpumap" || m.Depth != 1 || m.ParentID != uint32(dID) {
		t.Errorf("mid edge = %+v, want via=cpumap depth=1 parent=%d", m, uint32(dID))
	}
	if len(m.Keys) != 2 || m.Keys[0] != 0 || m.Keys[1] != 1 {
		t.Errorf("mid keys = %v, want [0 1] (collapsed CPUMAP slots)", m.Keys)
	}

	l, ok := byID[uint32(leafID)]
	if !ok {
		t.Fatalf("leaf (id=%d) not reached transitively; got %+v", uint32(leafID), progs)
	}
	if l.Via != "tailcall" || l.Depth != 2 || l.ParentID != uint32(midID) {
		t.Errorf("leaf edge = %+v, want via=tailcall depth=2 parent=%d", l, uint32(midID))
	}
}

// tailProgVia builds a tiny XDP program that references map m (so m shows
// up in its MapIDs), used to chain tail-call stages in tests.
func tailProgVia(t *testing.T, name string, m *ebpf.Map) *ebpf.Program {
	t.Helper()
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: name,
		Type: ebpf.XDP,
		Instructions: asm.Instructions{
			asm.LoadMapPtr(asm.R1, m.FD()),
			asm.Mov.Imm(asm.R0, 2),
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		t.Fatalf("prog %s: %v", name, err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func newProgArray(t *testing.T) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.ProgramArray, KeySize: 4, ValueSize: 4, MaxEntries: 4,
	})
	if err != nil {
		t.Skipf("prog array: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// TestWalkReachableProgramsDeepChain proves the walk has no depth cap: a
// 5-stage tail-call chain (root -> p1 -> p2 -> p3 -> p4 -> p5) is fully
// discovered, each at the expected depth.
func TestWalkReachableProgramsDeepChain(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	const stages = 5

	// Build from the leaf backwards so each stage can reference the map
	// holding the already-loaded next stage.
	leafArray := newProgArray(t)
	leaf, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "stage5",
		Type:         ebpf.XDP,
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()},
		License:      "GPL",
	})
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	t.Cleanup(func() { _ = leaf.Close() })
	if err := leafArray.Put(uint32(0), uint32(leaf.FD())); err != nil {
		t.Skipf("leaf array put: %v", err)
	}

	// wantDepth[progID] = expected depth from root.
	wantDepth := map[uint32]int{}
	li, _ := leaf.Info()
	if id, ok := li.ID(); ok {
		wantDepth[uint32(id)] = stages
	}

	// next stage references the current stage's array; wire successively.
	curArray := leafArray
	for s := stages - 1; s >= 1; s-- {
		prog := tailProgVia(t, fmt.Sprintf("stage%d", s), curArray)
		pi, _ := prog.Info()
		if id, ok := pi.ID(); ok {
			wantDepth[uint32(id)] = s
		}
		arr := newProgArray(t)
		if err := arr.Put(uint32(1), uint32(prog.FD())); err != nil {
			t.Skipf("stage%d array put: %v", s, err)
		}
		curArray = arr
	}

	root := tailProgVia(t, "stage0_root", curArray)
	ri, _ := root.Info()
	rootID, _ := ri.ID()

	progs, err := WalkReachablePrograms(root, uint32(rootID))
	if err != nil {
		t.Fatalf("WalkReachablePrograms: %v", err)
	}

	gotDepth := map[uint32]int{}
	for _, p := range progs {
		gotDepth[p.ProgID] = p.Depth
	}
	if len(gotDepth) != stages {
		t.Fatalf("discovered %d programs, want %d: %+v", len(gotDepth), stages, progs)
	}
	for id, want := range wantDepth {
		if gotDepth[id] != want {
			t.Errorf("prog id=%d depth = %d, want %d", id, gotDepth[id], want)
		}
	}
}

func TestMatchProgramsByName(t *testing.T) {
	// Root plus a reachable tree; names are kernel-truncated (<=15 chars).
	root := "cpu_dispatch"
	reach := []ReachableProgram{
		{ProgID: 1610, ProgName: "upf_dl_v4"},
		{ProgID: 1611, ProgName: "upf_dl_v6"},
		{ProgID: 1614, ProgName: "upf_ul_v4"},
		{ProgID: 99, ProgName: "upf_capture_poi"}, // truncated form of upf_capture_point_dl
		{ProgID: 88, ProgName: "dup_name"},
		{ProgID: 89, ProgName: "dup_name"}, // same name -> ambiguous
		{ProgID: 42, ProgName: ""},         // nameless, never matches
	}

	// Exact match on the root and a leaf.
	got, err := MatchProgramsByName(1600, root, reach, []string{"cpu_dispatch", "upf_ul_v4"})
	if err != nil {
		t.Fatalf("exact: %v", err)
	}
	if len(got) != 2 || got[0] != 1600 || got[1] != 1614 {
		t.Errorf("exact got %v, want [1600 1614]", got)
	}

	// A full (untruncated) name matches its truncated candidate by prefix.
	got, err = MatchProgramsByName(1600, root, reach, []string{"upf_capture_point_dl"})
	if err != nil {
		t.Fatalf("prefix: %v", err)
	}
	if len(got) != 1 || got[0] != 99 {
		t.Errorf("prefix got %v, want [99]", got)
	}

	// A genuinely short name (not truncated) must NOT falsely match a longer
	// requested name for a different program.
	if _, err := MatchProgramsByName(1600, root, reach, []string{"upf_ul_v4_extra"}); err == nil || !strings.Contains(err.Error(), "no reachable program") {
		t.Errorf("short-name false match: %v", err)
	}

	// Unknown name errors and lists the available names.
	if _, err := MatchProgramsByName(1600, root, reach, []string{"nope"}); err == nil || !strings.Contains(err.Error(), "no reachable program") {
		t.Errorf("unknown: %v", err)
	}

	// Two programs share a (truncated) name, so the name is ambiguous and
	// the error lists both ids for the user to disambiguate with -p.
	if _, err := MatchProgramsByName(1600, root, reach, []string{"dup_name"}); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("ambiguous: %v", err)
	}
}
